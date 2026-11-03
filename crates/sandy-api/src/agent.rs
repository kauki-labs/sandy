//! The agent-launch contract (#216, #238): how a backend launches the sandbox
//! agent, hands the orchestrator-side relay its end of the agent link, and
//! learns the job's result.
//!
//! Shared by every backend that runs jobs behind the agent: the process backend
//! (the link is a socket pair on the agent's stdin) and the VM backends (the
//! link is a vsock stream to the guest agent). The backend takes a job's exit
//! code only from the relay's [`AgentReport`], never from the agent's process
//! status: under a wrapper that status is the wrapper's, and the job could
//! signal the agent to fake one (INV-11).

use std::{
    os::fd::OwnedFd,
    path::PathBuf,
    sync::{
        Arc,
        mpsc::{Receiver, SyncSender, sync_channel},
    },
};

/// Called with a run's box id, the host end of its agent link, and the handle
/// to report the run's verdict on, right after the agent is launched.
///
/// It runs on a thread the backend owns (the one that called
/// [`VmBackend::run`](crate::backend::VmBackend::run), or a VM backend's link
/// connector), with no async runtime guaranteed. It must not block (start the relay
/// elsewhere and return) and should not panic; a panic fails the run as an
/// infra fault.
pub type OnLink = Arc<dyn Fn(&str, OwnedFd, AgentReport) + Send + Sync>;

/// The vsock port a VM backend's guest agent listens on for its link (#238).
pub const AGENT_VSOCK_PORT: u32 = 5_000;

/// The byte the guest agent writes as soon as it accepts the host's link
/// connection (#238). A hypervisor's vsock proxy (vfkit) accepts the host's
/// socket before it dials the guest, so a connected socket alone does not mean
/// the agent is there; the host hands the link to the relay, which writes the
/// cap first, only after this byte arrives.
pub const AGENT_LINK_READY: u8 = b'S';

/// The vsock port `sandy-agent port-relay` listens on in a guest (#590): one service relay per environment. The host
/// bridge reaches it as `<guest CID>:5100` over vhost-vsock on qemu, and through a
/// `virtio-vsock,port=5100,socketURL=<path>,connect` device declared before boot on vfkit. A vsock port is per guest,
/// so one fixed number serves every environment. It differs from [`AGENT_VSOCK_PORT`] (5000) and the egress proxy's
/// port (5001).
pub const PORT_RELAY_VSOCK_PORT: u32 = 5_100;

/// The byte `sandy-agent port-relay` writes to the host once it has connected to the guest service (#590).
/// A hypervisor's vsock proxy (vfkit) accepts the host's socket before it dials the guest, and the relay accepts
/// the host's vsock connection before it dials the service, so a connected socket proves neither. The host bridge
/// counts a dial as successful only after this byte arrives, and retries otherwise.
pub const PORT_RELAY_READY: u8 = b'P';

/// How a backend launches the sandbox agent.
///
/// An agent-mode backend runs ONE job: its `on_link` serves one cap on one
/// channel, and re-joining with a cap replays that channel's earlier stdin into
/// the next job. Build one per sandbox run.
#[derive(Clone)]
pub struct AgentLaunch {
    /// The `sandy-agent` binary, as a path the launcher can execute: a host path
    /// for the process backend, the guest's store path for a VM.
    pub program: PathBuf,
    /// Receives each run's host end of the agent link.
    pub on_link: OnLink,
}

impl std::fmt::Debug for AgentLaunch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentLaunch")
            .field("program", &self.program)
            .finish_non_exhaustive()
    }
}

/// What the relay concluded about one agent-mode run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentVerdict {
    /// The agent reported the job's exit code (`128 + signal` for a signal death).
    JobExited(i32),
    /// The agent failed: refused, faulted, or ended without reporting.
    AgentFailed(String),
}

/// The relay's handle for reporting one run's verdict back to the backend.
/// Dropping it without a report leaves the backend's receiver disconnected,
/// which the backend treats as an infra fault.
#[derive(Debug)]
pub struct AgentReport(SyncSender<AgentVerdict>);

impl AgentReport {
    /// A report handle for the relay and the backend's receiving end for it.
    #[must_use]
    pub fn channel() -> (Self, Receiver<AgentVerdict>) {
        let (report, verdict) = sync_channel(1);
        (Self(report), verdict)
    }

    /// The agent reported that the job exited with `code`.
    pub fn job_exited(self, code: i32) {
        let _ = self.0.send(AgentVerdict::JobExited(code));
    }

    /// The agent failed before or without reporting the job's exit: the run is
    /// an infra fault, not a job result (INV-11).
    pub fn agent_failed(self, why: impl Into<String>) {
        let _ = self.0.send(AgentVerdict::AgentFailed(why.into()));
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc::RecvError;

    use super::*;

    /// A vsock port is per guest, so the service relay needs one number, but it must not collide with the other
    /// ports the host and guest agree on (the agent link on 5000, the egress proxy on 5001). It must also be a
    /// privileged port: the kernel lets only a process with `CAP_NET_BIND_SERVICE` bind a vsock port of 1023 or
    /// below, so a harness running as the unprivileged service user cannot squat the relay's port and answer the
    /// bridge's dial with the ready byte.
    #[test]
    fn the_service_relay_port_is_privileged_and_collides_with_no_other_guest_port() {
        assert_eq!(PORT_RELAY_VSOCK_PORT, 1_000);
        assert!(
            PORT_RELAY_VSOCK_PORT <= 1_023,
            "a port above 1023 can be bound by any guest process"
        );
        for other in [AGENT_VSOCK_PORT, 5_001] {
            assert_ne!(PORT_RELAY_VSOCK_PORT, other);
        }
    }

    #[test]
    fn a_report_reaches_the_backend_once() {
        let (report, verdict) = AgentReport::channel();
        report.job_exited(7);
        assert_eq!(verdict.recv(), Ok(AgentVerdict::JobExited(7)));
        assert_eq!(verdict.recv(), Err(RecvError), "a report is delivered once");

        let (report, verdict) = AgentReport::channel();
        report.agent_failed("refused");
        assert_eq!(verdict.recv(), Ok(AgentVerdict::AgentFailed("refused".to_string())));
    }

    #[test]
    fn a_dropped_report_disconnects_the_backend() {
        let (report, verdict) = AgentReport::channel();
        drop(report);
        assert_eq!(verdict.recv(), Err(RecvError), "no report must not look like a verdict");
    }
}
