//! The process backend: a [`VmBackend`] that runs the sandbox as a raw OS
//! process on the host, with no VM. This is the trivial-local executor of the
//! fabric's Executor seam (#131 / #103): it advertises [`SandboxKind::Process`]
//! so a job that needs a real VM is refused (via `sandy::backend_accepts`),
//! captures the process's stdout and stderr as the [`Outcome::console`] tail and
//! its exit code as [`Outcome::guest_exit`], and honours the wall-clock timeout.
//!
//! INV-11: a non-zero exit is a real result (`guest_exit`), never a
//! `transport_error`; only an actual spawn/IO fault is an infra fault. A spawn
//! failure is [`BackendError::Spawn`] (the supervisor maps it to band 3,
//! retryable); a process that merely exits non-zero returns an [`Outcome`].
//!
//! INV-1: secrets are never placed on argv or env here. The process reads a
//! secret from the local-dir secret share (T4), the same 0600-file channel the
//! VM uses. The process backend provides no env isolation of its own (it is not
//! a security boundary — the VM backend is); it runs with the parent environment
//! plus `spec.env`, and the containment story is the sandbox kind, not this impl.

use std::{
    process::{Command, Stdio},
    sync::{Mutex, MutexGuard},
    time::SystemTime,
};

use sandy::{BackendError, BoxState, Outcome, RunSpec, SandboxKind, VmBackend};
use uuid::Uuid;

/// A [`VmBackend`] that runs the job as a raw OS process (no VM).
///
/// Owns its running-instance registry so [`boxes`](VmBackend::boxes) reports live
/// state. The run is synchronous: a box is present only while its
/// [`run`](VmBackend::run) call is in flight.
#[derive(Debug, Default)]
pub struct ProcessBackend {
    instances: Mutex<Vec<BoxState>>,
}

impl ProcessBackend {
    /// A backend with an empty instance registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Lock the instance registry, mapping a poisoned mutex to a typed error
    /// rather than panicking (no `.unwrap()` in library code).
    fn registry(&self) -> Result<MutexGuard<'_, Vec<BoxState>>, BackendError> {
        self.instances
            .lock()
            .map_err(|_| BackendError::Protocol("process instance registry mutex poisoned".to_string()))
    }
}

impl VmBackend for ProcessBackend {
    fn run(&self, spec: &RunSpec) -> Result<Outcome, BackendError> {
        // STUB (slice-B red): return a wrong outcome so the tests below fail on
        // behaviour, not compilation, before the real spawn/capture lands.
        let _ = (spec, Command::new("true").stdin(Stdio::null()));
        Ok(Outcome {
            booted: false,
            guest_exit: None,
            transport_error: None,
            timed_out: false,
            console: String::new(),
        })
    }

    fn kill(&self, box_id: &str) -> Result<(), BackendError> {
        self.registry()?.retain(|state| state.box_id != box_id);
        Ok(())
    }

    fn boxes(&self) -> Result<Vec<BoxState>, BackendError> {
        Ok(self.registry()?.clone())
    }

    fn kind(&self) -> SandboxKind {
        SandboxKind::Process
    }
}

#[cfg(test)]
mod tests {
    use sandy::Grants;

    use super::*;

    fn run_spec<'a>(command: &'a [String], grants: &'a Grants, timeout_secs: u32) -> RunSpec<'a> {
        RunSpec {
            template: "process",
            command,
            inputs: &[],
            outputs: &[],
            secrets: &[],
            env: &[],
            cpu: None,
            mem: None,
            timeout_secs,
            grants,
            outcome_file: None,
            secret_dir: None,
        }
    }

    fn no_grants() -> Grants {
        Grants {
            secrets: false,
            agent: false,
            shares: false,
        }
    }

    /// A non-zero exit is a real result: the process ran (booted), its exit code
    /// is carried on `guest_exit`, its output is on the console, and it is NOT a
    /// transport fault (INV-11 — a clean non-zero exit must not collapse to infra).
    #[test]
    fn runs_a_command_and_captures_a_nonzero_exit() -> anyhow::Result<()> {
        let grants = no_grants();
        let command = ["sh".to_string(), "-c".to_string(), "printf hi; exit 7".to_string()];
        let spec = run_spec(&command, &grants, 30);

        let outcome = ProcessBackend::new().run(&spec)?;

        assert!(outcome.booted, "a spawned process booted");
        assert_eq!(outcome.guest_exit, Some(7), "the real exit code is carried");
        assert!(
            outcome.console.contains("hi"),
            "stdout is captured, got {:?}",
            outcome.console
        );
        assert!(
            outcome.transport_error.is_none(),
            "a non-zero exit is not a transport fault"
        );
        assert!(!outcome.timed_out, "the job completed, it did not time out");
        Ok(())
    }

    /// A clean success is exit 0, booted, no transport error.
    #[test]
    fn a_successful_command_exits_zero() -> anyhow::Result<()> {
        let grants = no_grants();
        let command = ["true".to_string()];
        let spec = run_spec(&command, &grants, 30);

        let outcome = ProcessBackend::new().run(&spec)?;

        assert!(outcome.booted);
        assert_eq!(outcome.guest_exit, Some(0));
        assert!(outcome.transport_error.is_none());
        Ok(())
    }

    /// The backend advertises `Process`, so `backend_accepts` refuses a VM job.
    #[test]
    fn kind_is_process_and_refuses_a_vm_job() {
        assert_eq!(ProcessBackend::new().kind(), SandboxKind::Process);
        assert!(!sandy::backend_accepts(ProcessBackend::new().kind(), SandboxKind::Vm));
    }
}
