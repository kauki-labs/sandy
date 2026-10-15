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
    io::Read,
    os::unix::process::ExitStatusExt,
    process::{Command, Stdio},
    sync::{Mutex, MutexGuard},
    thread::JoinHandle,
    time::{Duration, Instant, SystemTime},
};

use sandy::{BackendError, BoxState, Outcome, RunSpec, SandboxKind, VmBackend};
use uuid::Uuid;

/// Cap the captured console so a chatty job cannot grow the outcome without
/// bound; the last bytes are kept, matching the VM console's bounded-tail intent.
const CONSOLE_TAIL_CAP: usize = 64 * 1024;

/// Poll interval while waiting for the child, so the wall-clock timeout can
/// interrupt a hung job (a blocking `wait()` cannot).
const POLL: Duration = Duration::from_millis(10);

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
        let Some((program, args)) = spec.command.split_first() else {
            return Err(BackendError::Spawn("empty command".to_string()));
        };

        // INV-1: only spec.env reaches the child, and the plan guarantees it
        // carries no secret (validate_no_secret_leak); secret bytes ride the
        // secret share, never argv/env.
        let spawned = Command::new(program)
            .args(args)
            .envs(spec.env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn();
        let mut child = match spawned {
            Ok(child) => child,
            // A spawn fault is infra (band 3, retryable), not a run result.
            Err(err) => return Err(BackendError::Spawn(format!("spawn `{program}`: {err}"))),
        };

        let box_id = Uuid::new_v4().to_string();
        self.registry()?.push(BoxState {
            box_id: box_id.clone(),
            box_name: spec.template.to_string(),
            pid: child.id(),
            started: SystemTime::now(),
            rvport: None,
        });

        // Drain both pipes on threads: an un-read piped stdout/stderr deadlocks a
        // chatty child once it fills the pipe buffer.
        let out_drain = child.stdout.take().map(drain);
        let err_drain = child.stderr.take().map(drain);

        // Wait against the wall-clock budget, polling so a timeout can kill a hung
        // child rather than block forever.
        let deadline = Instant::now() + Duration::from_secs(u64::from(spec.timeout_secs));
        let mut timed_out = false;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Some(status),
                Ok(None) => {
                    if Instant::now() >= deadline {
                        let _ = child.kill();
                        let _ = child.wait();
                        timed_out = true;
                        break None;
                    }
                    std::thread::sleep(POLL);
                }
                Err(err) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    self.registry()?.retain(|state| state.box_id != box_id);
                    return Err(BackendError::Transport(format!("wait on child `{program}`: {err}")));
                }
            }
        };

        self.registry()?.retain(|state| state.box_id != box_id);

        let stdout = out_drain.and_then(|h| h.join().ok()).unwrap_or_default();
        let stderr = err_drain.and_then(|h| h.join().ok()).unwrap_or_default();
        let console = merged_console(&stdout, &stderr);

        // INV-11: the process ran (booted), so its exit is a task result on
        // guest_exit, never a transport fault. A signal death maps to 128+signal
        // (shell convention) so it stays a task failure, not infra. A timeout
        // leaves guest_exit None; classification keys off timed_out first.
        let guest_exit = if timed_out {
            None
        } else {
            status.and_then(|s| s.code().or_else(|| s.signal().map(|sig| 128 + sig)))
        };

        Ok(Outcome {
            booted: true,
            guest_exit,
            transport_error: None,
            timed_out,
            console,
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

/// Drain a child pipe on its own thread, keeping only the last
/// [`CONSOLE_TAIL_CAP`] bytes, so a chatty child never blocks on a full pipe and
/// the console stays bounded. Returns the retained bytes when the thread joins.
fn drain<R: Read + Send + 'static>(mut reader: R) -> JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 8192];
        while let Ok(n) = reader.read(&mut chunk) {
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
            if buf.len() > CONSOLE_TAIL_CAP {
                buf.drain(..buf.len() - CONSOLE_TAIL_CAP);
            }
        }
        buf
    })
}

/// Combine the child's stdout and stderr into one bounded console string, stdout
/// then stderr, capped to the last [`CONSOLE_TAIL_CAP`] bytes.
fn merged_console(stdout: &[u8], stderr: &[u8]) -> String {
    let mut buf = Vec::with_capacity(stdout.len() + stderr.len());
    buf.extend_from_slice(stdout);
    buf.extend_from_slice(stderr);
    if buf.len() > CONSOLE_TAIL_CAP {
        buf.drain(..buf.len() - CONSOLE_TAIL_CAP);
    }
    String::from_utf8_lossy(&buf).into_owned()
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

    /// A job that outlives its wall-clock budget is killed near the deadline and
    /// reported `timed_out`, not run to completion.
    #[test]
    fn a_job_over_its_timeout_is_killed_and_marked_timed_out() -> anyhow::Result<()> {
        let grants = no_grants();
        let command = ["sh".to_string(), "-c".to_string(), "sleep 30".to_string()];
        let spec = run_spec(&command, &grants, 1);

        let start = Instant::now();
        let outcome = ProcessBackend::new().run(&spec)?;

        assert!(outcome.timed_out, "the job exceeded its 1s budget");
        assert!(outcome.booted, "it did spawn");
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "it was killed near the deadline, not after the full sleep"
        );
        Ok(())
    }

    /// The backend advertises `Process`, so `backend_accepts` refuses a VM job.
    #[test]
    fn kind_is_process_and_refuses_a_vm_job() {
        assert_eq!(ProcessBackend::new().kind(), SandboxKind::Process);
        assert!(!sandy::backend_accepts(ProcessBackend::new().kind(), SandboxKind::Vm));
    }
}
