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
//! Shares (inputs, outputs, secret) are staged by the shared `plan_shares` policy
//! into per-run dirs and presented via [`LocalDirTransport`]: the job reads each
//! at `SANDY_<TAG>_DIR` (e.g. `SANDY_INPUTS_DIR`), read-only shares made
//! unwritable cooperatively (`chmod a-w`). This diverges from the VM's fixed
//! `/run/sandy/...` mount paths (a weak-isolation divergence; namespace-faithful
//! paths are deferred to #135). Outputs are collected to each `Output::dest` at
//! teardown and the staging is wiped on every path.
//!
//! INV-1: secrets are never placed on argv or env here. The process reads a
//! secret from the local-dir secret share's 0600 files, the same channel the VM
//! uses; `SANDY_SECRETS_DIR` carries the dir PATH, never the bytes. The host
//! environment is cleared and only `PATH` (so commands resolve)
//! plus `spec.env` reach the child, so the ambient operator env (AWS_*,
//! GITHUB_TOKEN, …) never leaks into an untrusted job; anything else a job needs
//! (HOME/TERM) is passed explicitly in `spec.env`. When a containment wrapper is
//! active it also passes through its own non-secret plumbing env (e.g. systemd-run's
//! `XDG_RUNTIME_DIR`), named by [`Containment::passthrough_env`](sandy::Containment::passthrough_env). The child is
//! spawned as the leader of its own process group, so a timeout or teardown reaps the whole
//! group: a backgrounded descendant in the group is killed, no host orphan.
//! `run()` is always bounded — the console drains are read under a grace deadline,
//! never joined — so even a descendant that escapes the group via `setsid`/
//! `setpgid` cannot hang the run past its budget.
//!
//! Reaping such an escapee needs cgroup-level containment, which the backend reaches
//! through the injected [`Containment`](sandy::Containment) seam (#135): when it
//! reports [`Available`](sandy::ContainmentStatus::Available) the job is launched
//! inside a delegated cgroup scope and [`reap`](sandy::Containment::reap) destroys
//! the whole tree on exit/timeout/kill, escapees included. The default is
//! [`NoContainment`](sandy::NoContainment) (no cgroup), under which the backend
//! keeps its best-effort process-group reap and an escapee can still survive as a
//! host orphan — so the fail-closed gate ([`sandy::admits_untrusted`]) refuses an
//! UNTRUSTED job on an uncontained process backend. The VM backend remains the
//! strong boundary.

use std::{
    fs,
    io::Read,
    os::unix::process::ExitStatusExt,
    path::Path,
    process::{Command, Stdio},
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant, SystemTime},
};

use command_group::CommandGroup;
use sandy::{
    BackendError, BoxState, Containment, ContainmentStatus, NoContainment, Outcome, ResourceLimits, RunSpec,
    SandboxKind, ShareDirs, VmBackend, collect_outputs, ensure_sandy_staging_base, plan_shares, wipe,
};
use sandy_api::share::{GuestShareTransport, Presentation};
use uuid::Uuid;

use crate::share::LocalDirTransport;

/// Cap the captured console so a chatty job cannot grow the outcome without
/// bound; the last bytes are kept, matching the VM console's bounded-tail intent.
const CONSOLE_TAIL_CAP: usize = 64 * 1024;

/// Poll interval while waiting for the child, so the wall-clock timeout can
/// interrupt a hung job (a blocking `wait()` cannot).
const POLL: Duration = Duration::from_millis(10);

/// After the child's process group is reaped, how long to let the console-drain
/// threads flush before taking whatever they captured. A descendant that escaped
/// the group (`setsid`/`setpgid`) can hold the pipe open forever, so the drains
/// are NEVER joined unconditionally — `run()` stays bounded regardless of the job.
const DRAIN_GRACE: Duration = Duration::from_secs(2);

/// A [`VmBackend`] that runs the job as a raw OS process (no VM).
///
/// Owns its running-instance registry so [`boxes`](VmBackend::boxes) reports live
/// state. The run is synchronous: a box is present only while its
/// [`run`](VmBackend::run) call is in flight.
#[derive(Debug)]
pub struct ProcessBackend {
    instances: Mutex<Vec<BoxState>>,
    /// How a job is confined (#135). The default [`NoContainment`] keeps the backend
    /// hermetic and uncontained (best-effort group reap only); the composition root
    /// injects the host [`SystemdRunContainment`](crate::SystemdRunContainment).
    containment: Box<dyn Containment>,
}

impl Default for ProcessBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcessBackend {
    /// A backend with an empty instance registry and no containment (the uncontained
    /// MVP: best-effort process-group reap, refused for untrusted jobs by the gate).
    #[must_use]
    pub fn new() -> Self {
        Self::with_containment(Box::new(NoContainment))
    }

    /// A backend confined by `containment` (the host `SystemdRunContainment`, or a
    /// test double). The backend reaps each run's container on exit/timeout/kill.
    #[must_use]
    pub fn with_containment(containment: Box<dyn Containment>) -> Self {
        Self {
            instances: Mutex::new(Vec::new()),
            containment,
        }
    }

    /// The containment's current [`ContainmentStatus`], for the fail-closed gate
    /// ([`sandy::admits_untrusted`]) and `sandy doctor`.
    #[must_use]
    pub fn containment_status(&self) -> ContainmentStatus {
        self.containment.status()
    }

    /// Lock the instance registry, mapping a poisoned mutex to a typed error
    /// rather than panicking (no `.unwrap()` in library code).
    fn registry(&self) -> Result<MutexGuard<'_, Vec<BoxState>>, BackendError> {
        self.instances
            .lock()
            .map_err(|_| BackendError::Protocol("process instance registry mutex poisoned".to_string()))
    }

    /// Stage the run's shares into the per-run dirs, present them as local dirs
    /// (`SANDY_<TAG>_DIR` env, cooperative read-only), and run the job to
    /// completion or the timeout as a reaped process group. The caller
    /// ([`run`](VmBackend::run)) owns output collection and the wipe, so this
    /// returns the raw [`Outcome`] (or an infra [`BackendError`]) and never leaves
    /// a box registered on a returning path.
    fn run_staged(
        &self,
        spec: &RunSpec,
        run_id: Uuid,
        inst_dir: &Path,
        inputs_dir: &Path,
        outputs_dir: &Path,
    ) -> Result<Outcome, BackendError> {
        // The job's own program, kept for diagnostics: the launch program below may
        // be the containment wrapper (e.g. `systemd-run`), not the job.
        let (job_program, _) = spec
            .command
            .split_first()
            .ok_or_else(|| BackendError::Spawn("empty command".to_string()))?;
        let box_id = run_id.to_string();

        // inst_dir holds the default secret share; create it before staging.
        fs::create_dir_all(inst_dir)
            .map_err(|err| BackendError::Spawn(format!("create inst dir {}: {err}", inst_dir.display())))?;

        // Stage secret/input/output per the shared policy, then present them as
        // local dirs and enforce cooperative read-only on inputs/secrets.
        let shares = plan_shares(
            spec,
            &ShareDirs {
                inst_dir,
                inputs_dir,
                outputs_dir,
            },
        )?;
        let transport = LocalDirTransport::new(inst_dir.to_path_buf());
        let placements = match transport.plan(&shares, 0) {
            Presentation::LocalDir { placements, .. } => placements,
            // LocalDirTransport always yields a LocalDir; a Vm here is a seam-
            // invariant bug. Fail loud (infra) rather than silently run the job
            // with no SANDY_*_DIR env (inputs/secrets invisible).
            Presentation::Vm { .. } => {
                return Err(BackendError::Protocol(
                    "LocalDirTransport yielded a Vm presentation (share-seam invariant broken)".to_string(),
                ));
            }
        };
        transport.activate(&shares)?;

        // Confine the job (#135): an Available containment prepends a launch prefix
        // (a delegated cgroup scope) so its whole tree — setsid escapees included —
        // is reaped by reap(box_id) at teardown; NoContainment / an unavailable host
        // prepends nothing and the job runs directly under the best-effort group reap.
        let limits = ResourceLimits {
            cpu: spec.cpu,
            mem_mib: spec.mem,
        };
        let launch: Vec<String> = self
            .containment
            .wrap(&box_id, limits)
            .into_iter()
            .chain(spec.command.iter().cloned())
            .collect();
        let (program, args) = launch
            .split_first()
            .ok_or_else(|| BackendError::Spawn("empty command".to_string()))?;

        // INV-1 + isolation: clear the host env, keep only PATH, overlay spec.env,
        // then point SANDY_<TAG>_DIR at each staged share dir — the dir PATH, never
        // the secret bytes (those stay 0600 files in the secret dir). The env is set
        // on the launch command; `systemd-run --scope` runs the job as its own child
        // inheriting this env, so it reaches the job across the wrapper.
        let mut command = Command::new(program);
        command
            .args(args)
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .envs(spec.env.iter().map(|(k, v)| (k.as_str(), v.as_str())));
        // Plumbing the containment wrapper needs from the host (e.g. systemd-run's
        // XDG_RUNTIME_DIR to reach the user bus). Non-secret and empty for an
        // uncontained run, so the clean-env property holds unless a wrapper is active.
        for key in self.containment.passthrough_env() {
            if let Some(val) = std::env::var_os(&key) {
                command.env(&key, val);
            }
        }
        for placement in &placements {
            command.env(share_env_key(&placement.tag), &placement.dir);
        }
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        // Spawn the child as the leader of a NEW process group so a timeout or
        // teardown reaps the whole group. command-group encapsulates the
        // setpgid/killpg; sandy's crates stay forbid(unsafe_code).
        let mut child = match command.group_spawn() {
            Ok(child) => child,
            // A spawn fault is infra (band 3, retryable), not a run result.
            Err(err) => return Err(BackendError::Spawn(format!("spawn `{job_program}`: {err}"))),
        };

        self.registry()?.push(BoxState {
            box_id: box_id.clone(),
            box_name: spec.template.to_string(),
            pid: child.id(),
            started: SystemTime::now(),
            rvport: None,
        });

        // Drain both pipes on threads so a chatty child never blocks on a full pipe.
        let out_drain = child.inner().stdout.take().map(drain);
        let err_drain = child.inner().stderr.take().map(drain);

        // Wait for the group leader against the wall-clock budget, polling so a
        // timeout can interrupt a hung job rather than block forever.
        let deadline = Instant::now() + Duration::from_secs(u64::from(spec.timeout_secs));
        let mut timed_out = false;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Some(status),
                Ok(None) => {
                    if Instant::now() >= deadline {
                        timed_out = true;
                        break None;
                    }
                    std::thread::sleep(POLL);
                }
                Err(err) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    // Warn-log the reap failure like the exit/timeout paths — a silent
                    // no-op here would hide an escapee that survived a failed reap.
                    if let Err(reap_err) = self.containment.reap(&box_id) {
                        tracing::warn!(box_id = %box_id, err = %reap_err, "containment reap failed after wait error");
                    }
                    self.registry()?.retain(|state| state.box_id != box_id);
                    return Err(BackendError::Transport(format!("wait on child `{job_program}`: {err}")));
                }
            }
        };

        // Reap on every path, exit or timeout. First destroy the containment scope:
        // when containment is Available this kills the whole cgroup, including a
        // setsid/setpgid escapee the group-kill below would miss (#135). Best-effort
        // — a reap-mechanism failure is warn-logged, not fatal, and the group-kill
        // still runs. NoContainment makes this a no-op.
        if let Err(err) = self.containment.reap(&box_id) {
            tracing::warn!(box_id = %box_id, %err, "containment reap failed; falling back to process-group kill");
        }
        // Then reap the group leader so a backgrounded in-group descendant is killed
        // (no host orphan) and its pipe ends close. A group-escaped descendant
        // survives this when uncontained, so the console drains are read under a
        // deadline below, never joined — run() stays bounded regardless.
        let _ = child.kill();
        let _ = child.wait();
        self.registry()?.retain(|state| state.box_id != box_id);

        let drain_deadline = Instant::now() + DRAIN_GRACE;
        let stdout = take_bounded(out_drain, drain_deadline);
        let stderr = take_bounded(err_drain, drain_deadline);
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
}

impl VmBackend for ProcessBackend {
    fn run(&self, spec: &RunSpec) -> Result<Outcome, BackendError> {
        if spec.command.is_empty() {
            return Err(BackendError::Spawn("empty command".to_string()));
        }

        // Per-run, sandy-owned staging dirs, mirroring the VM backends' lifecycle
        // (same shape, so gc/reconcile/wipe and the registry behave identically).
        let run_id = Uuid::new_v4();
        let base = ensure_sandy_staging_base()?;
        let inst_dir = base.join(run_id.to_string());
        let inputs_dir = base.join(format!("{run_id}-inputs"));
        let outputs_dir = base.join(format!("{run_id}-outputs"));

        // Run the staged job, capturing the result so outputs are collected and
        // staging is wiped on EVERY path (INV-1 — secret bytes never outlive the run).
        let result = self.run_staged(spec, run_id, &inst_dir, &inputs_dir, &outputs_dir);

        // Collect the chosen outputs to the host before wiping, but only if the job
        // ran (nothing is produced otherwise). A collection failure is an infra
        // fault, never a silent drop.
        let collected = if result.as_ref().is_ok_and(|outcome| outcome.booted) {
            collect_outputs(spec.outputs, &outputs_dir)
        } else {
            Ok(())
        };
        for dir in [&inst_dir, &inputs_dir, &outputs_dir] {
            if let Err(err) = wipe(dir) {
                tracing::warn!(dir = %dir.display(), %err, "failed to wipe process staging on teardown");
            }
        }
        collected.and(result)
    }

    fn kill(&self, box_id: &str) -> Result<(), BackendError> {
        // Real termination (#135): reap the run's containment scope, destroying its
        // cgroup and the whole process tree — including a `setsid`/`setpgid`-escaped
        // descendant a `killpg` would miss. Best-effort: a reap-mechanism failure is
        // warn-logged, not fatal, and the registry entry is still dropped so `boxes()`
        // stops reporting the box (INV-3). An uncontained backend (NoContainment)
        // reaps nothing here — its box is only ever live for its synchronous run(),
        // and the fail-closed gate keeps untrusted jobs off it.
        if let Err(err) = self.containment.reap(box_id) {
            tracing::warn!(box_id, %err, "containment reap failed on kill");
        }
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

/// A console pipe being drained on a background thread into a shared, bounded
/// buffer. The buffer is readable at any time ([`take_bounded`]) without joining
/// the thread, so a descendant that keeps the pipe open can never block `run()`.
struct Drain {
    /// The last [`CONSOLE_TAIL_CAP`] bytes read so far.
    buf: Arc<Mutex<Vec<u8>>>,
    /// Set once the reader hits EOF (the pipe's write ends all closed).
    done: Arc<AtomicBool>,
}

/// Drain a child pipe on a detached thread into a shared bounded buffer. The
/// thread is never joined: a group-escaped descendant can hold the pipe open
/// forever, so the caller reads the buffer under a deadline instead
/// ([`take_bounded`]). Keeps only the last [`CONSOLE_TAIL_CAP`] bytes.
fn drain<R: Read + Send + 'static>(mut reader: R) -> Drain {
    let buf = Arc::new(Mutex::new(Vec::new()));
    let done = Arc::new(AtomicBool::new(false));
    let (tbuf, tdone) = (Arc::clone(&buf), Arc::clone(&done));
    std::thread::spawn(move || {
        let mut chunk = [0u8; 8192];
        while let Ok(n) = reader.read(&mut chunk) {
            if n == 0 {
                break;
            }
            if let Ok(mut held) = tbuf.lock() {
                held.extend_from_slice(&chunk[..n]);
                if held.len() > CONSOLE_TAIL_CAP {
                    let excess = held.len() - CONSOLE_TAIL_CAP;
                    held.drain(..excess);
                }
            }
        }
        tdone.store(true, Ordering::SeqCst);
    });
    Drain { buf, done }
}

/// Take a drain's captured bytes, waiting at most until `deadline` for a natural
/// EOF, then returning whatever was captured. Never joins the thread, so a
/// descendant holding the pipe open cannot make this block past `deadline`.
fn take_bounded(drain: Option<Drain>, deadline: Instant) -> Vec<u8> {
    let Some(drain) = drain else {
        return Vec::new();
    };
    while !drain.done.load(Ordering::SeqCst) && Instant::now() < deadline {
        std::thread::sleep(POLL);
    }
    drain.buf.lock().map(|held| held.clone()).unwrap_or_default()
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

/// The `SANDY_<TAG>_DIR` env key a process job reads a share dir from, derived
/// from the share's mount tag: `sandy-inputs` → `SANDY_INPUTS_DIR`, `sandy-secrets`
/// → `SANDY_SECRETS_DIR`. The dir PATH is exposed, never the bytes (INV-1).
fn share_env_key(tag: &str) -> String {
    let stem = tag
        .strip_prefix("sandy-")
        .unwrap_or(tag)
        .replace('-', "_")
        .to_uppercase();
    format!("SANDY_{stem}_DIR")
}

#[cfg(test)]
mod tests {
    use sandy::Grants;
    use sandy_test_support::FakeContainment;

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

    /// Adversarial: a job that backgrounds a process holding the console pipe open
    /// must be bounded by the timeout AND its backgrounded child must be reaped by
    /// the group-kill, not left a host orphan. Without the process group this
    /// run() would block past the budget and the child would survive.
    #[test]
    fn a_backgrounding_job_is_bounded_and_the_group_is_reaped() -> anyhow::Result<()> {
        use anyhow::Context;

        let grants = no_grants();
        // Background a child that inherits stdout and print its pid; the leader
        // then blocks on `wait`, so neither finishes before the 1s budget.
        let command = [
            "sh".to_string(),
            "-c".to_string(),
            "sleep 30 & echo pid=$!; wait".to_string(),
        ];
        let spec = run_spec(&command, &grants, 1);

        let start = Instant::now();
        let outcome = ProcessBackend::new().run(&spec)?;

        assert!(outcome.timed_out, "the job exceeded its 1s budget");
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "run() stayed bounded despite a backgrounded child holding the pipe open"
        );

        let pid = outcome
            .console
            .lines()
            .find_map(|line| line.trim().strip_prefix("pid="))
            .map(str::trim)
            .context("the job should have printed its background child's pid")?;

        // The group-kill must have reaped the backgrounded child. Poll `kill -0`
        // (which fails once the pid is gone) briefly, to absorb the reparent-reap
        // race rather than flake on it.
        let gone = (0..50).any(|_| {
            let alive = std::process::Command::new("kill")
                .args(["-0", pid])
                .status()
                .map(|status| status.success())
                .unwrap_or(false);
            if alive {
                std::thread::sleep(Duration::from_millis(40));
                false
            } else {
                true
            }
        });
        assert!(
            gone,
            "the backgrounded child (pid {pid}) must be reaped by the group-kill, not orphaned"
        );
        Ok(())
    }

    /// A process job reads a staged input via `SANDY_INPUTS_DIR` (the T3 input
    /// fail-closed is lifted — the share is now staged and presented).
    #[test]
    fn a_process_job_reads_an_input_via_sandy_inputs_dir() -> anyhow::Result<()> {
        let src = tempfile::TempDir::new()?;
        std::fs::write(src.path().join("data"), b"hello-input")?;
        let inputs = [sandy::Input {
            host: src.path().join("data"),
            name: "data".to_string(),
            guest_path: None,
        }];
        let grants = no_grants();
        let command = [
            "sh".to_string(),
            "-c".to_string(),
            "cat \"$SANDY_INPUTS_DIR/data\"".to_string(),
        ];
        let spec = RunSpec {
            inputs: &inputs,
            ..run_spec(&command, &grants, 30)
        };

        let outcome = ProcessBackend::new().run(&spec)?;

        assert_eq!(outcome.guest_exit, Some(0), "the job ran");
        assert!(
            outcome.console.contains("hello-input"),
            "the job read the input via SANDY_INPUTS_DIR, got {:?}",
            outcome.console
        );
        Ok(())
    }

    /// A process job writes under `SANDY_OUTPUTS_DIR`; the named output is collected
    /// to its dest at teardown (outputs fail-closed lifted — full parity).
    #[test]
    fn a_process_job_output_is_collected_to_dest() -> anyhow::Result<()> {
        let dest = tempfile::TempDir::new()?;
        let out_dest = dest.path().join("result");
        let outputs = [sandy::Output {
            name: Some("result".to_string()),
            dest: out_dest.clone(),
        }];
        let grants = no_grants();
        let command = [
            "sh".to_string(),
            "-c".to_string(),
            "mkdir -p \"$SANDY_OUTPUTS_DIR/result\"; printf done > \"$SANDY_OUTPUTS_DIR/result/f\"".to_string(),
        ];
        let spec = RunSpec {
            outputs: &outputs,
            ..run_spec(&command, &grants, 30)
        };

        let outcome = ProcessBackend::new().run(&spec)?;

        assert_eq!(outcome.guest_exit, Some(0), "the job ran");
        assert_eq!(
            std::fs::read(out_dest.join("f"))?,
            b"done",
            "the named output was collected to its dest"
        );
        Ok(())
    }

    /// A process job reads a secret via `SANDY_SECRETS_DIR`. INV-1: the bytes arrive
    /// as a 0600 file (named by the SecretRef), never on argv or env.
    #[test]
    fn a_process_job_reads_a_secret_via_sandy_secrets_dir() -> anyhow::Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let src = tempfile::TempDir::new()?;
        let secret_file = src.path().join("tok");
        std::fs::write(&secret_file, b"s3cr3t")?;
        // INV-1: the host secret source must be 0600, or stage_secrets refuses it.
        std::fs::set_permissions(&secret_file, std::fs::Permissions::from_mode(0o600))?;
        let secrets = [sandy::SecretRef {
            name: "TOKEN".to_string(),
            source: sandy::SecretSource::File(secret_file),
        }];
        let grants = Grants {
            secrets: true,
            agent: false,
            shares: false,
        };
        let command = [
            "sh".to_string(),
            "-c".to_string(),
            "cat \"$SANDY_SECRETS_DIR/TOKEN\"".to_string(),
        ];
        let spec = RunSpec {
            secrets: &secrets,
            grants: &grants,
            ..run_spec(&command, &grants, 30)
        };

        let outcome = ProcessBackend::new().run(&spec)?;

        assert_eq!(outcome.guest_exit, Some(0), "the job ran");
        assert!(
            outcome.console.contains("s3cr3t"),
            "the job read the secret via SANDY_SECRETS_DIR, got {:?}",
            outcome.console
        );
        Ok(())
    }

    /// Adversarial INV-1: the secret's BYTES never reach the job's environment —
    /// only the `SANDY_SECRETS_DIR` path does. The job dumps its env; the value is
    /// absent, the dir path present.
    #[test]
    fn a_secret_value_is_absent_from_the_process_env() -> anyhow::Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let src = tempfile::TempDir::new()?;
        let secret_file = src.path().join("tok");
        std::fs::write(&secret_file, b"s3cr3t-value")?;
        std::fs::set_permissions(&secret_file, std::fs::Permissions::from_mode(0o600))?;
        let secrets = [sandy::SecretRef {
            name: "TOKEN".to_string(),
            source: sandy::SecretSource::File(secret_file),
        }];
        let grants = Grants {
            secrets: true,
            agent: false,
            shares: false,
        };
        let command = ["sh".to_string(), "-c".to_string(), "env".to_string()];
        let spec = RunSpec {
            secrets: &secrets,
            grants: &grants,
            ..run_spec(&command, &grants, 30)
        };

        let outcome = ProcessBackend::new().run(&spec)?;

        assert_eq!(outcome.guest_exit, Some(0), "the job ran");
        assert!(
            outcome.console.contains("SANDY_SECRETS_DIR="),
            "the dir PATH is exposed via env"
        );
        assert!(
            !outcome.console.contains("s3cr3t-value"),
            "INV-1: the secret BYTES must never reach the job env, got {:?}",
            outcome.console
        );
        Ok(())
    }

    /// The backend advertises `Process`, so `backend_accepts` refuses a VM job.
    #[test]
    fn kind_is_process_and_refuses_a_vm_job() {
        assert_eq!(ProcessBackend::new().kind(), SandboxKind::Process);
        assert!(!sandy::backend_accepts(ProcessBackend::new().kind(), SandboxKind::Vm));
    }

    /// The fail-closed gate keys off the untrusted-BOUNDARY capability, not mere
    /// reaping: an uncontained backend AND a reaping-only one both refuse an untrusted
    /// job; only an isolating containment admits one. Asserts the BAD paths (refusal),
    /// not only the happy path.
    #[test]
    fn containment_status_drives_the_fail_closed_gate() {
        let uncontained = ProcessBackend::new();
        assert!(
            !sandy::admits_untrusted(uncontained.kind(), &uncontained.containment_status()),
            "an uncontained (NoContainment) process backend must refuse an untrusted job"
        );

        let reaping_only = ProcessBackend::with_containment(Box::new(FakeContainment::available()));
        assert!(
            !sandy::admits_untrusted(reaping_only.kind(), &reaping_only.containment_status()),
            "a reaping-only containment (no untrusted isolation) must still refuse an untrusted job"
        );

        let isolating = ProcessBackend::with_containment(Box::new(FakeContainment::isolating()));
        assert!(
            sandy::admits_untrusted(isolating.kind(), &isolating.containment_status()),
            "an isolating containment admits an untrusted job"
        );
    }

    /// Every run reaps its container exactly once (on the exit path), keyed by the
    /// run's box id. This is the escapee-reaping wiring: a real cgroup reap would
    /// kill a setsid descendant the group-kill misses.
    #[test]
    fn a_run_reaps_its_container() -> anyhow::Result<()> {
        let fake = Arc::new(FakeContainment::available());
        let backend = ProcessBackend::with_containment(Box::new(Arc::clone(&fake)));
        let grants = no_grants();
        let command = ["true".to_string()];
        let spec = run_spec(&command, &grants, 30);

        backend.run(&spec)?;

        assert_eq!(fake.reaped().len(), 1, "exactly one container reaped per run");
        Ok(())
    }

    /// A job over its timeout still reaps its container (the escapee path: a real
    /// cgroup reap kills what the group-kill cannot). Asserts reap fires on the
    /// timeout path, not only a clean exit.
    #[test]
    fn a_timed_out_run_reaps_its_container() -> anyhow::Result<()> {
        let fake = Arc::new(FakeContainment::available());
        let backend = ProcessBackend::with_containment(Box::new(Arc::clone(&fake)));
        let grants = no_grants();
        let command = ["sh".to_string(), "-c".to_string(), "sleep 30".to_string()];
        let spec = run_spec(&command, &grants, 1);

        let outcome = backend.run(&spec)?;

        assert!(outcome.timed_out, "the job exceeded its 1s budget");
        assert_eq!(fake.reaped().len(), 1, "the timed-out run reaped its container");
        Ok(())
    }

    /// `kill()` now really terminates: it reaps the box's container (the #135 fix for
    /// the deregister-only kill) and drops the registry entry so `boxes()` stops
    /// reporting it (INV-3).
    #[test]
    fn kill_reaps_the_container_and_deregisters() -> anyhow::Result<()> {
        let fake = Arc::new(FakeContainment::available());
        let backend = ProcessBackend::with_containment(Box::new(Arc::clone(&fake)));

        backend.kill("box-42")?;

        assert_eq!(
            fake.reaped(),
            vec!["box-42".to_string()],
            "kill() reaps the named box's container"
        );
        assert!(backend.boxes()?.is_empty(), "the box is deregistered");
        Ok(())
    }

    /// The backend prepends the containment's wrap prefix to the launch command: an
    /// available containment whose wrap is `["env"]` runs the job via `env`, and the
    /// job still executes (proving the prefix wraps rather than replaces).
    #[test]
    fn the_wrap_prefix_is_prepended_to_the_launch() -> anyhow::Result<()> {
        let fake = FakeContainment::available_wrapping(vec!["env".to_string()]);
        let backend = ProcessBackend::with_containment(Box::new(fake));
        let grants = no_grants();
        let command = ["sh".to_string(), "-c".to_string(), "printf wrapped-ok".to_string()];
        let spec = run_spec(&command, &grants, 30);

        let outcome = backend.run(&spec)?;

        assert_eq!(outcome.guest_exit, Some(0), "the wrapped job ran");
        assert!(
            outcome.console.contains("wrapped-ok"),
            "the job ran through the wrap prefix, got {:?}",
            outcome.console
        );
        Ok(())
    }
}
