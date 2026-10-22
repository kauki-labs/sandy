//! The backend seam (INV-8, pinned contract): the `VmBackend` trait and its
//! `snake_case` data/error types.
//!
//! [`VmBackend`] is the only way sandy reaches a hypervisor. The backend returns
//! the *physical* [`Outcome`] only; the core maps that into the result envelope
//! and the `retryable` / exit bands. Every [`BackendError`] is an infra fault.
//!
//! All wire types are `snake_case` in Rust and in JSON, with no serde rename
//! layer (INV-8). This module is the contract; the concrete backends, the fake,
//! and the plan/accept validators live in the crates that depend on it.

use std::{
    os::unix::io::RawFd,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicBool, Ordering},
    },
    time::{Instant, SystemTime},
};

use serde::{Deserialize, Serialize};

/// A live handle into a running [`VmBackend::run`] call, letting something
/// outside the call (a `daemon cancel`, an attach-state transition, a grace
/// period expiring) change its fate without that call having computed a
/// fixed deadline once at the start and never hearing from anyone again
/// (#340's "unlimited while attached" policy needs exactly this: the
/// deadline a running job is held to is no longer a constant, it's a value
/// that can be suspended while attached and reinstated on detach).
///
/// `Clone`, cheaply (an `Arc` underneath): the caller that starts a run
/// keeps one clone to drive it (suspend/extend the deadline, cancel), and
/// hands another to [`VmBackend::run`] itself via [`RunSpec::control`] to
/// poll. Neither side blocks the other — every method here is a quick
/// lock/atomic read or write, never an await or a condvar wait, so it's
/// equally usable from `run()`'s own blocking poll loop (`impls/local`,
/// `impls/vm`) and from an async caller holding the other clone.
#[derive(Clone)]
pub struct RunControl(Arc<RunControlInner>);

struct RunControlInner {
    cancelled: AtomicBool,
    deadline: Mutex<Option<Instant>>,
}

impl RunControl {
    /// A control handle enforcing `deadline` until something says otherwise.
    #[must_use]
    pub fn new(deadline: Instant) -> Self {
        Self(Arc::new(RunControlInner {
            cancelled: AtomicBool::new(false),
            deadline: Mutex::new(Some(deadline)),
        }))
    }

    /// A convenience constructor for the common case: a run's own
    /// `timeout_secs`, converted to a deadline from now.
    #[must_use]
    pub fn with_timeout_secs(timeout_secs: u32) -> Self {
        Self::new(Instant::now() + std::time::Duration::from_secs(u64::from(timeout_secs)))
    }

    /// Signal cancellation (`daemon cancel`): [`Self::is_cancelled`] becomes
    /// `true` immediately, for any clone of this handle. `run()`'s own poll
    /// loop checks this on every tick and tears the box down the same way a
    /// timeout does, just without waiting for one.
    pub fn cancel(&self) {
        self.0.cancelled.store(true, Ordering::SeqCst);
    }

    /// Whether [`Self::cancel`] has been called.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.0.cancelled.load(Ordering::SeqCst)
    }

    /// Suspend the deadline: [`Self::timed_out`] never reports true again
    /// until [`Self::set_deadline`] reinstates one. The attach-state-driven
    /// "unlimited while attached" policy calls this the moment a job's
    /// attach-membership count goes from 0 to 1.
    pub fn suspend_deadline(&self) {
        *self.0.deadline.lock().unwrap_or_else(PoisonError::into_inner) = None;
    }

    /// Set (or replace) the enforced deadline to `at`. The grace-period
    /// policy calls this with `Instant::now() + grace` the moment a job's
    /// attach-membership count drops back to 0.
    pub fn set_deadline(&self, at: Instant) {
        *self.0.deadline.lock().unwrap_or_else(PoisonError::into_inner) = Some(at);
    }

    /// The currently enforced deadline, if any (`None` while suspended).
    #[must_use]
    pub fn deadline(&self) -> Option<Instant> {
        *self.0.deadline.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Whether the current deadline (if any) has passed. `false` while
    /// suspended, by construction — there is no deadline to have passed.
    #[must_use]
    pub fn timed_out(&self) -> bool {
        self.deadline().is_some_and(|at| Instant::now() >= at)
    }
}

impl std::fmt::Debug for RunControl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RunControl")
            .field("cancelled", &self.is_cancelled())
            .field("deadline", &self.deadline())
            .finish()
    }
}

/// A read-only input exposed to the guest under `/run/sandy/inputs/<name>`.
///
/// The host path (a file or a directory) is staged into the inputs share; the
/// guest mounts that share read-only, so a write to the input fails with
/// `EROFS`. Inputs are plain data, not a secret channel (INV-1).
///
/// With [`guest_path`](Input::guest_path) set, a guest boot step additionally
/// symlinks that path to the staged entry, so the job reads the input where it
/// expects it (e.g. `/workspace`) rather than only under `/run/sandy/inputs`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Input {
    /// Host path to expose (a file or a directory tree).
    pub host: PathBuf,
    /// The name the input is staged under at `/run/sandy/inputs/<name>` in-guest.
    pub name: String,
    /// Optional absolute guest path to also surface this input at, via a
    /// guest-side symlink to the staged entry. `None` leaves it only at
    /// `/run/sandy/inputs/<name>`.
    pub guest_path: Option<PathBuf>,
}

/// A writable output collected from the guest at teardown.
///
/// `name = Some(n)` collects the subtree `/run/sandy/outputs/<n>` to
/// [`dest`](Output::dest); `name = None` is a catch-all that collects everything
/// the guest wrote under `/run/sandy/outputs`. The share is the one guest-writable,
/// host-visible surface, so collection never follows a symlink out of the output
/// root and is size/entry-capped (INV-1 on the way out).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output {
    /// The named subtree under `/run/sandy/outputs/<name>`, or `None` for the
    /// whole output dir (catch-all).
    pub name: Option<String>,
    /// The host path the subtree is collected to at teardown.
    pub dest: PathBuf,
}

/// Where a secret's bytes come from. Secrets travel this channel only — never
/// argv, env, mounts, or the Nix store (INV-1).
#[derive(Debug)]
pub enum SecretSource {
    /// A host file holding the secret bytes.
    File(PathBuf),
    /// An already-open file descriptor holding the secret bytes.
    Fd(RawFd),
}

/// A named secret to inject into the guest.
#[derive(Debug)]
pub struct SecretRef {
    /// The environment variable name the guest will see.
    pub name: String,
    /// The channel the bytes arrive on.
    pub source: SecretSource,
}

/// nix-vm trust tokens the run is granted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Grants {
    /// Allow the runtime secret channel.
    pub secrets: bool,
    /// Allow the agent forwarding channel.
    pub agent: bool,
    /// Allow extra shares.
    pub shares: bool,
}

/// A fully desugared request to run one job in one box.
#[derive(Debug)]
pub struct RunSpec<'a> {
    /// The template (flake attr / image) to boot.
    pub template: &'a str,
    /// The guest command and its arguments.
    pub command: &'a [String],
    /// Read-only inputs staged into the guest at `/run/sandy/inputs/<name>`.
    pub inputs: &'a [Input],
    /// Writable outputs the guest writes under `/run/sandy/outputs/<name>`,
    /// collected to each [`Output::dest`] at teardown.
    pub outputs: &'a [Output],
    /// Secrets to inject over the secret channel.
    pub secrets: &'a [SecretRef],
    /// Extra environment variables (never secrets — INV-1).
    pub env: &'a [(String, String)],
    /// Optional vCPU count.
    pub cpu: Option<u32>,
    /// Optional memory budget in MiB.
    pub mem: Option<u32>,
    /// Wall-clock timeout in seconds — the INITIAL deadline `control` is
    /// constructed with; once running, `control` (not this field) is the
    /// live source of truth a backend's own poll loop reads each tick.
    pub timeout_secs: u32,
    /// The live handle `run()` polls for cancellation and its current
    /// deadline (#340) — see [`RunControl`]'s own doc for why this isn't
    /// just `timeout_secs` read once at the start.
    pub control: &'a RunControl,
    /// The trust tokens the run is granted.
    pub grants: &'a Grants,
    /// `Some(path)` writes the outcome record to a file (D2, ssh); `None` uses
    /// fd3 (local).
    pub outcome_file: Option<&'a Path>,
    /// `Some(dir)` stages secrets into, and shares the guest secret mount from,
    /// this caller-owned directory instead of a fresh per-run staging dir. It lets
    /// the caller rewrite a staged secret while the guest runs (credential refresh
    /// re-delivery, #49): the directory is the live virtiofs share, so a rewrite is
    /// seen in-guest. `None` uses the backend's own staging dir (the default). The
    /// caller owns the directory's lifetime, the backend never wipes it.
    pub secret_dir: Option<&'a Path>,
}

/// The physical outcome of a run, mirroring nix-vm's `snake_case` record 1:1
/// (INV-8). The diagnostic `phase` / `box_id` / `box_name` fields of the wire
/// record are intentionally not carried here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Outcome {
    /// Whether the guest booted.
    pub booted: bool,
    /// The guest process exit code, if it ran to completion.
    pub guest_exit: Option<i32>,
    /// A transport/protocol error string, if the channel failed.
    pub transport_error: Option<String>,
    /// Whether the run hit its timeout.
    pub timed_out: bool,
    /// A bounded tail of the guest console (boot log + command output), for
    /// diagnostics: it is the one place a boot that never reached the command is
    /// visible. Empty when nothing was read. The supervisor surfaces it into the
    /// result envelope's `logs.tail`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub console: String,
}

/// The state of one running box, as reported by [`VmBackend::boxes`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoxState {
    /// The box's stable id.
    pub box_id: String,
    /// The box's human name.
    pub box_name: String,
    /// The supervisor pid (informational only — flock is the liveness
    /// authority, INV-3).
    pub pid: u32,
    /// When the box started.
    pub started: SystemTime,
    /// The reverse-vsock port, if assigned.
    pub rvport: Option<u16>,
}

/// A backend failure. Every variant is an infra fault → `retryable: true`
/// (INV-7).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BackendError {
    /// The box could not be spawned.
    #[error("spawn failed: {0}")]
    Spawn(String),
    /// The control channel to the box failed.
    #[error("transport error: {0}")]
    Transport(String),
    /// The box spoke the contract incorrectly.
    #[error("protocol error: {0}")]
    Protocol(String),
}

/// What kind of sandbox a backend provides, so a job that requires a particular
/// kind can be matched to (or refused by) a backend — a VM-only job must not land
/// on the raw-process backend. The executor seam advertises its kind via
/// [`VmBackend::kind`]; a dispatcher compares it against the job's requirement
/// with the core's `backend_accepts`. A closed set for now (richer capabilities —
/// arch, attestation — come later per the fabric spec's self-registration).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxKind {
    /// A raw OS process on the host: no VM, isolation only what the OS gives.
    Process,
    /// A virtual machine (qemu/vfkit/…): the full hypervisor isolation boundary.
    Vm,
}

/// The hypervisor seam. `FakeBackend` and the native backends implement this
/// identically; reconcile reaches running state through [`VmBackend::boxes`],
/// never a direct registry read, so the seam stays backend-agnostic.
pub trait VmBackend {
    /// Run `spec` to completion and return its physical [`Outcome`].
    fn run(&self, spec: &RunSpec) -> Result<Outcome, BackendError>;
    /// Tear down the box identified by `box_id`.
    fn kill(&self, box_id: &str) -> Result<(), BackendError>;
    /// Report the currently running boxes.
    fn boxes(&self) -> Result<Vec<BoxState>, BackendError>;
    /// The kind of sandbox this backend provides. Defaults to [`SandboxKind::Vm`]
    /// — the hypervisor backends — so only a non-VM backend (the process backend)
    /// overrides it; adding the method leaves `FakeBackend`/`QemuBackend`/
    /// `VfkitBackend` untouched.
    fn kind(&self) -> SandboxKind {
        SandboxKind::Vm
    }
}

/// An invalid plan / usage error (INV-11 process-exit band 2 — no boot).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PlanError {
    /// A secret's bytes would also travel the data/store plane (INV-1).
    #[error("secret `{0}` would leak onto the data plane")]
    SecretLeak(String),
    /// The plan is otherwise invalid (path escape, ungranted capability, …).
    #[error("invalid plan: {0}")]
    Invalid(String),
}
