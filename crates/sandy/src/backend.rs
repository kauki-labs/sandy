//! The backend seam (INV-8, pinned contract).
//!
//! [`VmBackend`] is the only way sandy reaches a hypervisor. It is defined
//! here and implemented identically by `FakeBackend` (this crate) and
//! `LauncherBackend` (Block 5). The backend returns the *physical* [`Outcome`]
//! only; sandy maps that into the result envelope and the `retryable` /
//! exit bands ([`crate::result`]). Every `BackendError` is an infra fault.
//!
//! All wire types are `snake_case` in Rust and in JSON, with no serde rename
//! layer (INV-8).

use std::{
    os::unix::io::RawFd,
    path::{Path, PathBuf},
    sync::Mutex,
    time::SystemTime,
};

use serde::{Deserialize, Serialize};

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
    /// Wall-clock timeout in seconds.
    pub timeout_secs: u32,
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
/// with [`backend_accepts`]. A closed set for now (richer capabilities — arch,
/// attestation — come later per the fabric spec's self-registration).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxKind {
    /// A raw OS process on the host: no VM, isolation only what the OS gives.
    Process,
    /// A virtual machine (qemu/vfkit/…): the full hypervisor isolation boundary.
    Vm,
}

/// Whether a backend providing `provided` can run a job requiring `required`.
///
/// Exact-match while the kind set is closed: a VM-required job matches only a VM
/// backend, a process-required job only a process backend. When kinds grow a
/// subsumption rule (a VM can host a process job) can replace this without
/// touching callers.
#[must_use]
pub fn backend_accepts(provided: SandboxKind, required: SandboxKind) -> bool {
    provided == required
}

/// The hypervisor seam. `FakeBackend` and `LauncherBackend` implement this
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

/// An in-memory [`VmBackend`] test double.
///
/// Script a run outcome with [`FakeBackend::with_outcome`] /
/// [`FakeBackend::with_error`], the running-box set with
/// [`FakeBackend::with_boxes`], and inspect teardown calls with
/// [`FakeBackend::killed`].
#[derive(Debug, Default)]
pub struct FakeBackend {
    /// The scripted result of the next [`VmBackend::run`] call. Set once by the
    /// by-value builders, then only read, so it needs no interior mutability.
    run_result: Option<Result<Outcome, BackendError>>,
    /// The boxes [`VmBackend::boxes`] should report.
    boxes: Vec<BoxState>,
    /// Box ids passed to [`VmBackend::kill`], in call order — the one field
    /// mutated through `&self`, so the only one behind a lock.
    killed: Mutex<Vec<String>>,
}

impl FakeBackend {
    /// A backend with no scripted outcome and no running boxes.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Script the [`Outcome`] the next [`VmBackend::run`] returns.
    #[must_use]
    pub fn with_outcome(mut self, outcome: Outcome) -> Self {
        self.run_result = Some(Ok(outcome));
        self
    }

    /// Script a [`BackendError`] for the next [`VmBackend::run`] call.
    #[must_use]
    pub fn with_error(mut self, error: BackendError) -> Self {
        self.run_result = Some(Err(error));
        self
    }

    /// Script the boxes [`VmBackend::boxes`] reports.
    #[must_use]
    pub fn with_boxes(mut self, boxes: Vec<BoxState>) -> Self {
        self.boxes = boxes;
        self
    }

    /// The box ids [`VmBackend::kill`] has been called with, in order.
    #[must_use]
    pub fn killed(&self) -> Vec<String> {
        self.killed.lock().expect("killed lock poisoned").clone()
    }
}

impl VmBackend for FakeBackend {
    fn run(&self, _spec: &RunSpec) -> Result<Outcome, BackendError> {
        self.run_result
            .clone()
            .unwrap_or_else(|| Err(BackendError::Protocol("no scripted run outcome".to_string())))
    }

    fn kill(&self, box_id: &str) -> Result<(), BackendError> {
        self.killed
            .lock()
            .expect("killed lock poisoned")
            .push(box_id.to_string());
        Ok(())
    }

    fn boxes(&self) -> Result<Vec<BoxState>, BackendError> {
        Ok(self.boxes.clone())
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

/// Reject a spec that would route a secret's bytes through the data/store plane
/// instead of the secret channel (INV-1): a secret value echoed into `env`.
///
/// # Errors
///
/// Returns [`PlanError::SecretLeak`] when a secret would reach the data plane.
pub fn validate_no_secret_leak(spec: &RunSpec) -> Result<(), PlanError> {
    for secret in spec.secrets {
        // The secret's name must not be set as a plain env var — env is not the
        // secret channel and travels host argv/environ (INV-1).
        if spec.env.iter().any(|(key, _)| key == &secret.name) {
            return Err(PlanError::SecretLeak(secret.name.clone()));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// INV-8: the physical `Outcome` round-trips as `snake_case` JSON with no
    /// rename layer — the field names match the pinned schema exactly.
    #[test]
    fn outcome_wire_fields_are_snake_case() -> anyhow::Result<()> {
        let outcome = Outcome {
            booted: true,
            guest_exit: Some(0),
            transport_error: None,
            timed_out: false,
            console: String::new(),
        };
        let value = serde_json::to_value(&outcome)?;
        let obj = value.as_object().expect("outcome serializes to an object");
        let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, ["booted", "guest_exit", "timed_out", "transport_error"]);
        Ok(())
    }

    /// INV-1: a secret whose name is also set as a plain env var (so its value
    /// would travel host argv/environ) must be rejected.
    #[test]
    fn secret_echoed_into_env_is_rejected() {
        let secrets = [SecretRef {
            name: "TOK".to_string(),
            source: SecretSource::File(PathBuf::from("/run/token")),
        }];
        let env = [("TOK".to_string(), "value".to_string())];
        let grants = Grants {
            secrets: true,
            agent: false,
            shares: false,
        };
        let command = ["true".to_string()];
        let spec = RunSpec {
            template: "demo",
            command: &command,
            inputs: &[],
            outputs: &[],
            secrets: &secrets,
            env: &env,
            cpu: None,
            mem: None,
            timeout_secs: 60,
            grants: &grants,
            outcome_file: None,
            secret_dir: None,
        };
        assert!(matches!(validate_no_secret_leak(&spec), Err(PlanError::SecretLeak(_))));
    }

    /// A job requiring a VM must not match the raw-process backend, and a kind
    /// matches only itself (exact-match while the kind set is closed).
    #[test]
    fn backend_accepts_matches_kind_exactly() {
        assert!(
            backend_accepts(SandboxKind::Vm, SandboxKind::Vm),
            "a vm backend runs a vm-required job"
        );
        assert!(
            backend_accepts(SandboxKind::Process, SandboxKind::Process),
            "a process backend runs a process-required job"
        );
        assert!(
            !backend_accepts(SandboxKind::Process, SandboxKind::Vm),
            "a vm-required job must not match the process backend"
        );
        assert!(
            !backend_accepts(SandboxKind::Vm, SandboxKind::Process),
            "a process-required job must not match a vm backend"
        );
    }

    /// The seam defaults to a VM: the existing hypervisor backends report `Vm`
    /// without overriding, so adding `kind()` leaves them untouched.
    #[test]
    fn vmbackend_kind_defaults_to_vm() {
        assert_eq!(FakeBackend::new().kind(), SandboxKind::Vm);
    }
}
