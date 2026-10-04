//! The backend seam (INV-8, pinned contract).
//!
//! [`VmBackend`] is the only way sandy-core reaches a hypervisor. It is defined
//! here and implemented identically by `FakeBackend` (this crate) and
//! `LauncherBackend` (Block 5). The backend returns the *physical* [`Outcome`]
//! only; sandy-core maps that into the result envelope and the `retryable` /
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

/// A host→guest bind mount. `ro` selects a read-only mount.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mount {
    /// Host path to expose.
    pub host: PathBuf,
    /// Guest path where it appears.
    pub guest: PathBuf,
    /// Whether the mount is read-only.
    pub ro: bool,
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
    /// Read-only inputs and the RW output area.
    pub mounts: &'a [Mount],
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
}

/// An in-memory [`VmBackend`] test double.
///
/// Script a run outcome with [`FakeBackend::with_outcome`] /
/// [`FakeBackend::with_error`], the running-box set with
/// [`FakeBackend::with_boxes`], and inspect teardown calls with
/// [`FakeBackend::killed`]. The trait methods are left for the implementer to
/// wire against these fields.
#[derive(Debug, Default)]
#[allow(
    dead_code,
    reason = "injection fields are read by the VmBackend impl the implementer fills (todo!())"
)]
pub struct FakeBackend {
    /// The scripted result of the next [`VmBackend::run`] call.
    run_result: Mutex<Option<Result<Outcome, BackendError>>>,
    /// The boxes [`VmBackend::boxes`] should report.
    boxes: Mutex<Vec<BoxState>>,
    /// Box ids passed to [`VmBackend::kill`], in call order.
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
    pub fn with_outcome(self, outcome: Outcome) -> Self {
        *self.run_result.lock().expect("run_result lock poisoned") = Some(Ok(outcome));
        self
    }

    /// Script a [`BackendError`] for the next [`VmBackend::run`] call.
    #[must_use]
    pub fn with_error(self, error: BackendError) -> Self {
        *self.run_result.lock().expect("run_result lock poisoned") = Some(Err(error));
        self
    }

    /// Script the boxes [`VmBackend::boxes`] reports.
    #[must_use]
    pub fn with_boxes(self, boxes: Vec<BoxState>) -> Self {
        *self.boxes.lock().expect("boxes lock poisoned") = boxes;
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
        todo!("return the scripted run_result")
    }

    fn kill(&self, _box_id: &str) -> Result<(), BackendError> {
        todo!("record box_id in `killed` and return Ok")
    }

    fn boxes(&self) -> Result<Vec<BoxState>, BackendError> {
        todo!("return a clone of the scripted `boxes`")
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
/// instead of the secret channel (INV-1): e.g. a [`SecretSource::File`] path
/// that is also a [`Mount::host`], or a secret value echoed into `env`.
///
/// # Errors
///
/// Returns [`PlanError::SecretLeak`] when a secret would reach the data plane.
pub fn validate_no_secret_leak(_spec: &RunSpec) -> Result<(), PlanError> {
    todo!("reject secrets that also appear as a mount host or in env")
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
        };
        let value = serde_json::to_value(&outcome)?;
        let obj = value.as_object().expect("outcome serializes to an object");
        let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, ["booted", "guest_exit", "timed_out", "transport_error"]);
        Ok(())
    }

    /// INV-1: a secret whose file source is also a mount host (so its bytes
    /// would enter the data/store plane) must be rejected.
    #[test]
    fn secret_routed_through_a_mount_is_rejected() {
        let shared = PathBuf::from("/tmp/token");
        let mounts = [Mount {
            host: shared.clone(),
            guest: PathBuf::from("/in/token"),
            ro: true,
        }];
        let secrets = [SecretRef {
            name: "TOK".to_string(),
            source: SecretSource::File(shared),
        }];
        let grants = Grants {
            secrets: true,
            agent: false,
            shares: false,
        };
        let command = ["true".to_string()];
        let spec = RunSpec {
            template: "demo",
            command: &command,
            mounts: &mounts,
            secrets: &secrets,
            env: &[],
            cpu: None,
            mem: None,
            timeout_secs: 60,
            grants: &grants,
            outcome_file: None,
        };
        assert!(matches!(validate_no_secret_leak(&spec), Err(PlanError::SecretLeak(_))));
    }
}
