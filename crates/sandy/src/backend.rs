//! The backend seam behaviors over the pinned contract.
//!
//! The contract itself — the [`VmBackend`] trait and its `snake_case` data/error
//! types — lives in [`sandy_api::backend`] and is re-exported here so `sandy::…`
//! import paths are unchanged. This module keeps the behaviors that are not part
//! of the contract: the plan/accept validators and the in-memory [`FakeBackend`]
//! test double.

use std::sync::Mutex;

pub use sandy_api::backend::*;

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
    use std::path::PathBuf;

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
