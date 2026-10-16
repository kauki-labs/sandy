//! The backend seam behaviors over the pinned contract.
//!
//! The contract itself — the [`VmBackend`] trait and its `snake_case` data/error
//! types — lives in [`sandy_api::backend`] and is re-exported here so `sandy::…`
//! import paths are unchanged. This module keeps the behaviors that are not part
//! of the contract: the plan/accept validators. The in-memory `FakeBackend` test
//! double now lives in `sandy-test-support`.

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

    use sandy_test_support::FakeBackend;

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
