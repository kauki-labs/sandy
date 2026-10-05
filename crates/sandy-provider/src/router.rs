//! HostNix router (Phase B, block 6a; B-REQ-5, B-REQ-7).
//!
//! The router maps a [`ProvisioningStrategy`] onto an action: `HostNix` runs via
//! Phase A's backend path (the [`HostNixProvisioner`] seam — the real
//! `LauncherBackend` + CLI run is deferred); `BuilderVM` / `RemoteBuild` refuse
//! with a stage pointer (B-REQ-7); `Refuse` propagates. Parent invariants are
//! preserved: the router forwards the job unchanged and adds nothing to argv /
//! env / the Nix store, so a secret never leaves its channel (INV-1).

use sandy::{ProvisioningStrategy, ResultEnvelope};

/// A minimal stand-in for Phase A's fully-desugared run request (`RunSpec`),
/// kept tiny for Phase B routing. The implementer expands or replaces this when
/// wiring the real `LauncherBackend` path; it exists so the router has a job to
/// forward unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Job {
    /// The template (flake attr / image) to boot.
    pub template: String,
    /// The guest command and its arguments.
    pub command: Vec<String>,
}

/// The Phase A provisioning seam the router drives for a `HostNix` strategy.
///
/// The real path (`LauncherBackend` + the `vm run` CLI) is deferred, so the
/// router depends only on this trait and tests inject a fake. An implementation
/// runs `job` natively at `arch` and returns Phase A's result envelope
/// unchanged.
pub trait HostNixProvisioner {
    /// Provision and run `job` at `arch`, returning the Phase A result envelope.
    fn provision_host_nix(&self, job: &Job, arch: &str) -> ResultEnvelope;
}

/// The result of routing a [`ProvisioningStrategy`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProvisionOutcome {
    /// `HostNix` ran via Phase A's backend; carries the result envelope unchanged.
    Provisioned(ResultEnvelope),
    /// The strategy could not run at stage B; `reason` names the blocker — an
    /// axis propagated from [`ProvisioningStrategy::Refuse`], or a "requires
    /// stage C/D" pointer (B-REQ-7).
    Refused {
        /// Why the run was refused.
        reason: String,
    },
}

/// Route `strategy` to an action (B-REQ-5, B-REQ-7):
///
/// - `HostNix { arch }` → `backend.provision_host_nix(job, &arch)`, wrapped in [`ProvisionOutcome::Provisioned`] (the
///   envelope is forwarded unchanged).
/// - `BuilderVM { .. }` → [`ProvisionOutcome::Refused`] whose reason contains "requires stage C" (deferred; never
///   attempts the unbuilt path).
/// - `RemoteBuild { .. }` → [`ProvisionOutcome::Refused`] whose reason contains "requires stage D".
/// - `Refuse { reason }` → [`ProvisionOutcome::Refused`] propagating `reason`.
///
/// `job` is forwarded unchanged and the router adds nothing to argv / env / the
/// store, so parent invariants (INV-1) are preserved.
#[must_use]
pub fn provision(strategy: ProvisioningStrategy, job: &Job, backend: &impl HostNixProvisioner) -> ProvisionOutcome {
    match strategy {
        // HostNix runs via Phase A's backend; the job is forwarded unchanged so
        // nothing enters argv / env / the store (INV-1, B-REQ-5).
        ProvisioningStrategy::HostNix { arch } => ProvisionOutcome::Provisioned(backend.provision_host_nix(job, &arch)),
        // Deferred paths refuse with a stage pointer, never touching the backend
        // (B-REQ-7).
        ProvisioningStrategy::BuilderVM { .. } => ProvisionOutcome::Refused {
            reason: "builder-VM provisioning requires stage C".to_string(),
        },
        ProvisioningStrategy::RemoteBuild { .. } => ProvisionOutcome::Refused {
            reason: "remote-build provisioning requires stage D".to_string(),
        },
        // A classify-time refusal propagates its reason verbatim (B-REQ-2).
        ProvisioningStrategy::Refuse { reason } => ProvisionOutcome::Refused { reason },
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use sandy::{Logs, Provenance, ProvisioningStrategy, RESULT_SCHEMA_VERSION, ResultEnvelope, Status};

    use super::{HostNixProvisioner, Job, ProvisionOutcome, provision};

    /// A fake Phase A provisioner: records the jobs it was handed (to prove the
    /// router forwards them unchanged) and returns a scripted envelope.
    struct FakeProvisioner {
        envelope: ResultEnvelope,
        received: RefCell<Vec<Job>>,
    }

    impl FakeProvisioner {
        fn new(envelope: ResultEnvelope) -> Self {
            Self {
                envelope,
                received: RefCell::new(Vec::new()),
            }
        }
    }

    impl HostNixProvisioner for FakeProvisioner {
        fn provision_host_nix(&self, job: &Job, _arch: &str) -> ResultEnvelope {
            self.received.borrow_mut().push(job.clone());
            self.envelope.clone()
        }
    }

    fn sample_envelope() -> ResultEnvelope {
        ResultEnvelope {
            result_schema_version: RESULT_SCHEMA_VERSION,
            job_id: "job-b".to_string(),
            box_id: Some("box-b".to_string()),
            status: Status::Succeeded,
            retryable: false,
            message: "ok".to_string(),
            exit_code: Some(0),
            outputs: Vec::new(),
            receipts: Vec::new(),
            provenance: Provenance {
                template_store_path: "/nix/store/xxx-template".to_string(),
            },
            logs: Logs {
                tail: "done".to_string(),
            },
        }
    }

    fn sample_job() -> Job {
        Job {
            template: "tpl".to_string(),
            command: vec!["echo".to_string(), "hi".to_string()],
        }
    }

    /// B-REQ-5: a `HostNix` strategy routes to the Phase A provisioner — the
    /// backend is called exactly once with the job **unchanged** (no parent
    /// invariant bypassed), and its envelope is returned unchanged.
    #[test]
    fn hostnix_routes_to_provisioner() {
        let job = sample_job();
        let backend = FakeProvisioner::new(sample_envelope());
        let outcome = provision(
            ProvisioningStrategy::HostNix {
                arch: "x86_64-linux".to_string(),
            },
            &job,
            &backend,
        );
        assert_eq!(outcome, ProvisionOutcome::Provisioned(sample_envelope()));

        let received = backend.received.borrow();
        assert_eq!(received.len(), 1, "the provisioner must be called exactly once");
        assert_eq!(received[0], job, "the router must forward the job unchanged (INV-1)");
    }

    /// B-REQ-7: a `BuilderVM` strategy refuses with a stage-C pointer and a
    /// `RemoteBuild` strategy with a stage-D pointer — never attempting the
    /// unbuilt path (the backend is never called).
    #[test]
    fn buildervm_remote_refuse_stage_cd() {
        let job = sample_job();

        let backend_c = FakeProvisioner::new(sample_envelope());
        let outcome_c = provision(
            ProvisioningStrategy::BuilderVM {
                seed_id: "seed-1".to_string(),
            },
            &job,
            &backend_c,
        );
        let ProvisionOutcome::Refused { reason } = outcome_c else {
            panic!("BuilderVM must refuse at stage B");
        };
        assert!(
            reason.contains("stage C"),
            "BuilderVM refusal must point at stage C, got: {reason}"
        );
        assert!(
            backend_c.received.borrow().is_empty(),
            "BuilderVM must not reach the backend"
        );

        let backend_d = FakeProvisioner::new(sample_envelope());
        let outcome_d = provision(
            ProvisioningStrategy::RemoteBuild {
                host: "builder.example".to_string(),
                arch: "x86_64-linux".to_string(),
            },
            &job,
            &backend_d,
        );
        let ProvisionOutcome::Refused { reason } = outcome_d else {
            panic!("RemoteBuild must refuse at stage B");
        };
        assert!(
            reason.contains("stage D"),
            "RemoteBuild refusal must point at stage D, got: {reason}"
        );
        assert!(
            backend_d.received.borrow().is_empty(),
            "RemoteBuild must not reach the backend"
        );
    }

    /// B-REQ-2 (router half): a `Refuse` strategy propagates its reason verbatim
    /// and never reaches the backend.
    #[test]
    fn refuse_strategy_propagates() {
        let job = sample_job();
        let backend = FakeProvisioner::new(sample_envelope());
        let outcome = provision(
            ProvisioningStrategy::Refuse {
                reason: "no boot axis, no build axis".to_string(),
            },
            &job,
            &backend,
        );
        assert_eq!(
            outcome,
            ProvisionOutcome::Refused {
                reason: "no boot axis, no build axis".to_string(),
            }
        );
        assert!(
            backend.received.borrow().is_empty(),
            "a Refuse must not reach the backend"
        );
    }
}
