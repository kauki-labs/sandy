//! `RemoteBuild` orchestration (Phase D, D.1 / D-REQ-1, D-REQ-6; INV-1, INV-7).
//!
//! Nix eval is single-machine, so `RemoteBuild` evaluates on the controller and
//! delegates only the *build* to a remote NixOS builder, copying artifacts back.
//! This module is the tier-1 orchestration over a faked remote seam; the real
//! `nix build --builders ssh://…` + `nix copy` and the secret-boundary proof are
//! host-tier (tier-3).
//!
//! Documented invariants the implementer must preserve (not asserted here):
//! - **INV-1 / D-REQ-6:** eval stays on the controller and a secret never enters the remote store plane or the remote
//!   host's argv/env — it rides the ssh control channel only. The live secret-boundary test is host-tier.
//! - **INV-7:** a remote fault (unreachable, build) is an *infra* fault → the result is `retryable: true`, never
//!   confused with a guest exit.

use std::fmt;

use sandy_core::{Logs, Provenance, RESULT_SCHEMA_VERSION, ResultEnvelope, Status};

use crate::router::{Job, ProvisionOutcome};

/// The store artifacts a remote NixOS builder produced and copied back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteArtifacts {
    /// The Nix store path of the built output, now present in the local store.
    pub output_store_path: String,
}

/// A fault from the remote build path.
///
/// `Unreachable` and `Build` are infra faults (INV-7 → `retryable: true`);
/// `ArchMismatch` is a refusal with no build attempted (D-REQ-1 adversarial).
///
/// Implemented by hand rather than via `thiserror`: `sandy-provider` depends only
/// on `sandy-core`, so the derive macro is not in scope. See the crate's
/// dependency set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteError {
    /// The remote builder host could not be reached (infra fault, INV-7).
    Unreachable(String),
    /// The remote builder cannot build the requested target arch.
    ArchMismatch {
        /// The arch the job requires.
        expected: String,
        /// The arch the remote builder advertises.
        found: String,
    },
    /// The remote build itself failed (infra fault, INV-7).
    Build(String),
}

impl fmt::Display for RemoteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RemoteError::Unreachable(host) => write!(f, "remote builder `{host}` is unreachable"),
            RemoteError::ArchMismatch { expected, found } => {
                write!(
                    f,
                    "remote builder cannot build arch `{expected}` (advertises `{found}`)"
                )
            }
            RemoteError::Build(msg) => write!(f, "remote build failed: {msg}"),
        }
    }
}

impl std::error::Error for RemoteError {}

/// A faked-remote seam over the eval-local / build-remote / copy-back path.
///
/// Two operations so the orchestration can confirm the remote's arch *before*
/// delegating a build (D-REQ-1: "confirm the remote builder's arch/reachability").
/// An arch mismatch must refuse with **no build attempted**, which a single
/// build-only method could not express — hence [`probe_arch`](RemoteBuilder::probe_arch).
/// The real seam drives `nix build --builders ssh://…` + `nix copy`; tests inject
/// a fake.
pub trait RemoteBuilder {
    /// Probe the remote builder's advertised system arch (cheap; no build).
    ///
    /// Returns [`RemoteError::Unreachable`] when the host cannot be reached.
    fn probe_arch(&self, host: &str) -> Result<String, RemoteError>;

    /// Build `derivation` on `host` for `arch` and copy the artifacts back.
    fn build_remote(&self, derivation: &str, host: &str, arch: &str) -> Result<RemoteArtifacts, RemoteError>;
}

/// Provision a host with no local build and no valid seed via a remote NixOS
/// builder (D-REQ-1): eval on the controller, confirm the remote's arch, build on
/// the remote, copy artifacts back, run the job.
///
/// Contract the implementer satisfies (pinned by the tests):
/// - a [`RemoteError::ArchMismatch`] (the probe arch ≠ `arch`) → [`ProvisionOutcome::Refused`] naming `arch`, with **no
///   build attempted** (`build_remote` is never called);
/// - a [`RemoteError::Unreachable`] / [`RemoteError::Build`] → [`ProvisionOutcome::Provisioned`] carrying a failed,
///   `retryable: true` envelope (infra fault, INV-7);
/// - success → [`ProvisionOutcome::Provisioned`] with a succeeded envelope.
///
/// Eval stays on the controller and secrets never cross to the remote store plane
/// or argv/env (INV-1 / D-REQ-6); the live secret-boundary proof is host-tier.
#[must_use]
pub fn provision_remote_build(job: &Job, host: &str, arch: &str, remote: &impl RemoteBuilder) -> ProvisionOutcome {
    // Confirm the remote's arch before delegating a build (D-REQ-1). A mismatch
    // refuses naming `arch` with no build attempted; an unreachable probe is an
    // infra fault (INV-7).
    match remote.probe_arch(host) {
        Ok(found) if found != arch => {
            return ProvisionOutcome::Refused {
                reason: format!(
                    "remote builder `{host}` cannot build arch `{arch}` (advertises `{found}`); no build attempted"
                ),
            };
        }
        Ok(_) => {}
        Err(err) => return ProvisionOutcome::Provisioned(infra_fault_envelope(job, &err.to_string())),
    }

    // Eval stays on the controller: the derivation is produced locally and only the
    // build is delegated, so a secret never enters the remote store plane or the
    // remote host's argv/env (INV-1 / D-REQ-6). Real eval + `nix copy` back are
    // host-tier.
    let derivation = eval_locally(job);
    match remote.build_remote(&derivation, host, arch) {
        Ok(artifacts) => ProvisionOutcome::Provisioned(succeeded_envelope(job, &artifacts)),
        // Unreachable / Build are infra faults → failed, retryable (INV-7), never
        // confused with a guest exit.
        Err(err) => ProvisionOutcome::Provisioned(infra_fault_envelope(job, &err.to_string())),
    }
}

/// Evaluate the job's template on the controller, yielding the derivation path to
/// build remotely. The real Nix eval is host-tier; this seam keeps eval local so
/// secrets never cross to the remote (INV-1 / D-REQ-6).
fn eval_locally(job: &Job) -> String {
    format!("{}.drv", job.template)
}

/// A succeeded envelope for a remote build that ran the job to exit 0.
fn succeeded_envelope(job: &Job, artifacts: &RemoteArtifacts) -> ResultEnvelope {
    ResultEnvelope {
        result_schema_version: RESULT_SCHEMA_VERSION,
        job_id: job.template.clone(),
        box_id: None,
        status: Status::Succeeded,
        retryable: false,
        message: "remote build provisioned; job ran to completion".to_string(),
        exit_code: Some(0),
        outputs: Vec::new(),
        receipts: Vec::new(),
        provenance: Provenance {
            template_store_path: artifacts.output_store_path.clone(),
        },
        logs: Logs { tail: String::new() },
    }
}

/// A failed, retryable envelope for a remote infra fault (INV-7): the build was
/// attempted but the remote was unreachable or the build itself failed.
fn infra_fault_envelope(job: &Job, message: &str) -> ResultEnvelope {
    ResultEnvelope {
        result_schema_version: RESULT_SCHEMA_VERSION,
        job_id: job.template.clone(),
        box_id: None,
        status: Status::Failed,
        retryable: true,
        message: message.to_string(),
        exit_code: None,
        outputs: Vec::new(),
        receipts: Vec::new(),
        provenance: Provenance {
            template_store_path: String::new(),
        },
        logs: Logs { tail: String::new() },
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use sandy_core::Status;

    use super::{RemoteArtifacts, RemoteBuilder, RemoteError, provision_remote_build};
    use crate::router::{Job, ProvisionOutcome};

    /// What the fake remote's `build_remote` should yield once reached.
    enum BuildBehavior {
        /// Return artifacts (a successful remote build).
        Artifacts,
        /// Fail as unreachable mid-build (infra fault).
        Unreachable,
    }

    /// A fake remote builder: advertises an arch via `probe_arch` and records
    /// whether `build_remote` was actually called (to prove arch mismatch skips
    /// the build).
    struct FakeRemote {
        advertised_arch: String,
        behavior: BuildBehavior,
        build_called: Cell<bool>,
    }

    impl FakeRemote {
        fn new(advertised_arch: &str, behavior: BuildBehavior) -> Self {
            Self {
                advertised_arch: advertised_arch.to_string(),
                behavior,
                build_called: Cell::new(false),
            }
        }
    }

    impl RemoteBuilder for FakeRemote {
        fn probe_arch(&self, _host: &str) -> Result<String, RemoteError> {
            Ok(self.advertised_arch.clone())
        }

        fn build_remote(&self, _derivation: &str, host: &str, _arch: &str) -> Result<RemoteArtifacts, RemoteError> {
            self.build_called.set(true);
            match self.behavior {
                BuildBehavior::Artifacts => Ok(RemoteArtifacts {
                    output_store_path: "/nix/store/zzz-out".to_string(),
                }),
                BuildBehavior::Unreachable => Err(RemoteError::Unreachable(host.to_string())),
            }
        }
    }

    fn sample_job() -> Job {
        Job {
            template: "tpl".to_string(),
            command: vec!["echo".to_string(), "hi".to_string()],
        }
    }

    /// D-REQ-1 (positive): a reachable remote of the right arch returns artifacts
    /// → the job provisions with a succeeded envelope.
    #[test]
    fn remote_build_provisions_runs_job() {
        let job = sample_job();
        let remote = FakeRemote::new("x86_64-linux", BuildBehavior::Artifacts);
        let outcome = provision_remote_build(&job, "builder.example", "x86_64-linux", &remote);
        let ProvisionOutcome::Provisioned(env) = outcome else {
            panic!("a successful remote build must provision, got {outcome:?}");
        };
        assert_eq!(env.status, Status::Succeeded, "a successful remote build is succeeded");
        assert!(!env.retryable, "a success is not retryable");
    }

    /// D-REQ-1 (adversarial) + INV-7: a remote unreachable mid-build is an infra
    /// fault → a failed, retryable envelope, never a guest exit.
    #[test]
    fn remote_unreachable_retryable() {
        let job = sample_job();
        let remote = FakeRemote::new("x86_64-linux", BuildBehavior::Unreachable);
        let outcome = provision_remote_build(&job, "builder.example", "x86_64-linux", &remote);
        let ProvisionOutcome::Provisioned(env) = outcome else {
            panic!("an infra fault maps to a failed envelope, got {outcome:?}");
        };
        assert_eq!(env.status, Status::Failed, "an infra fault is failed");
        assert!(env.retryable, "an infra fault is retryable (INV-7)");
    }

    /// D-REQ-1 (adversarial): a remote that can only build a different arch →
    /// `Refused` naming `arch`, with **no build attempted**.
    #[test]
    fn remote_arch_mismatch_refuses() {
        let job = sample_job();
        let remote = FakeRemote::new("aarch64-linux", BuildBehavior::Artifacts);
        let outcome = provision_remote_build(&job, "builder.example", "x86_64-linux", &remote);
        let ProvisionOutcome::Refused { reason } = outcome else {
            panic!("an arch mismatch must refuse, got {outcome:?}");
        };
        assert!(reason.contains("arch"), "the refusal must name the arch axis: {reason}");
        assert!(
            !remote.build_called.get(),
            "an arch mismatch must not attempt a build (build_remote was called)"
        );
    }
}
