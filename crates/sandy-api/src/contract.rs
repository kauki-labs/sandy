//! The run-plane's fake-free seam contract-test harness (#131 R4b): one suite per
//! seam — [`vmbackend_suite`], [`guest_share_transport_suite`],
//! [`egress_applier_suite`] — that any impl, trivial or real, runs itself against.
//! The caller supplies the impl through a factory (a fresh instance per check), so
//! the suite stays generic over the concrete type.
//!
//! This is the capstone proof the #131 restructure's seams stay interchangeable:
//! `sandy-cli`'s `acceptance-local` binary runs these against the real
//! `ProcessBackend` / `LocalDirTransport` / `NoEgress` (no hypervisor, CI-default);
//! `acceptance-vm` runs them against the real VM impls (live-gated, needs a
//! hypervisor). A suite returns `Err(ContractViolation)` naming the broken rule,
//! so a caller can assert on a violation as well as on a pass — mirrors
//! `sandy-fabric`'s `contract` module for the (separate, #103/#104) agent-fabric
//! seams.

use std::fmt::Display;

use crate::{
    backend::{Grants, RunControl, RunSpec, VmBackend},
    egress::EgressApplier,
    share::GuestShareTransport,
};

/// A seam implementation broke its contract.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{seam} contract violated: {rule}")]
pub struct ContractViolation {
    /// The seam whose contract was broken.
    pub seam: &'static str,
    /// The rule that was broken, and how.
    pub rule: String,
}

/// A violation of `rule` on `seam`.
fn violation(seam: &'static str, rule: impl Into<String>) -> ContractViolation {
    ContractViolation {
        seam,
        rule: rule.into(),
    }
}

/// Fail with `rule` unless `ok`.
fn require(seam: &'static str, ok: bool, rule: &str) -> Result<(), ContractViolation> {
    if ok { Ok(()) } else { Err(violation(seam, rule)) }
}

/// Unwrap a seam call the contract expects to succeed.
fn expect_ok<T, E: Display>(seam: &'static str, call: &str, res: Result<T, E>) -> Result<T, ContractViolation> {
    res.map_err(|e| violation(seam, format!("{call} failed unexpectedly: {e}")))
}

/// Build a `RunSpec` booting `template` with `command` and no inputs, outputs, or
/// secrets.
fn run_spec<'a>(template: &'a str, command: &'a [String], grants: &'a Grants, control: &'a RunControl) -> RunSpec<'a> {
    RunSpec {
        template,
        command,
        inputs: &[],
        outputs: &[],
        secrets: &[],
        env: &[],
        cpu: None,
        mem: None,
        timeout_secs: 30,
        grants,
        outcome_file: None,
        secret_dir: None,
        control,
    }
}

/// Run the [`VmBackend`] contract: a fresh backend has no boxes, killing an
/// unknown box is defined (no panic, no box appears), a trivially-successful job
/// (`true`) boots and exits 0 with no transport fault, and no box lingers after a
/// synchronous run.
///
/// `template` is a guest the backend can actually boot: ignored by the fake and
/// the process backend (which never resolve it), but a real VM backend needs a
/// genuine flake-attr/image reference — pass whatever that backend's `make`
/// factory is already configured to boot (the literal string `"contract"` is fine
/// for a non-VM backend).
pub fn vmbackend_suite<B: VmBackend>(template: &str, make: impl Fn() -> B) -> Result<(), ContractViolation> {
    const SEAM: &str = "VmBackend";
    let backend = make();
    require(
        SEAM,
        expect_ok(SEAM, "boxes", backend.boxes())?.is_empty(),
        "a fresh backend has no boxes",
    )?;

    expect_ok(SEAM, "kill of an unknown box", backend.kill("does-not-exist"))?;
    require(
        SEAM,
        expect_ok(SEAM, "boxes", backend.boxes())?.is_empty(),
        "killing an unknown box leaves no boxes",
    )?;

    let backend = make();
    let grants = Grants {
        secrets: false,
        agent: false,
        shares: false,
    };
    let command = ["true".to_string()];
    let control = RunControl::with_timeout_secs(30);
    let outcome = expect_ok(
        SEAM,
        "run",
        backend.run(&run_spec(template, &command, &grants, &control)),
    )?;
    require(
        SEAM,
        outcome.booted && outcome.guest_exit == Some(0) && outcome.transport_error.is_none() && !outcome.timed_out,
        "a successful run boots, exits 0, and is not a transport fault or a timeout",
    )?;
    require(
        SEAM,
        expect_ok(SEAM, "boxes", backend.boxes())?.is_empty(),
        "no box lingers after a synchronous run",
    )
}

/// Run the [`GuestShareTransport`] contract: [`plan`](GuestShareTransport::plan)
/// is PURE (the same shares yield the same presentation every time) and every
/// supplied share's tag is represented in the output; an empty share set yields an
/// empty presentation. `activate` (IO) is not exercised generically — it varies too
/// much by transport (a daemon spawn vs. a local-dir chmod) to have a useful
/// shared contract beyond what `plan` already pins; each impl proves its own
/// `activate` (e.g. the process backend's read-only share tests).
pub fn guest_share_transport_suite<T: GuestShareTransport>(make: impl Fn() -> T) -> Result<(), ContractViolation> {
    use crate::share::{Presentation, ShareSpec};
    const SEAM: &str = "GuestShareTransport";
    let transport = make();

    let empty = transport.plan(&[], 512);
    let empty_again = transport.plan(&[], 512);
    require(SEAM, empty == empty_again, "plan is pure: same input, same output")?;
    let empty_is_empty = match &empty {
        Presentation::Vm { args } => args.is_empty(),
        Presentation::LocalDir { placements, .. } => placements.is_empty(),
    };
    require(SEAM, empty_is_empty, "an empty share set yields an empty presentation")?;

    let shares = vec![
        ShareSpec {
            host_dir: "/tmp/contract-ro".into(),
            tag: "sandy-inputs".to_string(),
            readonly: true,
            socket: "/tmp/contract-ro.sock".into(),
        },
        ShareSpec {
            host_dir: "/tmp/contract-rw".into(),
            tag: "sandy-outputs".to_string(),
            readonly: false,
            socket: "/tmp/contract-rw.sock".into(),
        },
    ];
    let plan_a = transport.plan(&shares, 512);
    let plan_b = transport.plan(&shares, 512);
    require(SEAM, plan_a == plan_b, "plan is pure for a non-empty share set too")?;

    match plan_a {
        Presentation::Vm { args } => {
            require(SEAM, !args.is_empty(), "a non-empty share set yields non-empty argv")?;
            for share in &shares {
                require(
                    SEAM,
                    args.iter().any(|a| a.contains(&share.tag)),
                    "every supplied share's tag is represented in the argv",
                )?;
            }
        }
        Presentation::LocalDir { placements, .. } => {
            require(
                SEAM,
                placements.len() == shares.len(),
                "one placement per supplied share",
            )?;
            for share in &shares {
                let placement = placements.iter().find(|p| p.tag == share.tag);
                require(
                    SEAM,
                    placement.is_some(),
                    "every supplied share's tag has a matching placement",
                )?;
                if let Some(p) = placement {
                    require(
                        SEAM,
                        p.readonly == share.readonly,
                        "a placement's read-only flag matches its share's",
                    )?;
                }
            }
        }
    }
    Ok(())
}

/// Run the [`EgressApplier`] contract: `apply` then `revert` succeed, and `revert`
/// is safe to call when nothing is applied (teardown must never be the one failure
/// mode on an already-clean or already-reverted boundary).
///
/// Scope: this is a contract for a TRIVIAL/isolated applier (`NoEgress`, a fake, a
/// test double) — `make` must yield a fresh, independent instance per check, with
/// no shared host resource across instances. The real `NftablesApplier` is NOT a
/// conformant target: its `revert` unconditionally deletes one FIXED, shared host
/// table regardless of what `apply` loaded, so it errors on an already-reverted
/// boundary (the opposite of this suite's idempotence rule) and risks colliding
/// with another concurrent run's live boundary if driven outside its real
/// mint-apply-revert bracket. The real applier's enforcement is proven instead by
/// the dedicated, carefully root-gated `live_egress.rs` (#29), never by this
/// generic suite.
pub fn egress_applier_suite<A: EgressApplier>(make: impl Fn() -> A) -> Result<(), ContractViolation> {
    const SEAM: &str = "EgressApplier";
    let applier = make();
    expect_ok(SEAM, "apply", applier.apply("contract-ruleset"))?;
    expect_ok(SEAM, "revert", applier.revert())?;
    expect_ok(SEAM, "a second revert with nothing applied", applier.revert())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        backend::{BackendError, BoxState, Outcome},
        egress::EgressError,
        share::{Placement, Presentation, ShareSpec},
    };

    /// A trivial in-process `VmBackend` the suite must accept: no boxes, a `true`
    /// run that exits 0.
    struct TrivialBackend;
    impl VmBackend for TrivialBackend {
        fn run(&self, _spec: &RunSpec) -> Result<Outcome, BackendError> {
            Ok(Outcome {
                booted: true,
                guest_exit: Some(0),
                transport_error: None,
                timed_out: false,
                console: String::new(),
            })
        }

        fn kill(&self, _box_id: &str) -> Result<(), BackendError> {
            Ok(())
        }

        fn boxes(&self) -> Result<Vec<BoxState>, BackendError> {
            Ok(Vec::new())
        }
    }

    #[test]
    fn vmbackend_suite_accepts_a_trivial_conforming_backend() {
        assert!(vmbackend_suite("contract", || TrivialBackend).is_ok());
    }

    /// Adversarial: a backend that reports a lingering box after a synchronous run
    /// must be caught, not waved through. `boxes()` is honest (empty) until `run()`
    /// executes, so the suite's earlier "fresh backend has no boxes" check passes
    /// and the violation actually exercises the post-run lingering-box rule.
    #[derive(Default)]
    struct LingersBackend {
        ran: std::cell::Cell<bool>,
    }
    impl VmBackend for LingersBackend {
        fn run(&self, _spec: &RunSpec) -> Result<Outcome, BackendError> {
            self.ran.set(true);
            Ok(Outcome {
                booted: true,
                guest_exit: Some(0),
                transport_error: None,
                timed_out: false,
                console: String::new(),
            })
        }

        fn kill(&self, _box_id: &str) -> Result<(), BackendError> {
            Ok(())
        }

        fn boxes(&self) -> Result<Vec<BoxState>, BackendError> {
            if !self.ran.get() {
                return Ok(vec![]);
            }
            Ok(vec![BoxState {
                box_id: "ghost".to_string(),
                box_name: "ghost".to_string(),
                pid: 1,
                started: std::time::SystemTime::now(),
                rvport: None,
            }])
        }
    }

    #[test]
    fn vmbackend_suite_rejects_a_lingering_box() -> anyhow::Result<()> {
        let err = vmbackend_suite("contract", LingersBackend::default).expect_err("a lingering box must be caught");
        assert_eq!(err.seam, "VmBackend");
        assert!(
            err.rule.contains("linger"),
            "expected the post-run lingering-box rule, got: {}",
            err.rule
        );
        Ok(())
    }

    /// A LocalDir transport whose placements correctly track the supplied shares.
    struct TrivialLocalTransport;
    impl GuestShareTransport for TrivialLocalTransport {
        fn plan(&self, shares: &[ShareSpec], _mem_mib: u32) -> Presentation {
            Presentation::LocalDir {
                root: "/tmp".into(),
                placements: shares
                    .iter()
                    .map(|s| Placement {
                        tag: s.tag.clone(),
                        dir: s.host_dir.clone(),
                        readonly: s.readonly,
                    })
                    .collect(),
            }
        }

        fn activate(&self, _shares: &[ShareSpec]) -> Result<Vec<std::process::Child>, BackendError> {
            Ok(Vec::new())
        }
    }

    #[test]
    fn guest_share_transport_suite_accepts_a_conforming_local_dir_transport() {
        assert!(guest_share_transport_suite(|| TrivialLocalTransport).is_ok());
    }

    /// Adversarial: a transport that drops the read-only flag must be caught.
    struct DropsReadonlyTransport;
    impl GuestShareTransport for DropsReadonlyTransport {
        fn plan(&self, shares: &[ShareSpec], _mem_mib: u32) -> Presentation {
            Presentation::LocalDir {
                root: "/tmp".into(),
                placements: shares
                    .iter()
                    .map(|s| Placement {
                        tag: s.tag.clone(),
                        dir: s.host_dir.clone(),
                        readonly: false, // always writable — the bug under test
                    })
                    .collect(),
            }
        }

        fn activate(&self, _shares: &[ShareSpec]) -> Result<Vec<std::process::Child>, BackendError> {
            Ok(Vec::new())
        }
    }

    #[test]
    fn guest_share_transport_suite_rejects_a_dropped_readonly_flag() -> anyhow::Result<()> {
        let err =
            guest_share_transport_suite(|| DropsReadonlyTransport).expect_err("a dropped readonly flag must be caught");
        assert_eq!(err.seam, "GuestShareTransport");
        Ok(())
    }

    struct TrivialApplier;
    impl EgressApplier for TrivialApplier {
        fn apply(&self, _ruleset: &str) -> Result<(), EgressError> {
            Ok(())
        }

        fn revert(&self) -> Result<(), EgressError> {
            Ok(())
        }
    }

    #[test]
    fn egress_applier_suite_accepts_a_conforming_applier() {
        assert!(egress_applier_suite(|| TrivialApplier).is_ok());
    }

    /// Adversarial: an applier whose SECOND revert fails (the already-reverted
    /// case) must be caught — teardown must not be the one failure mode on a
    /// clean boundary. The first revert succeeds, so this isolates the
    /// idempotence rule specifically, not a generally-broken revert.
    struct FailsOnSecondRevertApplier {
        reverted: std::cell::Cell<bool>,
    }
    impl EgressApplier for FailsOnSecondRevertApplier {
        fn apply(&self, _ruleset: &str) -> Result<(), EgressError> {
            Ok(())
        }

        fn revert(&self) -> Result<(), EgressError> {
            if self.reverted.replace(true) {
                Err(EgressError::Apply("already reverted".to_string()))
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn egress_applier_suite_rejects_a_revert_that_fails_when_idempotent() -> anyhow::Result<()> {
        let err = egress_applier_suite(|| FailsOnSecondRevertApplier {
            reverted: std::cell::Cell::new(false),
        })
        .expect_err("a revert that fails the second time (idempotence) must be caught");
        assert_eq!(err.seam, "EgressApplier");
        Ok(())
    }
}
