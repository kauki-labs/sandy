//! Outcome classification over the LOCKED result types (INV-6, INV-7, INV-11).
//!
//! The envelope and classification *types* live in [`sandy_api::result`] and are
//! re-exported here so `sandy::…` import paths are unchanged. This module keeps
//! the classification *functions*: they map a physical [`Outcome`] (or a backend
//! / plan error) into the envelope `status`, the `retryable` flag, and sandy's
//! own *process* exit band — distinct from `exit_code` (the GUEST's code).

pub use sandy_api::result::*;

use crate::backend::{BackendError, Outcome, PlanError};

/// Clean guest success (band 0).
const fn succeeded() -> Classification {
    Classification {
        status: Status::Succeeded,
        retryable: false,
        process_exit: ProcessExit::Succeeded,
    }
}

/// Task/contract fault (band 1, never retryable).
const fn task_failure() -> Classification {
    Classification {
        status: Status::Failed,
        retryable: false,
        process_exit: ProcessExit::TaskFailure,
    }
}

/// Invalid plan / usage (band 2, never retryable).
const fn invalid_plan() -> Classification {
    Classification {
        status: Status::Failed,
        retryable: false,
        process_exit: ProcessExit::InvalidPlan,
    }
}

/// Infra fault (band 3) — the only retryable band (INV-7).
const fn infra_fault() -> Classification {
    Classification {
        status: Status::Failed,
        retryable: true,
        process_exit: ProcessExit::InfraFault,
    }
}

/// Classify a completed backend [`Outcome`] plus its output resolution into the
/// terminal [`Classification`] (INV-7/INV-11): exit-0 + complete → succeeded /
/// band 0; guest-nonzero / timeout / required-missing / over-quota → failed /
/// band 1 / not retryable; not-booted or transport error → failed / band 3 /
/// retryable.
#[must_use]
pub fn classify_outcome(outcome: &Outcome, outputs: OutputStatus) -> Classification {
    // A backend that never booted, or a broken control channel, is an infra
    // fault — the only retryable band (INV-7). A booted-but-silent guest
    // (no exit, no timeout) is also transport (D8).
    if !outcome.booted || outcome.transport_error.is_some() {
        return infra_fault();
    }
    // A timeout is a task/contract fault, never retryable by the platform.
    if outcome.timed_out {
        return task_failure();
    }
    match outcome.guest_exit {
        Some(0) => match outputs {
            OutputStatus::Complete => succeeded(),
            OutputStatus::RequiredMissing | OutputStatus::OverQuota => task_failure(),
        },
        Some(_) => task_failure(),
        None => infra_fault(),
    }
}

/// Classify a [`BackendError`] as an infra fault (band 3, `retryable: true`).
#[must_use]
pub fn classify_backend_error(_error: &BackendError) -> Classification {
    infra_fault()
}

/// Classify a [`PlanError`] as an invalid plan (band 2, `retryable: false`, no
/// boot).
#[must_use]
pub fn classify_invalid_plan(_error: &PlanError) -> Classification {
    invalid_plan()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_envelope() -> ResultEnvelope {
        ResultEnvelope {
            result_schema_version: RESULT_SCHEMA_VERSION,
            job_id: "job-1".to_string(),
            box_id: Some("box-1".to_string()),
            status: Status::Succeeded,
            retryable: false,
            message: "ok".to_string(),
            exit_code: Some(0),
            outputs: vec![OutputRef {
                path: "result.txt".to_string(),
            }],
            receipts: vec![Receipt {
                kind: "github-pr".to_string(),
                r#ref: "https://example/pull/1".to_string(),
            }],
            provenance: Provenance {
                template_store_path: "/nix/store/xxx-template".to_string(),
            },
            logs: Logs {
                tail: "done".to_string(),
            },
        }
    }

    /// INV-11: the envelope's wire keys are exactly the LOCKED `snake_case` set,
    /// including nested `outputs[].path`, `receipts[].ref` (raw-ident
    /// `r#ref`), `provenance.template_store_path`, and `logs.tail`.
    #[test]
    fn envelope_wire_keys_are_snake_case() -> anyhow::Result<()> {
        let value = serde_json::to_value(sample_envelope())?;
        let obj = value.as_object().expect("envelope is an object");
        let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "box_id",
                "exit_code",
                "job_id",
                "logs",
                "message",
                "outputs",
                "provenance",
                "receipts",
                "result_schema_version",
                "retryable",
                "status",
            ]
        );
        assert_eq!(value["receipts"][0]["ref"], "https://example/pull/1");
        assert_eq!(value["provenance"]["template_store_path"], "/nix/store/xxx-template");
        assert_eq!(value["logs"]["tail"], "done");
        assert_eq!(value["outputs"][0]["path"], "result.txt");
        Ok(())
    }

    /// INV-11: the wire `status` values are the LOCKED lowercase strings.
    #[test]
    fn status_wire_values_are_locked() -> anyhow::Result<()> {
        assert_eq!(serde_json::to_value(Status::Succeeded)?, "succeeded");
        assert_eq!(serde_json::to_value(Status::Failed)?, "failed");
        assert_eq!(serde_json::to_value(Status::Cancelled)?, "cancelled");
        Ok(())
    }

    /// INV-11: the process-exit bands are `0`/`1`/`2`/`3`.
    #[test]
    fn process_exit_bands_match_inv11() {
        assert_eq!(ProcessExit::Succeeded.code(), 0);
        assert_eq!(ProcessExit::TaskFailure.code(), 1);
        assert_eq!(ProcessExit::InvalidPlan.code(), 2);
        assert_eq!(ProcessExit::InfraFault.code(), 3);
    }

    /// INV-11 cross-check + INV-7: a clean exit-0 with all outputs is
    /// succeeded / band 0 / not retryable; and process-exit 0 ⟺ succeeded.
    #[test]
    fn exit_zero_maps_to_succeeded_band_zero() {
        let outcome = Outcome {
            booted: true,
            guest_exit: Some(0),
            transport_error: None,
            timed_out: false,
            console: String::new(),
        };
        let c = classify_outcome(&outcome, OutputStatus::Complete);
        assert_eq!(c.status, Status::Succeeded);
        assert_eq!(c.process_exit, ProcessExit::Succeeded);
        assert!(!c.retryable);
    }

    /// INV-7 + INV-11: a nonzero guest exit is a task failure (band 1), not
    /// retryable.
    #[test]
    fn guest_nonzero_is_task_failure_not_retryable() {
        let outcome = Outcome {
            booted: true,
            guest_exit: Some(7),
            transport_error: None,
            timed_out: false,
            console: String::new(),
        };
        let c = classify_outcome(&outcome, OutputStatus::Complete);
        assert_eq!(c.status, Status::Failed);
        assert_eq!(c.process_exit, ProcessExit::TaskFailure);
        assert!(!c.retryable);
    }

    /// INV-7 + INV-11: a timeout is a task failure (band 1), not retryable.
    #[test]
    fn timeout_is_task_failure_not_retryable() {
        let outcome = Outcome {
            booted: true,
            guest_exit: None,
            transport_error: None,
            timed_out: true,
            console: String::new(),
        };
        let c = classify_outcome(&outcome, OutputStatus::Complete);
        assert_eq!(c.process_exit, ProcessExit::TaskFailure);
        assert!(!c.retryable);
    }

    /// INV-7 + INV-11 cross-check: a boot failure is an infra fault (band 3)
    /// and process-exit 3 ⟺ retryable == true.
    #[test]
    fn boot_failure_is_infra_fault_and_retryable() {
        let outcome = Outcome {
            booted: false,
            guest_exit: None,
            transport_error: None,
            timed_out: false,
            console: String::new(),
        };
        let c = classify_outcome(&outcome, OutputStatus::RequiredMissing);
        assert_eq!(c.process_exit, ProcessExit::InfraFault);
        assert!(c.retryable);
        assert_ne!(c.status, Status::Succeeded);
    }

    /// INV-7: a transport error (contract broke) is an infra fault, retryable.
    #[test]
    fn transport_error_is_infra_fault_and_retryable() {
        let c = classify_backend_error(&BackendError::Transport("gone".to_string()));
        assert_eq!(c.process_exit, ProcessExit::InfraFault);
        assert!(c.retryable);
    }

    /// INV-7 + INV-11: an invalid plan is band 2 and never retryable.
    #[test]
    fn invalid_plan_is_band_two_not_retryable() {
        let c = classify_invalid_plan(&PlanError::Invalid("bad path".to_string()));
        assert_eq!(c.process_exit, ProcessExit::InvalidPlan);
        assert!(!c.retryable);
    }
}
