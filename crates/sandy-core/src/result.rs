//! The LOCKED result envelope and outcome classification (INV-6, INV-7, INV-11).
//!
//! The envelope is `snake_case` on the wire and in Rust, with no serde rename
//! layer. The classification functions map a physical [`Outcome`] (or a backend
//! / plan error) into the envelope `status`, the `retryable` flag, and sandy's
//! own *process* exit band — which is distinct from `exit_code` (the GUEST's
//! code).

use serde::{Deserialize, Serialize};

use crate::backend::{BackendError, Outcome, PlanError};

/// The schema version stamped into every envelope (INV-6/INV-11).
pub const RESULT_SCHEMA_VERSION: u32 = 1;

/// Terminal status of a job on the wire. The lowercase values are part of the
/// LOCKED schema; `rename_all` selects them without renaming any field key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// Guest exited 0 and all required outputs were collected.
    Succeeded,
    /// A task/contract fault, or an infra fault that aborted the run.
    Failed,
    /// The job was cancelled before a terminal guest result.
    Cancelled,
}

/// sandy's own *process* exit band (INV-11) — never conflated with the guest's
/// `exit_code`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessExit {
    /// `0` — succeeded.
    Succeeded,
    /// `1` — task failure (guest-nonzero / timeout / missing-required /
    /// cancelled); `retryable: false`.
    TaskFailure,
    /// `2` — invalid plan / usage; `retryable: false`; no boot.
    InvalidPlan,
    /// `3` — infra fault (boot / transport / unreachable / host-IO);
    /// `retryable: true`.
    InfraFault,
}

impl ProcessExit {
    /// The numeric process exit code for this band (`0`/`1`/`2`/`3`).
    #[must_use]
    pub fn code(self) -> i32 {
        todo!("map the band to 0/1/2/3")
    }
}

/// How a job's declared outputs resolved, fed into [`classify_outcome`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputStatus {
    /// Every required output was collected.
    Complete,
    /// A required output was absent after a clean exit.
    RequiredMissing,
    /// Collection exceeded the per-job cap.
    OverQuota,
}

/// The terminal classification of a job: the three values that MUST stay
/// consistent (INV-11 cross-checks).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Classification {
    /// The envelope status.
    pub status: Status,
    /// Whether the platform may retry (true only for infra faults, INV-7).
    pub retryable: bool,
    /// sandy's process exit band.
    pub process_exit: ProcessExit,
}

/// Classify a completed backend [`Outcome`] plus its output resolution into the
/// terminal [`Classification`] (INV-7/INV-11): exit-0 + complete → succeeded /
/// band 0; guest-nonzero / timeout / required-missing / over-quota → failed /
/// band 1 / not retryable; not-booted or transport error → failed / band 3 /
/// retryable.
#[must_use]
pub fn classify_outcome(_outcome: &Outcome, _outputs: OutputStatus) -> Classification {
    todo!("map Outcome + OutputStatus to status/retryable/process_exit")
}

/// Classify a [`BackendError`] as an infra fault (band 3, `retryable: true`).
#[must_use]
pub fn classify_backend_error(_error: &BackendError) -> Classification {
    todo!("every BackendError is an infra fault")
}

/// Classify a [`PlanError`] as an invalid plan (band 2, `retryable: false`, no
/// boot).
#[must_use]
pub fn classify_invalid_plan(_error: &PlanError) -> Classification {
    todo!("invalid plan is band 2, not retryable")
}

/// One collected output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputRef {
    /// Path of the collected output, relative to the job's `out/`.
    pub path: String,
}

/// A side effect produced by the job (e.g. a GitHub PR).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receipt {
    /// The receipt kind, e.g. `"github-pr"`.
    pub kind: String,
    /// A reference for the receipt, e.g. a PR URL. Serializes as the `ref` key.
    pub r#ref: String,
}

/// Provenance of the run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    /// The Nix store path of the template that was booted.
    pub template_store_path: String,
}

/// Captured guest logs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Logs {
    /// The tail of the guest's combined output.
    pub tail: String,
}

/// The LOCKED result envelope (INV-11). Written to the journal at the terminal
/// transition (INV-6) and printed by foreground `run`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResultEnvelope {
    /// Schema version of this envelope.
    pub result_schema_version: u32,
    /// The job id.
    pub job_id: String,
    /// The box the job ran in, if one booted.
    pub box_id: Option<String>,
    /// Terminal status.
    pub status: Status,
    /// Whether the platform may retry (INV-7).
    pub retryable: bool,
    /// A human-readable message.
    pub message: String,
    /// The GUEST's exit code (never sandy's process band — INV-11).
    pub exit_code: Option<i32>,
    /// Collected outputs.
    pub outputs: Vec<OutputRef>,
    /// Side-effect receipts.
    pub receipts: Vec<Receipt>,
    /// Run provenance.
    pub provenance: Provenance,
    /// Captured logs.
    pub logs: Logs,
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
