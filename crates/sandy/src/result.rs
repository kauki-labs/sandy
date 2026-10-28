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
    use anyhow::Context;

    use super::*;
    use crate::{AllowList, ContentDigests, FileDigest, SkipReason, SkippedEntry};

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
            warnings: vec!["credential \"GH_TOKEN\" revoke failed at teardown; relying on native expiry".to_string()],
            receipt: Some(sample_receipt()),
        }
    }

    /// A fully populated [`AuditReceipt`] exercising every nested wire key,
    /// including the `where`/`guest_reported` raw-ish names (#361).
    fn sample_receipt() -> AuditReceipt {
        AuditReceipt {
            host_observed: HostObserved {
                who: Who {
                    identity: "1000".to_string(),
                    authenticated: false,
                },
                what: What {
                    job_id: "job-1".to_string(),
                    template: "demo".to_string(),
                    template_store_path: None,
                    manifest_digest: None,
                },
                location: Location {
                    backend: "qemu".to_string(),
                    executor_host_id: None,
                    executor_mesh_ip: None,
                },
                credential: None,
                egress: EgressReceipt {
                    status: EgressEnforcement::Enforced,
                    reason: None,
                    allow_list: Some(AllowList::default()),
                    attempts: vec![],
                },
                timing: Timing {
                    boot_started_at: std::time::SystemTime::UNIX_EPOCH,
                    job_started_at: None,
                    teardown_at: std::time::SystemTime::UNIX_EPOCH,
                },
                input_digests: None,
            },
            guest_reported: GuestReported {
                exit_code: Some(0),
                outputs: vec![OutputSizeRef {
                    path: "result.txt".to_string(),
                    size_bytes: 3,
                    sha256: None,
                }],
                skipped_outputs: vec![],
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
                "receipt",
                "receipts",
                "result_schema_version",
                "retryable",
                "status",
                "warnings",
            ]
        );
        assert_eq!(value["receipts"][0]["ref"], "https://example/pull/1");
        assert_eq!(value["provenance"]["template_store_path"], "/nix/store/xxx-template");
        assert_eq!(value["logs"]["tail"], "done");
        assert_eq!(value["outputs"][0]["path"], "result.txt");
        assert_eq!(
            value["warnings"][0],
            "credential \"GH_TOKEN\" revoke failed at teardown; relying on native expiry"
        );
        // #361: the new receipt's nested keys, including the `where`/`guest_reported`
        // names the issue's own vocabulary uses — never `location` or `guestReported`.
        let receipt = &value["receipt"];
        assert_eq!(receipt["host_observed"]["who"]["identity"], "1000");
        assert_eq!(receipt["host_observed"]["who"]["authenticated"], false);
        assert_eq!(receipt["host_observed"]["what"]["job_id"], "job-1");
        assert_eq!(receipt["host_observed"]["where"]["backend"], "qemu");
        assert!(
            receipt["host_observed"].get("location").is_none(),
            "the wire key must be `where`, not the Rust field name `location`"
        );
        assert_eq!(receipt["host_observed"]["egress"]["status"], "enforced");
        assert_eq!(receipt["guest_reported"]["exit_code"], 0);
        assert_eq!(receipt["guest_reported"]["outputs"][0]["path"], "result.txt");
        assert_eq!(receipt["guest_reported"]["outputs"][0]["size_bytes"], 3);
        Ok(())
    }

    /// L-12: a pre-`warnings` (schema v1) journal record with no `warnings` key
    /// still deserializes, defaulting to empty — `#[serde(default)]` keeps old
    /// records readable across the schema bump.
    #[test]
    fn an_old_schema_v1_record_with_no_warnings_key_deserializes_to_empty() -> anyhow::Result<()> {
        let v1_json = serde_json::json!({
            "result_schema_version": 1,
            "job_id": "job-1",
            "box_id": null,
            "status": "succeeded",
            "retryable": false,
            "message": "ok",
            "exit_code": 0,
            "outputs": [],
            "receipts": [],
            "provenance": { "template_store_path": "" },
            "logs": { "tail": "" },
        });
        let envelope: ResultEnvelope = serde_json::from_value(v1_json)?;
        assert!(envelope.warnings.is_empty());
        Ok(())
    }

    /// #361: a pre-`3` (schema `2`) journal record with no `receipt` key still
    /// deserializes, defaulting to `None` — same `#[serde(default)]` precedent as
    /// `warnings` above, one schema bump later.
    #[test]
    fn an_old_schema_v2_record_with_no_receipt_key_deserializes_to_none() -> anyhow::Result<()> {
        let v2_json = serde_json::json!({
            "result_schema_version": 2,
            "job_id": "job-1",
            "box_id": null,
            "status": "succeeded",
            "retryable": false,
            "message": "ok",
            "exit_code": 0,
            "outputs": [],
            "receipts": [],
            "provenance": { "template_store_path": "" },
            "logs": { "tail": "" },
            "warnings": [],
        });
        let envelope: ResultEnvelope = serde_json::from_value(v2_json)?;
        assert!(envelope.receipt.is_none());
        Ok(())
    }

    /// #373: a pre-`4` (schema `3`) receipt, with none of the digest keys, still
    /// deserializes, every digest field defaulting to absent.
    #[test]
    fn an_old_schema_v3_receipt_with_no_digest_keys_deserializes_to_none() -> anyhow::Result<()> {
        let mut v3 = serde_json::to_value(sample_envelope())?;
        v3["result_schema_version"] = 3.into();
        let receipt = v3["receipt"].as_object().context("receipt object")?;
        assert!(receipt["host_observed"].get("input_digests").is_none());

        let envelope: ResultEnvelope = serde_json::from_value(v3)?;

        let receipt = envelope.receipt.context("receipt")?;
        assert_eq!(receipt.host_observed.input_digests, None);
        assert_eq!(receipt.guest_reported.outputs[0].sha256, None);
        assert!(receipt.guest_reported.skipped_outputs.is_empty());
        Ok(())
    }

    /// #373: with the flag off no digest key reaches the wire at all, at any
    /// level of the receipt.
    #[test]
    fn a_receipt_without_digests_serializes_no_digest_keys() -> anyhow::Result<()> {
        let json = serde_json::to_string(&sample_envelope())?;
        for key in ["sha256", "input_digests", "skipped_outputs", "skipped"] {
            assert!(!json.contains(key), "unexpected `{key}` in {json}");
        }
        Ok(())
    }

    /// #373: the digest wire shape, including the `snake_case` skip reasons.
    #[test]
    fn digest_wire_shape_is_locked() -> anyhow::Result<()> {
        let mut receipt = sample_receipt();
        receipt.host_observed.input_digests = Some(ContentDigests {
            files: vec![FileDigest {
                path: "in/a".to_string(),
                sha256: "ab".to_string(),
            }],
            skipped: vec![],
        });
        receipt.guest_reported.outputs[0].sha256 = Some("cd".to_string());
        receipt.guest_reported.skipped_outputs = vec![
            SkippedEntry {
                path: "o/l".to_string(),
                reason: SkipReason::Symlink,
            },
            SkippedEntry {
                path: "o/p".to_string(),
                reason: SkipReason::NonRegular,
            },
        ];

        let value = serde_json::to_value(&receipt)?;

        assert_eq!(value["host_observed"]["input_digests"]["files"][0]["path"], "in/a");
        assert_eq!(value["host_observed"]["input_digests"]["files"][0]["sha256"], "ab");
        assert!(value["host_observed"]["input_digests"].get("skipped").is_none());
        assert_eq!(value["guest_reported"]["outputs"][0]["sha256"], "cd");
        assert_eq!(value["guest_reported"]["skipped_outputs"][0]["reason"], "symlink");
        assert_eq!(value["guest_reported"]["skipped_outputs"][1]["reason"], "non_regular");
        let back: AuditReceipt = serde_json::from_value(value)?;
        assert_eq!(back, receipt);
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
            digests: None,
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
            digests: None,
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
            digests: None,
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
            digests: None,
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

    /// INV-7 + INV-11 (#360): a dead egress proxy is band 3 and retryable whatever
    /// the guest exit. A guest that exited 0 behind a dead proxy must not read as
    /// `succeeded`: it ran without its network.
    #[test]
    fn a_dead_egress_proxy_is_an_infra_fault_whatever_the_guest_exit() {
        for guest_exit in [None, Some(0), Some(7)] {
            let c = classify_backend_error(&BackendError::EgressProxyDied {
                status: Some(2),
                booted: true,
                guest_exit,
            });
            assert_eq!(c.process_exit, ProcessExit::InfraFault, "guest_exit {guest_exit:?}");
            assert!(c.retryable, "guest_exit {guest_exit:?}");
            assert_ne!(c.status, Status::Succeeded, "guest_exit {guest_exit:?}");
            // Status, retryable, and exit band agree (INV-11).
            assert_eq!(c.process_exit == ProcessExit::InfraFault, c.retryable);
        }
    }
}
