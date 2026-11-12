//! The result envelope `sandyd` builds for a terminal job (A2 of #483, INV-11): the same locked
//! [`sandy::ResultEnvelope`] a direct `sandy run` prints, from the physical facts the executor reported and the
//! daemon's own classifier call, never a look-alike. The facts this daemon cannot observe are reported as unknown
//! (`Unenforced` egress with a reason, `authenticated: false`), never as applied.

use std::time::SystemTime;

use sandy::{
    AuditReceipt, EgressEnforcement, EgressReceipt, GuestReported, HostObserved, Location, OutputStatus,
    ResultEnvelope, Timing, What, Who, build_envelope, classify_backend_error, classify_outcome,
};
use sandy_api::backend::{BackendError, Outcome};

/// The physical facts of a run, as the executor's `JobResult` reports them.
#[derive(Debug, Clone)]
pub(crate) struct RunFacts {
    /// Whether the guest booted.
    pub booted: bool,
    /// Whether the run hit its timeout.
    pub timed_out: bool,
    /// A transport or protocol fault, if the executor reported one.
    pub transport_error: Option<String>,
}

fn receipt(job_id: &str, exit_code: Option<i32>, host_id: Option<&str>) -> AuditReceipt {
    let now = SystemTime::now();
    AuditReceipt {
        host_observed: HostObserved {
            who: Who {
                // The local-uid fallback, as the direct path records it. A verified submitter is #413.
                identity: sandy_fsutil::current_uid().to_string(),
                authenticated: false,
            },
            what: What {
                job_id: job_id.to_owned(),
                template: String::new(),
                template_store_path: None,
                manifest_digest: None,
            },
            location: Location {
                backend: "executor".to_owned(),
                executor_host_id: host_id.map(str::to_owned),
                executor_mesh_ip: None,
            },
            credential: None,
            // Until an executor reports its egress outcome, nothing is claimed as applied.
            egress: EgressReceipt {
                status: EgressEnforcement::Unenforced,
                reason: Some("the executor did not report an egress outcome".to_owned()),
                allow_list: None,
                attempts: Vec::new(),
            },
            // The daemon sees neither the boot nor the teardown: both are the moment it recorded the result.
            timing: Timing {
                boot_started_at: now,
                job_started_at: None,
                teardown_at: now,
            },
            input_digests: None,
        },
        guest_reported: GuestReported {
            exit_code,
            outputs: Vec::new(),
            skipped_outputs: Vec::new(),
        },
    }
}

/// The envelope for a run that ended with `facts` and `exit_code`, once its outputs are settled to `outputs`.
/// `console` is the already-redacted tail.
pub(crate) fn from_run(
    job_id: &str,
    facts: &RunFacts,
    exit_code: Option<i32>,
    outputs: OutputStatus,
    console: String,
    host_id: Option<&str>,
) -> ResultEnvelope {
    let outcome = Outcome {
        booted: facts.booted,
        guest_exit: exit_code,
        transport_error: facts.transport_error.clone(),
        timed_out: facts.timed_out,
        console: String::new(),
        digests: None,
    };
    let classification = classify_outcome(&outcome, outputs);
    let message = match (&facts.transport_error, facts.timed_out, exit_code) {
        (Some(reason), ..) => reason.clone(),
        (None, true, _) => "the job timed out".to_owned(),
        (None, false, Some(0)) if outputs != OutputStatus::Complete => {
            "the job exited 0 but its outputs are missing".to_owned()
        }
        (None, false, Some(0)) => String::new(),
        (None, false, Some(code)) => format!("the job exited with code {code}"),
        (None, false, None) => "the job produced no exit code".to_owned(),
    };
    build_envelope(
        job_id,
        None,
        classification,
        exit_code,
        message,
        console,
        Vec::new(),
        Some(receipt(job_id, exit_code, host_id)),
    )
}

/// The envelope for a job that failed on the infrastructure side (the host disconnected, the submit could not be
/// dispatched): a failed, retryable run with `reason`, with no guest facts.
pub(crate) fn infra_fault(job_id: &str, reason: &str, host_id: Option<&str>) -> ResultEnvelope {
    let classification = classify_backend_error(&BackendError::Spawn(reason.to_owned()));
    build_envelope(
        job_id,
        None,
        classification,
        None,
        reason.to_owned(),
        String::new(),
        Vec::new(),
        Some(receipt(job_id, None, host_id)),
    )
}
