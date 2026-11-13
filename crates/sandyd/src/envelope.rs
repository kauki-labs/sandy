//! The result envelope `sandyd` builds for a terminal job (A2 of #483, INV-11): the same locked
//! [`sandy::ResultEnvelope`] a direct `sandy run` prints, from the physical facts the executor reported and the
//! daemon's own classifier call, never a look-alike. The facts this daemon cannot observe are reported as unknown
//! (`Unenforced` egress with a reason, `authenticated: false`), never as applied.

use std::time::SystemTime;

/// The most bytes of console the daemon keeps for a job, in the row and in its envelope's log tail: the tail (the
/// end is what diagnoses a run). The executor sends at most about this much; the cap holds a hostile or buggy one to
/// it, so a `Status` reply (the console twice, one of them JSON-escaped at up to six bytes per byte) fits one frame.
pub(crate) const MAX_CONSOLE_BYTES: usize = 64 * 1024;

/// The most output paths the envelope lists (with their sizes in the receipt).
const MAX_LISTED_OUTPUTS: usize = 256;

/// The most bytes of output paths the envelope lists, per copy (each path is in `outputs` and in the receipt, so the
/// envelope holds twice this). With the console, the message and the egress reason it keeps a `Status` reply inside one
/// frame.
const MAX_LISTED_PATH_BYTES: usize = 32 * 1024;

/// The most bytes of the envelope's `message` the daemon keeps. Applied after redaction, never before: a cut first
/// would leave the end of a token that straddles it.
pub(crate) const MAX_MESSAGE_BYTES: usize = 4 * 1024;

/// `text` cut to its last `max` bytes, on a character boundary.
pub(crate) fn tail(text: &str, max: usize) -> &str {
    if text.len() <= max {
        return text;
    }
    let mut start = text.len() - max;
    while !text.is_char_boundary(start) {
        start += 1;
    }
    &text[start..]
}

use sandy::{
    AllowList, AuditReceipt, EgressEnforcement, EgressReceipt, GuestReported, HostObserved, Location, OutputStatus,
    ResultEnvelope, Timing, What, Who, build_envelope, classify_backend_error, classify_outcome,
};
use sandy_api::backend::{BackendError, Outcome};

/// The physical facts of a run, as the executor's `JobResult` reports them.
#[derive(Debug, Clone)]
pub(crate) struct RunFacts {
    /// The executor's egress report, read as the direct path's `Result<EgressOutcome, String>`: `None` when it sent
    /// none (no policy, an older executor, a run that ended before it could say) or an unspecified one.
    pub egress: Option<Result<sandy::EgressOutcome, String>>,
    /// The executor's digests of the run, as sent (A2c of #483). Validated and bounded when the envelope is built.
    pub digests: Option<sandy_executor_proto::RunDigests>,
    /// Whether the guest booted.
    pub booted: bool,
    /// Whether the run hit its timeout.
    pub timed_out: bool,
    /// A transport or protocol fault, if the executor reported one.
    pub transport_error: Option<String>,
}

/// The egress half of the receipt. With an executor report it is the direct path's own builder over the same facts, so
/// the two agree by construction; without one nothing is claimed as applied.
fn egress_receipt(report: Option<&Result<sandy::EgressOutcome, String>>, allow: Option<&AllowList>) -> EgressReceipt {
    match report {
        Some(result) => sandy::build_egress_receipt(result, &allow.cloned().unwrap_or_default()),
        None => EgressReceipt {
            status: EgressEnforcement::Unenforced,
            reason: Some("the executor did not report an egress outcome".to_owned()),
            allow_list: None,
            attempts: Vec::new(),
        },
    }
}

/// The wire egress report as the direct path's `Result<EgressOutcome, String>`; `None` for no report or an unspecified
/// one.
pub(crate) fn egress_from_report(
    report: Option<&sandy_executor_proto::EgressReport>,
) -> Option<Result<sandy::EgressOutcome, String>> {
    use sandy_executor_proto::EgressState;
    let report = report?;
    let reason = || report.reason.clone().unwrap_or_default();
    match EgressState::try_from(report.state).ok()? {
        EgressState::Proxied => Some(Ok(sandy::EgressOutcome::Proxied)),
        EgressState::Unenforced => Some(Ok(sandy::EgressOutcome::Unenforced { reason: reason() })),
        EgressState::Failed => Some(Err(reason())),
        EgressState::Unspecified => None,
    }
}

fn receipt(
    job_id: &str,
    exit_code: Option<i32>,
    host_id: Option<&str>,
    outputs: Vec<sandy::OutputSizeRef>,
    egress: EgressReceipt,
) -> AuditReceipt {
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
            egress,
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
            outputs,
            skipped_outputs: Vec::new(),
        },
    }
}

/// Where and how a job was placed, as the daemon recorded it when it dispatched the job.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Placement<'a> {
    /// The executor host that ran it.
    pub host_id: Option<&'a str>,
    /// The egress allow-list it was dispatched with, `None` for a job with no policy.
    pub allow: Option<&'a AllowList>,
    /// The outputs its Submit declared, as `(name, destination)`.
    pub declared: &'a [(Option<String>, std::path::PathBuf)],
    /// Whether the Submit asked for digests.
    pub digests_requested: bool,
}

/// The envelope for a run that ended with `facts` and `exit_code`, once its outputs are settled to `outputs`.
/// `console` is the already-redacted tail. The `message` is the executor's own words, unredacted and uncut: the caller
/// redacts it, then cuts it to `MAX_MESSAGE_BYTES`.
pub(crate) fn from_run(
    job_id: &str,
    facts: &RunFacts,
    exit_code: Option<i32>,
    outputs: OutputStatus,
    console: String,
    placed: &Placement<'_>,
) -> ResultEnvelope {
    let Placement {
        host_id,
        allow,
        declared,
        digests_requested,
    } = *placed;
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
    // What the run left at the declared destinations, listed as the direct path lists it (A2c of #483). Best effort:
    // an unreadable destination lists nothing. Bounded, so a tree of many files cannot push the `Status` reply past
    // one frame; the cut is said in a warning.
    let destinations: Vec<sandy::DeclaredOutput<'_>> = declared
        .iter()
        .map(|(name, dest)| (name.as_deref(), dest.as_path()))
        .collect();
    // The digests the executor reported, for a job that asked for them (A2c of #483): validated and bounded here, so a
    // hostile or buggy executor cannot put a bad hash, a path out of the tree or an unbounded list into the envelope.
    let mut digest_warnings = Vec::new();
    let mut digests = None;
    if digests_requested {
        match facts.digests.as_ref() {
            None => digest_warnings.push("digests were requested but the executor reported none".to_owned()),
            Some(report) => match ingest_digests(report) {
                Ok((accepted, warning)) => {
                    digests = Some(accepted);
                    digest_warnings.extend(warning);
                }
                Err(why) => digest_warnings.push(format!(
                    "digests: the executor's report is malformed ({why}); it was dropped"
                )),
            },
        }
    }
    let mut listed = sandy::collect_output_size_refs(&destinations, digests.as_ref().map(|(_, outputs)| outputs));
    let total = listed.len();
    // Bounded by count and by path bytes: a job chooses its own output names (up to 4096 bytes a path) and each path
    // is listed twice, so a count cap alone would still overflow the frame.
    let mut path_bytes = 0usize;
    let kept = listed
        .iter()
        .take(MAX_LISTED_OUTPUTS)
        .take_while(|output| {
            path_bytes += output.path.len();
            path_bytes <= MAX_LISTED_PATH_BYTES
        })
        .count();
    let mut cut = None;
    if kept < total {
        listed.truncate(kept);
        cut = Some(format!(
            "outputs: {total} files were left at the declared destinations, only the first {kept} are listed"
        ));
    }
    let refs = listed
        .iter()
        .map(|output| sandy::OutputRef {
            path: output.path.clone(),
        })
        .collect();
    let mut envelope = build_envelope(
        job_id,
        None,
        classification,
        exit_code,
        message,
        tail(&console, MAX_CONSOLE_BYTES).to_owned(),
        refs,
        Some(receipt(
            job_id,
            exit_code,
            host_id,
            listed,
            // A report is meaningful only for a job that asked for a boundary: a `PROXIED` for a job with no
            // policy would read as `Enforced` with an empty allow-list.
            egress_receipt(facts.egress.as_ref().filter(|_| allow.is_some()), allow),
        )),
    );
    envelope.warnings.extend(cut);
    envelope.warnings.extend(digest_warnings);
    if let (Some((inputs, outputs)), Some(receipt)) = (digests, envelope.receipt.as_mut()) {
        receipt.host_observed.input_digests = Some(inputs);
        receipt.guest_reported.skipped_outputs = outputs.skipped;
    }
    envelope
}

/// The most digest entries the daemon keeps per list (files and skipped entries, inputs and outputs each).
const MAX_DIGEST_ENTRIES: usize = 256;

/// The most bytes of digest paths the daemon keeps per list. Together with the entry cap it keeps the stored envelope,
/// the output listing and the console inside one `Status` frame.
const MAX_DIGEST_PATH_BYTES: usize = 8 * 1024;

/// Whether `path` is a path the data link accepts: a plain relative path of at most 4096 bytes, by the receiver's own
/// rule (`DataLinkMessage::validate`).
fn valid_digest_path(path: &str) -> bool {
    sandy_executor_proto::DataLinkMessage {
        op: Some(sandy_executor_proto::data_link_message::Op::InputChunk(
            sandy_executor_proto::InputChunk {
                name: path.to_owned(),
                offset: 0,
                bytes: Vec::new(),
            },
        )),
    }
    .validate()
    .is_ok()
}

/// One side of the executor's digests, validated: every path a plain relative path, every hash 64 lowercase hex digits,
/// every skip reason a known one. The first failure rejects the side, so a report is never partly believed.
fn validate_side(side: Option<&sandy_executor_proto::ContentDigests>) -> Result<sandy::ContentDigests, String> {
    let Some(side) = side else {
        return Ok(sandy::ContentDigests::default());
    };
    let mut files = Vec::with_capacity(side.files.len());
    for file in &side.files {
        if !valid_digest_path(&file.path) {
            return Err(format!("a file path {:?} is not a plain relative path", file.path));
        }
        if file.sha256.len() != 64 || !file.sha256.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            return Err(format!("the hash of {:?} is not 64 lowercase hex digits", file.path));
        }
        files.push(sandy::FileDigest {
            path: file.path.clone(),
            sha256: file.sha256.clone(),
        });
    }
    let mut skipped = Vec::with_capacity(side.skipped.len());
    for entry in &side.skipped {
        if !valid_digest_path(&entry.path) {
            return Err(format!("a skipped path {:?} is not a plain relative path", entry.path));
        }
        let reason = match sandy_executor_proto::SkipReason::try_from(entry.reason) {
            Ok(sandy_executor_proto::SkipReason::Symlink) => sandy::SkipReason::Symlink,
            Ok(sandy_executor_proto::SkipReason::NonRegular) => sandy::SkipReason::NonRegular,
            Ok(sandy_executor_proto::SkipReason::Unspecified) | Err(_) => {
                return Err(format!("the skip reason of {:?} is unspecified or unknown", entry.path));
            }
        };
        skipped.push(sandy::SkippedEntry {
            path: entry.path.clone(),
            reason,
        });
    }
    Ok(sandy::ContentDigests { files, skipped })
}

/// Keep the first entries of `list` while they stay inside the entry and path-byte caps; the total before the cut.
fn bound_list<T>(list: &mut Vec<T>, path: impl Fn(&T) -> &str) -> usize {
    let total = list.len();
    let mut bytes = 0usize;
    let kept = list
        .iter()
        .take(MAX_DIGEST_ENTRIES)
        .take_while(|entry| {
            bytes += path(entry).len();
            bytes <= MAX_DIGEST_PATH_BYTES
        })
        .count();
    list.truncate(kept);
    total
}

/// The executor's digests as the daemon records them: `(inputs, outputs)`, sorted by path and bounded, with a warning
/// when something was cut. `Err` names why the report is malformed.
fn ingest_digests(
    report: &sandy_executor_proto::RunDigests,
) -> Result<((sandy::ContentDigests, sandy::ContentDigests), Option<String>), String> {
    let mut inputs = validate_side(report.inputs.as_ref()).map_err(|why| format!("inputs: {why}"))?;
    let mut outputs = validate_side(report.outputs.as_ref()).map_err(|why| format!("outputs: {why}"))?;
    inputs.sort();
    outputs.sort();
    let mut cut = Vec::new();
    for (name, list) in [("input files", &mut inputs.files), ("output files", &mut outputs.files)] {
        let total = bound_list(list, |entry| &entry.path);
        if total > list.len() {
            cut.push(format!("{total} {name}, only the first {} kept", list.len()));
        }
    }
    for (name, list) in [
        ("input entries", &mut inputs.skipped),
        ("output entries", &mut outputs.skipped),
    ] {
        let total = bound_list(list, |entry| &entry.path);
        if total > list.len() {
            cut.push(format!("{total} skipped {name}, only the first {} kept", list.len()));
        }
    }
    let warning = (!cut.is_empty()).then(|| format!("digests: the executor reported {}", cut.join(", ")));
    Ok(((inputs, outputs), warning))
}

/// Redact, then cut, the egress reason in `envelope`'s receipt: it is the executor's own error string, as the message
/// is, so it can hold a token and can be as large as the frame that carried it (sandy-5e on #835). Redact first so a
/// token straddling the cut leaves no suffix, then keep the last `MAX_MESSAGE_BYTES`.
pub(crate) fn bound_egress_reason(envelope: &mut ResultEnvelope, redact: impl FnOnce(String) -> String) {
    let Some(reason) = envelope
        .receipt
        .as_mut()
        .and_then(|receipt| receipt.host_observed.egress.reason.take())
    else {
        return;
    };
    let reason = redact(reason);
    if let Some(receipt) = envelope.receipt.as_mut() {
        receipt.host_observed.egress.reason = Some(tail(&reason, MAX_MESSAGE_BYTES).to_owned());
    }
}

/// The envelope for a job cancelled before a terminal guest result: the shape the direct `kill` writes (status
/// `Cancelled`, not retryable, no exit, no receipt: no backend run was observed).
pub(crate) fn cancelled(job_id: &str) -> ResultEnvelope {
    build_envelope(
        job_id,
        None,
        sandy::Classification {
            status: sandy::Status::Cancelled,
            retryable: false,
            process_exit: sandy::ProcessExit::TaskFailure,
        },
        None,
        "cancelled".to_owned(),
        String::new(),
        Vec::new(),
        None,
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
        Some(receipt(job_id, None, host_id, Vec::new(), egress_receipt(None, None))),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A2b (#483, sandy-5e on #835): the egress reason is redacted whole and then cut, so a token that straddles the
    /// cut leaves no suffix, and a huge reason is bounded.
    #[test]
    fn the_egress_reason_is_redacted_then_cut() {
        const TOKEN: &str = "ghs_sentinel835_never_log_me";
        let mut envelope = infra_fault("job-1", "x", None);
        let filler = "z".repeat(MAX_MESSAGE_BYTES - TOKEN.len() / 2);
        if let Some(receipt) = envelope.receipt.as_mut() {
            receipt.host_observed.egress.reason = Some(format!("{TOKEN}{filler}"));
        }
        bound_egress_reason(&mut envelope, |text| text.replace(TOKEN, "[REDACTED]"));
        let reason = envelope
            .receipt
            .and_then(|receipt| receipt.host_observed.egress.reason)
            .unwrap_or_default();
        assert!(reason.len() <= MAX_MESSAGE_BYTES, "reason is {} bytes", reason.len());
        assert!(
            !reason.contains(&TOKEN[TOKEN.len() / 2..]),
            "a suffix of the token survived the cut"
        );
    }
}
