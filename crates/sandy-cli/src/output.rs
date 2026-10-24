//! CLI output formatting: human `plain` (default) or `json` (`-o json`).
//!
//! The `json` format exists so an agent can drive `sandy` and parse stdout
//! directly. Every command routes its result through one of the `format_*`
//! helpers, so the two formats stay in lock-step and JSON output is the
//! `serde` serialization of the same contract types the journal persists.
//!
//! The format applies to stdout (the data channel) only. Diagnostics stay on
//! stderr as text, and the process exit band (INV-11) carries success/failure
//! regardless of format.

use std::fmt::Write as _;

use base64::Engine as _;
use clap::ValueEnum;
use sandy::{JobRecord, ResultEnvelope};
use sandy_control_proto::{AttachResponse, JobStatus, JobSummary, ListResponse, StatusResponse, SubmitResponse};

/// Which representation the CLI prints on stdout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum)]
pub enum OutputFormat {
    /// Human-readable lines (the default).
    #[default]
    Plain,
    /// `serde_json`-serialized output for automated/agent consumption.
    Json,
}

/// One job record as a human line: the id and its lifecycle state.
fn plain_record(record: &JobRecord) -> String {
    format!("{:<36}  {:?}", record.job_id, record.state)
}

/// A concise human summary of a terminal result envelope, including the collected
/// outputs (one `  out: <path>` line each) so the plain format carries the same
/// information the JSON `outputs` array does.
fn plain_envelope(envelope: &ResultEnvelope) -> String {
    let exit = envelope
        .exit_code
        .map_or_else(|| "-".to_string(), |code| code.to_string());
    let mut out = format!(
        "job {}: {:?} (guest exit {exit}, retryable {})\n{}",
        envelope.job_id, envelope.status, envelope.retryable, envelope.message
    );
    for output in &envelope.outputs {
        let _ = write!(out, "\n  out: {}", output.path);
    }
    for warning in &envelope.warnings {
        let _ = write!(out, "\n  warning: {warning}");
    }
    out
}

/// Format a single job record in the chosen format.
///
/// # Errors
///
/// Returns a [`serde_json::Error`] only if JSON serialization fails.
pub fn format_record(record: &JobRecord, format: OutputFormat) -> serde_json::Result<String> {
    match format {
        OutputFormat::Plain => Ok(plain_record(record)),
        OutputFormat::Json => serde_json::to_string_pretty(record),
    }
}

/// Format a list of job records (e.g. `ls`). Plain yields one line per record;
/// JSON yields an array (so an empty list is a valid `[]`).
///
/// # Errors
///
/// Returns a [`serde_json::Error`] only if JSON serialization fails.
pub fn format_records(records: &[JobRecord], format: OutputFormat) -> serde_json::Result<String> {
    match format {
        OutputFormat::Plain => Ok(records.iter().map(plain_record).collect::<Vec<_>>().join("\n")),
        OutputFormat::Json => serde_json::to_string_pretty(records),
    }
}

/// Format a `run` result envelope: a human summary, or the full envelope as JSON.
///
/// # Errors
///
/// Returns a [`serde_json::Error`] only if JSON serialization fails.
pub fn format_envelope(envelope: &ResultEnvelope, format: OutputFormat) -> serde_json::Result<String> {
    match format {
        OutputFormat::Plain => Ok(plain_envelope(envelope)),
        OutputFormat::Json => serde_json::to_string_pretty(envelope),
    }
}

/// Format the `gc` result: the evicted job ids, followed by the names of any
/// swept stale credential staging dirs (#195).
///
/// # Errors
///
/// Returns a [`serde_json::Error`] only if JSON serialization fails.
pub fn format_gc(evicted: &[String], format: OutputFormat) -> serde_json::Result<String> {
    match format {
        OutputFormat::Plain => {
            let mut out = format!("gc: evicted {} record(s)", evicted.len());
            for id in evicted {
                let _ = write!(out, "\n  {id}");
            }
            Ok(out)
        }
        OutputFormat::Json => serde_json::to_string_pretty(&serde_json::json!({ "evicted": evicted })),
    }
}

/// Format a `doctor` verdict (its exit code + message).
///
/// # Errors
///
/// Returns a [`serde_json::Error`] only if JSON serialization fails.
pub fn format_doctor(exit_code: i32, message: &str, format: OutputFormat) -> serde_json::Result<String> {
    match format {
        OutputFormat::Plain => Ok(message.to_string()),
        OutputFormat::Json => {
            serde_json::to_string_pretty(&serde_json::json!({ "exit_code": exit_code, "message": message }))
        }
    }
}

/// A `JobStatus` wire value outside the enum's known range renders as
/// `JOB_STATUS_UNSPECIFIED` rather than failing the whole command: display is
/// best-effort, and the CLI and `sandyd` share the same generated enum, so an
/// out-of-range value would mean a version skew worth showing, not hiding.
fn job_status_name(wire: i32) -> &'static str {
    JobStatus::try_from(wire)
        .unwrap_or(JobStatus::Unspecified)
        .as_str_name()
}

/// Format a `daemon submit` result: the job id `sandyd` assigned.
///
/// # Errors
///
/// Returns a [`serde_json::Error`] only if JSON serialization fails.
pub fn format_submit(response: &SubmitResponse, format: OutputFormat) -> serde_json::Result<String> {
    match format {
        OutputFormat::Plain => Ok(format!("submitted job {}", response.job_id)),
        OutputFormat::Json => serde_json::to_string_pretty(&serde_json::json!({ "job_id": response.job_id })),
    }
}

/// Format a `daemon cancel` result. `CancelResponse` carries no fields, so
/// `job_id` is the id the caller passed on the command line, not something
/// read back off the response.
///
/// # Errors
///
/// Returns a [`serde_json::Error`] only if JSON serialization fails.
pub fn format_cancel(job_id: &str, format: OutputFormat) -> serde_json::Result<String> {
    match format {
        OutputFormat::Plain => Ok(format!("cancelled job {job_id}")),
        OutputFormat::Json => serde_json::to_string_pretty(&serde_json::json!({ "job_id": job_id, "cancelled": true })),
    }
}

/// Format a `daemon attach` result: the data-plane channel id and the
/// attenuated join cap `sandyd` hands back.
///
/// The cap is a bearer credential — the same reason
/// [`sandy_control_proto::AttachResponse`]'s own `Debug` redacts it. `plain`
/// never prints it (a human terminal isn't `attach`'s intended consumer);
/// `json` carries it base64-encoded, since the automation layer that actually
/// joins the channel needs the real bytes, not a redaction marker.
///
/// # Errors
///
/// Returns a [`serde_json::Error`] only if JSON serialization fails.
pub fn format_attach(response: &AttachResponse, format: OutputFormat) -> serde_json::Result<String> {
    match format {
        OutputFormat::Plain => Ok(format!(
            "channel {} (cap: {} bytes, redacted — use -o json to retrieve)",
            response.channel_id,
            response.cap.len()
        )),
        OutputFormat::Json => serde_json::to_string_pretty(&serde_json::json!({
            "channel_id": response.channel_id,
            "cap": base64::engine::general_purpose::STANDARD.encode(&response.cap),
        })),
    }
}

/// Format a `daemon status` result: the job id and its lifecycle state.
///
/// # Errors
///
/// Returns a [`serde_json::Error`] only if JSON serialization fails.
pub fn format_status(response: &StatusResponse, format: OutputFormat) -> serde_json::Result<String> {
    let status = job_status_name(response.status);
    match format {
        OutputFormat::Plain => {
            // Surface the exit code when a terminal run reported one (#292), so
            // `status` shows what the job exited with, not only its band. The
            // console tail stays out of the one-line plain form (it can be up
            // to ~64 KiB); it is in the JSON form for a caller that wants it.
            let mut line = format!("job {}: {status}", response.job_id);
            if let Some(exit_code) = response.exit_code {
                line.push_str(&format!(" (exit {exit_code})"));
            }
            Ok(line)
        }
        OutputFormat::Json => serde_json::to_string_pretty(&serde_json::json!({
            "job_id": response.job_id,
            "status": status,
            "exit_code": response.exit_code,
            "console_tail": response.console_tail,
        })),
    }
}

/// One job summary as a human line: the id and its lifecycle state.
fn plain_job_summary(job: &JobSummary) -> String {
    format!("{:<36}  {}", job.job_id, job_status_name(job.status))
}

/// Format a `daemon list` result: every job `sandyd` knows about.
///
/// # Errors
///
/// Returns a [`serde_json::Error`] only if JSON serialization fails.
pub fn format_list(response: &ListResponse, format: OutputFormat) -> serde_json::Result<String> {
    match format {
        OutputFormat::Plain => Ok(response
            .jobs
            .iter()
            .map(plain_job_summary)
            .collect::<Vec<_>>()
            .join("\n")),
        OutputFormat::Json => serde_json::to_string_pretty(
            &response
                .jobs
                .iter()
                .map(|job| serde_json::json!({ "job_id": job.job_id, "status": job_status_name(job.status) }))
                .collect::<Vec<_>>(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use anyhow::Context;
    use base64::Engine as _;
    use sandy::{
        JOURNAL_SCHEMA_VERSION, JobRecord, JobState, Logs, Provenance, RESULT_SCHEMA_VERSION, ResultEnvelope, Status,
    };
    use sandy_control_proto::{AttachResponse, JobStatus, JobSummary, ListResponse, StatusResponse, SubmitResponse};

    use super::{
        OutputFormat, format_attach, format_cancel, format_doctor, format_envelope, format_gc, format_list,
        format_record, format_records, format_status, format_submit,
    };

    fn sample_record(job_id: &str) -> JobRecord {
        JobRecord {
            schema_version: JOURNAL_SCHEMA_VERSION,
            job_id: job_id.to_string(),
            box_id: Some(format!("box-{job_id}")),
            state: JobState::Succeeded,
            writer_pid: 1,
            started: SystemTime::UNIX_EPOCH,
            result: None,
        }
    }

    fn sample_envelope(job_id: &str) -> ResultEnvelope {
        ResultEnvelope {
            result_schema_version: RESULT_SCHEMA_VERSION,
            job_id: job_id.to_string(),
            box_id: None,
            status: Status::Failed,
            retryable: true,
            message: "infra fault: spawn failed".to_string(),
            exit_code: None,
            outputs: vec![],
            receipts: vec![],
            provenance: Provenance {
                template_store_path: String::new(),
            },
            logs: Logs { tail: String::new() },
            warnings: Vec::new(),
        }
    }

    #[test]
    fn default_format_is_plain() {
        assert_eq!(OutputFormat::default(), OutputFormat::Plain);
    }

    #[test]
    fn json_record_round_trips_to_the_same_record() -> anyhow::Result<()> {
        let record = sample_record("job-a");
        let json = format_record(&record, OutputFormat::Json).context("format json")?;
        let parsed: JobRecord = serde_json::from_str(&json).context("parse json record")?;
        assert_eq!(parsed, record, "json output must round-trip to the same record");
        Ok(())
    }

    #[test]
    fn plain_record_names_the_job_and_state() -> anyhow::Result<()> {
        let plain = format_record(&sample_record("job-a"), OutputFormat::Plain).context("format plain")?;
        assert!(plain.contains("job-a"), "plain must name the job id: {plain}");
        assert!(plain.contains("Succeeded"), "plain must name the state: {plain}");
        Ok(())
    }

    /// Collected outputs appear in both formats: a `out: <path>` line in plain, and
    /// the `outputs` array in JSON.
    #[test]
    fn both_formats_carry_collected_outputs() -> anyhow::Result<()> {
        let mut envelope = sample_envelope("job-a");
        envelope.outputs = vec![
            sandy::OutputRef {
                path: "result/f".to_string(),
            },
            sandy::OutputRef {
                path: "result/sub/g".to_string(),
            },
        ];

        let plain = format_envelope(&envelope, OutputFormat::Plain).context("format plain envelope")?;
        assert!(plain.contains("out: result/f"), "plain lists the output: {plain}");
        assert!(
            plain.contains("out: result/sub/g"),
            "plain lists the nested output: {plain}"
        );

        let json = format_envelope(&envelope, OutputFormat::Json).context("format json envelope")?;
        let parsed: ResultEnvelope = serde_json::from_str(&json).context("parse json envelope")?;
        assert_eq!(parsed.outputs.len(), 2, "json carries the outputs array");
        Ok(())
    }

    /// L-12: a non-fatal warning (e.g. a credential revoke failure) appears in
    /// both formats, same as outputs — a `warning: <text>` line in plain, and the
    /// `warnings` array in JSON.
    #[test]
    fn both_formats_carry_warnings() -> anyhow::Result<()> {
        let mut envelope = sample_envelope("job-a");
        envelope.warnings = vec!["credential \"GH_TOKEN\" revoke failed at teardown".to_string()];

        let plain = format_envelope(&envelope, OutputFormat::Plain).context("format plain envelope")?;
        assert!(
            plain.contains("warning: credential \"GH_TOKEN\" revoke failed at teardown"),
            "plain lists the warning: {plain}"
        );

        let json = format_envelope(&envelope, OutputFormat::Json).context("format json envelope")?;
        let parsed: ResultEnvelope = serde_json::from_str(&json).context("parse json envelope")?;
        assert_eq!(parsed.warnings, envelope.warnings, "json carries the warnings array");
        Ok(())
    }

    #[test]
    fn json_records_is_an_array_even_when_empty() -> anyhow::Result<()> {
        let empty = format_records(&[], OutputFormat::Json).context("format empty json")?;
        let parsed: Vec<JobRecord> = serde_json::from_str(&empty).context("parse empty array")?;
        assert!(parsed.is_empty(), "empty ls must serialize to an empty JSON array");

        let two = [sample_record("a"), sample_record("b")];
        let json = format_records(&two, OutputFormat::Json).context("format two json")?;
        let parsed: Vec<JobRecord> = serde_json::from_str(&json).context("parse two")?;
        assert_eq!(parsed.len(), 2);
        Ok(())
    }

    #[test]
    fn json_envelope_round_trips() -> anyhow::Result<()> {
        let envelope = sample_envelope("job-a");
        let json = format_envelope(&envelope, OutputFormat::Json).context("format json envelope")?;
        let parsed: ResultEnvelope = serde_json::from_str(&json).context("parse json envelope")?;
        assert_eq!(parsed, envelope);
        Ok(())
    }

    #[test]
    fn plain_envelope_summarizes_status_and_message() -> anyhow::Result<()> {
        let plain = format_envelope(&sample_envelope("job-a"), OutputFormat::Plain).context("format plain envelope")?;
        assert!(plain.contains("job-a"));
        assert!(plain.contains("Failed"), "summary must name the status: {plain}");
        assert!(
            plain.contains("retryable true"),
            "summary must name retryability: {plain}"
        );
        Ok(())
    }

    #[test]
    fn gc_json_carries_the_evicted_ids() -> anyhow::Result<()> {
        let json = format_gc(&["x".to_string(), "y".to_string()], OutputFormat::Json).context("format gc json")?;
        let parsed: serde_json::Value = serde_json::from_str(&json).context("parse gc json")?;
        let evicted = parsed
            .get("evicted")
            .and_then(|v| v.as_array())
            .context("gc json must have an `evicted` array")?;
        assert_eq!(evicted.len(), 2);
        Ok(())
    }

    #[test]
    fn doctor_json_carries_exit_code_and_message() -> anyhow::Result<()> {
        let json = format_doctor(2, "refusing to start", OutputFormat::Json).context("format doctor json")?;
        let parsed: serde_json::Value = serde_json::from_str(&json).context("parse doctor json")?;
        assert_eq!(parsed.get("exit_code").and_then(serde_json::Value::as_i64), Some(2));
        assert_eq!(
            parsed.get("message").and_then(serde_json::Value::as_str),
            Some("refusing to start")
        );
        Ok(())
    }

    #[test]
    fn submit_json_carries_the_assigned_job_id() -> anyhow::Result<()> {
        let response = SubmitResponse {
            job_id: "job-a".to_string(),
            attach_token: Vec::new(),
        };
        let json = format_submit(&response, OutputFormat::Json).context("format submit json")?;
        let parsed: serde_json::Value = serde_json::from_str(&json).context("parse submit json")?;
        assert_eq!(parsed.get("job_id").and_then(serde_json::Value::as_str), Some("job-a"));
        Ok(())
    }

    #[test]
    fn submit_plain_names_the_job_id() -> anyhow::Result<()> {
        let response = SubmitResponse {
            job_id: "job-a".to_string(),
            attach_token: Vec::new(),
        };
        let plain = format_submit(&response, OutputFormat::Plain).context("format submit plain")?;
        assert!(plain.contains("job-a"), "plain must name the job id: {plain}");
        Ok(())
    }

    #[test]
    fn cancel_echoes_the_caller_supplied_job_id_in_both_formats() -> anyhow::Result<()> {
        let plain = format_cancel("job-a", OutputFormat::Plain).context("format cancel plain")?;
        assert!(plain.contains("job-a"), "plain must name the job id: {plain}");

        let json = format_cancel("job-a", OutputFormat::Json).context("format cancel json")?;
        let parsed: serde_json::Value = serde_json::from_str(&json).context("parse cancel json")?;
        assert_eq!(parsed.get("job_id").and_then(serde_json::Value::as_str), Some("job-a"));
        assert_eq!(parsed.get("cancelled").and_then(serde_json::Value::as_bool), Some(true));
        Ok(())
    }

    /// Adversarial (credential leak): `attach`'s plain output must never print
    /// the cap's bytes, in any encoding — a human terminal is not attach's
    /// intended consumer for the actual credential.
    #[test]
    fn attach_plain_never_prints_the_cap_bytes() -> anyhow::Result<()> {
        let marker = "sandy-cap-leak-marker-7e2b";
        let cap = marker.as_bytes().to_vec();
        let response = AttachResponse {
            channel_id: "orchestrator".to_string(),
            cap: cap.clone(),
        };
        let plain = format_attach(&response, OutputFormat::Plain).context("format attach plain")?;
        assert!(!plain.contains(marker), "cap text leaked into plain output: {plain}");
        let encoded = base64::engine::general_purpose::STANDARD.encode(&cap);
        assert!(
            !plain.contains(&encoded),
            "base64 cap leaked into plain output: {plain}"
        );
        assert!(
            plain.contains("orchestrator"),
            "plain must still name the channel: {plain}"
        );
        Ok(())
    }

    /// `attach`'s json output DOES carry the cap, base64-encoded: the
    /// automation layer that joins the channel needs the real bytes.
    #[test]
    fn attach_json_carries_the_base64_cap() -> anyhow::Result<()> {
        let cap = b"not-a-real-cap".to_vec();
        let response = AttachResponse {
            channel_id: "orchestrator".to_string(),
            cap: cap.clone(),
        };
        let json = format_attach(&response, OutputFormat::Json).context("format attach json")?;
        let parsed: serde_json::Value = serde_json::from_str(&json).context("parse attach json")?;
        assert_eq!(
            parsed.get("channel_id").and_then(serde_json::Value::as_str),
            Some("orchestrator")
        );
        let cap_field = parsed
            .get("cap")
            .and_then(serde_json::Value::as_str)
            .context("attach json must carry a cap field")?;
        assert_eq!(
            base64::engine::general_purpose::STANDARD.decode(cap_field)?,
            cap,
            "the cap must round-trip through base64"
        );
        Ok(())
    }

    #[test]
    fn status_names_the_job_and_its_lifecycle_state_in_both_formats() -> anyhow::Result<()> {
        let response = StatusResponse {
            job_id: "job-a".to_string(),
            status: JobStatus::Running as i32,
            exit_code: None,
            console_tail: String::new(),
        };
        let plain = format_status(&response, OutputFormat::Plain).context("format status plain")?;
        assert!(
            plain.contains("job-a") && plain.contains("JOB_STATUS_RUNNING"),
            "got: {plain}"
        );

        let json = format_status(&response, OutputFormat::Json).context("format status json")?;
        let parsed: serde_json::Value = serde_json::from_str(&json).context("parse status json")?;
        assert_eq!(
            parsed.get("status").and_then(serde_json::Value::as_str),
            Some("JOB_STATUS_RUNNING")
        );
        Ok(())
    }

    /// A terminal job's exit code and console tail reach both output forms
    /// (#292): the plain line names the exit, the JSON carries the exit code
    /// and the output tail.
    #[test]
    fn status_surfaces_the_exit_code_and_console_tail() -> anyhow::Result<()> {
        let response = StatusResponse {
            job_id: "job-a".to_string(),
            status: JobStatus::Succeeded as i32,
            exit_code: Some(0),
            console_tail: "hi\n".to_string(),
        };

        let plain = format_status(&response, OutputFormat::Plain).context("format status plain")?;
        assert!(plain.contains("exit 0"), "the plain line must name the exit: {plain}");

        let json = format_status(&response, OutputFormat::Json).context("format status json")?;
        let parsed: serde_json::Value = serde_json::from_str(&json).context("parse status json")?;
        assert_eq!(parsed.get("exit_code").and_then(serde_json::Value::as_i64), Some(0));
        assert_eq!(
            parsed.get("console_tail").and_then(serde_json::Value::as_str),
            Some("hi\n")
        );
        Ok(())
    }

    /// Adversarial: a `status` value outside the enum's known range renders
    /// as unspecified rather than panicking the whole command.
    #[test]
    fn status_tolerates_an_out_of_range_wire_value() -> anyhow::Result<()> {
        let response = StatusResponse {
            job_id: "job-a".to_string(),
            status: 99,
            exit_code: None,
            console_tail: String::new(),
        };
        let plain = format_status(&response, OutputFormat::Plain).context("format status plain")?;
        assert!(plain.contains("JOB_STATUS_UNSPECIFIED"), "got: {plain}");
        Ok(())
    }

    #[test]
    fn list_json_is_an_array_even_when_empty() -> anyhow::Result<()> {
        let empty = format_list(&ListResponse { jobs: vec![] }, OutputFormat::Json).context("format empty list")?;
        let parsed: serde_json::Value = serde_json::from_str(&empty).context("parse empty list json")?;
        assert_eq!(parsed.as_array().map(Vec::len), Some(0));
        Ok(())
    }

    #[test]
    fn list_carries_every_job_and_its_state_in_both_formats() -> anyhow::Result<()> {
        let response = ListResponse {
            jobs: vec![
                JobSummary {
                    job_id: "job-a".to_string(),
                    status: JobStatus::Running as i32,
                },
                JobSummary {
                    job_id: "job-b".to_string(),
                    status: JobStatus::Succeeded as i32,
                },
            ],
        };
        let plain = format_list(&response, OutputFormat::Plain).context("format list plain")?;
        assert!(
            plain.contains("job-a") && plain.contains("JOB_STATUS_RUNNING"),
            "got: {plain}"
        );
        assert!(
            plain.contains("job-b") && plain.contains("JOB_STATUS_SUCCEEDED"),
            "got: {plain}"
        );

        let json = format_list(&response, OutputFormat::Json).context("format list json")?;
        let parsed: serde_json::Value = serde_json::from_str(&json).context("parse list json")?;
        assert_eq!(parsed.as_array().map(Vec::len), Some(2));
        Ok(())
    }
}
