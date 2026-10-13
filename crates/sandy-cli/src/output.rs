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

use clap::ValueEnum;
use sandy::{JobRecord, ResultEnvelope};

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

/// Format the `gc` result (the evicted job ids).
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

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use anyhow::Context;
    use sandy::{
        JOURNAL_SCHEMA_VERSION, JobRecord, JobState, Logs, Provenance, RESULT_SCHEMA_VERSION, ResultEnvelope, Status,
    };

    use super::{OutputFormat, format_doctor, format_envelope, format_gc, format_record, format_records};

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
}
