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

use std::io;

use base64::Engine as _;
use clap::ValueEnum;
use sandy::{JobRecord, ResultEnvelope};
use sandy_control_proto::{AttachResponse, JobStatus, JobSummary, ListResponse, StatusResponse, SubmitResponse};
use serde::{Deserialize, Serialize};

use crate::supervisor::GcReport;

/// Which representation the CLI prints on stdout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum)]
pub enum OutputFormat {
    /// Human-readable lines (the default).
    #[default]
    Plain,
    /// `serde_json`-serialized output for automated/agent consumption.
    Json,
}

/// A command's result, in both directions: it serializes/deserializes with
/// `serde` for `-o json` (so JSON output is a real type, not a hand-built
/// shape with no contract), and renders its own human-readable form for
/// `-o plain` via [`Render::render_plain`]. [`emit`] is the only function
/// that writes either form to stdout.
pub trait Render {
    /// Write this value's human-readable (`-o plain`) rendering to `out`.
    ///
    /// # Errors
    /// Propagates a write failure on `out`.
    fn render_plain(&self, out: &mut dyn io::Write) -> io::Result<()>;
}

/// Either half of [`emit`]/[`emit_stream`] failing: JSON serialization, or
/// writing to the sink itself.
#[derive(Debug, thiserror::Error)]
pub enum EmitError {
    /// `-o json` serialization failed.
    #[error("could not serialize output: {0}")]
    Serialize(#[from] serde_json::Error),
    /// Writing the rendered output to its sink failed.
    #[error("could not write output: {0}")]
    Io(#[from] io::Error),
}

/// Writes `value` to `out` in `format`: the plain rendering (skipped
/// entirely if it would be empty — `ls` with zero jobs prints nothing, not a
/// blank line) or the pretty-printed JSON serialization.
///
/// # Errors
/// [`EmitError::Serialize`] or [`EmitError::Io`], see [`EmitError`].
pub fn emit_to<T, W>(value: &T, format: OutputFormat, out: &mut W) -> Result<(), EmitError>
where
    T: Render + Serialize,
    W: io::Write,
{
    match format {
        OutputFormat::Plain => {
            let mut buf = Vec::new();
            value.render_plain(&mut buf)?;
            if !buf.is_empty() {
                out.write_all(&buf)?;
                out.write_all(b"\n")?;
            }
        }
        OutputFormat::Json => writeln!(out, "{}", serde_json::to_string_pretty(value)?)?,
    }
    Ok(())
}

/// [`emit_to`] against real stdout, mapped to a process exit band on failure
/// (band 3, infra fault) — the one function in this crate allowed to call
/// `println!`/`print!` directly ([`clippy::print_stdout`] is denied
/// everywhere else).
///
/// # Errors
/// `Err` carries the process exit code to use; the failure is already
/// reported on stderr.
#[allow(
    clippy::print_stdout,
    reason = "the one sanctioned stdout sink; see EmitError's own eprintln above it"
)]
pub fn emit<T: Render + Serialize>(value: &T, format: OutputFormat) -> Result<(), i32> {
    let mut buf = Vec::new();
    match emit_to(value, format, &mut buf) {
        Ok(()) => {
            if !buf.is_empty() {
                print!("{}", String::from_utf8_lossy(&buf));
            }
            Ok(())
        }
        Err(e) => {
            eprintln!("sandy: {e}");
            Err(sandy::ProcessExit::InfraFault.code())
        }
    }
}

/// Writes every item of a stream to `out` as it arrives: one plain line, or
/// one NDJSON object, per item — flushed after each so a consumer reading
/// the stream live sees each event as soon as it's produced, never buffered
/// to the end.
///
/// # Errors
/// [`EmitError::Serialize`] or [`EmitError::Io`] from the failing item;
/// already-written items are not rolled back.
pub fn emit_stream_to<T, I, W>(items: I, format: OutputFormat, out: &mut W) -> Result<(), EmitError>
where
    T: Render + Serialize,
    I: IntoIterator<Item = T>,
    W: io::Write,
{
    for item in items {
        match format {
            OutputFormat::Plain => {
                item.render_plain(out)?;
                writeln!(out)?;
            }
            // NDJSON: one COMPACT object per line — `to_string_pretty` (what
            // `emit_to` uses for a single value) would spread one item
            // across several lines, breaking "each line parses alone".
            OutputFormat::Json => writeln!(out, "{}", serde_json::to_string(&item)?)?,
        }
        out.flush()?;
    }
    Ok(())
}

/// One job record as a human line: the id and its lifecycle state.
impl Render for JobRecord {
    fn render_plain(&self, out: &mut dyn io::Write) -> io::Result<()> {
        write!(out, "{:<36}  {:?}", self.job_id, self.state)
    }
}

/// `ls`'s result: every job record `sandy` knows about, as one named type
/// (not a bare `Vec`) per #512's spec — `#[serde(transparent)]` keeps the
/// JSON an array, byte-identical to serializing the `Vec` directly.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct JobRecords(pub Vec<JobRecord>);

impl Render for JobRecords {
    fn render_plain(&self, out: &mut dyn io::Write) -> io::Result<()> {
        for (i, record) in self.0.iter().enumerate() {
            if i > 0 {
                writeln!(out)?;
            }
            record.render_plain(out)?;
        }
        Ok(())
    }
}

/// A concise human summary of a terminal result envelope, including the collected
/// outputs (one `  out: <path>` line each) so the plain format carries the same
/// information the JSON `outputs` array does.
impl Render for ResultEnvelope {
    fn render_plain(&self, out: &mut dyn io::Write) -> io::Result<()> {
        let exit = self.exit_code.map_or_else(|| "-".to_string(), |code| code.to_string());
        write!(
            out,
            "job {}: {:?} (guest exit {exit}, retryable {})\n{}",
            self.job_id, self.status, self.retryable, self.message
        )?;
        for output in &self.outputs {
            write!(out, "\n  out: {}", output.path)?;
        }
        for warning in &self.warnings {
            write!(out, "\n  warning: {warning}")?;
        }
        Ok(())
    }
}

/// `gc`'s result: the evicted job ids, followed by the names of any swept
/// stale credential staging dirs (#195).
impl Render for GcReport {
    fn render_plain(&self, out: &mut dyn io::Write) -> io::Result<()> {
        write!(out, "gc: evicted {} record(s)", self.evicted.len())?;
        for id in &self.evicted {
            write!(out, "\n  {id}")?;
        }
        write!(out, "\ngc: swept {} staging dir(s)", self.swept_staging_dirs.len())?;
        for name in &self.swept_staging_dirs {
            write!(out, "\n  {name}")?;
        }
        Ok(())
    }
}

/// `doctor`'s verdict (its exit code + message).
impl Render for crate::doctor::DoctorResult {
    fn render_plain(&self, out: &mut dyn io::Write) -> io::Result<()> {
        write!(out, "{}", self.message)
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
        GcReport, JobRecords, OutputFormat, Render, format_attach, format_cancel, format_list, format_status,
        format_submit,
    };
    use crate::doctor::DoctorResult;

    /// A value's plain rendering, as a `String` — what [`emit_to`](super::emit_to)
    /// writes for [`OutputFormat::Plain`], minus the trailing newline `emit_to`
    /// itself adds (so content assertions below match the old `format_*`
    /// functions' return values exactly).
    fn plain_of<T: Render>(value: &T) -> String {
        let mut buf = Vec::new();
        value.render_plain(&mut buf).expect("render_plain to a Vec never fails");
        String::from_utf8(buf).expect("render_plain output must be UTF-8")
    }

    /// A value's pretty JSON — what [`emit_to`](super::emit_to) writes for
    /// [`OutputFormat::Json`], minus the trailing newline.
    fn json_of<T: serde::Serialize>(value: &T) -> String {
        serde_json::to_string_pretty(value).expect("serializing a sample value never fails")
    }

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
            receipt: None,
        }
    }

    #[test]
    fn default_format_is_plain() {
        assert_eq!(OutputFormat::default(), OutputFormat::Plain);
    }

    // Snapshots taken against the pre-#512 `format_*` functions, now exercised
    // against the typed `Render`/`emit_to` pipeline that replaced them — same
    // snapshot files, so a shape change is a reviewed diff, not a silent one.
    // `plain_of`/`json_of` are exactly what `emit_to` writes, minus its
    // trailing newline (snapshotting doesn't care about a trailing newline,
    // but matching keeps these assertions symmetric with the rest of the
    // module's tests).
    mod pre_refactor_snapshots {
        use super::{DoctorResult, GcReport, JobRecords, json_of, plain_of, sample_envelope, sample_record};

        #[test]
        fn record_plain() {
            insta::assert_snapshot!(plain_of(&sample_record("job-a")));
        }

        #[test]
        fn record_json() {
            insta::assert_snapshot!(json_of(&sample_record("job-a")));
        }

        #[test]
        fn records_plain_empty_is_an_empty_string() {
            insta::assert_snapshot!(plain_of(&JobRecords(vec![])));
        }

        #[test]
        fn records_json_empty_is_an_empty_array() {
            insta::assert_snapshot!(json_of(&JobRecords(vec![])));
        }

        #[test]
        fn envelope_plain() {
            insta::assert_snapshot!(plain_of(&sample_envelope("job-a")));
        }

        #[test]
        fn envelope_json() {
            insta::assert_snapshot!(json_of(&sample_envelope("job-a")));
        }

        #[test]
        fn gc_plain() {
            let report = GcReport {
                evicted: vec!["job-a".to_string(), "job-b".to_string()],
                swept_staging_dirs: vec!["cred-abc".to_string()],
            };
            insta::assert_snapshot!(plain_of(&report));
        }

        #[test]
        fn gc_json() {
            let report = GcReport {
                evicted: vec!["job-a".to_string(), "job-b".to_string()],
                swept_staging_dirs: vec!["cred-abc".to_string()],
            };
            insta::assert_snapshot!(json_of(&report));
        }

        #[test]
        fn doctor_plain() {
            let result = DoctorResult {
                exit_code: 0,
                message: "sandy doctor: ok".to_string(),
            };
            insta::assert_snapshot!(plain_of(&result));
        }

        #[test]
        fn doctor_json() {
            let result = DoctorResult {
                exit_code: 2,
                message: "sandy doctor: refused".to_string(),
            };
            insta::assert_snapshot!(json_of(&result));
        }
    }

    #[test]
    fn json_record_round_trips_to_the_same_record() -> anyhow::Result<()> {
        let record = sample_record("job-a");
        let json = json_of(&record);
        let parsed: JobRecord = serde_json::from_str(&json).context("parse json record")?;
        assert_eq!(parsed, record, "json output must round-trip to the same record");
        Ok(())
    }

    #[test]
    fn plain_record_names_the_job_and_state() {
        let plain = plain_of(&sample_record("job-a"));
        assert!(plain.contains("job-a"), "plain must name the job id: {plain}");
        assert!(plain.contains("Succeeded"), "plain must name the state: {plain}");
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

        let plain = plain_of(&envelope);
        assert!(plain.contains("out: result/f"), "plain lists the output: {plain}");
        assert!(
            plain.contains("out: result/sub/g"),
            "plain lists the nested output: {plain}"
        );

        let json = json_of(&envelope);
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

        let plain = plain_of(&envelope);
        assert!(
            plain.contains("warning: credential \"GH_TOKEN\" revoke failed at teardown"),
            "plain lists the warning: {plain}"
        );

        let json = json_of(&envelope);
        let parsed: ResultEnvelope = serde_json::from_str(&json).context("parse json envelope")?;
        assert_eq!(parsed.warnings, envelope.warnings, "json carries the warnings array");
        Ok(())
    }

    #[test]
    fn json_records_is_an_array_even_when_empty() -> anyhow::Result<()> {
        let empty = json_of(&JobRecords(vec![]));
        let parsed: Vec<JobRecord> = serde_json::from_str(&empty).context("parse empty array")?;
        assert!(parsed.is_empty(), "empty ls must serialize to an empty JSON array");

        let two = JobRecords(vec![sample_record("a"), sample_record("b")]);
        let json = json_of(&two);
        let parsed: Vec<JobRecord> = serde_json::from_str(&json).context("parse two")?;
        assert_eq!(parsed.len(), 2);
        Ok(())
    }

    #[test]
    fn json_envelope_round_trips() -> anyhow::Result<()> {
        let envelope = sample_envelope("job-a");
        let json = json_of(&envelope);
        let parsed: ResultEnvelope = serde_json::from_str(&json).context("parse json envelope")?;
        assert_eq!(parsed, envelope);
        Ok(())
    }

    #[test]
    fn plain_envelope_summarizes_status_and_message() {
        let plain = plain_of(&sample_envelope("job-a"));
        assert!(plain.contains("job-a"));
        assert!(plain.contains("Failed"), "summary must name the status: {plain}");
        assert!(
            plain.contains("retryable true"),
            "summary must name retryability: {plain}"
        );
    }

    #[test]
    fn gc_json_carries_the_evicted_ids() -> anyhow::Result<()> {
        let report = GcReport {
            evicted: vec!["x".to_string(), "y".to_string()],
            swept_staging_dirs: Vec::new(),
        };
        let json = json_of(&report);
        let parsed: serde_json::Value = serde_json::from_str(&json).context("parse gc json")?;
        let evicted = parsed
            .get("evicted")
            .and_then(|v| v.as_array())
            .context("gc json must have an `evicted` array")?;
        assert_eq!(evicted.len(), 2);
        Ok(())
    }

    /// #195 follow-up: a swept staging-dir name must never land in the
    /// `evicted` key (a JSON consumer may pass that key's entries to
    /// `status`/`wait`, which expect job ids only), and must appear under its
    /// own `swept_staging_dirs` key instead.
    #[test]
    fn gc_json_keeps_swept_staging_dirs_out_of_evicted() -> anyhow::Result<()> {
        let report = GcReport {
            evicted: vec!["job-a".to_string()],
            swept_staging_dirs: vec!["cred-deadbeef".to_string()],
        };
        let json = json_of(&report);
        let parsed: serde_json::Value = serde_json::from_str(&json).context("parse gc json")?;
        let evicted = parsed
            .get("evicted")
            .and_then(|v| v.as_array())
            .context("gc json must have an `evicted` array")?;
        assert_eq!(evicted, &vec![serde_json::Value::String("job-a".to_string())]);
        let swept = parsed
            .get("swept_staging_dirs")
            .and_then(|v| v.as_array())
            .context("gc json must have a `swept_staging_dirs` array")?;
        assert_eq!(swept, &vec![serde_json::Value::String("cred-deadbeef".to_string())]);
        Ok(())
    }

    /// The plain-text "evicted N record(s)" count must count job ids only,
    /// never a swept staging-dir name (#195 follow-up).
    #[test]
    fn gc_plain_text_evicted_count_excludes_swept_staging_dirs() {
        let report = GcReport {
            evicted: Vec::new(),
            swept_staging_dirs: vec!["cred-deadbeef".to_string()],
        };
        let plain = plain_of(&report);
        assert!(
            plain.contains("evicted 0 record(s)"),
            "a swept staging dir must not inflate the evicted-record count: {plain}"
        );
        assert!(
            plain.contains("swept 1 staging dir(s)"),
            "the swept-dir count must be reported separately: {plain}"
        );
    }

    #[test]
    fn doctor_json_carries_exit_code_and_message() -> anyhow::Result<()> {
        let result = DoctorResult {
            exit_code: 2,
            message: "refusing to start".to_string(),
        };
        let json = json_of(&result);
        let parsed: serde_json::Value = serde_json::from_str(&json).context("parse doctor json")?;
        assert_eq!(parsed.get("exit_code").and_then(serde_json::Value::as_i64), Some(2));
        assert_eq!(
            parsed.get("message").and_then(serde_json::Value::as_str),
            Some("refusing to start")
        );
        Ok(())
    }

    #[test]
    fn doctor_round_trips_through_json() -> anyhow::Result<()> {
        let result = DoctorResult {
            exit_code: 0,
            message: "sandy doctor: ok".to_string(),
        };
        let json = json_of(&result);
        let parsed: DoctorResult = serde_json::from_str(&json).context("parse doctor json")?;
        assert_eq!(parsed, result);
        Ok(())
    }

    /// The generic `emit_to`/`emit_stream_to` machinery itself (the new
    /// deliverable, not a migration of an existing `format_*` function):
    /// a single value, the empty-plain-prints-nothing convention, and NDJSON
    /// streaming with a per-line flush.
    mod emit_mechanism {
        use serde::{Deserialize, Serialize};

        use super::{
            super::{emit_stream_to, emit_to},
            OutputFormat, Render,
        };

        #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
        #[serde(tag = "type")]
        enum TestStreamEvent {
            /// Models the attach data plane's real output-delivery shape
            /// (`sandy_fabric_local::link::LinkFrame`'s data variants) so the
            /// follow-up that wires a real stream through this reuses this
            /// shape rather than redesigning it.
            Output { line: String },
            /// Models `LinkFrame::Exit { code }` — the terminal event every
            /// stream ends with.
            Exit { code: i32 },
        }

        impl Render for TestStreamEvent {
            fn render_plain(&self, out: &mut dyn std::io::Write) -> std::io::Result<()> {
                match self {
                    TestStreamEvent::Output { line } => write!(out, "{line}"),
                    TestStreamEvent::Exit { code } => write!(out, "(exited {code})"),
                }
            }
        }

        /// A `Write` that snapshots its buffer's content every time `flush`
        /// is called, so a test can assert what was visible to a reader at
        /// each flush point, not just the final concatenated output.
        #[derive(Default)]
        struct FlushCapture {
            buf: Vec<u8>,
            at_each_flush: Vec<Vec<u8>>,
        }

        impl std::io::Write for FlushCapture {
            fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
                self.buf.extend_from_slice(data);
                Ok(data.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                self.at_each_flush.push(self.buf.clone());
                Ok(())
            }
        }

        #[test]
        fn emit_to_plain_skips_an_empty_rendering() {
            let empty = super::JobRecords(vec![]);
            let mut buf = Vec::new();
            emit_to(&empty, OutputFormat::Plain, &mut buf).expect("emit_to");
            assert!(
                buf.is_empty(),
                "an empty plain rendering must print nothing, not a blank line"
            );
        }

        #[test]
        fn emit_to_json_always_prints_even_when_empty() {
            let empty = super::JobRecords(vec![]);
            let mut buf = Vec::new();
            emit_to(&empty, OutputFormat::Json, &mut buf).expect("emit_to");
            assert_eq!(String::from_utf8(buf).unwrap().trim(), "[]");
        }

        #[test]
        fn emit_stream_writes_one_tagged_ndjson_object_per_line_flushed_after_each() {
            let events = vec![
                TestStreamEvent::Output {
                    line: "hello".to_string(),
                },
                TestStreamEvent::Output {
                    line: "world".to_string(),
                },
                TestStreamEvent::Exit { code: 0 },
            ];
            let mut out = FlushCapture::default();
            emit_stream_to(events.clone(), OutputFormat::Json, &mut out).expect("emit_stream_to");

            assert_eq!(out.at_each_flush.len(), 3, "one flush per item");
            let lines: Vec<String> = String::from_utf8(out.buf.clone())
                .unwrap()
                .lines()
                .map(str::to_string)
                .collect();
            assert_eq!(lines.len(), 3, "one NDJSON line per item");

            for (line, event) in lines.iter().zip(&events) {
                let parsed: TestStreamEvent =
                    serde_json::from_str(line).unwrap_or_else(|e| panic!("line did not parse alone: {line:?}: {e}"));
                assert_eq!(&parsed, event, "line {line:?} must decode back to its event");
                assert!(line.starts_with("{\"type\":"), "each line must be tagged: {line}");
            }
            assert!(
                matches!(events.last(), Some(TestStreamEvent::Exit { .. })),
                "the stream's last event must be the terminal object"
            );

            // Flushing happens after each item is fully written: the first
            // captured buffer must already contain the first line in full.
            let first_flush = String::from_utf8(out.at_each_flush[0].clone()).unwrap();
            assert_eq!(first_flush.trim_end(), lines[0]);
        }

        #[test]
        fn emit_stream_plain_renders_one_human_line_per_item_as_they_arrive() {
            let events = vec![
                TestStreamEvent::Output { line: "hi".to_string() },
                TestStreamEvent::Exit { code: 1 },
            ];
            let mut out = Vec::new();
            emit_stream_to(events, OutputFormat::Plain, &mut out).expect("emit_stream_to");
            let text = String::from_utf8(out).unwrap();
            assert_eq!(text, "hi\n(exited 1)\n");
        }
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
