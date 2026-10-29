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
use sandy_control_proto::{AttachResponse, JobStatus, ListResponse, StatusResponse, SubmitResponse};
use serde::{Deserialize, Serialize};

use crate::{
    app_register::{CredDeregistered, CredImported, CredRegistered, CredVerified},
    supervisor::GcReport,
};

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

/// A node's persisted mesh TLS identity fingerprint (decision 20), as
/// printed by `sandy mesh key generate`/`fingerprint`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MeshFingerprint {
    /// The hex-encoded SHA-256 fingerprint of the identity's certificate.
    pub fingerprint: String,
}

impl Render for MeshFingerprint {
    fn render_plain(&self, out: &mut dyn io::Write) -> io::Result<()> {
        write!(out, "{}", self.fingerprint)
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

impl Render for CredRegistered {
    fn render_plain(&self, out: &mut dyn io::Write) -> io::Result<()> {
        writeln!(
            out,
            "Registered GitHub App \"{}\": app_id={}, installation_id={}",
            self.app_name, self.app_id, self.installation_id
        )?;
        writeln!(out, "Trust root: {}", self.trust_root.display())?;
        write!(out, "Private key: {} (0600)", self.private_key.display())
    }
}

impl Render for CredImported {
    fn render_plain(&self, out: &mut dyn io::Write) -> io::Result<()> {
        writeln!(
            out,
            "Imported shared GitHub App trust root: app_id={}, installation_id={}",
            self.app_id, self.installation_id
        )?;
        write!(out, "Trust root: {}", self.trust_root.display())
    }
}

impl Render for CredVerified {
    fn render_plain(&self, out: &mut dyn io::Write) -> io::Result<()> {
        write!(
            out,
            "Verified: mints a scoped token and the installation grants the requested capabilities."
        )
    }
}

impl Render for CredDeregistered {
    fn render_plain(&self, out: &mut dyn io::Write) -> io::Result<()> {
        if self.uninstalled {
            writeln!(out, "Uninstalled the App at the forge.")?;
            if let Some(url) = &self.registration_residue {
                writeln!(
                    out,
                    "The App registration shell can't be deleted via API; remove it in the UI: {url}"
                )?;
            }
        } else if let Some(url) = &self.registration_residue {
            writeln!(
                out,
                "Did not uninstall at the forge (needs the App key, which only its live .pem can sign)."
            )?;
            writeln!(out, "Uninstall it yourself in the GitHub UI (no key needed): {url}")?;
        }
        write!(out, "Shredded the local key and removed {}", self.trust_root.display())
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

/// `daemon submit`'s result: the job id `sandyd` assigned. The attach token `Submit` also returns is a
/// bearer credential and is persisted by the CLI, never printed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmittedJob {
    /// The id `sandyd` assigned.
    pub job_id: String,
}

impl From<&SubmitResponse> for SubmittedJob {
    fn from(response: &SubmitResponse) -> Self {
        Self {
            job_id: response.job_id.clone(),
        }
    }
}

impl Render for SubmittedJob {
    fn render_plain(&self, out: &mut dyn io::Write) -> io::Result<()> {
        write!(out, "submitted job {}", self.job_id)
    }
}

/// `daemon cancel`'s result. `CancelResponse` carries no fields, so `job_id` is the id the caller passed on
/// the command line, not something read back off the response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CancelledJob {
    /// The id the caller asked to cancel.
    pub job_id: String,
    /// Always `true` on success; a refused cancel is an error, not a result.
    pub cancelled: bool,
}

impl CancelledJob {
    /// The result for `job_id`, cancelled.
    #[must_use]
    pub fn new(job_id: &str) -> Self {
        Self {
            job_id: job_id.to_owned(),
            cancelled: true,
        }
    }
}

impl Render for CancelledJob {
    fn render_plain(&self, out: &mut dyn io::Write) -> io::Result<()> {
        write!(out, "cancelled job {}", self.job_id)
    }
}

/// `daemon attach`'s result: the data-plane channel id and the attenuated join cap `sandyd` hands back.
///
/// The cap is a bearer credential, the same reason [`sandy_control_proto::AttachResponse`]'s own `Debug`
/// redacts it. `plain` never prints it (a human terminal is not `attach`'s intended consumer); `json` carries
/// it base64-encoded, since the automation layer that joins the channel needs the real bytes. `Debug` redacts
/// it too, so a stray `{:?}` cannot leak it.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachedChannel {
    /// The channel to join.
    pub channel_id: String,
    /// The join cap, base64 (standard alphabet).
    pub cap: String,
}

impl From<&AttachResponse> for AttachedChannel {
    fn from(response: &AttachResponse) -> Self {
        Self {
            channel_id: response.channel_id.clone(),
            cap: base64::engine::general_purpose::STANDARD.encode(&response.cap),
        }
    }
}

impl std::fmt::Debug for AttachedChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttachedChannel")
            .field("channel_id", &self.channel_id)
            .field("cap", &format_args!("<redacted {} chars>", self.cap.len()))
            .finish()
    }
}

impl Render for AttachedChannel {
    fn render_plain(&self, out: &mut dyn io::Write) -> io::Result<()> {
        // A hand-built view may carry a cap that is not valid base64: say so rather than print "0 bytes".
        let size = base64::engine::general_purpose::STANDARD
            .decode(&self.cap)
            .map_or_else(|_| "unreadable".to_owned(), |cap| format!("{} bytes", cap.len()));
        write!(
            out,
            "channel {} (cap: {size}, redacted — use -o json to retrieve)",
            self.channel_id
        )
    }
}

/// `daemon status`'s result: the job id, its lifecycle state, and (once terminal) the exit code and console
/// tail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobStatusReport {
    /// The job asked about.
    pub job_id: String,
    /// The state's wire name, e.g. `JOB_STATUS_RUNNING`.
    pub status: String,
    /// The guest's exit code, when a terminal run reported one (#292).
    pub exit_code: Option<i32>,
    /// The console tail, up to about 64 KiB. JSON only: the plain form stays one line.
    pub console_tail: String,
}

impl From<&StatusResponse> for JobStatusReport {
    fn from(response: &StatusResponse) -> Self {
        Self {
            job_id: response.job_id.clone(),
            status: job_status_name(response.status).to_owned(),
            exit_code: response.exit_code,
            console_tail: response.console_tail.clone(),
        }
    }
}

impl Render for JobStatusReport {
    fn render_plain(&self, out: &mut dyn io::Write) -> io::Result<()> {
        write!(out, "job {}: {}", self.job_id, self.status)?;
        if let Some(exit_code) = self.exit_code {
            write!(out, " (exit {exit_code})")?;
        }
        Ok(())
    }
}

/// One job in `daemon list`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobSummaryView {
    /// The job id.
    pub job_id: String,
    /// The state's wire name.
    pub status: String,
}

/// `daemon list`'s result: every job `sandyd` knows about. `#[serde(transparent)]` keeps the JSON an array.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct JobSummaries(pub Vec<JobSummaryView>);

impl From<&ListResponse> for JobSummaries {
    fn from(response: &ListResponse) -> Self {
        Self(
            response
                .jobs
                .iter()
                .map(|job| JobSummaryView {
                    job_id: job.job_id.clone(),
                    status: job_status_name(job.status).to_owned(),
                })
                .collect(),
        )
    }
}

impl Render for JobSummaries {
    fn render_plain(&self, out: &mut dyn io::Write) -> io::Result<()> {
        for (i, job) in self.0.iter().enumerate() {
            if i > 0 {
                writeln!(out)?;
            }
            write!(out, "{:<36}  {}", job.job_id, job.status)?;
        }
        Ok(())
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
        AttachedChannel, CancelledJob, EmitError, GcReport, JobRecords, JobStatusReport, JobSummaries, OutputFormat,
        Render, SubmittedJob, emit_to,
    };

    /// `emit_to` into a string without the trailing newline, so the contract tests below read as they did
    /// when each command had its own `format_*` helper (#513: the typed views must keep that exact output).
    fn emitted<T: Render + serde::Serialize>(value: &T, format: OutputFormat) -> Result<String, EmitError> {
        let mut buf = Vec::new();
        emit_to(value, format, &mut buf)?;
        Ok(String::from_utf8_lossy(&buf).trim_end_matches('\n').to_owned())
    }

    fn format_submit(response: &SubmitResponse, format: OutputFormat) -> Result<String, EmitError> {
        emitted(&SubmittedJob::from(response), format)
    }

    fn format_cancel(job_id: &str, format: OutputFormat) -> Result<String, EmitError> {
        emitted(&CancelledJob::new(job_id), format)
    }

    fn format_attach(response: &AttachResponse, format: OutputFormat) -> Result<String, EmitError> {
        emitted(&AttachedChannel::from(response), format)
    }

    fn format_status(response: &StatusResponse, format: OutputFormat) -> Result<String, EmitError> {
        emitted(&JobStatusReport::from(response), format)
    }

    fn format_list(response: &ListResponse, format: OutputFormat) -> Result<String, EmitError> {
        emitted(&JobSummaries::from(response), format)
    }

    /// #513: every daemon output type is a real serde type: its JSON deserializes back to itself.
    #[test]
    fn every_daemon_output_type_round_trips_through_json() -> anyhow::Result<()> {
        fn round_trip<T>(value: &T) -> anyhow::Result<()>
        where
            T: serde::Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug,
        {
            let json = serde_json::to_string(value).context("serialize")?;
            let back: T = serde_json::from_str(&json).context("deserialize")?;
            assert_eq!(&back, value, "round trip changed the value: {json}");
            Ok(())
        }
        round_trip(&SubmittedJob { job_id: "j".into() })?;
        round_trip(&CancelledJob::new("j"))?;
        round_trip(&AttachedChannel::from(&AttachResponse {
            channel_id: "c".into(),
            cap: vec![1, 2, 3],
        }))?;
        round_trip(&JobStatusReport {
            job_id: "j".into(),
            status: "JOB_STATUS_SUCCEEDED".into(),
            exit_code: Some(0),
            console_tail: "hi\n".into(),
        })?;
        round_trip(&JobSummaries::from(&ListResponse {
            jobs: vec![JobSummary {
                job_id: "j".into(),
                status: JobStatus::Running as i32,
            }],
        }))?;
        Ok(())
    }

    /// A stray `{:?}` of the attach view must not print the cap (it is a bearer credential).
    #[test]
    fn attached_channel_debug_redacts_the_cap() {
        let marker = "sandy-cap-debug-marker-31c9";
        let view = AttachedChannel::from(&AttachResponse {
            channel_id: "orchestrator".into(),
            cap: marker.as_bytes().to_vec(),
        });
        let encoded = base64::engine::general_purpose::STANDARD.encode(marker);
        let rendered = format!("{view:?}");
        assert!(!rendered.contains(marker) && !rendered.contains(&encoded), "{rendered}");
        assert!(rendered.contains("redacted"), "{rendered}");
    }

    /// A cap that is not valid base64 must not print as "0 bytes", and must stay out of the output.
    #[test]
    fn a_malformed_cap_renders_as_unreadable_not_zero_bytes() -> anyhow::Result<()> {
        let view = AttachedChannel {
            channel_id: "orchestrator".into(),
            cap: "not base64 !!".into(),
        };
        let mut buf = Vec::new();
        view.render_plain(&mut buf)?;
        let line = String::from_utf8(buf)?;
        assert!(line.contains("unreadable") && !line.contains("0 bytes"), "{line}");
        assert!(!line.contains("not base64"), "{line}");
        Ok(())
    }

    /// Plain `list` with no jobs prints nothing at all (not a blank line), as `ls` does.
    #[test]
    fn an_empty_list_renders_no_plain_output() -> anyhow::Result<()> {
        let mut buf = Vec::new();
        emit_to(&JobSummaries(Vec::new()), OutputFormat::Plain, &mut buf).context("emit")?;
        assert!(buf.is_empty(), "got {:?}", String::from_utf8_lossy(&buf));
        Ok(())
    }

    /// The JSON keys are the contract scripts already parse; a rename must be a deliberate, reviewed change.
    #[test]
    fn the_json_shapes_keep_their_keys() -> anyhow::Result<()> {
        let status = serde_json::to_value(JobStatusReport {
            job_id: "j".into(),
            status: "JOB_STATUS_FAILED".into(),
            exit_code: None,
            console_tail: String::new(),
        })?;
        assert_eq!(
            status,
            serde_json::json!({"job_id": "j", "status": "JOB_STATUS_FAILED", "exit_code": null, "console_tail": ""})
        );
        assert_eq!(
            serde_json::to_value(CancelledJob::new("j"))?,
            serde_json::json!({"job_id": "j", "cancelled": true})
        );
        assert_eq!(
            serde_json::to_value(SubmittedJob { job_id: "j".into() })?,
            serde_json::json!({"job_id": "j"})
        );
        Ok(())
    }

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
        use anyhow::Context;
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
        fn emit_to_json_always_prints_even_when_empty() -> anyhow::Result<()> {
            let empty = super::JobRecords(vec![]);
            let mut buf = Vec::new();
            emit_to(&empty, OutputFormat::Json, &mut buf).expect("emit_to");
            let text = String::from_utf8(buf).context("emit_to output must be UTF-8")?;
            assert_eq!(text.trim(), "[]");
            Ok(())
        }

        #[test]
        fn emit_stream_writes_one_tagged_ndjson_object_per_line_flushed_after_each() -> anyhow::Result<()> {
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
                .context("emit_stream_to output must be UTF-8")?
                .lines()
                .map(str::to_string)
                .collect();
            assert_eq!(lines.len(), 3, "one NDJSON line per item");

            for (line, event) in lines.iter().zip(&events) {
                let parsed: TestStreamEvent =
                    serde_json::from_str(line).with_context(|| format!("line did not parse alone: {line:?}"))?;
                assert_eq!(&parsed, event, "line {line:?} must decode back to its event");
                assert!(line.starts_with("{\"type\":"), "each line must be tagged: {line}");
            }
            assert!(
                matches!(events.last(), Some(TestStreamEvent::Exit { .. })),
                "the stream's last event must be the terminal object"
            );

            // Flushing happens after each item is fully written: the first
            // captured buffer must already contain the first line in full.
            let first_flush = String::from_utf8(out.at_each_flush[0].clone()).context("first flush must be UTF-8")?;
            assert_eq!(first_flush.trim_end(), lines[0]);
            Ok(())
        }

        #[test]
        fn emit_stream_plain_renders_one_human_line_per_item_as_they_arrive() -> anyhow::Result<()> {
            let events = vec![
                TestStreamEvent::Output { line: "hi".to_string() },
                TestStreamEvent::Exit { code: 1 },
            ];
            let mut out = Vec::new();
            emit_stream_to(events, OutputFormat::Plain, &mut out).expect("emit_stream_to");
            let text = String::from_utf8(out).context("emit_stream_to output must be UTF-8")?;
            assert_eq!(text, "hi\n(exited 1)\n");
            Ok(())
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

    /// The cred commands' typed results (#514): plain and JSON snapshots, a serde
    /// round trip, and INV-1 (no secret in either rendering) for each command.
    mod cred {
        use std::path::PathBuf;

        use super::{json_of, plain_of};
        use crate::app_register::{CredDeregistered, CredImported, CredRegistered, CredVerified};

        const SECRET: &str = "-----BEGIN RSA PRIVATE KEY-----\nsentinel-secret-0451\n-----END RSA PRIVATE KEY-----\n";

        /// A key file holding [`SECRET`], so a rendering that read the file
        /// instead of naming its path would show up.
        fn key_file(dir: &tempfile::TempDir, name: &str) -> anyhow::Result<PathBuf> {
            let path = dir.path().join(name);
            std::fs::write(&path, SECRET)?;
            Ok(path)
        }

        fn registered(key: PathBuf) -> CredRegistered {
            CredRegistered {
                app_name: "sandy-runner".to_string(),
                app_id: "5285548".to_string(),
                installation_id: 170_585_018,
                trust_root: PathBuf::from("/cfg/trust-roots/sandy-runner.json"),
                private_key: key,
            }
        }

        fn deregistered(uninstalled: bool, residue: Option<&str>) -> CredDeregistered {
            CredDeregistered {
                uninstalled,
                registration_residue: residue.map(str::to_string),
                trust_root: PathBuf::from("/cfg/trust-roots/sandy-runner.json"),
            }
        }

        fn no_secret(rendered: &str) -> anyhow::Result<()> {
            anyhow::ensure!(!rendered.contains("sentinel-secret-0451"), "secret leaked: {rendered}");
            anyhow::ensure!(!rendered.contains("PRIVATE KEY"), "key material leaked: {rendered}");
            Ok(())
        }

        #[test]
        fn registered_plain() {
            insta::assert_snapshot!(plain_of(&registered(PathBuf::from(
                "/cfg/trust-roots/sandy-runner.pem"
            ))));
        }

        #[test]
        fn registered_json() {
            insta::assert_snapshot!(json_of(&registered(PathBuf::from("/cfg/trust-roots/sandy-runner.pem"))));
        }

        #[test]
        fn imported_plain() {
            insta::assert_snapshot!(plain_of(&CredImported {
                app_id: "5285548".to_string(),
                installation_id: 170_585_018,
                trust_root: PathBuf::from("/cfg/trust-roots/sandy-runner.json"),
            }));
        }

        #[test]
        fn imported_json() {
            insta::assert_snapshot!(json_of(&CredImported {
                app_id: "5285548".to_string(),
                installation_id: 170_585_018,
                trust_root: PathBuf::from("/cfg/trust-roots/sandy-runner.json"),
            }));
        }

        #[test]
        fn verified_plain() {
            insta::assert_snapshot!(plain_of(&CredVerified { verified: true }));
        }

        #[test]
        fn verified_json() {
            insta::assert_snapshot!(json_of(&CredVerified { verified: true }));
        }

        #[test]
        fn deregistered_plain_uninstalled_with_residue() {
            insta::assert_snapshot!(plain_of(&deregistered(
                true,
                Some("https://github.com/settings/apps/x")
            )));
        }

        #[test]
        fn deregistered_plain_not_uninstalled_with_residue() {
            insta::assert_snapshot!(plain_of(&deregistered(
                false,
                Some("https://github.com/settings/installations/1")
            )));
        }

        #[test]
        fn deregistered_plain_keep_remote_without_residue() {
            insta::assert_snapshot!(plain_of(&deregistered(false, None)));
        }

        #[test]
        fn deregistered_json() {
            insta::assert_snapshot!(json_of(&deregistered(true, Some("https://github.com/settings/apps/x"))));
        }

        #[test]
        fn every_cred_result_round_trips_through_json() -> anyhow::Result<()> {
            let dereg = deregistered(true, None);
            let reg = registered(PathBuf::from("/k.pem"));
            let ver = CredVerified { verified: true };
            anyhow::ensure!(serde_json::from_str::<CredDeregistered>(&json_of(&dereg))? == dereg);
            anyhow::ensure!(serde_json::from_str::<CredRegistered>(&json_of(&reg))? == reg);
            anyhow::ensure!(serde_json::from_str::<CredVerified>(&json_of(&ver))? == ver);
            Ok(())
        }

        #[test]
        fn register_never_prints_the_key_in_either_format() -> anyhow::Result<()> {
            let dir = tempfile::TempDir::new()?;
            let out = registered(key_file(&dir, "k.pem")?);
            no_secret(&plain_of(&out))?;
            no_secret(&json_of(&out))
        }

        #[test]
        fn deregister_never_prints_the_key_in_either_format() -> anyhow::Result<()> {
            let dir = tempfile::TempDir::new()?;
            let mut out = deregistered(true, Some("https://github.com/settings/apps/x"));
            out.trust_root = key_file(&dir, "sandy-runner.json")?;
            no_secret(&plain_of(&out))?;
            no_secret(&json_of(&out))
        }

        #[test]
        fn verify_never_prints_the_key_in_either_format() -> anyhow::Result<()> {
            no_secret(&plain_of(&CredVerified { verified: true }))?;
            no_secret(&json_of(&CredVerified { verified: true }))
        }
    }
}
