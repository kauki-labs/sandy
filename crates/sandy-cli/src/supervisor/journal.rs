//! Persist a job's terminal [`JobRecord`] carrying its [`ResultEnvelope`]
//! (INV-6), through the [`JournalWriter`] seam [`super::run_job_core`]'s
//! callers need.

use std::time::SystemTime;

use sandy::{CoreError, JOURNAL_SCHEMA_VERSION, JobRecord, JobState, Journal, Status};

use super::RunReport;

/// Map a terminal envelope [`Status`] to the journal [`JobState`] it persists as.
fn terminal_state(status: Status) -> JobState {
    match status {
        Status::Succeeded => JobState::Succeeded,
        Status::Failed => JobState::Failed,
        Status::Cancelled => JobState::Cancelled,
    }
}

/// The write side of the journal that [`super::run_job_core`]/[`super::run_job_with_credential`]
/// need. A trait, not the concrete [`Journal`], only so a test can wrap a real
/// journal and observe write order/count without touching the filesystem; every
/// production caller passes a real `&Journal`, which implements this by
/// delegating to [`Journal::write_record`].
pub trait JournalWriter {
    /// Persist `record` unconditionally.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] on journal I/O failure.
    fn persist(&self, record: &JobRecord) -> Result<(), CoreError>;

    /// Persist `record` under the job flock, but only if the current record is
    /// not already a REAL terminal result: a concurrent `kill` takes the same
    /// flock, re-reads, and writes `Cancelled` carrying its own envelope
    /// (INV-3/INV-6); that result must never be overwritten. `reconcile_job`'s
    /// `Crashed`, by contrast, carries no envelope and rests on a liveness
    /// inference ("the box is gone, so the owner must be") that this run's own
    /// live write disproves — the live owner's real result overwrites it rather
    /// than losing to a stale guess (`run_job_core` never updates `box_id` on
    /// the `Running` record, so `reconcile_job`'s box-liveness check never even
    /// fires for it; flock-freeness during the whole run is its only signal).
    /// Returns whether `record` was actually written: `false` means a
    /// competing REAL result already stood, and the caller must not report its
    /// own `record` as this job's result (it would drift from the journal).
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] on journal I/O failure.
    fn persist_if_still_running(&self, record: &JobRecord) -> Result<bool, CoreError>;
}

impl JournalWriter for Journal {
    fn persist(&self, record: &JobRecord) -> Result<(), CoreError> {
        self.write_record(record)
    }

    fn persist_if_still_running(&self, record: &JobRecord) -> Result<bool, CoreError> {
        let _lock = self.lock_job(&record.job_id)?;
        let current = self.read_record(&record.job_id)?;
        if current.state != JobState::Running && current.result.is_some() {
            // A concurrent kill already landed a REAL terminal record (one
            // carrying an envelope, e.g. Cancelled) under this same flock; that
            // result stands (INV-3/INV-6). An envelope-less Crashed from
            // reconcile_job's liveness guess does not count: this write IS the
            // live owner, so the guess was wrong and loses.
            return Ok(false);
        }
        self.write_record(record)?;
        Ok(true)
    }
}

/// [`super::run_job_core`]'s result: the report, plus the job's start time when a
/// terminal record is still owed. `started` is `None` only for the invalid-plan
/// early return (band 2): no `Running` record was ever written, so persisting a
/// terminal one would break the silent-run guard.
pub(super) struct JobOutcome {
    pub(super) report: RunReport,
    pub(super) started: Option<SystemTime>,
}

/// Build and persist the terminal [`JobRecord`] carrying `report`'s envelope
/// (INV-6). `started` is the time the job's `Running` record was written.
/// Returns whether the write actually landed (see
/// [`JournalWriter::persist_if_still_running`]).
pub(super) fn write_terminal_record<J: JournalWriter + ?Sized>(
    journal: &J,
    started: SystemTime,
    report: &RunReport,
) -> Result<bool, CoreError> {
    let terminal = JobRecord {
        schema_version: JOURNAL_SCHEMA_VERSION,
        job_id: report.envelope.job_id.clone(),
        box_id: report.envelope.box_id.clone(),
        state: terminal_state(report.envelope.status),
        writer_pid: std::process::id(),
        started,
        result: Some(report.envelope.clone()),
    };
    journal.persist_if_still_running(&terminal)
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use anyhow::Context;
    use sandy::{
        JOURNAL_SCHEMA_VERSION, JobRecord, JobState, Journal, Logs, Provenance, RESULT_SCHEMA_VERSION, ResultEnvelope,
        Status,
    };

    use super::JournalWriter;

    /// A journal on a fresh local temp `$SANDY_HOME`.
    fn fresh_journal() -> anyhow::Result<(tempfile::TempDir, Journal)> {
        let tmp = tempfile::tempdir().context("creating a temp SANDY_HOME")?;
        let journal = Journal::new(tmp.path());
        journal.ensure_dirs().context("ensure_dirs")?;
        Ok((tmp, journal))
    }

    // --- terminal write never clobbers a concurrent kill/reconcile (review on #415) --

    /// `persist_if_still_running` must not overwrite a terminal record a
    /// concurrent writer (e.g. `kill`) already landed under the job flock while
    /// this run was still finishing up: the other writer's result stands.
    /// Before this guard, `write_terminal_record` called plain `persist`, which
    /// would have clobbered the `Cancelled` record below with `Succeeded`.
    #[test]
    fn persist_if_still_running_never_overwrites_an_already_terminal_record() -> anyhow::Result<()> {
        let (_tmp, journal) = fresh_journal()?;
        let job_id = "job-concurrent-kill".to_string();
        let started = SystemTime::now();

        journal.write_record(&JobRecord {
            schema_version: JOURNAL_SCHEMA_VERSION,
            job_id: job_id.clone(),
            box_id: None,
            state: JobState::Running,
            writer_pid: std::process::id(),
            started,
            result: None,
        })?;

        // Simulate a concurrent `kill` landing first, under the job flock, with
        // its own real envelope — exactly as `kill` writes it, never `None`.
        let cancelled = JobRecord {
            schema_version: JOURNAL_SCHEMA_VERSION,
            job_id: job_id.clone(),
            box_id: None,
            state: JobState::Cancelled,
            writer_pid: std::process::id() + 1,
            started,
            result: Some(ResultEnvelope {
                result_schema_version: RESULT_SCHEMA_VERSION,
                job_id: job_id.clone(),
                box_id: None,
                status: Status::Cancelled,
                retryable: false,
                message: "cancelled".to_string(),
                exit_code: None,
                outputs: vec![],
                receipts: vec![],
                provenance: Provenance {
                    template_store_path: String::new(),
                },
                logs: Logs { tail: String::new() },
                warnings: vec![],
                receipt: None,
            }),
        };
        journal.write_record(&cancelled)?;

        // This run finishes up on its own thread, unaware of the kill, and tries
        // to write its own (different) terminal state.
        let late_succeeded = JobRecord {
            schema_version: JOURNAL_SCHEMA_VERSION,
            job_id: job_id.clone(),
            box_id: Some("box-1".to_string()),
            state: JobState::Succeeded,
            writer_pid: std::process::id(),
            started,
            result: None,
        };
        let wrote = JournalWriter::persist_if_still_running(&journal, &late_succeeded)?;

        assert!(
            !wrote,
            "the skipped write must report false so the caller knows not to report its own result"
        );
        let on_disk = journal.read_record(&job_id)?;
        assert_eq!(
            on_disk.state,
            JobState::Cancelled,
            "the concurrent kill's result must stand, never overwritten by a late terminal write"
        );
        Ok(())
    }

    /// `reconcile_job`'s `Crashed` carries no envelope (`result: None`) and rests
    /// on a liveness guess ("the box is gone, so the owner must be"): it is not a
    /// real result like `kill`'s `Cancelled`. When the live owner's own write
    /// lands right after, that write must win — the owner being able to write at
    /// all disproves the guess, and INV-6 requires a terminal record to carry an
    /// envelope. Before this test's fix, `persist_if_still_running` treated any
    /// non-`Running` state as final and would have skipped this write too,
    /// permanently stranding the job behind a `Crashed`/`None` record even
    /// though it actually succeeded.
    #[test]
    fn persist_if_still_running_overwrites_an_envelope_less_reconcile_crash() -> anyhow::Result<()> {
        let (_tmp, journal) = fresh_journal()?;
        let job_id = "job-spurious-reconcile".to_string();
        let started = SystemTime::now();

        journal.write_record(&JobRecord {
            schema_version: JOURNAL_SCHEMA_VERSION,
            job_id: job_id.clone(),
            box_id: None,
            state: JobState::Running,
            writer_pid: std::process::id(),
            started,
            result: None,
        })?;

        // Simulate reconcile_job's guess: the box looked gone, so it flipped the
        // record to Crashed with no envelope, under the same flock.
        journal.write_record(&JobRecord {
            schema_version: JOURNAL_SCHEMA_VERSION,
            job_id: job_id.clone(),
            box_id: None,
            state: JobState::Crashed,
            writer_pid: std::process::id() + 1,
            started,
            result: None,
        })?;

        // The actual owner was alive all along and now writes its real result.
        let succeeded = JobRecord {
            schema_version: JOURNAL_SCHEMA_VERSION,
            job_id: job_id.clone(),
            box_id: Some("box-1".to_string()),
            state: JobState::Succeeded,
            writer_pid: std::process::id(),
            started,
            result: None,
        };
        let wrote = JournalWriter::persist_if_still_running(&journal, &succeeded)?;

        assert!(
            wrote,
            "the owner's real result must win over reconcile_job's envelope-less guess"
        );
        let on_disk = journal.read_record(&job_id)?;
        assert_eq!(
            on_disk.state,
            JobState::Succeeded,
            "the owner's own write must land, not stay stranded behind the spurious Crashed"
        );
        Ok(())
    }
}
