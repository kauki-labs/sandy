//! The per-job journal: one JSON record per job under `$SANDY_HOME/jobs/`.
//!
//! Records are written atomically (tmp + rename). Each job has a sibling flock
//! lockfile opened `O_CLOEXEC`; acquiring it proves the previous owner is
//! dead/absent and is the ONLY liveness authority — `writer_pid` is
//! informational (INV-3). `$SANDY_HOME` must be a local POSIX filesystem,
//! because flock is unreliable on virtiofs/networked FS (INV-5).

use std::{
    path::{Path, PathBuf},
    time::SystemTime,
};

use serde::{Deserialize, Serialize};

use crate::{CoreError, result::ResultEnvelope};

/// The schema version stamped into every journal record.
pub const JOURNAL_SCHEMA_VERSION: u32 = 1;

/// The lifecycle state of a job record. Terminal states carry the result
/// envelope (INV-6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    /// The box is (believed to be) running.
    Running,
    /// Reconcile found the owner gone before a terminal transition (INV-3).
    Crashed,
    /// The guest exited 0 and outputs were collected.
    Succeeded,
    /// A task or infra fault ended the job.
    Failed,
    /// The job was cancelled.
    Cancelled,
}

/// One job's journal record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobRecord {
    /// Schema version of this record.
    pub schema_version: u32,
    /// The job id.
    pub job_id: String,
    /// The box the job ran in, if one booted.
    pub box_id: Option<String>,
    /// The current lifecycle state.
    pub state: JobState,
    /// The pid that wrote this record — informational only (INV-3).
    pub writer_pid: u32,
    /// When the record was first created.
    pub started: SystemTime,
    /// The terminal result envelope, present once the job reaches a terminal
    /// state (INV-6).
    pub result: Option<ResultEnvelope>,
}

/// A held per-job flock. The lock is released when this value is dropped.
#[derive(Debug)]
pub struct JobLock {
    /// The job this lock guards.
    job_id: String,
    /// The locked file; held only for its RAII lifetime.
    #[allow(dead_code, reason = "held to keep the flock until drop")]
    file: std::fs::File,
}

impl JobLock {
    /// The job id this lock guards.
    #[must_use]
    pub fn job_id(&self) -> &str {
        &self.job_id
    }
}

/// The journal rooted at `$SANDY_HOME`.
#[derive(Debug, Clone)]
pub struct Journal {
    /// `$SANDY_HOME`.
    root: PathBuf,
}

impl Journal {
    /// A journal rooted at `sandy_home` (`$SANDY_HOME`). Performs no I/O; call
    /// [`Journal::ensure_dirs`] to create the layout.
    #[must_use]
    pub fn new(sandy_home: impl Into<PathBuf>) -> Self {
        Self {
            root: sandy_home.into(),
        }
    }

    /// The directory holding per-job records (`$SANDY_HOME/jobs`).
    #[must_use]
    pub fn jobs_dir(&self) -> PathBuf {
        self.root.join("jobs")
    }

    /// The record path for `job_id` (`$SANDY_HOME/jobs/<job_id>.json`).
    #[must_use]
    pub fn record_path(&self, job_id: &str) -> PathBuf {
        self.jobs_dir().join(format!("{job_id}.json"))
    }

    /// The lockfile path for `job_id` (`$SANDY_HOME/jobs/<job_id>.lock`).
    #[must_use]
    pub fn lock_path(&self, job_id: &str) -> PathBuf {
        self.jobs_dir().join(format!("{job_id}.lock"))
    }

    /// Create the journal directory layout.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Io`] if the directories cannot be created.
    pub fn ensure_dirs(&self) -> Result<(), CoreError> {
        todo!("create $SANDY_HOME/jobs")
    }

    /// Write `record` atomically (tmp + fsync + rename).
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Io`] / [`CoreError::Serde`] on failure.
    pub fn write_record(&self, _record: &JobRecord) -> Result<(), CoreError> {
        todo!("serialize to <id>.json.tmp, fsync, rename over <id>.json")
    }

    /// Read the record for `job_id`.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::NotFound`] when no record exists.
    pub fn read_record(&self, _job_id: &str) -> Result<JobRecord, CoreError> {
        todo!("read and deserialize <id>.json")
    }

    /// List every job record.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Io`] / [`CoreError::Serde`] on failure.
    pub fn list(&self) -> Result<Vec<JobRecord>, CoreError> {
        todo!("read every <id>.json under jobs/")
    }

    /// Block until the per-job flock is acquired (`O_CLOEXEC`).
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Io`] if the lockfile cannot be opened.
    pub fn lock_job(&self, _job_id: &str) -> Result<JobLock, CoreError> {
        todo!("open <id>.lock O_CLOEXEC and flock-exclusive (blocking)")
    }

    /// Try to acquire the per-job flock without blocking; `Ok(None)` if another
    /// writer holds it (proving the owner is live — INV-3).
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Io`] if the lockfile cannot be opened.
    pub fn try_lock_job(&self, _job_id: &str) -> Result<Option<JobLock>, CoreError> {
        todo!("open <id>.lock O_CLOEXEC and try_lock_exclusive")
    }
}

/// Generate a fresh job id (UUID v4).
#[must_use]
pub fn new_job_id() -> String {
    todo!("uuid::Uuid::new_v4()")
}

/// Verify that `path` lives on a local POSIX filesystem, not virtiofs/NFS,
/// where flock is unreliable (INV-5).
///
/// # Errors
///
/// Returns [`CoreError::NonLocalFs`] when `path` is on a non-local filesystem.
pub fn ensure_local_posix_fs(_path: &Path) -> Result<(), CoreError> {
    todo!("reject virtiofs / networked filesystems")
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use super::*;
    use crate::result::{Logs, OutputRef, Provenance, RESULT_SCHEMA_VERSION, Status};

    fn terminal_record() -> JobRecord {
        JobRecord {
            schema_version: JOURNAL_SCHEMA_VERSION,
            job_id: "job-1".to_string(),
            box_id: Some("box-1".to_string()),
            state: JobState::Succeeded,
            writer_pid: 4242,
            started: SystemTime::UNIX_EPOCH,
            result: Some(ResultEnvelope {
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
                receipts: vec![],
                provenance: Provenance {
                    template_store_path: "/nix/store/xxx".to_string(),
                },
                logs: Logs { tail: String::new() },
            }),
        }
    }

    /// INV-6: a terminal record round-trips through the journal carrying the
    /// full result envelope and its `result_schema_version`.
    #[test]
    fn terminal_record_round_trips_with_result() -> anyhow::Result<()> {
        let tmp = tempfile::tempdir()?;
        let journal = Journal::new(tmp.path());
        journal.ensure_dirs()?;
        let record = terminal_record();
        journal.write_record(&record)?;
        let read = journal.read_record("job-1")?;
        let result = read.result.expect("terminal record carries a result");
        assert_eq!(result.result_schema_version, RESULT_SCHEMA_VERSION);
        assert_eq!(result.status, Status::Succeeded);
        Ok(())
    }

    /// INV-3: the per-job flock is single-writer — a second non-blocking
    /// acquire fails while the first is held.
    #[test]
    fn job_lock_is_single_writer() -> anyhow::Result<()> {
        let tmp = tempfile::tempdir()?;
        let journal = Journal::new(tmp.path());
        journal.ensure_dirs()?;
        let held = journal.lock_job("job-1")?;
        assert_eq!(held.job_id(), "job-1");
        assert!(
            journal.try_lock_job("job-1")?.is_none(),
            "a second writer must not acquire the held lock"
        );
        Ok(())
    }

    /// INV-5: a local POSIX `$SANDY_HOME` is accepted.
    #[test]
    fn local_posix_home_is_accepted() -> anyhow::Result<()> {
        let tmp = tempfile::tempdir()?;
        ensure_local_posix_fs(tmp.path())?;
        Ok(())
    }
}
