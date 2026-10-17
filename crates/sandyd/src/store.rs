//! The job state store (#212, B1): a `jobs` table in `rusqlite` (vendored
//! SQLite, docs/decisions/sandyd.md §4), holding only what this skeleton
//! needs — a job's id, lifecycle status, and the manifest bytes it was
//! submitted with. No dispatch: nothing here provisions a sandbox, mints a
//! cap, or wires a channel — B2 (`sandy-orchestrator`) replaces these stub
//! transitions with real dispatch once it lands.
//!
//! Synchronous by design (`rusqlite` has no async API): every call blocks on
//! the single connection behind a mutex. Callers on an async runtime must
//! wrap calls in `tokio::task::spawn_blocking` — this module does not do that
//! itself, so it stays usable from a plain synchronous test too.

use std::{
    path::Path,
    sync::{Mutex, PoisonError},
};

use rusqlite::Connection;
use sandy_control_proto::JobStatus;

/// A job store failure.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// The underlying SQLite connection faulted.
    #[error("job store: {0}")]
    Sqlite(#[from] rusqlite::Error),
}

/// The outcome of a [`JobStore::cancel`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancelOutcome {
    /// The job was `Pending` or `Running` and is now `Cancelled`.
    Cancelled,
    /// No job has this id.
    NotFound,
    /// The job exists but already reached a terminal status
    /// (`Succeeded`/`Failed`/`Cancelled`); cancelling it again is refused,
    /// not silently accepted as a no-op success.
    AlreadyTerminal(JobStatus),
}

/// One submitted job's row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobSummary {
    /// The job's id.
    pub job_id: String,
    /// Its current lifecycle status.
    pub status: JobStatus,
}

/// The `jobs` table behind a single `rusqlite` connection.
pub struct JobStore {
    conn: Mutex<Connection>,
}

impl JobStore {
    /// Open (creating if needed) the job store at `path`, and ensure its
    /// schema exists.
    ///
    /// # Errors
    /// [`StoreError::Sqlite`] if the file cannot be opened or the schema
    /// cannot be created.
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        let conn = Connection::open(path)?;
        Self::from_connection(conn)
    }

    /// An in-memory store, for tests: no file, gone when the store is dropped.
    ///
    /// # Errors
    /// [`StoreError::Sqlite`] if the schema cannot be created.
    pub fn open_in_memory() -> Result<Self, StoreError> {
        Self::from_connection(Connection::open_in_memory()?)
    }

    fn from_connection(conn: Connection) -> Result<Self, StoreError> {
        conn.execute(
            "CREATE TABLE IF NOT EXISTS jobs (
                job_id             TEXT PRIMARY KEY,
                status             TEXT NOT NULL,
                manifest           BLOB NOT NULL,
                manifest_encoding  TEXT NOT NULL,
                created_at         INTEGER NOT NULL,
                updated_at         INTEGER NOT NULL
            )",
            (),
        )?;
        Ok(Self { conn: Mutex::new(conn) })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Insert a fresh `Pending` job row for `job_id`.
    ///
    /// # Errors
    /// [`StoreError::Sqlite`] if `job_id` already exists, or the write fails.
    pub fn insert_pending(&self, job_id: &str, manifest: &[u8], manifest_encoding: &str) -> Result<(), StoreError> {
        let now = now_unix();
        self.lock().execute(
            "INSERT INTO jobs (job_id, status, manifest, manifest_encoding, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?5)",
            (
                job_id,
                status_name(JobStatus::Pending),
                manifest,
                manifest_encoding,
                now,
            ),
        )?;
        Ok(())
    }

    /// The status of `job_id`, or `None` if no such job exists.
    ///
    /// # Errors
    /// [`StoreError::Sqlite`] if the read fails, or the stored status string
    /// is not a recognised [`JobStatus`] (a corrupt row, never guessed at).
    pub fn status(&self, job_id: &str) -> Result<Option<JobStatus>, StoreError> {
        self.lock()
            .query_row("SELECT status FROM jobs WHERE job_id = ?1", [job_id], |row| {
                row.get::<_, String>(0)
            })
            .map(|raw| Some(parse_status(&raw)))
            .or_else(|e| {
                if matches!(e, rusqlite::Error::QueryReturnedNoRows) {
                    Ok(None)
                } else {
                    Err(e.into())
                }
            })
    }

    /// Mark `job_id` `Cancelled` if it is `Pending` or `Running`.
    ///
    /// # Errors
    /// [`StoreError::Sqlite`] if the read or write fails.
    pub fn cancel(&self, job_id: &str) -> Result<CancelOutcome, StoreError> {
        let conn = self.lock();
        let current = conn
            .query_row("SELECT status FROM jobs WHERE job_id = ?1", [job_id], |row| {
                row.get::<_, String>(0)
            })
            .map(|raw| Some(parse_status(&raw)))
            .or_else(|e| {
                if matches!(e, rusqlite::Error::QueryReturnedNoRows) {
                    Ok(None)
                } else {
                    Err(e)
                }
            })?;

        let Some(status) = current else {
            return Ok(CancelOutcome::NotFound);
        };
        if !matches!(status, JobStatus::Pending | JobStatus::Running) {
            return Ok(CancelOutcome::AlreadyTerminal(status));
        }
        conn.execute(
            "UPDATE jobs SET status = ?1, updated_at = ?2 WHERE job_id = ?3",
            (status_name(JobStatus::Cancelled), now_unix(), job_id),
        )?;
        Ok(CancelOutcome::Cancelled)
    }

    /// Every job's id and current status, in no particular guaranteed order
    /// beyond SQLite's own default row order.
    ///
    /// # Errors
    /// [`StoreError::Sqlite`] if the read fails.
    pub fn list(&self) -> Result<Vec<JobSummary>, StoreError> {
        let conn = self.lock();
        let mut stmt = conn.prepare("SELECT job_id, status FROM jobs")?;
        let rows = stmt.query_map((), |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))?;
        let mut summaries = Vec::new();
        for row in rows {
            let (job_id, raw_status) = row?;
            summaries.push(JobSummary {
                job_id,
                status: parse_status(&raw_status),
            });
        }
        Ok(summaries)
    }
}

/// The stable, stored name for `status` — `JobStatus::as_str_name()`, the same
/// mapping `control.proto` already generates, so the stored value and the
/// wire value never drift into two separate vocabularies.
fn status_name(status: JobStatus) -> &'static str {
    status.as_str_name()
}

/// Parse a stored status string back to a [`JobStatus`].
///
/// # Panics
/// Panics if `raw` is not one of [`JobStatus::as_str_name`]'s values: a row
/// this store itself wrote should never hold anything else, and silently
/// mapping an unrecognised value to `Unspecified` would hide real corruption
/// behind a valid-looking status.
fn parse_status(raw: &str) -> JobStatus {
    JobStatus::from_str_name(raw).unwrap_or_else(|| panic!("job store: unrecognised stored status {raw:?}"))
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0) as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_submitted_job_is_pending_and_listed() -> Result<(), StoreError> {
        let store = JobStore::open_in_memory()?;
        store.insert_pending("job-1", b"manifest-bytes", "test/v1")?;

        assert_eq!(store.status("job-1")?, Some(JobStatus::Pending));
        assert_eq!(
            store.list()?,
            vec![JobSummary {
                job_id: "job-1".to_owned(),
                status: JobStatus::Pending,
            }]
        );
        Ok(())
    }

    #[test]
    fn status_of_an_unknown_job_is_none_not_an_error() -> Result<(), StoreError> {
        let store = JobStore::open_in_memory()?;
        assert_eq!(store.status("does-not-exist")?, None);
        Ok(())
    }

    #[test]
    fn cancelling_a_pending_job_marks_it_cancelled() -> Result<(), StoreError> {
        let store = JobStore::open_in_memory()?;
        store.insert_pending("job-1", b"m", "test/v1")?;

        assert_eq!(store.cancel("job-1")?, CancelOutcome::Cancelled);
        assert_eq!(store.status("job-1")?, Some(JobStatus::Cancelled));
        Ok(())
    }

    /// Adversarial: cancelling an unknown job id is refused, not silently
    /// treated as already-cancelled.
    #[test]
    fn cancelling_an_unknown_job_is_not_found() -> Result<(), StoreError> {
        let store = JobStore::open_in_memory()?;
        assert_eq!(store.cancel("ghost")?, CancelOutcome::NotFound);
        Ok(())
    }

    /// Adversarial: cancelling an already-terminal job is refused, not
    /// silently accepted as a no-op — the caller learns the real status it
    /// collided with.
    #[test]
    fn cancelling_an_already_cancelled_job_is_refused() -> Result<(), StoreError> {
        let store = JobStore::open_in_memory()?;
        store.insert_pending("job-1", b"m", "test/v1")?;
        store.cancel("job-1")?;

        assert_eq!(
            store.cancel("job-1")?,
            CancelOutcome::AlreadyTerminal(JobStatus::Cancelled)
        );
        Ok(())
    }

    /// Adversarial: two jobs submitted with the same id must not silently
    /// collide (the second overwriting or merging into the first's row) —
    /// the id is the primary key, so a duplicate insert is a hard error the
    /// caller must handle, never silent data loss.
    #[test]
    fn inserting_a_duplicate_job_id_is_rejected() -> Result<(), StoreError> {
        let store = JobStore::open_in_memory()?;
        store.insert_pending("job-1", b"first", "test/v1")?;
        let result = store.insert_pending("job-1", b"second", "test/v1");
        assert!(result.is_err(), "a duplicate job_id must not silently succeed");
        Ok(())
    }
}
