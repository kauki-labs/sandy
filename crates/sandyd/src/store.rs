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
    os::unix::fs::PermissionsExt,
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
    /// A stored `status` value isn't one of [`JobStatus::as_str_name`]'s
    /// strings — a row this store itself wrote should never hold anything
    /// else. Surfaced as an error, not guessed at or defaulted, so a corrupt
    /// row fails the one read that touches it instead of silently reporting
    /// a wrong status or panicking every caller that lists jobs.
    #[error("job store: job {job_id:?} has an unrecognised stored status {raw:?}")]
    CorruptStatus {
        /// The job whose row is corrupt.
        job_id: String,
        /// The unrecognised stored value.
        raw: String,
    },
    /// Could not chmod the store file (CF-M-7).
    #[error("job store: {0}")]
    Io(#[from] std::io::Error),
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

/// What a lifecycle transition ([`JobStore::mark_running`]/[`JobStore::finish`])
/// did to a job row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transition {
    /// The row moved to the requested state.
    Applied,
    /// No job has this id.
    NotFound,
    /// The job was not in a state this transition applies from, so it was
    /// refused, not applied — a late result never clobbers an already-terminal
    /// row (a cancelled job stays cancelled; a job that already reported a
    /// result keeps it). Carries the status the row actually held.
    Refused(JobStatus),
}

/// The outcome of a [`JobStore::insert_pending`] call (CF-M-2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsertOutcome {
    /// The row was inserted.
    Inserted,
    /// The `jobs` table already holds `max` rows (see
    /// [`JobStore::with_max_rows`]); the insert was refused rather than
    /// growing the table further. Counts every row regardless of status —
    /// terminal jobs are not pruned by this store, so once the cap is hit it
    /// stays hit until an operator clears old rows some other way.
    CapExceeded {
        /// The configured cap that would have been exceeded.
        max: usize,
    },
}

/// One submitted job's row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobSummary {
    /// The job's id.
    pub job_id: String,
    /// Its current lifecycle status.
    pub status: JobStatus,
}

/// A job's status plus the terminal detail a finished run reported back
/// (#292): the guest exit code it classified the status from, and a bounded
/// tail of the job's own console output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobDetail {
    /// Its current lifecycle status.
    pub status: JobStatus,
    /// The guest exit code a terminal run reported, if it produced one. `None`
    /// while non-terminal, or for a terminal state with no exit (infra fault,
    /// timeout, cancel).
    pub exit_code: Option<i32>,
    /// A bounded tail of the job's own stdout/stderr, empty until a run
    /// reports one back.
    pub console: String,
}

/// The `jobs` table behind a single `rusqlite` connection.
pub struct JobStore {
    conn: Mutex<Connection>,
    /// CF-M-2: the row cap `insert_pending` enforces. `None` (the default) is
    /// uncapped — today's unchanged behavior.
    max_rows: Option<usize>,
}

impl JobStore {
    /// Open (creating if needed) the job store at `path`, ensure its schema
    /// exists, and tighten the file to `0600` (CF-M-7) — the same floor the
    /// control socket already gets (`main.rs`'s `bind_unix_listener`), since
    /// this file holds the same job manifests and results that socket
    /// carries.
    ///
    /// # Errors
    /// [`StoreError::Sqlite`] if the file cannot be opened or the schema
    /// cannot be created; [`StoreError::Io`] if the permissions cannot be
    /// set.
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        let conn = Connection::open(path)?;
        let store = Self::from_connection(conn)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        Ok(store)
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
        // Add the terminal-result columns (#292) to a table created before
        // they existed. `CREATE TABLE IF NOT EXISTS` above never alters an
        // existing table, so a `jobs` table from an earlier sandyd would
        // otherwise lack these and every `finish`/`detail` query would fail;
        // add each only if absent (SQLite has no `ADD COLUMN IF NOT EXISTS`).
        ensure_column(&conn, "exit_code", "ALTER TABLE jobs ADD COLUMN exit_code INTEGER")?;
        ensure_column(
            &conn,
            "console",
            "ALTER TABLE jobs ADD COLUMN console TEXT NOT NULL DEFAULT ''",
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
            max_rows: None,
        })
    }

    /// Cap the `jobs` table at `max_rows` total rows (CF-M-2): once reached,
    /// `insert_pending` refuses further inserts instead of growing it
    /// unbounded off operator-controlled Submit traffic. `None` is uncapped.
    #[must_use]
    pub fn with_max_rows(mut self, max_rows: Option<usize>) -> Self {
        self.max_rows = max_rows;
        self
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Insert a fresh `Pending` job row for `job_id`, unless the table is
    /// already at its configured row cap ([`JobStore::with_max_rows`]).
    ///
    /// # Errors
    /// [`StoreError::Sqlite`] if `job_id` already exists, or a read/write
    /// faults.
    pub fn insert_pending(
        &self,
        job_id: &str,
        manifest: &[u8],
        manifest_encoding: &str,
    ) -> Result<InsertOutcome, StoreError> {
        let conn = self.lock();
        // CF-M-2: counted under the same lock the insert itself takes, so a
        // concurrent insert can never slip the table past the cap between
        // the count and the write.
        if let Some(max) = self.max_rows {
            let count: i64 = conn.query_row("SELECT COUNT(*) FROM jobs", (), |row| row.get(0))?;
            if count as usize >= max {
                return Ok(InsertOutcome::CapExceeded { max });
            }
        }
        let now = now_unix();
        conn.execute(
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
        Ok(InsertOutcome::Inserted)
    }

    /// The status of `job_id`, or `None` if no such job exists.
    ///
    /// # Errors
    /// [`StoreError::Sqlite`] if the read fails; [`StoreError::CorruptStatus`]
    /// if the stored status string is not a recognised [`JobStatus`].
    pub fn status(&self, job_id: &str) -> Result<Option<JobStatus>, StoreError> {
        query_status(&self.lock(), job_id)
    }

    /// Mark `job_id` `Cancelled` if it is `Pending` or `Running`.
    ///
    /// # Errors
    /// [`StoreError::Sqlite`] if the read or write fails;
    /// [`StoreError::CorruptStatus`] if the stored status string is not a
    /// recognised [`JobStatus`].
    pub fn cancel(&self, job_id: &str) -> Result<CancelOutcome, StoreError> {
        let conn = self.lock();
        let current = query_status(&conn, job_id)?;

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

    /// Move `job_id` from `Pending` to `Running` — the dispatch actually
    /// reached its host (#292). Refused (not applied) from any other state, so
    /// a late or duplicate mark never pulls a terminal or cancelled job back
    /// to `Running`.
    ///
    /// # Errors
    /// [`StoreError::Sqlite`] if the read or write fails;
    /// [`StoreError::CorruptStatus`] if the stored status string is not a
    /// recognised [`JobStatus`].
    pub fn mark_running(&self, job_id: &str) -> Result<Transition, StoreError> {
        let conn = self.lock();
        let Some(current) = query_status(&conn, job_id)? else {
            return Ok(Transition::NotFound);
        };
        if current != JobStatus::Pending {
            return Ok(Transition::Refused(current));
        }
        conn.execute(
            "UPDATE jobs SET status = ?1, updated_at = ?2 WHERE job_id = ?3",
            (status_name(JobStatus::Running), now_unix(), job_id),
        )?;
        Ok(Transition::Applied)
    }

    /// Record a terminal result for `job_id`: its final `status`, the guest
    /// `exit_code` (if any), and a bounded `console` tail (#292). Applies only
    /// from `Pending` or `Running`; refused from any terminal state, so a
    /// result arriving after a cancel (decision 12: a cancel cannot retract an
    /// already-dispatched job) never overwrites `Cancelled`, and a second
    /// result never overwrites the first.
    ///
    /// # Errors
    /// [`StoreError::Sqlite`] if the read or write fails;
    /// [`StoreError::CorruptStatus`] if the stored status string is not a
    /// recognised [`JobStatus`].
    pub fn finish(
        &self,
        job_id: &str,
        status: JobStatus,
        exit_code: Option<i32>,
        console: &str,
    ) -> Result<Transition, StoreError> {
        let conn = self.lock();
        let Some(current) = query_status(&conn, job_id)? else {
            return Ok(Transition::NotFound);
        };
        if !matches!(current, JobStatus::Pending | JobStatus::Running) {
            return Ok(Transition::Refused(current));
        }
        conn.execute(
            "UPDATE jobs SET status = ?1, exit_code = ?2, console = ?3, updated_at = ?4 WHERE job_id = ?5",
            (status_name(status), exit_code, console, now_unix(), job_id),
        )?;
        Ok(Transition::Applied)
    }

    /// `job_id`'s status plus any terminal detail (exit code, console tail), or
    /// `None` if no such job exists.
    ///
    /// # Errors
    /// [`StoreError::Sqlite`] if the read fails; [`StoreError::CorruptStatus`]
    /// if the stored status string is not a recognised [`JobStatus`].
    pub fn detail(&self, job_id: &str) -> Result<Option<JobDetail>, StoreError> {
        let conn = self.lock();
        match conn.query_row(
            "SELECT status, exit_code, console FROM jobs WHERE job_id = ?1",
            [job_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<i32>>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        ) {
            Ok((raw_status, exit_code, console)) => Ok(Some(JobDetail {
                status: parse_status(job_id, &raw_status)?,
                exit_code,
                console,
            })),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
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
            let status = parse_status(&job_id, &raw_status)?;
            summaries.push(JobSummary { job_id, status });
        }
        Ok(summaries)
    }
}

/// `SELECT status FROM jobs WHERE job_id = ?1`, parsed, or `None` if no such
/// row exists. Shared by [`JobStore::status`] and [`JobStore::cancel`] so the
/// not-found/corrupt-row handling lives in one place.
fn query_status(conn: &Connection, job_id: &str) -> Result<Option<JobStatus>, StoreError> {
    match conn.query_row("SELECT status FROM jobs WHERE job_id = ?1", [job_id], |row| {
        row.get::<_, String>(0)
    }) {
        Ok(raw) => Ok(Some(parse_status(job_id, &raw)?)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e.into()),
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
/// # Errors
/// [`StoreError::CorruptStatus`] if `raw` is not one of
/// [`JobStatus::as_str_name`]'s values.
fn parse_status(job_id: &str, raw: &str) -> Result<JobStatus, StoreError> {
    JobStatus::from_str_name(raw).ok_or_else(|| StoreError::CorruptStatus {
        job_id: job_id.to_owned(),
        raw: raw.to_owned(),
    })
}

/// Run `add_column_sql` only if `column` is not already on the `jobs` table —
/// an idempotent `ADD COLUMN IF NOT EXISTS`, which SQLite itself lacks. Reads
/// `PRAGMA table_info` rather than matching on the "duplicate column" error
/// string, so it stays correct regardless of SQLite's error wording.
fn ensure_column(conn: &Connection, column: &str, add_column_sql: &str) -> Result<(), StoreError> {
    let mut stmt = conn.prepare("SELECT name FROM pragma_table_info('jobs') WHERE name = ?1")?;
    let present = stmt.exists([column])?;
    if !present {
        conn.execute(add_column_sql, ())?;
    }
    Ok(())
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

    /// A dispatched job advances Pending -> Running, then records a terminal
    /// result with its real exit code and console tail (#292) — the whole
    /// PENDING -> RUNNING -> SUCCEEDED path a completed remote run drives.
    #[test]
    fn a_job_advances_pending_running_then_records_its_result() -> Result<(), StoreError> {
        let store = JobStore::open_in_memory()?;
        store.insert_pending("job-1", b"m", "argv/v1")?;

        assert_eq!(store.mark_running("job-1")?, Transition::Applied);
        assert_eq!(store.status("job-1")?, Some(JobStatus::Running));

        assert_eq!(
            store.finish("job-1", JobStatus::Succeeded, Some(0), "hi\n")?,
            Transition::Applied
        );
        assert_eq!(
            store.detail("job-1")?,
            Some(JobDetail {
                status: JobStatus::Succeeded,
                exit_code: Some(0),
                console: "hi\n".to_owned(),
            })
        );
        Ok(())
    }

    /// A non-zero exit is still recorded faithfully — the raw code is kept
    /// even when the orchestrator classifies the band as Failed.
    #[test]
    fn finish_records_a_non_zero_exit_code() -> Result<(), StoreError> {
        let store = JobStore::open_in_memory()?;
        store.insert_pending("job-1", b"m", "argv/v1")?;
        store.mark_running("job-1")?;

        store.finish("job-1", JobStatus::Failed, Some(3), "boom\n")?;
        let detail = store.detail("job-1")?.expect("job-1 exists");
        assert_eq!(detail.status, JobStatus::Failed);
        assert_eq!(detail.exit_code, Some(3));
        Ok(())
    }

    /// Adversarial (decision 12): a result arriving after a cancel must not
    /// overwrite `Cancelled` — the cancel is the terminal truth, the stale
    /// run's late result is refused, not applied.
    #[test]
    fn a_result_after_cancel_is_refused_not_applied() -> Result<(), StoreError> {
        let store = JobStore::open_in_memory()?;
        store.insert_pending("job-1", b"m", "argv/v1")?;
        store.cancel("job-1")?;

        assert_eq!(
            store.finish("job-1", JobStatus::Succeeded, Some(0), "hi\n")?,
            Transition::Refused(JobStatus::Cancelled)
        );
        assert_eq!(store.status("job-1")?, Some(JobStatus::Cancelled));
        Ok(())
    }

    /// Adversarial: a second result never overwrites the first terminal one.
    #[test]
    fn a_second_result_is_refused() -> Result<(), StoreError> {
        let store = JobStore::open_in_memory()?;
        store.insert_pending("job-1", b"m", "argv/v1")?;
        store.mark_running("job-1")?;
        store.finish("job-1", JobStatus::Succeeded, Some(0), "first")?;

        assert_eq!(
            store.finish("job-1", JobStatus::Failed, Some(1), "second")?,
            Transition::Refused(JobStatus::Succeeded)
        );
        let detail = store.detail("job-1")?.expect("job-1 exists");
        assert_eq!(detail.exit_code, Some(0));
        assert_eq!(detail.console, "first");
        Ok(())
    }

    /// `mark_running`/`finish` on an unknown job report `NotFound`, never a
    /// silent success.
    #[test]
    fn transitions_on_an_unknown_job_are_not_found() -> Result<(), StoreError> {
        let store = JobStore::open_in_memory()?;
        assert_eq!(store.mark_running("ghost")?, Transition::NotFound);
        assert_eq!(
            store.finish("ghost", JobStatus::Succeeded, Some(0), "")?,
            Transition::NotFound
        );
        Ok(())
    }

    /// `mark_running` is refused once a job is no longer Pending, so a late or
    /// duplicate dispatch mark can't drag a terminal job back to Running.
    #[test]
    fn mark_running_is_refused_once_terminal() -> Result<(), StoreError> {
        let store = JobStore::open_in_memory()?;
        store.insert_pending("job-1", b"m", "argv/v1")?;
        store.mark_running("job-1")?;
        store.finish("job-1", JobStatus::Succeeded, Some(0), "")?;

        assert_eq!(store.mark_running("job-1")?, Transition::Refused(JobStatus::Succeeded));
        Ok(())
    }

    /// Migration (#292): a `jobs` table created before the result columns
    /// existed gets them added, so `finish`/`detail` work against a store
    /// opened on an older on-disk schema instead of failing on a missing
    /// column.
    #[test]
    fn an_old_schema_without_result_columns_is_migrated() -> Result<(), StoreError> {
        let conn = Connection::open_in_memory()?;
        // The exact pre-#292 schema: no exit_code, no console.
        conn.execute(
            "CREATE TABLE jobs (
                job_id             TEXT PRIMARY KEY,
                status             TEXT NOT NULL,
                manifest           BLOB NOT NULL,
                manifest_encoding  TEXT NOT NULL,
                created_at         INTEGER NOT NULL,
                updated_at         INTEGER NOT NULL
            )",
            (),
        )?;
        conn.execute(
            "INSERT INTO jobs VALUES ('job-1', 'JOB_STATUS_PENDING', X'6d', 'argv/v1', 0, 0)",
            (),
        )?;

        let store = JobStore::from_connection(conn)?;
        store.mark_running("job-1")?;
        assert_eq!(
            store.finish("job-1", JobStatus::Succeeded, Some(0), "hi\n")?,
            Transition::Applied
        );
        assert_eq!(
            store.detail("job-1")?,
            Some(JobDetail {
                status: JobStatus::Succeeded,
                exit_code: Some(0),
                console: "hi\n".to_owned(),
            })
        );
        Ok(())
    }

    /// CF-M-2: an uncapped store (the default) accepts inserts past what
    /// would be a cap elsewhere — proves `max_rows: None` really means
    /// unbounded, not "zero by accident".
    #[test]
    fn an_uncapped_store_accepts_inserts_with_no_limit() -> Result<(), StoreError> {
        let store = JobStore::open_in_memory()?;
        for i in 0..5 {
            assert_eq!(
                store.insert_pending(&format!("job-{i}"), b"m", "test/v1")?,
                InsertOutcome::Inserted
            );
        }
        Ok(())
    }

    /// CF-M-2: the cap boundary is exact — the (cap)th insert succeeds, the
    /// (cap+1)th is refused by name, not a silent drop or a panic.
    #[test]
    fn insert_pending_refuses_once_the_row_cap_is_reached() -> Result<(), StoreError> {
        let store = JobStore::open_in_memory()?.with_max_rows(Some(2));

        assert_eq!(store.insert_pending("job-1", b"m", "test/v1")?, InsertOutcome::Inserted);
        assert_eq!(store.insert_pending("job-2", b"m", "test/v1")?, InsertOutcome::Inserted);
        assert_eq!(
            store.insert_pending("job-3", b"m", "test/v1")?,
            InsertOutcome::CapExceeded { max: 2 }
        );
        // The refused row must not have been written.
        assert_eq!(store.status("job-3")?, None);
        Ok(())
    }

    /// CF-M-7: a freshly created store file is `0600`, not left at whatever
    /// the process umask would otherwise give it — the same floor the
    /// control socket already gets.
    #[test]
    fn a_fresh_store_file_is_chmod_0600() -> anyhow::Result<()> {
        let tmp = tempfile::tempdir()?;
        let db_path = tmp.path().join("sandyd.db");
        let _store = JobStore::open(&db_path)?;

        let mode = std::fs::metadata(&db_path)?.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "got {mode:o}");
        Ok(())
    }

    /// CF-M-7: a store file left loose by an older `sandyd` (or an operator's
    /// `cp`) is tightened to `0600` on open, not merely checked — re-opening
    /// an existing file must not skip the chmod just because the file was
    /// already there.
    #[test]
    fn a_pre_existing_loosely_permissioned_store_file_is_tightened_on_open() -> anyhow::Result<()> {
        let tmp = tempfile::tempdir()?;
        let db_path = tmp.path().join("sandyd.db");
        // Create the file ahead of time at a loose mode, simulating a pre-CF-M-7
        // on-disk file.
        std::fs::File::create(&db_path)?.set_permissions(std::fs::Permissions::from_mode(0o644))?;

        let _store = JobStore::open(&db_path)?;

        let mode = std::fs::metadata(&db_path)?.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "got {mode:o}");
        Ok(())
    }

    /// Adversarial: a row this store never wrote (a corrupt or hand-edited
    /// status string) must fail `status`/`list` with a named error, never
    /// panic the connection task or silently report a plausible-looking
    /// status.
    #[test]
    fn a_corrupt_stored_status_is_a_named_error_not_a_panic() -> Result<(), StoreError> {
        let store = JobStore::open_in_memory()?;
        store.insert_pending("job-1", b"m", "test/v1")?;
        store.lock().execute(
            "UPDATE jobs SET status = 'NOT_A_REAL_STATUS' WHERE job_id = 'job-1'",
            (),
        )?;

        let err = store.status("job-1").expect_err("a corrupt status must be refused");
        assert!(matches!(err, StoreError::CorruptStatus { .. }), "got {err:?}");

        let err = store.list().expect_err("list must also refuse a corrupt row");
        assert!(matches!(err, StoreError::CorruptStatus { .. }), "got {err:?}");
        Ok(())
    }
}
