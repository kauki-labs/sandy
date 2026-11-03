//! The environment state store (#587, slice A): an `environments` table beside
//! `jobs`, holding a durable [`EnvironmentRecord`] per on-demand environment and
//! the state machine that guards its lifecycle.
//!
//! An environment outlives any single boot, so it cannot live in the per-job,
//! run-to-completion journal (`docs/decisions/journal.md`). This store is
//! bookkeeping only: it records the desired state and refuses illegal moves. It
//! launches nothing; a driver (slice A2 onward) turns a transition into a VM
//! action and reports the result back here.
//!
//! Like [`crate::store::JobStore`] it is synchronous: every call blocks on one
//! connection behind a mutex, so an async caller wraps it in `spawn_blocking`.
//!
//! State machine (every other move is [`EnvTransition::Refused`]):
//!
//! ```text
//! Provisioning --mark_ready--> Ready --stop--> Stopped --resume--> Provisioning
//! Provisioning --mark_failed--> Failed
//! any state but Deleted --delete--> Deleted
//! ```
//!
//! `resume` goes back through `Provisioning`, not straight to `Ready`: a resumed
//! environment is Ready only once the driver's health probe has passed (#585 O2).

use std::{
    path::Path,
    sync::{Mutex, PoisonError},
    time::Duration,
};

use rusqlite::{Connection, OptionalExtension, TransactionBehavior};

use crate::store::{StoreError, open_private_connection};

/// An environment store failure.
#[derive(Debug, thiserror::Error)]
pub enum EnvironmentStoreError {
    /// The underlying SQLite connection faulted.
    #[error("environment store: {0}")]
    Sqlite(#[from] rusqlite::Error),
    /// The store file could not be opened or tightened to `0600`.
    #[error("environment store: {0}")]
    File(#[from] StoreError),
    /// A stored `state` value is not one of [`EnvironmentState::as_str`]'s
    /// strings. A row this store wrote never holds anything else, so it is
    /// surfaced as an error on the one read that touches it, not defaulted.
    #[error("environment store: environment {environment_id:?} has an unrecognised stored state {raw:?}")]
    CorruptState {
        /// The environment whose row is corrupt.
        environment_id: String,
        /// The unrecognised stored value.
        raw: String,
    },
}

/// Where an environment is in its lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvironmentState {
    /// Booting, or waiting for its health probe. No connection details yet.
    Provisioning,
    /// The health probe passed; the environment is usable.
    Ready,
    /// Halted but kept: it can be resumed with the same id.
    Stopped,
    /// Provisioning failed. Terminal except for `delete`.
    Failed,
    /// Deleted. Terminal; the row stays so a retried `request_id` finds it.
    Deleted,
}

impl EnvironmentState {
    /// The stable string stored in the `state` column.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Provisioning => "provisioning",
            Self::Ready => "ready",
            Self::Stopped => "stopped",
            Self::Failed => "failed",
            Self::Deleted => "deleted",
        }
    }

    fn parse(raw: &str) -> Option<Self> {
        [
            Self::Provisioning,
            Self::Ready,
            Self::Stopped,
            Self::Failed,
            Self::Deleted,
        ]
        .into_iter()
        .find(|s| s.as_str() == raw)
    }
}

/// Why and where provisioning failed (#585 O4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvironmentFailure {
    /// The provisioning step that failed.
    pub step: String,
    /// Why it failed.
    pub reason: String,
}

/// One environment's row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvironmentRecord {
    /// The environment's id.
    pub environment_id: String,
    /// The caller's idempotency key.
    pub request_id: String,
    /// Its current lifecycle state.
    pub state: EnvironmentState,
    /// The create request's payload, opaque to this store: a retry is the same
    /// request only if these bytes are equal.
    pub spec: Vec<u8>,
    /// Names the encoding of `spec`.
    pub spec_encoding: String,
    /// Set once provisioning failed; it stays on the row if the environment
    /// is then deleted.
    pub failure: Option<EnvironmentFailure>,
    /// Unix seconds at creation.
    pub created_at: i64,
    /// Unix seconds at the last state change.
    pub updated_at: i64,
}

/// The outcome of [`EnvironmentStore::create`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CreateOutcome {
    /// A new environment row was inserted in `Provisioning`.
    Created(EnvironmentRecord),
    /// The `request_id` was seen before with the same payload: the existing
    /// environment, in whatever state it is now (a deleted one stays deleted,
    /// never replaced by a new one).
    Existing(EnvironmentRecord),
    /// The `request_id` was seen before with a different payload. Nothing was
    /// written.
    Conflict,
    /// `new_id` already names another request's environment, so nothing was
    /// written. The caller mints ids, so this is a minting fault, not a retry.
    IdTaken,
    /// The table already holds `max` rows (see
    /// [`EnvironmentStore::with_max_rows`]); the insert was refused.
    CapExceeded {
        /// The configured cap that would have been exceeded.
        max: usize,
    },
}

/// What a lifecycle transition did to an environment row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvTransition {
    /// The row moved to the requested state.
    Applied,
    /// The row was already in the requested terminal state (`delete` of a
    /// deleted environment): nothing changed, and that is not an error.
    Unchanged,
    /// No environment has this id.
    NotFound,
    /// The row was not in a state this transition applies from, so it was
    /// refused, not applied. Carries the state the row actually held.
    Refused(EnvironmentState),
}

/// The `environments` table behind a single `rusqlite` connection.
pub struct EnvironmentStore {
    conn: Mutex<Connection>,
    /// The row cap `create` enforces; `None` is uncapped.
    max_rows: Option<usize>,
}

/// A raw `environments` row, read before its `state` string is validated.
struct RawRow {
    environment_id: String,
    request_id: String,
    state: String,
    spec: Vec<u8>,
    spec_encoding: String,
    failure_step: Option<String>,
    failure_reason: Option<String>,
    created_at: i64,
    updated_at: i64,
}

const COLUMNS: &str =
    "environment_id, request_id, state, spec, spec_encoding, failure_step, failure_reason, created_at, updated_at";

impl RawRow {
    fn read(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            environment_id: row.get(0)?,
            request_id: row.get(1)?,
            state: row.get(2)?,
            spec: row.get(3)?,
            spec_encoding: row.get(4)?,
            failure_step: row.get(5)?,
            failure_reason: row.get(6)?,
            created_at: row.get(7)?,
            updated_at: row.get(8)?,
        })
    }

    fn into_record(self) -> Result<EnvironmentRecord, EnvironmentStoreError> {
        let state = EnvironmentState::parse(&self.state).ok_or_else(|| EnvironmentStoreError::CorruptState {
            environment_id: self.environment_id.clone(),
            raw: self.state.clone(),
        })?;
        let failure = match (self.failure_step, self.failure_reason) {
            (Some(step), Some(reason)) => Some(EnvironmentFailure { step, reason }),
            _ => None,
        };
        Ok(EnvironmentRecord {
            environment_id: self.environment_id,
            request_id: self.request_id,
            state,
            spec: self.spec,
            spec_encoding: self.spec_encoding,
            failure,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0) as i64
}

/// The states `delete` applies from: every one but `Deleted`.
const LIVE: [EnvironmentState; 4] = [
    EnvironmentState::Provisioning,
    EnvironmentState::Ready,
    EnvironmentState::Stopped,
    EnvironmentState::Failed,
];

impl EnvironmentStore {
    /// Open (creating if needed) the store at `path` with the same `0600`
    /// floor as the job store, then ensure its schema exists.
    ///
    /// # Errors
    /// [`EnvironmentStoreError::File`] if the file cannot be created or
    /// tightened; [`EnvironmentStoreError::Sqlite`] if the schema cannot be
    /// created.
    pub fn open(path: &Path) -> Result<Self, EnvironmentStoreError> {
        Self::from_connection(open_private_connection(path)?)
    }

    /// An in-memory store, for tests.
    ///
    /// # Errors
    /// [`EnvironmentStoreError::Sqlite`] if the schema cannot be created.
    pub fn open_in_memory() -> Result<Self, EnvironmentStoreError> {
        Self::from_connection(Connection::open_in_memory()?)
    }

    fn from_connection(conn: Connection) -> Result<Self, EnvironmentStoreError> {
        // Wait briefly instead of failing at once if another process holds the file.
        conn.busy_timeout(Duration::from_secs(5))?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS environments (
                environment_id  TEXT PRIMARY KEY,
                request_id      TEXT NOT NULL UNIQUE,
                state           TEXT NOT NULL,
                spec            BLOB NOT NULL,
                spec_encoding   TEXT NOT NULL,
                failure_step    TEXT,
                failure_reason  TEXT,
                created_at      INTEGER NOT NULL,
                updated_at      INTEGER NOT NULL
            )",
            (),
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
            max_rows: None,
        })
    }

    /// Cap the table at `max_rows` rows in total (every state counts, since
    /// deleted rows are kept for replay): once reached, `create` refuses a new
    /// environment. A retry of a stored `request_id` needs no new row and is
    /// never refused.
    #[must_use]
    pub fn with_max_rows(mut self, max_rows: Option<usize>) -> Self {
        self.max_rows = max_rows;
        self
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Create an environment for `request_id`, or return the one this
    /// `request_id` already made. `new_id` is used only when a row is
    /// inserted; the caller mints it, so the store stays deterministic.
    ///
    /// # Errors
    /// [`EnvironmentStoreError::Sqlite`] if a read or write faults, or
    /// [`EnvironmentStoreError::CorruptState`] for a row it cannot read.
    pub fn create(
        &self,
        request_id: &str,
        new_id: &str,
        spec: &[u8],
        spec_encoding: &str,
    ) -> Result<CreateOutcome, EnvironmentStoreError> {
        let mut conn = self.lock();
        // IMMEDIATE takes the write lock up front, so the lookup, the cap check
        // and the insert are one step even across processes sharing the file.
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let found = tx
            .query_row(
                &format!("SELECT {COLUMNS} FROM environments WHERE request_id = ?1"),
                [request_id],
                RawRow::read,
            )
            .optional()?;
        if let Some(raw) = found {
            let existing = raw.into_record()?;
            return Ok(if existing.spec == spec && existing.spec_encoding == spec_encoding {
                CreateOutcome::Existing(existing)
            } else {
                CreateOutcome::Conflict
            });
        }
        if let Some(max) = self.max_rows {
            let count: i64 = tx.query_row("SELECT COUNT(*) FROM environments", (), |row| row.get(0))?;
            if count as usize >= max {
                return Ok(CreateOutcome::CapExceeded { max });
            }
        }
        let id_taken: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM environments WHERE environment_id = ?1)",
            [new_id],
            |row| row.get(0),
        )?;
        if id_taken {
            return Ok(CreateOutcome::IdTaken);
        }
        let now = now_unix();
        tx.execute(
            "INSERT INTO environments
                 (environment_id, request_id, state, spec, spec_encoding, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)",
            (
                new_id,
                request_id,
                EnvironmentState::Provisioning.as_str(),
                spec,
                spec_encoding,
                now,
            ),
        )?;
        let raw = tx.query_row(
            &format!("SELECT {COLUMNS} FROM environments WHERE environment_id = ?1"),
            [new_id],
            RawRow::read,
        )?;
        tx.commit()?;
        Ok(CreateOutcome::Created(raw.into_record()?))
    }

    /// The environment `request_id` created, if any. Writes nothing.
    ///
    /// # Errors
    /// As [`EnvironmentStore::create`].
    pub fn get_by_request_id(&self, request_id: &str) -> Result<Option<EnvironmentRecord>, EnvironmentStoreError> {
        let conn = self.lock();
        conn.query_row(
            &format!("SELECT {COLUMNS} FROM environments WHERE request_id = ?1"),
            [request_id],
            RawRow::read,
        )
        .optional()?
        .map(RawRow::into_record)
        .transpose()
    }

    /// The environment with this id, if any.
    ///
    /// # Errors
    /// As [`EnvironmentStore::create`].
    pub fn get(&self, environment_id: &str) -> Result<Option<EnvironmentRecord>, EnvironmentStoreError> {
        let conn = self.lock();
        conn.query_row(
            &format!("SELECT {COLUMNS} FROM environments WHERE environment_id = ?1"),
            [environment_id],
            RawRow::read,
        )
        .optional()?
        .map(RawRow::into_record)
        .transpose()
    }

    /// Every environment, oldest first.
    ///
    /// # Errors
    /// As [`EnvironmentStore::create`].
    pub fn list(&self) -> Result<Vec<EnvironmentRecord>, EnvironmentStoreError> {
        self.query_many("", ())
    }

    /// Every environment in `state`, oldest first.
    ///
    /// # Errors
    /// As [`EnvironmentStore::create`].
    pub fn list_by_state(&self, state: EnvironmentState) -> Result<Vec<EnvironmentRecord>, EnvironmentStoreError> {
        self.query_many("WHERE state = ?1", [state.as_str()])
    }

    fn query_many(
        &self,
        filter: &str,
        params: impl rusqlite::Params,
    ) -> Result<Vec<EnvironmentRecord>, EnvironmentStoreError> {
        let conn = self.lock();
        let mut stmt = conn.prepare(&format!(
            "SELECT {COLUMNS} FROM environments {filter} ORDER BY created_at, rowid"
        ))?;
        let rows = stmt
            .query_map(params, RawRow::read)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows.into_iter().map(RawRow::into_record).collect()
    }

    /// `Provisioning` to `Ready`: the health probe passed.
    ///
    /// # Errors
    /// As [`EnvironmentStore::create`].
    pub fn mark_ready(&self, environment_id: &str) -> Result<EnvTransition, EnvironmentStoreError> {
        self.transition(
            environment_id,
            &[EnvironmentState::Provisioning],
            EnvironmentState::Ready,
            None,
        )
    }

    /// `Provisioning` to `Failed`, recording the failing `step` and `reason`.
    ///
    /// # Errors
    /// As [`EnvironmentStore::create`].
    pub fn mark_failed(
        &self,
        environment_id: &str,
        step: &str,
        reason: &str,
    ) -> Result<EnvTransition, EnvironmentStoreError> {
        self.transition(
            environment_id,
            &[EnvironmentState::Provisioning],
            EnvironmentState::Failed,
            Some((step, reason)),
        )
    }

    /// `Ready` to `Stopped`.
    ///
    /// # Errors
    /// As [`EnvironmentStore::create`].
    pub fn stop(&self, environment_id: &str) -> Result<EnvTransition, EnvironmentStoreError> {
        self.transition(
            environment_id,
            &[EnvironmentState::Ready],
            EnvironmentState::Stopped,
            None,
        )
    }

    /// `Stopped` to `Provisioning`: the environment boots again under the same id.
    ///
    /// # Errors
    /// As [`EnvironmentStore::create`].
    pub fn resume(&self, environment_id: &str) -> Result<EnvTransition, EnvironmentStoreError> {
        self.transition(
            environment_id,
            &[EnvironmentState::Stopped],
            EnvironmentState::Provisioning,
            None,
        )
    }

    /// Any state but `Deleted` to `Deleted`. Deleting a deleted environment is
    /// [`EnvTransition::Unchanged`].
    ///
    /// # Errors
    /// As [`EnvironmentStore::create`].
    pub fn delete(&self, environment_id: &str) -> Result<EnvTransition, EnvironmentStoreError> {
        self.transition(environment_id, &LIVE, EnvironmentState::Deleted, None)
    }

    /// `Provisioning` to `Deleted`: cancel a launch that has not finished.
    /// Cancelling a deleted environment is [`EnvTransition::Unchanged`].
    ///
    /// # Errors
    /// As [`EnvironmentStore::create`].
    pub fn cancel(&self, environment_id: &str) -> Result<EnvTransition, EnvironmentStoreError> {
        self.transition(
            environment_id,
            &[EnvironmentState::Provisioning],
            EnvironmentState::Deleted,
            None,
        )
    }

    /// Move `environment_id` to `to` if it is in one of the `from` states.
    /// Read and write share one IMMEDIATE transaction, so two racing
    /// transitions cannot both pass the same guard.
    fn transition(
        &self,
        environment_id: &str,
        from: &[EnvironmentState],
        to: EnvironmentState,
        failure: Option<(&str, &str)>,
    ) -> Result<EnvTransition, EnvironmentStoreError> {
        let mut conn = self.lock();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let raw: Option<String> = tx
            .query_row(
                "SELECT state FROM environments WHERE environment_id = ?1",
                [environment_id],
                |row| row.get(0),
            )
            .optional()?;
        let Some(raw) = raw else {
            return Ok(EnvTransition::NotFound);
        };
        let current = EnvironmentState::parse(&raw).ok_or_else(|| EnvironmentStoreError::CorruptState {
            environment_id: environment_id.to_owned(),
            raw,
        })?;
        if current == to && to == EnvironmentState::Deleted {
            return Ok(EnvTransition::Unchanged);
        }
        if !from.contains(&current) {
            return Ok(EnvTransition::Refused(current));
        }
        let (step, reason) = failure.unzip();
        tx.execute(
            "UPDATE environments
                SET state = ?2, failure_step = COALESCE(?3, failure_step),
                    failure_reason = COALESCE(?4, failure_reason), updated_at = ?5
              WHERE environment_id = ?1",
            (environment_id, to.as_str(), step, reason, now_unix()),
        )?;
        tx.commit()?;
        Ok(EnvTransition::Applied)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use anyhow::{Context, Result, bail};

    use super::*;

    const SPEC: &[u8] = b"profile=harness;size=small";
    const ENC: &str = "sandy.environment.v1";

    fn store() -> Result<EnvironmentStore> {
        Ok(EnvironmentStore::open_in_memory()?)
    }

    /// Creates `env-1` for request `r1` and returns it.
    fn created(store: &EnvironmentStore) -> Result<EnvironmentRecord> {
        match store.create("r1", "env-1", SPEC, ENC)? {
            CreateOutcome::Created(rec) => Ok(rec),
            other => bail!("expected Created, got {other:?}"),
        }
    }

    fn state_of(store: &EnvironmentStore, id: &str) -> Result<EnvironmentState> {
        Ok(store.get(id)?.with_context(|| format!("{id} missing"))?.state)
    }

    #[test]
    fn a_new_environment_starts_provisioning_with_no_failure() -> Result<()> {
        let s = store()?;
        let rec = created(&s)?;
        assert_eq!(rec.environment_id, "env-1");
        assert_eq!(rec.request_id, "r1");
        assert_eq!(rec.state, EnvironmentState::Provisioning);
        assert_eq!(rec.failure, None);
        assert_eq!((rec.spec.as_slice(), rec.spec_encoding.as_str()), (SPEC, ENC));
        assert_eq!(s.get("env-1")?, Some(rec));
        Ok(())
    }

    #[test]
    fn two_creates_with_one_request_id_return_one_environment() -> Result<()> {
        let s = store()?;
        let first = created(&s)?;
        // The second call offers a different new id: it must be ignored.
        let CreateOutcome::Existing(second) = s.create("r1", "env-2", SPEC, ENC)? else {
            bail!("a retry must return the existing environment");
        };
        assert_eq!(second, first);
        assert_eq!(s.list()?.len(), 1, "a retry must not add a row");
        Ok(())
    }

    #[test]
    fn the_same_request_id_with_another_payload_is_a_conflict_and_writes_nothing() -> Result<()> {
        let s = store()?;
        let first = created(&s)?;
        assert_eq!(
            s.create("r1", "env-2", b"profile=other;size=small", ENC)?,
            CreateOutcome::Conflict
        );
        assert_eq!(
            s.create("r1", "env-3", SPEC, "another.encoding")?,
            CreateOutcome::Conflict,
            "the encoding is part of the payload"
        );
        assert_eq!(s.list()?, vec![first], "a conflict must change nothing");
        Ok(())
    }

    #[test]
    fn a_retry_after_delete_returns_the_deleted_environment_never_a_new_one() -> Result<()> {
        let s = store()?;
        created(&s)?;
        assert_eq!(s.delete("env-1")?, EnvTransition::Applied);
        let CreateOutcome::Existing(rec) = s.create("r1", "env-2", SPEC, ENC)? else {
            bail!("a retry after delete must find the old environment");
        };
        assert_eq!(
            (rec.environment_id.as_str(), rec.state),
            ("env-1", EnvironmentState::Deleted)
        );
        assert_eq!(s.get("env-2")?, None, "no second environment may exist");
        Ok(())
    }

    #[test]
    fn stop_then_resume_keeps_the_id_and_goes_back_through_provisioning() -> Result<()> {
        let s = store()?;
        created(&s)?;
        assert_eq!(s.mark_ready("env-1")?, EnvTransition::Applied);
        assert_eq!(s.stop("env-1")?, EnvTransition::Applied);
        assert_eq!(state_of(&s, "env-1")?, EnvironmentState::Stopped);
        assert_eq!(s.resume("env-1")?, EnvTransition::Applied);
        assert_eq!(
            state_of(&s, "env-1")?,
            EnvironmentState::Provisioning,
            "Ready only after the probe passes again"
        );
        assert_eq!(s.mark_ready("env-1")?, EnvTransition::Applied);
        assert_eq!(s.list()?.len(), 1);
        Ok(())
    }

    #[test]
    fn a_failed_provisioning_records_the_step_and_reason() -> Result<()> {
        let s = store()?;
        created(&s)?;
        assert_eq!(
            s.mark_failed("env-1", "boot", "probe timed out")?,
            EnvTransition::Applied
        );
        let rec = s.get("env-1")?.context("env-1")?;
        assert_eq!(rec.state, EnvironmentState::Failed);
        assert_eq!(
            rec.failure,
            Some(EnvironmentFailure {
                step: "boot".into(),
                reason: "probe timed out".into(),
            })
        );
        Ok(())
    }

    #[test]
    fn illegal_moves_are_refused_with_the_state_the_row_holds() -> Result<()> {
        use EnvironmentState::{Deleted, Failed, Provisioning, Ready, Stopped};
        let s = store()?;
        created(&s)?;
        // Provisioning: only ready, failed and delete apply.
        assert_eq!(s.stop("env-1")?, EnvTransition::Refused(Provisioning));
        assert_eq!(s.resume("env-1")?, EnvTransition::Refused(Provisioning));
        s.mark_ready("env-1")?;
        // Ready: no second ready, no failed, no resume.
        assert_eq!(s.mark_ready("env-1")?, EnvTransition::Refused(Ready));
        assert_eq!(s.mark_failed("env-1", "x", "y")?, EnvTransition::Refused(Ready));
        assert_eq!(s.resume("env-1")?, EnvTransition::Refused(Ready));
        s.stop("env-1")?;
        // Stopped: no stop, no ready, no failed.
        assert_eq!(s.stop("env-1")?, EnvTransition::Refused(Stopped));
        assert_eq!(s.mark_ready("env-1")?, EnvTransition::Refused(Stopped));
        assert_eq!(s.mark_failed("env-1", "x", "y")?, EnvTransition::Refused(Stopped));

        // A failed environment cannot be stopped, resumed or made ready.
        s.create("r2", "env-2", SPEC, ENC)?;
        s.mark_failed("env-2", "boot", "no")?;
        assert_eq!(s.stop("env-2")?, EnvTransition::Refused(Failed));
        assert_eq!(s.resume("env-2")?, EnvTransition::Refused(Failed));
        assert_eq!(s.mark_ready("env-2")?, EnvTransition::Refused(Failed));

        // A late result never resurrects a deleted environment.
        s.delete("env-1")?;
        assert_eq!(s.mark_ready("env-1")?, EnvTransition::Refused(Deleted));
        assert_eq!(s.resume("env-1")?, EnvTransition::Refused(Deleted));
        assert_eq!(s.stop("env-1")?, EnvTransition::Refused(Deleted));
        assert_eq!(s.mark_failed("env-1", "x", "y")?, EnvTransition::Refused(Deleted));
        assert_eq!(state_of(&s, "env-1")?, Deleted, "refused moves must not change the row");
        Ok(())
    }

    #[test]
    fn delete_applies_from_every_live_state_without_a_prior_stop() -> Result<()> {
        use EnvironmentState::{Failed, Provisioning, Ready, Stopped};
        let s = store()?;
        for (i, (want, setup)) in [
            (Provisioning, &[][..]),
            (Ready, &["ready"][..]),
            (Stopped, &["ready", "stop"][..]),
            (Failed, &["fail"][..]),
        ]
        .into_iter()
        .enumerate()
        {
            let id = format!("env-{i}");
            s.create(&format!("r{i}"), &id, SPEC, ENC)?;
            for step in setup {
                let moved = match *step {
                    "ready" => s.mark_ready(&id)?,
                    "stop" => s.stop(&id)?,
                    _ => s.mark_failed(&id, "boot", "no")?,
                };
                assert_eq!(moved, EnvTransition::Applied, "setup step {step} for {id}");
            }
            assert_eq!(state_of(&s, &id)?, want, "the setup must reach the state under test");
            assert_eq!(s.delete(&id)?, EnvTransition::Applied, "from {want:?}");
            assert_eq!(state_of(&s, &id)?, EnvironmentState::Deleted);
        }
        Ok(())
    }

    #[test]
    fn a_request_id_finds_its_environment_without_creating_one() -> Result<()> {
        let s = store()?;
        assert_eq!(s.get_by_request_id("r1")?, None);
        let rec = created(&s)?;
        assert_eq!(s.get_by_request_id("r1")?, Some(rec));
        assert_eq!(s.get_by_request_id("r2")?, None);
        assert_eq!(s.list()?.len(), 1, "a lookup must write nothing");
        Ok(())
    }

    #[test]
    fn cancel_applies_only_while_provisioning_and_is_idempotent_once_deleted() -> Result<()> {
        let s = store()?;
        created(&s)?;
        assert_eq!(s.cancel("env-1")?, EnvTransition::Applied);
        assert_eq!(state_of(&s, "env-1")?, EnvironmentState::Deleted);
        assert_eq!(s.cancel("env-1")?, EnvTransition::Unchanged);
        s.create("r2", "env-2", SPEC, ENC)?;
        s.mark_ready("env-2")?;
        assert_eq!(s.cancel("env-2")?, EnvTransition::Refused(EnvironmentState::Ready));
        assert_eq!(
            state_of(&s, "env-2")?,
            EnvironmentState::Ready,
            "a refused cancel changes nothing"
        );
        assert_eq!(s.cancel("nope")?, EnvTransition::NotFound);
        Ok(())
    }

    #[test]
    fn delete_is_idempotent_and_an_unknown_id_is_not_found() -> Result<()> {
        let s = store()?;
        created(&s)?;
        assert_eq!(s.delete("env-1")?, EnvTransition::Applied);
        assert_eq!(s.delete("env-1")?, EnvTransition::Unchanged);
        assert_eq!(s.delete("env-1")?, EnvTransition::Unchanged);
        for result in [
            s.delete("nope")?,
            s.mark_ready("nope")?,
            s.mark_failed("nope", "x", "y")?,
            s.stop("nope")?,
            s.resume("nope")?,
        ] {
            assert_eq!(result, EnvTransition::NotFound);
        }
        assert_eq!(s.get("nope")?, None);
        Ok(())
    }

    #[test]
    fn list_is_oldest_first_and_filters_by_state() -> Result<()> {
        let s = store()?;
        for n in 1..=3 {
            s.create(&format!("r{n}"), &format!("env-{n}"), SPEC, ENC)?;
        }
        s.mark_ready("env-2")?;
        let ids = |recs: Vec<EnvironmentRecord>| recs.into_iter().map(|r| r.environment_id).collect::<Vec<_>>();
        assert_eq!(ids(s.list()?), ["env-1", "env-2", "env-3"]);
        assert_eq!(ids(s.list_by_state(EnvironmentState::Ready)?), ["env-2"]);
        assert_eq!(
            ids(s.list_by_state(EnvironmentState::Provisioning)?),
            ["env-1", "env-3"]
        );
        assert!(s.list_by_state(EnvironmentState::Stopped)?.is_empty());
        Ok(())
    }

    #[test]
    fn the_row_cap_refuses_a_new_environment_but_not_a_retry() -> Result<()> {
        let s = store()?.with_max_rows(Some(1));
        created(&s)?;
        assert_eq!(
            s.create("r2", "env-2", SPEC, ENC)?,
            CreateOutcome::CapExceeded { max: 1 }
        );
        assert!(
            matches!(s.create("r1", "env-9", SPEC, ENC)?, CreateOutcome::Existing(_)),
            "a retry of a stored request needs no new row, so the cap must not refuse it"
        );
        let uncapped = store()?;
        created(&uncapped)?;
        assert!(matches!(
            uncapped.create("r2", "env-2", SPEC, ENC)?,
            CreateOutcome::Created(_)
        ));
        Ok(())
    }

    #[test]
    fn state_survives_closing_and_reopening_the_store_file() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("env.db");
        {
            let s = EnvironmentStore::open(&path)?;
            created(&s)?;
            s.mark_ready("env-1")?;
            s.stop("env-1")?;
        }
        let reopened = EnvironmentStore::open(&path)?;
        assert_eq!(state_of(&reopened, "env-1")?, EnvironmentState::Stopped);
        assert!(matches!(
            reopened.create("r1", "env-2", SPEC, ENC)?,
            CreateOutcome::Existing(_)
        ));
        Ok(())
    }

    #[test]
    fn a_fresh_store_file_is_0600() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("env.db");
        drop(EnvironmentStore::open(&path)?);
        assert_eq!(std::fs::metadata(&path)?.permissions().mode() & 0o777, 0o600);
        Ok(())
    }

    /// Opens `n` stores on one file, as separate processes sharing it would:
    /// each has its own connection, so only the database lock orders them.
    fn stores_on_one_file(n: usize) -> Result<(tempfile::TempDir, Vec<Arc<EnvironmentStore>>)> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("env.db");
        let stores = (0..n)
            .map(|_| Ok(Arc::new(EnvironmentStore::open(&path)?)))
            .collect::<Result<Vec<_>>>()?;
        Ok((dir, stores))
    }

    #[test]
    fn creates_racing_across_connections_make_exactly_one_environment() -> Result<()> {
        let (_dir, stores) = stores_on_one_file(4)?;
        let handles: Vec<_> = (0..16)
            .map(|n| {
                let s = Arc::clone(&stores[n % stores.len()]);
                std::thread::spawn(move || s.create("r1", &format!("env-{n}"), SPEC, ENC))
            })
            .collect();
        let mut outcomes = Vec::new();
        for h in handles {
            outcomes.push(h.join().map_err(|_| anyhow::anyhow!("thread panicked"))??);
        }
        let created = outcomes
            .iter()
            .filter(|r| matches!(r, CreateOutcome::Created(_)))
            .count();
        let existing = outcomes
            .iter()
            .filter(|r| matches!(r, CreateOutcome::Existing(_)))
            .count();
        assert_eq!((created, existing), (1, 15));
        assert_eq!(stores[0].list()?.len(), 1);
        Ok(())
    }

    #[test]
    fn two_deletes_racing_across_connections_apply_once_and_report_unchanged_for_the_rest() -> Result<()> {
        let (_dir, stores) = stores_on_one_file(4)?;
        stores[0].create("r1", "env-1", SPEC, ENC)?;
        let handles: Vec<_> = (0..8)
            .map(|n| {
                let s = Arc::clone(&stores[n % stores.len()]);
                std::thread::spawn(move || s.delete("env-1"))
            })
            .collect();
        let mut results = Vec::new();
        for h in handles {
            results.push(h.join().map_err(|_| anyhow::anyhow!("thread panicked"))??);
        }
        let applied = results.iter().filter(|r| **r == EnvTransition::Applied).count();
        let unchanged = results.iter().filter(|r| **r == EnvTransition::Unchanged).count();
        assert_eq!((applied, unchanged), (1, 7));
        Ok(())
    }

    #[test]
    fn an_id_already_taken_by_another_request_is_a_typed_outcome_and_writes_nothing() -> Result<()> {
        let s = store()?;
        let first = created(&s)?;
        assert_eq!(s.create("r2", "env-1", SPEC, ENC)?, CreateOutcome::IdTaken);
        assert_eq!(s.list()?, vec![first], "the first environment must be untouched");
        assert_eq!(s.get("env-1")?.map(|r| r.request_id), Some("r1".to_owned()));
        Ok(())
    }

    #[test]
    fn a_corrupt_row_fails_list_and_reads_of_that_row_but_not_reads_of_others() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("env.db");
        {
            let s = EnvironmentStore::open(&path)?;
            created(&s)?;
            s.create("r2", "env-2", SPEC, ENC)?;
        }
        Connection::open(&path)?.execute(
            "UPDATE environments SET state = 'bogus' WHERE environment_id = 'env-1'",
            (),
        )?;
        let s = EnvironmentStore::open(&path)?;
        assert!(matches!(
            s.get("env-1"),
            Err(EnvironmentStoreError::CorruptState { .. })
        ));
        assert!(matches!(
            s.delete("env-1"),
            Err(EnvironmentStoreError::CorruptState { .. })
        ));
        assert!(matches!(s.list(), Err(EnvironmentStoreError::CorruptState { .. })));
        assert_eq!(state_of(&s, "env-2")?, EnvironmentState::Provisioning);
        Ok(())
    }
}
