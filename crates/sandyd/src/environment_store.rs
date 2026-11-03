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

use rusqlite::Connection;

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
    /// Set when `state` is [`EnvironmentState::Failed`].
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

impl EnvironmentStore {
    /// Open (creating if needed) the store at `path` with the same `0600`
    /// floor as the job store, then ensure its schema exists.
    ///
    /// # Errors
    /// [`EnvironmentStoreError::File`] if the file cannot be created or
    /// tightened; [`EnvironmentStoreError::Sqlite`] if the schema cannot be
    /// created.
    pub fn open(path: &Path) -> Result<Self, EnvironmentStoreError> {
        let _ = (path, open_private_connection);
        unimplemented!("#587 slice A: red")
    }

    /// An in-memory store, for tests.
    ///
    /// # Errors
    /// [`EnvironmentStoreError::Sqlite`] if the schema cannot be created.
    pub fn open_in_memory() -> Result<Self, EnvironmentStoreError> {
        let _ = (Duration::ZERO, &PoisonError::<()>::into_inner);
        unimplemented!("#587 slice A: red")
    }

    /// Cap the table at `max_rows` rows in total (every state counts, since
    /// deleted rows are kept for replay): once reached, `create` refuses.
    #[must_use]
    pub fn with_max_rows(mut self, max_rows: Option<usize>) -> Self {
        self.max_rows = max_rows;
        self
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
        let _ = (request_id, new_id, spec, spec_encoding, &self.conn, self.max_rows);
        unimplemented!("#587 slice A: red")
    }

    /// The environment with this id, if any.
    ///
    /// # Errors
    /// As [`EnvironmentStore::create`].
    pub fn get(&self, environment_id: &str) -> Result<Option<EnvironmentRecord>, EnvironmentStoreError> {
        let _ = environment_id;
        unimplemented!("#587 slice A: red")
    }

    /// Every environment, oldest first.
    ///
    /// # Errors
    /// As [`EnvironmentStore::create`].
    pub fn list(&self) -> Result<Vec<EnvironmentRecord>, EnvironmentStoreError> {
        unimplemented!("#587 slice A: red")
    }

    /// Every environment in `state`, oldest first.
    ///
    /// # Errors
    /// As [`EnvironmentStore::create`].
    pub fn list_by_state(&self, state: EnvironmentState) -> Result<Vec<EnvironmentRecord>, EnvironmentStoreError> {
        let _ = state;
        unimplemented!("#587 slice A: red")
    }

    /// `Provisioning` to `Ready`: the health probe passed.
    ///
    /// # Errors
    /// As [`EnvironmentStore::create`].
    pub fn mark_ready(&self, environment_id: &str) -> Result<EnvTransition, EnvironmentStoreError> {
        let _ = environment_id;
        unimplemented!("#587 slice A: red")
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
        let _ = (environment_id, step, reason);
        unimplemented!("#587 slice A: red")
    }

    /// `Ready` to `Stopped`.
    ///
    /// # Errors
    /// As [`EnvironmentStore::create`].
    pub fn stop(&self, environment_id: &str) -> Result<EnvTransition, EnvironmentStoreError> {
        let _ = environment_id;
        unimplemented!("#587 slice A: red")
    }

    /// `Stopped` to `Provisioning`: the environment boots again under the same id.
    ///
    /// # Errors
    /// As [`EnvironmentStore::create`].
    pub fn resume(&self, environment_id: &str) -> Result<EnvTransition, EnvironmentStoreError> {
        let _ = environment_id;
        unimplemented!("#587 slice A: red")
    }

    /// Any state but `Deleted` to `Deleted`. Deleting a deleted environment is
    /// [`EnvTransition::Unchanged`].
    ///
    /// # Errors
    /// As [`EnvironmentStore::create`].
    pub fn delete(&self, environment_id: &str) -> Result<EnvTransition, EnvironmentStoreError> {
        let _ = environment_id;
        unimplemented!("#587 slice A: red")
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
        let s = store()?;
        for (i, prepare) in [
            |_: &EnvironmentStore, _: &str| Ok(()) as Result<()>,
            |s: &EnvironmentStore, id: &str| {
                s.mark_ready(id)?;
                Ok(())
            },
            |s: &EnvironmentStore, id: &str| {
                s.mark_ready(id)?;
                s.stop(id)?;
                Ok(())
            },
            |s: &EnvironmentStore, id: &str| {
                s.mark_failed(id, "boot", "no")?;
                Ok(())
            },
        ]
        .into_iter()
        .enumerate()
        {
            let id = format!("env-{i}");
            s.create(&format!("r{i}"), &id, SPEC, ENC)?;
            prepare(&s, &id)?;
            assert_eq!(
                s.delete(&id)?,
                EnvTransition::Applied,
                "from {}",
                state_of(&s, &id)?.as_str()
            );
            assert_eq!(state_of(&s, &id)?, EnvironmentState::Deleted);
        }
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

    #[test]
    fn a_corrupt_stored_state_fails_that_read_and_no_other() -> Result<()> {
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
            Err(EnvironmentStoreError::CorruptState { ref raw, .. }) if raw == "bogus"
        ));
        assert_eq!(state_of(&s, "env-2")?, EnvironmentState::Provisioning);
        Ok(())
    }

    #[test]
    fn concurrent_creates_with_one_request_id_make_exactly_one_environment() -> Result<()> {
        let s = Arc::new(store()?);
        let results: Vec<_> = (0..16)
            .map(|n| {
                let s = Arc::clone(&s);
                std::thread::spawn(move || s.create("r1", &format!("env-{n}"), SPEC, ENC))
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|h| {
                h.join()
                    .map_err(|_| anyhow::anyhow!("thread panicked"))?
                    .map_err(Into::into)
            })
            .collect::<Result<Vec<_>>>()?;
        let created = results
            .iter()
            .filter(|r| matches!(r, CreateOutcome::Created(_)))
            .count();
        let existing = results
            .iter()
            .filter(|r| matches!(r, CreateOutcome::Existing(_)))
            .count();
        assert_eq!((created, existing), (1, 15));
        assert_eq!(s.list()?.len(), 1);
        Ok(())
    }

    #[test]
    fn a_create_racing_a_delete_of_the_same_environment_ends_deleted_not_resurrected() -> Result<()> {
        let s = Arc::new(store()?);
        created(&s)?;
        let racer = {
            let s = Arc::clone(&s);
            std::thread::spawn(move || s.create("r1", "env-2", SPEC, ENC))
        };
        s.delete("env-1")?;
        let outcome = racer.join().map_err(|_| anyhow::anyhow!("thread panicked"))??;
        assert!(matches!(outcome, CreateOutcome::Existing(_)));
        assert_eq!(state_of(&s, "env-1")?, EnvironmentState::Deleted);
        assert_eq!(s.list()?.len(), 1);
        Ok(())
    }
}
