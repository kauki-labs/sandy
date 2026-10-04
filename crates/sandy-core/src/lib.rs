//! Core library for the `sandy` workspace: the pure, testable heart.
//!
//! This crate holds everything provable without a hypervisor:
//!
//! - [`backend`] — the pinned [`VmBackend`](backend::VmBackend) seam plus the `snake_case` data types (INV-8) and a
//!   [`FakeBackend`](backend::FakeBackend) test double.
//! - [`result`] — the LOCKED result envelope (INV-11) and the mapping from a backend [`Outcome`](backend::Outcome) to
//!   `status` / `retryable` / the process-exit band.
//! - [`journal`] — one JSON record per job under `$SANDY_HOME/jobs/`, written atomically and guarded by a per-job flock
//!   (INV-3, INV-5, INV-6).
//! - [`collect`] — exit-0-only, atomic, `O_NOFOLLOW` output collection (INV-2, INV-4).
//! - [`reconcile`] — reconcile-on-read, acting only under the job's flock (INV-3).
//!
//! Function bodies throughout are `todo!()`: this crate currently ships the API
//! skeleton and its red test suite. A separate implementer fills the behaviour.

pub mod backend;
pub mod collect;
pub mod journal;
pub mod reconcile;
pub mod result;

pub use backend::{
    BackendError, BoxState, FakeBackend, Grants, Mount, Outcome, PlanError, RunSpec, SecretRef, SecretSource,
    VmBackend, validate_no_secret_leak,
};
pub use collect::{CollectError, CollectionConfig, OutputSpec, collect};
pub use journal::{
    JOURNAL_SCHEMA_VERSION, JobLock, JobRecord, JobState, Journal, detect_fs_type, ensure_local_posix_fs,
    is_networked_fs, new_job_id,
};
pub use reconcile::reconcile_job;
pub use result::{
    Classification, Logs, OutputRef, OutputStatus, ProcessExit, Provenance, RESULT_SCHEMA_VERSION, Receipt,
    ResultEnvelope, Status, classify_backend_error, classify_invalid_plan, classify_outcome,
};

/// Errors raised by the core journal / reconcile layer.
#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    /// A filesystem operation failed.
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    /// A journal record could not be (de)serialized.
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    /// No journal record exists for the given job id.
    #[error("job record not found: {0}")]
    NotFound(String),
    /// The per-job flock could not be acquired (another writer holds it).
    #[error("could not acquire job lock for {0}")]
    Lock(String),
    /// `$SANDY_HOME` is not a local POSIX filesystem (INV-5).
    #[error("$SANDY_HOME is not a local POSIX filesystem: {0}")]
    NonLocalFs(String),
    /// A journal record is in an unexpected state for the requested transition.
    #[error("invalid journal state: {0}")]
    State(String),
}

/// fsync a directory so a preceding create/rename within it is durable across a
/// crash (INV-4/INV-6).
pub(crate) fn fsync_dir(dir: &std::path::Path) -> std::io::Result<()> {
    std::fs::File::open(dir)?.sync_all()
}
