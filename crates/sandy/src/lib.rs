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

pub mod backend;
pub mod collect;
pub mod config;
pub mod egress;
pub mod error;
pub mod gc;
pub mod journal;
pub mod metrics;
pub mod reconcile;
pub mod result;
pub mod schema;
pub mod strategy;

pub use backend::{
    BackendError, BoxState, FakeBackend, Grants, Mount, Outcome, PlanError, RunSpec, SecretRef, SecretSource,
    VmBackend, validate_no_secret_leak,
};
pub use collect::{CollectError, OutputSpec, collect};
pub use config::CollectionConfig;
pub use egress::{AllowList, EgressRule, macos_egress_statement, to_nftables};
pub use error::CoreError;
pub use gc::{StagedImage, plan_eviction};
pub use journal::{JobLock, Journal, detect_fs_type, ensure_local_posix_fs, is_networked_fs, new_job_id};
pub use metrics::{RunMetrics, RunPhase};
pub use reconcile::reconcile_job;
pub use result::{
    Classification, Logs, OutputRef, OutputStatus, ProcessExit, Provenance, RESULT_SCHEMA_VERSION, Receipt,
    ResultEnvelope, Status, classify_backend_error, classify_invalid_plan, classify_outcome,
};
pub use schema::v1::{JOURNAL_SCHEMA_VERSION, JobRecord, JobState};
pub use strategy::{BootAxis, BuildAxis, HostFacts, ProvisioningStrategy, classify};

/// fsync a directory so a preceding create/rename within it is durable across a
/// crash (INV-4/INV-6).
pub(crate) fn fsync_dir(dir: &std::path::Path) -> std::io::Result<()> {
    std::fs::File::open(dir)?.sync_all()
}
