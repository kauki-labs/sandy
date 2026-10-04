//! Reconcile-on-read (INV-3).
//!
//! When a `running` record is read, the reconciler checks liveness through the
//! backend's [`boxes`](crate::backend::VmBackend::boxes) — never a direct
//! registry read — and, if the box is gone, acquires the job's flock (proving
//! the owner is dead) *before* flipping `running → crashed` and tearing the box
//! down. A live owner still holds the lock, so a live job is never reaped even
//! if its pid was reused (INV-3).

use crate::{
    CoreError,
    backend::VmBackend,
    journal::{JobRecord, Journal},
};

/// Reconcile a single job's record against live backend state.
///
/// If the record is not `running`, it is returned unchanged. If it is `running`
/// and [`VmBackend::boxes`] still lists its box, the live job is left untouched.
/// Only when the box is absent AND the job's flock can be acquired does the
/// reconciler flip the record to `crashed` and call [`VmBackend::kill`] (INV-3).
///
/// # Errors
///
/// Returns [`CoreError`] on journal I/O failure or if liveness cannot be
/// determined; backend errors surface as [`CoreError`].
pub fn reconcile_job<B: VmBackend>(_journal: &Journal, _backend: &B, _job_id: &str) -> Result<JobRecord, CoreError> {
    todo!("read record; if running and box absent, lock then flip to crashed + kill")
}
