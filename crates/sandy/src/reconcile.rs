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
    journal::{JobRecord, JobState, Journal},
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
pub fn reconcile_job<B: VmBackend>(journal: &Journal, backend: &B, job_id: &str) -> Result<JobRecord, CoreError> {
    let record = journal.read_record(job_id)?;
    if record.state != JobState::Running {
        return Ok(record);
    }

    // Liveness via the backend's running-box set — never a direct registry read
    // (INV-3). A box still listed means the owner is alive; leave it untouched.
    let boxes = backend
        .boxes()
        .map_err(|e| CoreError::State(format!("backend box query failed: {e}")))?;
    let box_still_listed = record
        .box_id
        .as_deref()
        .is_some_and(|id| boxes.iter().any(|b| b.box_id == id));
    if box_still_listed {
        return Ok(record);
    }

    // The box is gone from the backend, but the pid may have been reused — so the
    // flock, not the pid, is the liveness authority (INV-3). Only acquiring it
    // proves the owner is gone; if another writer holds it, the job is live.
    let Some(_lock) = journal.try_lock_job(job_id)? else {
        return Ok(record);
    };

    // The first read happened before the lock; the owner may have written a
    // terminal record (and released the lock) in that window. Re-read under the
    // lock and bail unless it is still `running`, so a completed result is never
    // clobbered by a stale `crashed` (INV-3/INV-6).
    let record = journal.read_record(job_id)?;
    if record.state != JobState::Running {
        return Ok(record);
    }

    // Owner confirmed gone: flip running → crashed and tear the box down, all
    // under the held lock (TOCTOU-safe).
    let mut crashed = record;
    crashed.state = JobState::Crashed;
    crashed.writer_pid = std::process::id();
    journal.write_record(&crashed)?;
    if let Some(box_id) = &crashed.box_id {
        backend
            .kill(box_id)
            .map_err(|e| CoreError::State(format!("teardown of box {box_id} failed: {e}")))?;
    }
    Ok(crashed)
}
