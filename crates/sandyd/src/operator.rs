//! The operator's offline cancel (#545): `sandyd cancel <job-id>`.
//!
//! A job with no usable stored attach token cannot be cancelled over the control RPC (decision 23).
//! The operator runs this as the daemon's uid, on the daemon's host, against the job store directly.
//! It is not reachable over the control socket or the mesh.
//!
//! It holds the daemon's lock file for the whole call, so it refuses while a daemon is running. A
//! stopped daemon has no live job to stop, so marking the row `Cancelled` is all that is left to do.

use std::path::{Path, PathBuf};

use crate::store::{CancelOutcome, JobStore, StoreError};

/// Why [`cancel_offline`] did not cancel.
#[derive(Debug, thiserror::Error)]
pub enum OperatorCancelError {
    /// A sandyd holds the lock for this socket path: stop it first.
    #[error("a sandyd is running on {0}: stop it before cancelling offline")]
    DaemonRunning(PathBuf),
    /// The lock file could not be opened or locked.
    #[error("cannot lock {path}: {source}")]
    Lock {
        /// The lock file.
        path: PathBuf,
        /// The OS error.
        #[source]
        source: std::io::Error,
    },
    /// The job store faulted.
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// The lock file a sandyd holds while it serves `socket`.
#[must_use]
pub fn daemon_lock_path(socket: &Path) -> PathBuf {
    socket.with_extension("lock")
}

/// Mark `job_id` `Cancelled` in the job store at `db`, if no sandyd serves `socket`.
///
/// # Errors
/// [`OperatorCancelError::DaemonRunning`] while a sandyd holds the lock;
/// [`OperatorCancelError::Lock`] if the lock file cannot be opened; [`OperatorCancelError::Store`]
/// if the store cannot be opened or written.
pub fn cancel_offline(socket: &Path, db: &Path, job_id: &str) -> Result<CancelOutcome, OperatorCancelError> {
    let lock_path = daemon_lock_path(socket);
    let lock_file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&lock_path)
        .map_err(|source| OperatorCancelError::Lock {
            path: lock_path.clone(),
            source,
        })?;
    fs2::FileExt::try_lock_exclusive(&lock_file).map_err(|source| {
        if source.kind() == std::io::ErrorKind::WouldBlock {
            OperatorCancelError::DaemonRunning(socket.to_owned())
        } else {
            OperatorCancelError::Lock {
                path: lock_path,
                source,
            }
        }
    })?;
    Ok(JobStore::open(db)?.cancel(job_id)?)
}

#[cfg(test)]
mod tests {
    use anyhow::Context;
    use sandy_control_proto::{CancelRequest, ControlRequest, JobStatus, control_request, control_response};
    use uuid::Uuid;

    use super::*;
    use crate::{dispatch::JobRegistry, handler, host_registry::HostRegistry};

    fn paths(dir: &Path) -> (PathBuf, PathBuf) {
        (dir.join("sandyd.sock"), dir.join("sandyd.db"))
    }

    /// Acceptance (#545): a job with an empty stored token is refused by the RPC and cancelled by the operator.
    #[tokio::test]
    async fn a_job_with_no_stored_token_is_refused_by_the_rpc_and_cancelled_by_the_operator() -> anyhow::Result<()> {
        let tmp = tempfile::tempdir()?;
        let (socket, db) = paths(tmp.path());
        {
            let store = JobStore::open(&db)?;
            store.insert_pending("job-1", b"m", "enc")?;
            store.set_attach_token("job-1", &[])?;
        }

        let store = std::sync::Arc::new(JobStore::open(&db)?);
        let registry = std::sync::Arc::new(JobRegistry::new()?);
        let hosts = std::sync::Arc::new(HostRegistry::default());
        let request = ControlRequest {
            request_id: 1,
            op: Some(control_request::Op::Cancel(CancelRequest {
                job_id: "job-1".to_owned(),
                attach_token: Some(Vec::new()),
            })),
        };
        let response = handler::handle(&store, &registry, &hosts, None, Uuid::new_v4(), request).await?;
        assert!(
            matches!(response.result, Some(control_response::Result::Error(_))),
            "the RPC must refuse a cancel for a job with no stored token"
        );
        drop(store);

        let outcome = cancel_offline(&socket, &db, "job-1")?;
        assert_eq!(outcome, CancelOutcome::Cancelled);
        assert_eq!(JobStore::open(&db)?.status("job-1")?, Some(JobStatus::Cancelled));
        Ok(())
    }

    #[test]
    fn an_unknown_and_an_already_terminal_job_are_reported_as_such() -> anyhow::Result<()> {
        let tmp = tempfile::tempdir()?;
        let (socket, db) = paths(tmp.path());
        JobStore::open(&db)?.insert_pending("job-1", b"m", "enc")?;

        assert_eq!(cancel_offline(&socket, &db, "nope")?, CancelOutcome::NotFound);
        assert_eq!(cancel_offline(&socket, &db, "job-1")?, CancelOutcome::Cancelled);
        assert_eq!(
            cancel_offline(&socket, &db, "job-1")?,
            CancelOutcome::AlreadyTerminal(JobStatus::Cancelled)
        );
        Ok(())
    }

    #[test]
    fn it_refuses_while_a_daemon_holds_the_lock() -> anyhow::Result<()> {
        let tmp = tempfile::tempdir()?;
        let (socket, db) = paths(tmp.path());
        JobStore::open(&db)?.insert_pending("job-1", b"m", "enc")?;
        let held = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(daemon_lock_path(&socket))?;
        fs2::FileExt::try_lock_exclusive(&held).context("hold the daemon lock")?;

        let err = cancel_offline(&socket, &db, "job-1").expect_err("must refuse");

        assert!(matches!(err, OperatorCancelError::DaemonRunning(_)), "got {err:?}");
        assert_eq!(JobStore::open(&db)?.status("job-1")?, Some(JobStatus::Pending));
        Ok(())
    }
}
