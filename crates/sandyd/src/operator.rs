//! The operator's offline cancel (#545): `sandyd cancel <job-id>`.
//!
//! A job with no usable stored attach token cannot be cancelled over the control RPC (decision 23).
//! The operator runs this as the daemon's uid, on the daemon's host, against the job store directly.
//! It is not reachable over the control socket or the mesh.
//!
//! It holds the store's lock file for the whole call, so it refuses while a daemon uses that store.
//! It only marks the row `Cancelled`: see [`cancel_offline`] for what it does not stop.

use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use crate::{
    credential::{CredentialResolver, DAEMON_CALL_TIMEOUT, revoke_recorded_bounded},
    store::{CancelOutcome, JobStore, StoreError},
};

/// Why [`cancel_offline`] did not cancel.
#[derive(Debug, thiserror::Error)]
pub enum OperatorCancelError {
    /// A sandyd holds the lock for this job store: stop it first.
    #[error("a sandyd is running on the job store {0}: stop it before cancelling offline")]
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
    /// No job store exists at the path: a wrong `SANDY_DB`, not an empty store.
    #[error("no job store at {0}: check SANDY_DB")]
    NoStore(PathBuf),
    /// The job store faulted.
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// The lock file a sandyd holds while it uses the job store `db`. Keyed on the store, not the
/// socket, so `sandyd cancel` is refused whichever `SANDY_SOCK` the operator's shell sets.
#[must_use]
pub fn daemon_lock_path(db: &Path) -> PathBuf {
    db.with_extension("lock")
}

/// Take the exclusive lock on the store's lock file and keep it for as long as the file lives.
///
/// # Errors
/// [`OperatorCancelError::DaemonRunning`] when another process holds it;
/// [`OperatorCancelError::Lock`] if the file cannot be opened or locked.
pub fn lock_store(db: &Path) -> Result<std::fs::File, OperatorCancelError> {
    let lock_path = daemon_lock_path(db);
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
            OperatorCancelError::DaemonRunning(db.to_owned())
        } else {
            OperatorCancelError::Lock {
                path: lock_path,
                source,
            }
        }
    })?;
    Ok(lock_file)
}

/// Mark `job_id` `Cancelled` in the job store at `db`, if no sandyd uses that store.
///
/// This only marks the row. It does not stop a sandbox still running on a host-executor (a
/// stopped sandyd leaves a remote dispatch to drain until its deadline) or one left behind by a
/// crashed local daemon.
///
/// # Errors
/// [`OperatorCancelError::DaemonRunning`] while a sandyd holds the store's lock;
/// [`OperatorCancelError::NoStore`] if `db` does not exist; [`OperatorCancelError::Lock`] if the
/// lock file cannot be opened; [`OperatorCancelError::Store`] if the store cannot be written.
pub fn cancel_offline(db: &Path, job_id: &str) -> Result<CancelOutcome, OperatorCancelError> {
    let _lock = lock_store(db)?;
    if !db.exists() {
        return Err(OperatorCancelError::NoStore(db.to_owned()));
    }
    Ok(JobStore::open(db)?.cancel(job_id)?)
}

/// [`cancel_offline`], then revoke the job's recorded credential through `resolver` (#830, #719 item 1) while the
/// store is still locked, bounded by the provider call bound. The revoke result is `None` when the job holds no
/// credential record, so a cancel with nothing to revoke prints nothing extra. A failed revoke keeps the record: the
/// next daemon start tries again.
///
/// # Errors
/// As [`cancel_offline`].
pub fn cancel_offline_and_revoke(
    db: &Path,
    job_id: &str,
    resolver: Arc<dyn CredentialResolver>,
) -> Result<(CancelOutcome, Option<Result<(), String>>), OperatorCancelError> {
    let _lock = lock_store(db)?;
    if !db.exists() {
        return Err(OperatorCancelError::NoStore(db.to_owned()));
    }
    let store = JobStore::open(db)?;
    let outcome = store.cancel(job_id)?;
    if outcome == CancelOutcome::NotFound {
        return Ok((outcome, None));
    }
    let Some(record) = store.credential_record(job_id)? else {
        return Ok((outcome, None));
    };
    let revoked = revoke_recorded_bounded(resolver, &record, DAEMON_CALL_TIMEOUT);
    if revoked.is_ok() {
        store.clear_credential(job_id)?;
    }
    Ok((outcome, Some(revoked)))
}

#[cfg(test)]
mod tests {
    use anyhow::Context;
    use sandy_control_proto::{CancelRequest, ControlRequest, JobStatus, control_request, control_response};
    use uuid::Uuid;

    use super::*;
    use crate::{dispatch::JobRegistry, handler, host_registry::HostRegistry};

    /// Acceptance (#545): a job with an empty stored token is refused by the RPC and cancelled by the operator.
    #[tokio::test]
    async fn a_job_with_no_stored_token_is_refused_by_the_rpc_and_cancelled_by_the_operator() -> anyhow::Result<()> {
        let tmp = tempfile::tempdir()?;
        let db = tmp.path().join("sandyd.db");
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

        let outcome = cancel_offline(&db, "job-1")?;
        assert_eq!(outcome, CancelOutcome::Cancelled);
        assert_eq!(JobStore::open(&db)?.status("job-1")?, Some(JobStatus::Cancelled));
        Ok(())
    }

    #[test]
    fn an_unknown_and_an_already_terminal_job_are_reported_as_such() -> anyhow::Result<()> {
        let tmp = tempfile::tempdir()?;
        let db = tmp.path().join("sandyd.db");
        JobStore::open(&db)?.insert_pending("job-1", b"m", "enc")?;

        assert_eq!(cancel_offline(&db, "nope")?, CancelOutcome::NotFound);
        assert_eq!(cancel_offline(&db, "job-1")?, CancelOutcome::Cancelled);
        assert_eq!(
            cancel_offline(&db, "job-1")?,
            CancelOutcome::AlreadyTerminal(JobStatus::Cancelled)
        );
        Ok(())
    }

    #[test]
    fn a_missing_store_is_refused_not_created() -> anyhow::Result<()> {
        let tmp = tempfile::tempdir()?;
        let db = tmp.path().join("sandyd.db");

        let err = cancel_offline(&db, "job-1").expect_err("must refuse");

        assert!(matches!(err, OperatorCancelError::NoStore(_)), "got {err:?}");
        assert!(!db.exists(), "a wrong path must not leave an empty store behind");
        Ok(())
    }

    #[test]
    fn it_refuses_while_a_daemon_holds_the_lock() -> anyhow::Result<()> {
        let tmp = tempfile::tempdir()?;
        let db = tmp.path().join("sandyd.db");
        JobStore::open(&db)?.insert_pending("job-1", b"m", "enc")?;
        let held = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(daemon_lock_path(&db))?;
        fs2::FileExt::try_lock_exclusive(&held).context("hold the daemon lock")?;

        let err = cancel_offline(&db, "job-1").expect_err("must refuse");

        assert!(matches!(err, OperatorCancelError::DaemonRunning(_)), "got {err:?}");
        assert_eq!(JobStore::open(&db)?.status("job-1")?, Some(JobStatus::Pending));
        Ok(())
    }
    /// A resolver that hands every trust root the same provider.
    struct OneProvider(std::sync::Arc<sandy_test_support::FakeProvider>);

    impl CredentialResolver for OneProvider {
        fn resolve(&self, _: &str, _: &[String]) -> Result<(sandy::SharedProvider, sandy::Scope), String> {
            Err("the offline cancel resolves a provider only".to_owned())
        }

        fn provider(&self, _: &str) -> Result<sandy::SharedProvider, String> {
            let provider: sandy::SharedProvider = self.0.clone();
            Ok(provider)
        }
    }

    /// A store holding `job-1` with a credential record and a staged token file in a `cred-*` dir.
    fn store_with_a_credentialed_job(tmp: &Path) -> anyhow::Result<(PathBuf, PathBuf)> {
        let db = tmp.join("sandyd.db");
        let dir = tmp.join("cred-abc");
        std::fs::create_dir(&dir)?;
        let token = dir.join(crate::credential::CREDENTIAL_SECRET_NAME);
        std::fs::write(&token, b"t")?;
        let store = JobStore::open(&db)?;
        store.insert_pending("job-1", b"m", "enc")?;
        store.set_credential(
            "job-1",
            &crate::store::CredentialRecord {
                trust_root: "gh".to_owned(),
                handle_id: "h-1".to_owned(),
                expires_at_unix: u64::MAX / 2,
                token_path: token.clone(),
            },
        )?;
        Ok((db, token))
    }

    /// #830, #719 item 1: the offline cancel marks the row and also revokes the job's recorded credential, removes
    /// its staged file and forgets the record.
    #[test]
    fn an_offline_cancel_revokes_the_recorded_credential() -> anyhow::Result<()> {
        let tmp = tempfile::tempdir()?;
        let (db, token) = store_with_a_credentialed_job(tmp.path())?;
        let provider = std::sync::Arc::new(sandy_test_support::FakeProvider::returning("t"));

        let (outcome, revoked) = cancel_offline_and_revoke(&db, "job-1", Arc::new(OneProvider(provider.clone())))?;

        assert_eq!(outcome, CancelOutcome::Cancelled);
        assert!(matches!(revoked, Some(Ok(()))), "{revoked:?}");
        assert_eq!(provider.revoked().len(), 1, "revoked exactly once");
        assert!(!token.exists(), "the staged token file is removed");
        assert_eq!(JobStore::open(&db)?.credential_record("job-1")?, None);
        Ok(())
    }

    /// A revoke that fails is reported and keeps the record for the next daemon start.
    #[test]
    fn an_offline_cancel_keeps_the_record_when_the_revoke_fails() -> anyhow::Result<()> {
        let tmp = tempfile::tempdir()?;
        let (db, _token) = store_with_a_credentialed_job(tmp.path())?;
        let provider = std::sync::Arc::new(sandy_test_support::FakeProvider::returning("t").with_failing_revoke());

        let (outcome, revoked) = cancel_offline_and_revoke(&db, "job-1", Arc::new(OneProvider(provider)))?;

        assert_eq!(outcome, CancelOutcome::Cancelled);
        assert!(matches!(revoked, Some(Err(_))), "{revoked:?}");
        assert!(JobStore::open(&db)?.credential_record("job-1")?.is_some());
        Ok(())
    }

    /// A job with no credential record cancels as before and reports no revoke.
    #[test]
    fn an_offline_cancel_of_a_job_with_no_credential_reports_no_revoke() -> anyhow::Result<()> {
        let tmp = tempfile::tempdir()?;
        let db = tmp.path().join("sandyd.db");
        JobStore::open(&db)?.insert_pending("job-1", b"m", "enc")?;
        let provider = std::sync::Arc::new(sandy_test_support::FakeProvider::returning("t"));

        let (outcome, revoked) = cancel_offline_and_revoke(&db, "job-1", Arc::new(OneProvider(provider.clone())))?;

        assert_eq!(outcome, CancelOutcome::Cancelled);
        assert!(revoked.is_none());
        assert!(provider.revoked().is_empty());
        Ok(())
    }
}
