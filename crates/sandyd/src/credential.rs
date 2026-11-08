//! A job's daemon-minted forge credential (#481, `sandyd.md` decision 34).
//!
//! A Submit naming `credential` gets a scoped token minted here, before dispatch,
//! through the reusable [`sandy::CredentialBracket`]. A mint failure refuses the
//! Submit, so no host is ever dispatched without its token. The token is staged as
//! a `0600` file in a fresh `0700` daemon-owned dir and handed to the job as the
//! [`CREDENTIAL_SECRET_NAME`] secret, by path, through the #496 path-secret field of
//! `Dispatch`. [`JobCredentials::release`] revokes it and removes the file on every
//! terminal state: finish, cancel, dispatch failure, and executor loss.
//!
//! Local dispatch only: the token file is only readable on this machine, so a
//! credentialed job must land on a host-executor that declared
//! `shares_submitter_filesystem` (#495 tracks the encrypted mesh transport a remote
//! hand-off would need).

use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use sandy::{CredentialBracket, DirFingerprint, Scope, SharedProvider, StagingTarget};

/// The secret name the job sees the token under: the same name `sandy run
/// --credential` injects.
pub const CREDENTIAL_SECRET_NAME: &str = "GITHUB_TOKEN";

/// Builds the provider and scope for a named credential. The production resolver
/// is [`TrustRootResolver`]; a test injects a fake provider.
pub trait CredentialResolver: Send + Sync {
    /// Resolve trust root `name` with `capabilities` (CLI spellings, empty means
    /// `read-code`) into a provider and the scope to mint for.
    ///
    /// # Errors
    /// A human-readable reason: an unknown trust root, a bad capability, or an
    /// adapter that cannot be built. It never carries a token: none exists yet.
    fn resolve(&self, name: &str, capabilities: &[String]) -> Result<(SharedProvider, Scope), String>;
}

/// The production resolver: the trust roots `sandy cred github register` wrote
/// under [`sandy::trust_roots_dir`], resolved by [`sandy::resolve_provider`], the
/// same resolution `sandy run --credential` uses.
pub struct TrustRootResolver;

impl CredentialResolver for TrustRootResolver {
    fn resolve(&self, name: &str, capabilities: &[String]) -> Result<(SharedProvider, Scope), String> {
        let dir = sandy::trust_roots_dir().map_err(|e| format!("trust-roots dir: {e}"))?;
        let (adapter, scope) = sandy::resolve_provider(&dir, name, capabilities)?;
        Ok((Arc::new(adapter), scope))
    }
}

/// The daemon's credential configuration and the brackets of its live jobs.
pub struct JobCredentials {
    resolver: Arc<dyn CredentialResolver>,
    /// Where per-job `cred-*` dirs are created. `None` uses the sandy staging base
    /// ([`sandy_fsutil::private_staging_dir`]), whose stale `cred-*` dirs `sandy gc`
    /// sweeps after a crash.
    staging_base: Option<PathBuf>,
    /// The bound on each provider call (mint, revoke).
    call_timeout: Duration,
    live: Mutex<HashMap<String, CredentialBracket>>,
}

impl JobCredentials {
    /// Credentials resolved by `resolver`, staged under the sandy staging base,
    /// with each provider call bounded by [`sandy::CALL_DEADLINE`].
    #[must_use]
    pub fn new(resolver: Arc<dyn CredentialResolver>) -> Self {
        Self {
            resolver,
            staging_base: None,
            call_timeout: sandy::CALL_DEADLINE,
            live: Mutex::new(HashMap::new()),
        }
    }

    /// Stage per-job dirs under `base` instead of the sandy staging base.
    #[must_use]
    pub fn with_staging_base(mut self, base: PathBuf) -> Self {
        self.staging_base = Some(base);
        self
    }

    /// Bound each provider call by `timeout` instead of [`sandy::CALL_DEADLINE`].
    #[must_use]
    pub fn with_call_timeout(mut self, timeout: Duration) -> Self {
        self.call_timeout = timeout;
        self
    }

    /// The number of jobs holding a live credential.
    #[must_use]
    pub fn live_count(&self) -> usize {
        self.lock_live().len()
    }

    /// Mint credential `name` with `capabilities` and stage it as a `0600`
    /// [`CREDENTIAL_SECRET_NAME`] file in a fresh `0700` dir. Blocking: run it off
    /// the async runtime. The returned bracket revokes on drop, so a Submit that
    /// fails after this call cannot leak the token; hand it to
    /// [`JobCredentials::adopt`] once the job exists.
    ///
    /// # Errors
    /// A human-readable reason when the trust root cannot be resolved, the dir
    /// cannot be created, or the mint or stage fails. Nothing stays staged or
    /// live on an error.
    pub fn mint(&self, name: &str, capabilities: &[String]) -> Result<CredentialBracket, String> {
        let (provider, scope) = self.resolver.resolve(name, capabilities)?;
        let dir = self
            .create_dir()
            .map_err(|e| format!("create the credential staging dir: {e}"))?;
        let (dev, ino) = dir
            .dev_ino()
            .map_err(|e| format!("fingerprint the credential staging dir: {e}"))?;
        let target = StagingTarget {
            dir: dir.path().to_path_buf(),
            fingerprint: DirFingerprint { dev, ino },
            secret_name: CREDENTIAL_SECRET_NAME.to_owned(),
            remove_dir_on_revoke: true,
        };
        drop(dir);
        let dir_path = target.dir.clone();
        CredentialBracket::mint_and_stage(provider, &scope, target, sandy::MAX_TTL_SECS, self.call_timeout).map_err(
            |e| {
                if let Err(rm) = std::fs::remove_dir(&dir_path) {
                    tracing::warn!(dir = %dir_path.display(), error = %rm, "could not remove an unused credential staging dir");
                }
                e.to_string()
            },
        )
    }

    /// Hold `bracket` as `job_id`'s live credential until [`JobCredentials::release`].
    pub fn adopt(&self, job_id: &str, bracket: CredentialBracket) {
        let previous = self.lock_live().insert(job_id.to_owned(), bracket);
        if previous.is_some() {
            // Job ids are fresh UUIDs; a second adopt is a caller bug. The
            // displaced bracket revokes on drop, so it still does not leak.
            tracing::warn!(job_id, "a job adopted a second credential; revoking the first");
        }
    }

    /// Revoke `job_id`'s credential and remove its staged file and dir, if it
    /// holds one. Idempotent: every terminal path calls this, and only the first
    /// call finds the credential. The revoke runs on the blocking pool when a
    /// tokio runtime is current. A revoke failure is logged as a warning naming
    /// the job and the handle; the token then stays valid until its native expiry.
    pub fn release(&self, job_id: &str) {
        let Some(bracket) = self.lock_live().remove(job_id) else {
            return;
        };
        let job_id = job_id.to_owned();
        let teardown = move || {
            let handle = bracket.handle().map(|h| h.id).unwrap_or_default();
            match bracket.revoke() {
                Ok(()) => tracing::info!(
                    job_id,
                    handle,
                    "revoked the job's credential and removed its staged file"
                ),
                Err(e) => tracing::warn!(
                    job_id,
                    handle,
                    error = %e,
                    "credential revoke at job teardown failed; the token stays valid until its native expiry"
                ),
            }
            // The provider drops here, on this blocking thread: a live adapter
            // owns a tokio runtime, which must not drop on an async worker.
            drop(bracket);
        };
        if tokio::runtime::Handle::try_current().is_ok() {
            drop(tokio::task::spawn_blocking(teardown));
        } else {
            teardown();
        }
    }

    fn create_dir(&self) -> Result<sandy_fsutil::OwnedDir, sandy_fsutil::FsError> {
        match &self.staging_base {
            Some(base) => sandy_fsutil::OwnedDir::open_or_create(base)?
                .create_private_dir(&format!("cred-{}", uuid::Uuid::new_v4().simple())),
            None => sandy_fsutil::private_staging_dir("cred"),
        }
    }

    fn lock_live(&self) -> std::sync::MutexGuard<'_, HashMap<String, CredentialBracket>> {
        self.live.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Acceptance tests for #481, driven through the real Submit handler and the real
/// host-executor connection, over `FakeProvider` (tier-2: no forge, no VM).
#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, SocketAddr},
        sync::{Arc, OnceLock},
        time::{Duration, Instant},
    };

    use anyhow::Context;
    use sandy_control_proto::{
        CancelRequest, ControlRequest, JobStatus, SubmitRequest, SubmitResponse, control_request, control_response,
    };
    use sandy_executor_proto::{
        Capabilities, Dispatch, HostExecutorMessage, IsolationClass, JobResult, OrchestratorMessage, Register,
        SandboxKind, host_executor_message, orchestrator_message,
    };
    use sandy_test_support::FakeProvider;
    use uuid::Uuid;

    use super::*;
    use crate::{
        dispatch::JobRegistry,
        handler::handle,
        host_registry::{ExecutorAllowlist, HostRegistry},
        store::JobStore,
        test_support::SharedBuf,
    };

    /// The token every test's provider mints. A distinct string, so finding it
    /// anywhere it must not be is unambiguous.
    const TOKEN: &str = "ghs_sentinel481_never_log_me";
    /// How long a test waits for an asynchronous revoke.
    const WAIT: Duration = Duration::from_secs(5);

    fn forward_back() -> anyhow::Result<SocketAddr> {
        "100.64.0.1:9000".parse().context("forward_back literal")
    }

    fn peer_ip() -> anyhow::Result<IpAddr> {
        "100.64.0.7".parse().context("peer ip literal")
    }

    fn test_fp() -> anyhow::Result<sandy_conn::Fingerprint> {
        sandy_conn::Fingerprint::from_hex(&"aa".repeat(32)).context("fingerprint literal")
    }

    /// One process-wide log capture. A global subscriber, not a thread-local one:
    /// the revoke runs on a blocking-pool thread.
    fn captured_logs() -> &'static SharedBuf {
        static CAPTURE: OnceLock<SharedBuf> = OnceLock::new();
        CAPTURE.get_or_init(|| {
            let buf = SharedBuf::default();
            let subscriber = tracing_subscriber::fmt()
                .with_writer(buf.clone())
                .with_ansi(false)
                .with_max_level(tracing::Level::TRACE)
                .finish();
            let _ = tracing::subscriber::set_global_default(subscriber);
            buf
        })
    }

    struct FakeResolver(Arc<FakeProvider>);

    impl CredentialResolver for FakeResolver {
        fn resolve(&self, _name: &str, _capabilities: &[String]) -> Result<(SharedProvider, Scope), String> {
            let provider: SharedProvider = self.0.clone();
            Ok((provider, Scope::default()))
        }
    }

    /// A daemon's job-side state with a fake credential provider.
    struct Daemon {
        store: Arc<JobStore>,
        registry: Arc<JobRegistry>,
        hosts: Arc<HostRegistry>,
        provider: Arc<FakeProvider>,
        staging: PathBuf,
        _tmp: tempfile::TempDir,
    }

    fn daemon(provider: FakeProvider) -> anyhow::Result<Daemon> {
        daemon_with_store(provider, |_| Ok(JobStore::open_in_memory()?))
    }

    fn daemon_with_store(
        provider: FakeProvider,
        open_store: impl FnOnce(&std::path::Path) -> anyhow::Result<JobStore>,
    ) -> anyhow::Result<Daemon> {
        captured_logs();
        let tmp = tempfile::tempdir().context("tempdir")?;
        let staging = tmp.path().join("staging");
        let provider = Arc::new(provider);
        let credentials = JobCredentials::new(Arc::new(FakeResolver(Arc::clone(&provider))))
            .with_staging_base(staging.clone())
            .with_call_timeout(WAIT);
        Ok(Daemon {
            store: Arc::new(open_store(tmp.path())?),
            registry: Arc::new(JobRegistry::new()?.with_credentials(credentials)),
            hosts: Arc::new(HostRegistry::default()),
            provider,
            staging,
            _tmp: tmp,
        })
    }

    fn capabilities(shares_submitter_filesystem: bool) -> Capabilities {
        Capabilities {
            supported_sandbox_kinds: vec![SandboxKind::Process.into()],
            arch: sandy_executor_proto::Arch::X8664.into(),
            attestation: false,
            supported_isolation_classes: vec![IsolationClass::Trusted.into()],
            shares_submitter_filesystem,
        }
    }

    /// Register a host directly (no wire), returning its dispatch channel.
    fn register_host(
        d: &Daemon,
        shares_submitter_filesystem: bool,
    ) -> anyhow::Result<tokio::sync::mpsc::Receiver<Dispatch>> {
        let allowlist = ExecutorAllowlist::new([(peer_ip()?, test_fp()?)]);
        let registration = d
            .hosts
            .register(
                &allowlist,
                peer_ip()?,
                test_fp()?,
                "host-1".to_owned(),
                capabilities(shares_submitter_filesystem),
            )
            .map_err(|e| anyhow::anyhow!("register a test host: {e}"))?;
        Ok(registration.dispatch_rx)
    }

    /// Register a local host over a real wire connection served by
    /// `serve_host_executor`, returning the host's end of it.
    async fn connect_local_host(d: &Daemon) -> anyhow::Result<(tokio::io::DuplexStream, tokio::task::JoinHandle<()>)> {
        let (mut client, server) = tokio::io::duplex(1 << 16);
        sandy_control_proto::write_frame(
            &mut client,
            &HostExecutorMessage {
                op: Some(host_executor_message::Op::Register(Register {
                    host_id: "host-1".to_owned(),
                    capabilities: Some(capabilities(true)),
                })),
            },
        )
        .await?;
        let (hosts, store, registry) = (Arc::clone(&d.hosts), Arc::clone(&d.store), Arc::clone(&d.registry));
        let allowlist = ExecutorAllowlist::new([(peer_ip()?, test_fp()?)]);
        let peer = sandy_conn::PeerAddr::TcpTls(SocketAddr::new(peer_ip()?, 9000), test_fp()?);
        let serve = tokio::spawn(async move {
            crate::host_conn::serve_host_executor(Box::new(server), peer, &allowlist, &hosts, &store, &registry).await;
        });
        let registered: OrchestratorMessage = sandy_control_proto::read_frame(&mut client)
            .await?
            .context("expected Registered")?;
        anyhow::ensure!(
            matches!(registered.op, Some(orchestrator_message::Op::Registered(_))),
            "expected Registered, got {registered:?}"
        );
        Ok((client, serve))
    }

    async fn read_dispatch(client: &mut tokio::io::DuplexStream) -> anyhow::Result<Dispatch> {
        let pushed: OrchestratorMessage = tokio::time::timeout(WAIT, sandy_control_proto::read_frame(client))
            .await
            .context("timed out waiting for a Dispatch")??
            .context("connection closed before a Dispatch")?;
        match pushed.op {
            Some(orchestrator_message::Op::Dispatch(dispatch)) => Ok(dispatch),
            other => anyhow::bail!("expected a Dispatch, got {other:?}"),
        }
    }

    fn submit_req(credential: Option<&str>, cred_capabilities: Vec<String>) -> ControlRequest {
        ControlRequest {
            request_id: 1,
            op: Some(control_request::Op::Submit(SubmitRequest {
                manifest: b"m".to_vec(),
                manifest_encoding: "test/v1".to_owned(),
                submitter_caps: Vec::new(),
                required_isolation_class: sandy_control_proto::IsolationClass::Trusted.into(),
                inputs: Vec::new(),
                outputs: Vec::new(),
                secrets: Vec::new(),
                credential: credential.map(str::to_owned),
                cred_capabilities,
            })),
        }
    }

    async fn submit(d: &Daemon, request: ControlRequest) -> anyhow::Result<control_response::Result> {
        let response = handle(
            &d.store,
            &d.registry,
            &d.hosts,
            Some(forward_back()?),
            Uuid::new_v4(),
            request,
        )
        .await?;
        response.result.context("a response carries a result")
    }

    async fn submit_ok(d: &Daemon) -> anyhow::Result<SubmitResponse> {
        match submit(d, submit_req(Some("gh-test"), Vec::new())).await? {
            control_response::Result::Submit(ok) => Ok(ok),
            other => anyhow::bail!("expected the Submit to succeed, got {other:?}"),
        }
    }

    /// The staged token file the dispatch names, after checking it is the only
    /// path the token rides: the `GITHUB_TOKEN` secret, holding the minted token.
    fn staged_token_path(dispatch: &Dispatch) -> anyhow::Result<PathBuf> {
        let secret = dispatch
            .secrets
            .iter()
            .find(|s| s.name == CREDENTIAL_SECRET_NAME)
            .context("the dispatch must carry the minted credential as the GITHUB_TOKEN secret")?;
        let path = PathBuf::from(&secret.host_path);
        let staged = std::fs::read_to_string(&path).context("the staged token file is readable")?;
        anyhow::ensure!(staged == TOKEN, "the staged file holds the minted token");
        Ok(path)
    }

    async fn cancel(d: &Daemon, submitted: &SubmitResponse) -> anyhow::Result<()> {
        let response = handle(
            &d.store,
            &d.registry,
            &d.hosts,
            Some(forward_back()?),
            Uuid::new_v4(),
            ControlRequest {
                request_id: 2,
                op: Some(control_request::Op::Cancel(CancelRequest {
                    job_id: submitted.job_id.clone(),
                    attach_token: Some(submitted.attach_token.clone()),
                })),
            },
        )
        .await?;
        anyhow::ensure!(
            matches!(response.result, Some(control_response::Result::Cancel(_))),
            "cancel must succeed: {:?}",
            response.result
        );
        Ok(())
    }

    /// Wait until the provider saw a revoke and `path` is gone.
    async fn wait_revoked_and_removed(d: &Daemon, path: &std::path::Path) -> anyhow::Result<()> {
        let dir_exists = || path.parent().is_some_and(std::path::Path::exists);
        let deadline = Instant::now() + WAIT;
        while (d.provider.revoked().is_empty() || path.exists() || dir_exists()) && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        anyhow::ensure!(!d.provider.revoked().is_empty(), "the credential must be revoked");
        anyhow::ensure!(!path.exists(), "the staged token file must be removed");
        anyhow::ensure!(!dir_exists(), "the job's staging dir must be removed");
        Ok(())
    }

    async fn wait_status(d: &Daemon, job_id: &str, want: JobStatus) -> anyhow::Result<()> {
        let deadline = Instant::now() + WAIT;
        loop {
            let status = d.store.status(job_id)?;
            if status == Some(want) {
                return Ok(());
            }
            anyhow::ensure!(
                Instant::now() < deadline,
                "job {job_id} is {status:?}, expected {want:?}"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// Acceptance 1: a mint failure refuses the Submit with a named error, before
    /// any side effect. No host is dispatched and no job row exists.
    #[tokio::test]
    async fn a_mint_failure_refuses_the_submit_and_dispatches_nothing() -> anyhow::Result<()> {
        let d = daemon(FakeProvider::failing())?;
        let mut dispatch_rx = register_host(&d, true)?;
        match submit(&d, submit_req(Some("gh-test"), Vec::new())).await? {
            control_response::Result::Error(e) => {
                assert!(e.message.contains("credential"), "{}", e.message);
                assert!(e.message.contains("mint"), "{}", e.message);
            }
            other => anyhow::bail!("a mint failure must refuse the Submit, got {other:?}"),
        }
        assert!(dispatch_rx.try_recv().is_err(), "no dispatch may reach a host");
        assert!(d.store.list()?.is_empty(), "a refused Submit leaves no job row");
        Ok(())
    }

    /// Acceptance 2: a cancel mid-run revokes the credential and removes the
    /// staged file and its dir.
    #[tokio::test]
    async fn a_cancel_mid_run_revokes_and_removes_the_staged_file() -> anyhow::Result<()> {
        let d = daemon(FakeProvider::returning(TOKEN))?;
        let mut dispatch_rx = register_host(&d, true)?;
        let submitted = submit_ok(&d).await?;
        let dispatch = tokio::time::timeout(WAIT, dispatch_rx.recv())
            .await
            .context("timed out waiting for the dispatch")?
            .context("dispatch channel closed")?;
        let path = staged_token_path(&dispatch)?;
        assert!(d.provider.revoked().is_empty(), "nothing is revoked while the job runs");

        cancel(&d, &submitted).await?;
        wait_revoked_and_removed(&d, &path).await?;
        assert_eq!(d.registry.credentials().map(|c| c.live_count()), Some(0));
        Ok(())
    }

    /// Acceptance 3: a terminal finish reported by the host-executor revokes the
    /// credential and removes the staged file.
    #[tokio::test]
    async fn a_finished_job_revokes_and_removes_the_staged_file() -> anyhow::Result<()> {
        let d = daemon(FakeProvider::returning(TOKEN))?;
        let (mut client, serve) = connect_local_host(&d).await?;
        let submitted = submit_ok(&d).await?;
        let dispatch = read_dispatch(&mut client).await?;
        let path = staged_token_path(&dispatch)?;

        sandy_control_proto::write_frame(
            &mut client,
            &HostExecutorMessage {
                op: Some(host_executor_message::Op::Result(JobResult {
                    job_id: submitted.job_id.clone(),
                    booted: true,
                    exit_code: Some(0),
                    timed_out: false,
                    transport_error: None,
                    console: "done\n".to_owned(),
                })),
            },
        )
        .await?;
        wait_status(&d, &submitted.job_id, JobStatus::Succeeded).await?;
        wait_revoked_and_removed(&d, &path).await?;

        drop(client);
        tokio::time::timeout(WAIT, serve).await??;
        Ok(())
    }

    /// Acceptance 5: a revoke failure is surfaced in the daemon log, naming the
    /// job, and the staged file is still removed.
    #[tokio::test]
    async fn a_revoke_failure_is_surfaced_and_the_staged_file_is_still_removed() -> anyhow::Result<()> {
        let d = daemon(FakeProvider::returning(TOKEN).with_failing_revoke())?;
        let mut dispatch_rx = register_host(&d, true)?;
        let submitted = submit_ok(&d).await?;
        let dispatch = tokio::time::timeout(WAIT, dispatch_rx.recv())
            .await
            .context("timed out waiting for the dispatch")?
            .context("dispatch channel closed")?;
        let path = staged_token_path(&dispatch)?;

        cancel(&d, &submitted).await?;
        wait_revoked_and_removed(&d, &path).await?;
        let deadline = Instant::now() + WAIT;
        loop {
            let logs = captured_logs().contents()?;
            if logs
                .lines()
                .any(|l| l.contains("WARN") && l.contains(&submitted.job_id) && l.contains("revoke"))
            {
                break;
            }
            anyhow::ensure!(
                Instant::now() < deadline,
                "a revoke failure must be logged as a warning naming the job"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        Ok(())
    }

    /// Acceptance 6: a credential whose job could only place on a remote host
    /// (no `shares_submitter_filesystem`) is refused with a named error, and
    /// nothing is minted.
    #[tokio::test]
    async fn a_credential_that_could_only_place_remotely_is_refused_and_nothing_is_minted() -> anyhow::Result<()> {
        let d = daemon(FakeProvider::returning(TOKEN))?;
        let mut dispatch_rx = register_host(&d, false)?;
        match submit(&d, submit_req(Some("gh-test"), Vec::new())).await? {
            control_response::Result::Error(e) => {
                assert!(e.message.contains("credential"), "{}", e.message);
                assert!(e.message.contains("#495"), "{}", e.message);
            }
            other => anyhow::bail!("a remote-only credential must be refused, got {other:?}"),
        }
        assert!(
            d.provider.mints().is_empty(),
            "nothing may be minted for a refused Submit"
        );
        assert!(dispatch_rx.try_recv().is_err(), "no dispatch may reach the remote host");
        assert!(d.store.list()?.is_empty());
        Ok(())
    }

    /// Acceptance 7: the token reaches the job only through the staged file. It
    /// never appears in the sqlite store, the daemon log, or the Dispatch's other
    /// fields.
    #[tokio::test]
    async fn the_token_never_reaches_the_store_the_logs_or_the_dispatch() -> anyhow::Result<()> {
        let d = daemon_with_store(FakeProvider::returning(TOKEN), |dir| {
            Ok(JobStore::open(&dir.join("jobs.sqlite"))?)
        })?;
        let (mut client, serve) = connect_local_host(&d).await?;
        let submitted = submit_ok(&d).await?;
        let dispatch = read_dispatch(&mut client).await?;
        let path = staged_token_path(&dispatch)?;
        assert!(
            !format!("{dispatch:?}").contains(TOKEN),
            "the Dispatch carries the token's path, never the token"
        );

        sandy_control_proto::write_frame(
            &mut client,
            &HostExecutorMessage {
                op: Some(host_executor_message::Op::Result(JobResult {
                    job_id: submitted.job_id.clone(),
                    booted: true,
                    exit_code: Some(0),
                    timed_out: false,
                    transport_error: None,
                    console: "done\n".to_owned(),
                })),
            },
        )
        .await?;
        wait_status(&d, &submitted.job_id, JobStatus::Succeeded).await?;
        wait_revoked_and_removed(&d, &path).await?;
        drop(client);
        tokio::time::timeout(WAIT, serve).await??;

        for entry in std::fs::read_dir(d._tmp.path())? {
            let entry = entry?;
            if entry.file_name().to_string_lossy().starts_with("jobs.sqlite") {
                let bytes = std::fs::read(entry.path())?;
                assert!(
                    !bytes.windows(TOKEN.len()).any(|w| w == TOKEN.as_bytes()),
                    "the token must not reach the store file {}",
                    entry.path().display()
                );
            }
        }
        let logs = captured_logs().contents()?;
        assert!(
            logs.contains(&submitted.job_id),
            "the capture must hold this job's log lines"
        );
        assert!(!logs.contains(TOKEN), "the token must never be logged");
        Ok(())
    }

    /// Acceptance 8: a dispatch that fails after the mint fails the job and
    /// revokes the credential.
    #[tokio::test]
    async fn a_dispatch_failure_after_the_mint_revokes() -> anyhow::Result<()> {
        let d = daemon(FakeProvider::returning(TOKEN))?;
        let dispatch_rx = register_host(&d, true)?;
        drop(dispatch_rx);
        let submitted = submit_ok(&d).await?;
        assert_eq!(
            d.provider.mints().len(),
            1,
            "the credential is minted before the dispatch"
        );
        wait_status(&d, &submitted.job_id, JobStatus::Failed).await?;
        let staging_is_empty = || -> anyhow::Result<bool> { Ok(std::fs::read_dir(&d.staging)?.next().is_none()) };
        let deadline = Instant::now() + WAIT;
        while (d.provider.revoked().is_empty() || !staging_is_empty()?) && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(!d.provider.revoked().is_empty(), "the credential must be revoked");
        assert!(staging_is_empty()?, "no staging dir may remain");
        Ok(())
    }

    /// Executor loss: a host-executor that disconnects mid-run fails the job and
    /// revokes the credential.
    #[tokio::test]
    async fn an_executor_disconnect_mid_run_revokes() -> anyhow::Result<()> {
        let d = daemon(FakeProvider::returning(TOKEN))?;
        let (mut client, serve) = connect_local_host(&d).await?;
        let submitted = submit_ok(&d).await?;
        let dispatch = read_dispatch(&mut client).await?;
        let path = staged_token_path(&dispatch)?;
        drop(client);
        tokio::time::timeout(WAIT, serve).await??;
        wait_status(&d, &submitted.job_id, JobStatus::Failed).await?;
        wait_revoked_and_removed(&d, &path).await?;
        Ok(())
    }

    /// `cred_capabilities` without a `credential` is refused rather than ignored.
    #[tokio::test]
    async fn a_cred_capability_without_a_credential_is_refused() -> anyhow::Result<()> {
        let d = daemon(FakeProvider::returning(TOKEN))?;
        let _dispatch_rx = register_host(&d, true)?;
        match submit(&d, submit_req(None, vec!["write-code".to_owned()])).await? {
            control_response::Result::Error(e) => assert!(e.message.contains("cred_capabilities"), "{}", e.message),
            other => anyhow::bail!("cred_capabilities alone must be refused, got {other:?}"),
        }
        assert!(d.provider.mints().is_empty());
        Ok(())
    }
}
