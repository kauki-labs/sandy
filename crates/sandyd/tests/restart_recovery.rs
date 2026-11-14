//! A killed `sandyd` leaves no job open (#830): the next start fails it, with the result envelope a caller reads.

use std::{
    path::Path,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use anyhow::Context;
use sandy_control_proto::{
    IsolationClass, JobStatus, StatusRequest, SubmitRequest, client::call, control_request, control_response,
};

/// A running `sandyd`, killed on drop so a failing assertion never leaves an orphan.
struct Daemon {
    child: Child,
    sock: std::path::PathBuf,
    /// The stand-in host-executor's connection, kept open so it stays registered with the daemon.
    _stand_in_host: Option<Box<dyn sandy_conn::Conn>>,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn base_command(dir: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_sandyd"));
    command
        .env("SANDY_SOCK", dir.join("sandyd.sock"))
        .env("SANDY_DB", dir.join("sandyd.db"))
        .env_remove("SANDY_ENV_BACKEND")
        .env_remove("SANDY_PROFILES")
        .env_remove("SANDY_MAX_JOBS")
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command
}

fn wait_for_socket(daemon: &Daemon) -> anyhow::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(10);
    while std::os::unix::net::UnixStream::connect(&daemon.sock).is_err() {
        anyhow::ensure!(Instant::now() < deadline, "sandyd never accepted a connection");
        std::thread::sleep(Duration::from_millis(20));
    }
    Ok(())
}

/// Start `sandyd` on `dir`'s socket and store, and wait until it accepts a connection.
fn start(dir: &Path) -> anyhow::Result<Daemon> {
    let child = base_command(dir).spawn().context("spawn sandyd")?;
    let daemon = Daemon {
        child,
        sock: dir.join("sandyd.sock"),
        _stand_in_host: None,
    };
    wait_for_socket(&daemon)?;
    Ok(daemon)
}

/// Start `sandyd` with its mesh and agent-link listeners on and a stand-in trusted process host registered over the
/// real mesh wire. A Submit with no capable host is refused (#868), so a test that needs a live, accepted job starts
/// the daemon this way. The stand-in never answers a Dispatch, so the job is left open.
async fn start_with_host(dir: &Path) -> anyhow::Result<Daemon> {
    use sandy_executor_proto::{
        Arch, Capabilities, HostExecutorMessage, IsolationClass as HostClass, OrchestratorMessage, Register,
        SandboxKind, host_executor_message, orchestrator_message,
    };

    let reserve = || -> anyhow::Result<(std::net::TcpListener, std::net::SocketAddr)> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").context("bind an ephemeral port")?;
        let addr = listener.local_addr()?;
        Ok((listener, addr))
    };
    let (mesh_reserved, mesh_addr) = reserve()?;
    let (link_reserved, link_addr) = reserve()?;
    // Pre-generate the orchestrator's mesh identity to learn its fingerprint before sandyd starts.
    let identity_dir = dir.join("mesh-tls");
    let orchestrator_fingerprint = sandy_conn::TlsIdentity::load_or_generate(&identity_dir)
        .context("pre-generating the orchestrator's mesh TLS identity")?
        .fingerprint();
    let host_identity = sandy_conn::TlsIdentity::generate().context("generate a stand-in host identity")?;
    drop((mesh_reserved, link_reserved));
    let child = base_command(dir)
        .env("SANDY_MESH_LISTEN", mesh_addr.to_string())
        .env(
            "SANDY_MESH_ALLOWLIST",
            format!("127.0.0.1={}", host_identity.fingerprint().to_hex()),
        )
        .env("SANDY_MESH_AGENT_LINK_LISTEN", link_addr.to_string())
        .env("SANDY_MESH_TLS_IDENTITY_DIR", &identity_dir)
        .spawn()
        .context("spawn sandyd")?;
    let mut daemon = Daemon {
        child,
        sock: dir.join("sandyd.sock"),
        _stand_in_host: None,
    };
    let deadline = Instant::now() + Duration::from_secs(20);
    while !(std::net::TcpStream::connect(mesh_addr).is_ok()
        && std::net::TcpStream::connect(link_addr).is_ok()
        && std::os::unix::net::UnixStream::connect(&daemon.sock).is_ok())
    {
        anyhow::ensure!(Instant::now() < deadline, "sandyd never opened its listeners");
        std::thread::sleep(Duration::from_millis(20));
    }

    let conn = async {
        let mut conn = sandy_conn::connect_tls(mesh_addr, &host_identity, orchestrator_fingerprint, None)
            .await
            .context("dialing the orchestrator's mesh listener over TLS")?;
        sandy_control_proto::write_frame(
            &mut conn,
            &HostExecutorMessage {
                op: Some(host_executor_message::Op::Register(Register {
                    host_id: "stand-in-host".to_owned(),
                    capabilities: Some(Capabilities {
                        digests: false,
                        supported_sandbox_kinds: vec![SandboxKind::Process.into()],
                        arch: Arch::X8664.into(),
                        attestation: false,
                        supported_isolation_classes: vec![HostClass::Trusted.into()],
                        shares_submitter_filesystem: false,
                        transfer: false,
                        egress_proxy: false,
                    }),
                })),
            },
        )
        .await
        .context("writing Register")?;
        let registered: OrchestratorMessage = sandy_control_proto::read_frame(&mut conn)
            .await
            .context("reading the Register response")?
            .context("connection closed before a Register response")?;
        anyhow::ensure!(
            matches!(registered.op, Some(orchestrator_message::Op::Registered(_))),
            "expected Registered, got {:?}",
            registered.op
        );
        Ok::<_, anyhow::Error>(conn)
    }
    .await?;
    daemon._stand_in_host = Some(conn);
    Ok(daemon)
}

async fn rpc(daemon: &Daemon, op: control_request::Op) -> anyhow::Result<control_response::Result> {
    let mut stream = tokio::net::UnixStream::connect(&daemon.sock)
        .await
        .context("connect to sandyd")?;
    let response = call(&mut stream, 1, op).await.context("control call")?;
    response.result.context("a response carries a result")
}

/// A real Submit to a live daemon that has a host to place on.
async fn submit_a_job(daemon: &Daemon) -> anyhow::Result<String> {
    let submit = SubmitRequest {
        manifest: b"opaque".to_vec(),
        manifest_encoding: "test/v1".to_owned(),
        required_isolation_class: IsolationClass::Trusted.into(),
        ..SubmitRequest::default()
    };
    match rpc(daemon, control_request::Op::Submit(submit)).await? {
        control_response::Result::Submit(ok) => Ok(ok.job_id),
        other => anyhow::bail!("expected the Submit to succeed, got {other:?}"),
    }
}

/// Leave a `Pending` row in `dir`'s store, as a daemon killed between accepting a job and dispatching it would.
/// A real Submit places the job and marks it `Running`, so this row state is written through the store directly.
fn seed_pending_job(dir: &Path) -> anyhow::Result<String> {
    let store = sandyd::store::JobStore::open(&dir.join("sandyd.db")).context("open the job store")?;
    let job_id = "seeded-pending-job".to_owned();
    store
        .insert_pending(&job_id, b"opaque", "test/v1")
        .context("insert the pending row")?;
    Ok(job_id)
}

async fn status(daemon: &Daemon, job_id: &str) -> anyhow::Result<sandy_control_proto::StatusResponse> {
    let request = control_request::Op::Status(StatusRequest {
        job_id: job_id.to_owned(),
    });
    match rpc(daemon, request).await? {
        control_response::Result::Status(status) => Ok(status),
        other => anyhow::bail!("expected a Status, got {other:?}"),
    }
}

/// Restart on `dir` (no host needed), assert `job_id` is `Failed` with a retryable infra-fault envelope, restart once
/// more and assert nothing was rewritten.
async fn assert_restart_fails_the_open_job_once(dir: &Path, job_id: &str) -> anyhow::Result<()> {
    let second = start(dir)?;
    let recovered = status(&second, job_id).await?;
    assert_eq!(
        recovered.status(),
        JobStatus::Failed,
        "the open job is failed, not left open"
    );
    let envelope: sandy::ResultEnvelope = serde_json::from_slice(
        &recovered
            .result_envelope
            .context("a recovered job carries an envelope")?,
    )
    .context("the envelope decodes")?;
    assert_eq!(envelope.status, sandy::Status::Failed);
    assert!(envelope.retryable, "a restart is an infrastructure fault: retryable");
    assert_eq!(envelope.job_id, job_id);
    assert!(envelope.message.contains("sandyd restarted"), "{:?}", envelope.message);
    let first_envelope = serde_json::to_string(&envelope)?;
    drop(second);

    let third = start(dir)?;
    let again = status(&third, job_id).await?;
    assert_eq!(again.status(), JobStatus::Failed);
    let again_envelope: sandy::ResultEnvelope =
        serde_json::from_slice(&again.result_envelope.context("the envelope stays")?)?;
    assert_eq!(
        serde_json::to_string(&again_envelope)?,
        first_envelope,
        "a second restart rewrites nothing"
    );
    Ok(())
}

/// `kill -9` a live daemon holding a really submitted job: the restarted daemon reports it `Failed`, with a retryable
/// infra-fault envelope, and a second restart changes nothing.
#[tokio::test]
async fn a_job_open_when_the_daemon_is_killed_is_failed_by_the_next_start() -> anyhow::Result<()> {
    let tmp = tempfile::tempdir().context("tempdir")?;
    let first = start_with_host(tmp.path()).await?;
    let job_id = submit_a_job(&first).await?;
    let before = status(&first, &job_id).await?.status();
    assert!(
        matches!(before, JobStatus::Pending | JobStatus::Running),
        "the accepted job is open, got {before:?}"
    );
    drop(first); // SIGKILL, then wait

    assert_restart_fails_the_open_job_once(tmp.path(), &job_id).await
}

/// A `Pending` row left in the store (accepted, never dispatched) is failed by the next start the same way.
#[tokio::test]
async fn a_pending_row_left_in_the_store_is_failed_by_the_next_start() -> anyhow::Result<()> {
    let tmp = tempfile::tempdir().context("tempdir")?;
    let job_id = seed_pending_job(tmp.path())?;

    assert_restart_fails_the_open_job_once(tmp.path(), &job_id).await
}
