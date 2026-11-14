//! A killed `sandyd` leaves no job open (#830): the next start fails it, with the result envelope a caller reads.

use std::{
    path::Path,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use anyhow::Context;
use sandy_control_proto::{JobStatus, StatusRequest, client::call, control_request, control_response};

/// A running `sandyd`, killed on drop so a failing assertion never leaves an orphan.
struct Daemon {
    child: Child,
    sock: std::path::PathBuf,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Start `sandyd` on `dir`'s socket and store, and wait until it accepts a connection.
fn start(dir: &Path) -> anyhow::Result<Daemon> {
    let sock = dir.join("sandyd.sock");
    let child = Command::new(env!("CARGO_BIN_EXE_sandyd"))
        .env("SANDY_SOCK", &sock)
        .env("SANDY_DB", dir.join("sandyd.db"))
        .env_remove("SANDY_ENV_BACKEND")
        .env_remove("SANDY_PROFILES")
        .env_remove("SANDY_MAX_JOBS")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("spawn sandyd")?;
    let daemon = Daemon { child, sock };
    let deadline = Instant::now() + Duration::from_secs(10);
    while std::os::unix::net::UnixStream::connect(&daemon.sock).is_err() {
        anyhow::ensure!(Instant::now() < deadline, "sandyd never accepted a connection");
        std::thread::sleep(Duration::from_millis(20));
    }
    Ok(daemon)
}

async fn rpc(daemon: &Daemon, op: control_request::Op) -> anyhow::Result<control_response::Result> {
    let mut stream = tokio::net::UnixStream::connect(&daemon.sock)
        .await
        .context("connect to sandyd")?;
    let response = call(&mut stream, 1, op).await.context("control call")?;
    response.result.context("a response carries a result")
}

/// Leave a `Pending` row in `dir`'s store, as a daemon killed with an open job would. A Submit with no host is
/// refused (#868), so the row is written through the store directly.
fn seed_open_job(dir: &Path) -> anyhow::Result<String> {
    let store = sandyd::store::JobStore::open(&dir.join("sandyd.db")).context("open the job store")?;
    let job_id = "seeded-open-job".to_owned();
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

/// A daemon killed with a job open leaves a `Pending` row: the restarted daemon reports it `Failed`, with a retryable
/// infra-fault envelope, and a second restart changes nothing.
#[tokio::test]
async fn a_job_open_when_the_daemon_is_killed_is_failed_by_the_next_start() -> anyhow::Result<()> {
    let tmp = tempfile::tempdir().context("tempdir")?;
    let job_id = seed_open_job(tmp.path())?;

    let second = start(tmp.path())?;
    let recovered = status(&second, &job_id).await?;
    assert_eq!(
        recovered.status(),
        JobStatus::Failed,
        "the open job is failed, not left Pending"
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

    let third = start(tmp.path())?;
    let again = status(&third, &job_id).await?;
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
