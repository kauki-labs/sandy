//! The broker socket (#888): the real `sandyd` creates it only when `SANDYD_BROKER_SOCK` is set, privately, and honours
//! a client id only there.

use std::{
    os::unix::fs::{FileTypeExt, PermissionsExt},
    path::Path,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, ensure};
use sandy_control_proto::{SubmitRequest, client::call, control_request, control_response};
use tokio::net::UnixStream;

/// A `sandyd` this test started. Dropping it kills that child, and nothing else.
struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn start(dir: &Path, broker: Option<&Path>) -> Result<Daemon> {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_sandyd"));
    cmd.env("SANDY_SOCK", dir.join("main.sock"))
        .env("SANDY_DB", dir.join("d.db"))
        .env_remove("SANDY_ENV_BACKEND")
        .env_remove("SANDY_AUDIT_LOG")
        .env_remove("SANDY_MAX_JOBS")
        .env_remove("SANDY_MAX_ENVIRONMENTS")
        .env_remove("SANDY_PROFILES")
        .env_remove("SANDYD_BROKER_SOCK")
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if let Some(broker) = broker {
        cmd.env("SANDYD_BROKER_SOCK", broker);
    }
    let daemon = Daemon(cmd.spawn().context("spawn sandyd")?);
    wait_for_socket(&dir.join("main.sock"), 20)?;
    Ok(daemon)
}

fn wait_for_socket(path: &Path, secs: u64) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while std::os::unix::net::UnixStream::connect(path).is_err() {
        ensure!(
            Instant::now() < deadline,
            "nothing accepted on {} within {secs}s",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    Ok(())
}

fn submit() -> control_request::Op {
    control_request::Op::Submit(SubmitRequest {
        client_id: Some("alice".to_owned()),
        manifest: b"m".to_vec(),
        manifest_encoding: "test/v1".to_owned(),
        required_isolation_class: sandy_control_proto::IsolationClass::Trusted.into(),
        ..SubmitRequest::default()
    })
}

fn refusal(response: sandy_control_proto::ControlResponse) -> Result<String> {
    match response.result {
        Some(control_response::Result::Error(e)) => Ok(e.message),
        other => anyhow::bail!("expected a refusal, got {other:?}"),
    }
}

/// With `SANDYD_BROKER_SOCK` set the daemon listens on a second socket, a socket file of mode `0600`. With it unset
/// there is no second socket: the directory holds the main socket only.
#[tokio::test]
async fn the_broker_socket_exists_only_when_configured_and_is_private() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let broker = dir.path().join("broker.sock");
    {
        let _daemon = start(dir.path(), Some(&broker))?;
        wait_for_socket(&broker, 5).context("the broker socket")?;
        let meta = std::fs::symlink_metadata(&broker)?;
        ensure!(meta.file_type().is_socket(), "{} is not a socket", broker.display());
        ensure!(
            meta.permissions().mode() & 0o777 == 0o600,
            "mode {:o}, want 600",
            meta.permissions().mode() & 0o777
        );
    }

    let other = tempfile::tempdir()?;
    let _daemon = start(other.path(), None)?;
    let sockets = std::fs::read_dir(other.path())?
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_ok_and(|t| t.is_socket()))
        .count();
    ensure!(
        sockets == 1,
        "without SANDYD_BROKER_SOCK there is only the main socket, found {sockets}"
    );
    Ok(())
}

/// A Submit with a client id is refused on the main socket naming the field, and is not refused for the field on the
/// broker socket (it fails later for placement: this daemon has no host).
#[tokio::test]
async fn a_client_id_is_refused_on_the_main_socket_and_honoured_on_the_broker_socket() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let broker = dir.path().join("broker.sock");
    let _daemon = start(dir.path(), Some(&broker))?;
    wait_for_socket(&broker, 5).context("the broker socket")?;

    let mut main = UnixStream::connect(dir.path().join("main.sock")).await?;
    let on_main = refusal(call(&mut main, 1, submit()).await?)?;
    ensure!(
        on_main.contains("client_id"),
        "the main socket must name the field: {on_main}"
    );

    let mut broker_conn = UnixStream::connect(&broker).await?;
    let on_broker = refusal(call(&mut broker_conn, 1, submit()).await?)?;
    ensure!(
        !on_broker.contains("client_id"),
        "the broker socket must not refuse the client id: {on_broker}"
    );
    Ok(())
}
