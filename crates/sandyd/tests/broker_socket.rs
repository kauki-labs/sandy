//! The broker socket (#888): the real `sandyd` creates it only when `SANDYD_BROKER_SOCK` is set, privately, and honours
//! a client id only there.

use std::{
    ffi::OsStr,
    io::Read,
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
/// there is no second socket: the directory holds the main and the attach sockets only.
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
    let mut sockets: Vec<String> = std::fs::read_dir(other.path())?
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_ok_and(|t| t.is_socket()))
        .filter_map(|e| e.file_name().into_string().ok())
        .collect();
    sockets.sort();
    ensure!(
        sockets == ["main.sock", "sandyd-attach.sock"],
        "without SANDYD_BROKER_SOCK there are the main and the attach sockets only, found {sockets:?}"
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

/// Run `sandyd` with `SANDYD_BROKER_SOCK` set to `value` and return its exit code and log. A daemon that keeps running
/// is killed (its own child, nothing else) and the result is `None`.
fn run_with_broker_sock(dir: &Path, value: &OsStr) -> Result<(Option<i32>, String)> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_sandyd"))
        .env("SANDY_SOCK", dir.join("main.sock"))
        .env("SANDY_DB", dir.join("d.db"))
        .env("SANDYD_BROKER_SOCK", value)
        .env_remove("SANDY_ENV_BACKEND")
        .env_remove("SANDY_AUDIT_LOG")
        .env_remove("SANDY_MAX_JOBS")
        .env_remove("SANDY_MAX_ENVIRONMENTS")
        .env_remove("SANDY_PROFILES")
        .env("RUST_LOG", "info")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("spawn sandyd")?;
    let deadline = Instant::now() + Duration::from_secs(10);
    let code = loop {
        if let Some(status) = child.try_wait().context("wait for sandyd")? {
            break Some(status.code());
        }
        if Instant::now() >= deadline {
            child.kill().context("kill a daemon that did not exit")?;
            child.wait().context("reap sandyd")?;
            break None;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let mut log = String::new();
    child.stdout.take().context("stdout")?.read_to_string(&mut log)?;
    child.stderr.take().context("stderr")?.read_to_string(&mut log)?;
    Ok((code.flatten(), log))
}

/// A broker socket the daemon cannot trust stops it at start, exit 1, naming the cause: empty, relative, the main
/// socket or the attach socket itself, or a directory other than `SANDY_SOCK`'s (both paths named).
#[test]
fn a_broker_socket_that_cannot_be_trusted_stops_the_daemon_naming_it() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let elsewhere = tempfile::tempdir()?;
    let other_dir_sock = elsewhere.path().join("broker.sock");
    let main_sock = dir.path().join("main.sock");
    let attach_sock = dir.path().join("sandyd-attach.sock");
    let cases: [(&str, &OsStr, &str); 5] = [
        ("empty", OsStr::new(""), "empty"),
        ("relative", OsStr::new("broker.sock"), "absolute"),
        ("the main socket", main_sock.as_os_str(), "main socket"),
        ("the attach socket", attach_sock.as_os_str(), "attach socket"),
        ("another directory", other_dir_sock.as_os_str(), "same directory"),
    ];
    for (name, value, needle) in cases {
        let (code, log) = run_with_broker_sock(dir.path(), value)?;
        ensure!(
            code == Some(1),
            "{name}: exit {code:?} (None means it kept running): {log}"
        );
        ensure!(log.contains(needle), "{name}: the log must say `{needle}`: {log}");
        if name == "another directory" {
            ensure!(
                log.contains(&other_dir_sock.display().to_string()) && log.contains(&main_sock.display().to_string()),
                "{name}: the log must name both paths: {log}"
            );
        }
    }
    Ok(())
}

/// The directories are compared after links are resolved: a broker socket reached through a symlinked directory that is
/// the main socket's own directory is accepted, and the socket appears in that directory.
#[tokio::test]
async fn a_broker_socket_through_a_symlinked_directory_is_accepted() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let holder = tempfile::tempdir()?;
    let link = holder.path().join("link");
    std::os::unix::fs::symlink(dir.path(), &link)?;
    let via_link = link.join("broker.sock");
    let _daemon = start(dir.path(), Some(&via_link))?;

    wait_for_socket(&dir.path().join("broker.sock"), 5).context("the broker socket in the main directory")?;
    Ok(())
}
