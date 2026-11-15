//! The real `sandy-broker` binary in mTLS mode (#887): an operator can learn the fingerprint to pin without setting a
//! log filter, and that value is the one a pinned caller connects with.

use std::{
    io::{BufRead, BufReader},
    os::unix::fs::PermissionsExt,
    process::{Child, Command, Stdio},
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use sandy_conn::{Fingerprint, TlsIdentity};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// A broker this test started. Dropping it kills that child, and nothing else.
struct Broker(Child);

impl Drop for Broker {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The broker prints `broker mTLS fingerprint: <64 hex digits>` on stdout, with no `RUST_LOG` set (the default log
/// filter shows errors only, so a log line would be invisible to the operator who has to pin it). A caller pinned to
/// that value, with a certificate the clients file pins, reaches the broker and is authenticated: the status is `503
/// unavailable` because no `sandyd` is behind this broker, not `401 unauthenticated`.
#[tokio::test]
async fn the_binary_prints_the_fingerprint_a_pinned_caller_connects_with() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let caller = TlsIdentity::generate()?;
    let clients = dir.path().join("clients.json");
    std::fs::write(
        &clients,
        format!(
            r#"[{{"id":"remote-a","certs":[{{"sha256":"{}"}}],"max_isolation_class":"untrusted","roots":[]}}]"#,
            caller.fingerprint().to_hex()
        ),
    )?;
    std::fs::set_permissions(&clients, std::fs::Permissions::from_mode(0o600))?;
    let port = std::net::TcpListener::bind("127.0.0.1:0")?.local_addr()?.port();

    let mut child = Command::new(env!("CARGO_BIN_EXE_sandy-broker"))
        .args(["--control-socket"])
        .arg(dir.path().join("none.sock"))
        .arg("--state-dir")
        .arg(dir.path().join("state"))
        .arg("--clients-file")
        .arg(&clients)
        .arg("--bind")
        .arg(format!("0.0.0.0:{port}"))
        .arg("--tls-identity-dir")
        .arg(dir.path().join("tls"))
        .env_remove("RUST_LOG")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .context("spawn sandy-broker")?;
    let stdout = child.stdout.take().context("the broker's stdout")?;
    let _broker = Broker(child);

    // Read stdout on a thread: a broker that prints nothing must fail the test at the deadline, not hang it.
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    let line = rx
        .recv_timeout(Duration::from_secs(30))
        .context("the broker printed nothing on stdout within 30 s")?;
    let printed = line
        .strip_prefix("broker mTLS fingerprint: ")
        .with_context(|| format!("not the fingerprint line: {line:?}"))?;
    ensure!(printed.len() == 64, "a fingerprint is 64 hex digits: {printed:?}");
    let broker = Fingerprint::from_hex(printed).context("the printed fingerprint parses")?;

    let mut conn = sandy_conn::connect_tls(([127, 0, 0, 1], port).into(), &caller, broker, None)
        .await
        .context("a caller pinned to the printed fingerprint connects")?;
    conn.write_all(b"GET /v1/jobs HTTP/1.1\r\nHost: broker\r\nConnection: close\r\n\r\n")
        .await?;
    let mut response = Vec::new();
    conn.read_to_end(&mut response).await.context("read the response")?;
    let head = String::from_utf8_lossy(&response);
    ensure!(
        head.starts_with("HTTP/1.1 503"),
        "an authenticated caller with no sandyd behind the broker gets 503, not 401: {head}"
    );
    Ok(())
}
