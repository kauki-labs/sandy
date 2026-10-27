//! The binary over a unix socket: READY, tunnel, denial, head limits, the cap.

use std::{
    io::Write,
    path::Path,
    process::{Child, Command, Stdio},
    time::Duration,
};

use anyhow::{Context, Result};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UnixStream},
    time::timeout,
};

struct Proxy {
    child: Child,
    sock: std::path::PathBuf,
    _dir: tempfile::TempDir,
}

impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Spawn the proxy with `policy_json` on stdin and wait for its `READY` line.
fn start(policy_json: &str) -> Result<Proxy> {
    use std::io::{BufRead, BufReader};
    let dir = tempfile::tempdir()?;
    let sock = dir.path().join("proxy.sock");
    let mut child = Command::new(env!("CARGO_BIN_EXE_sandy-egress-proxy"))
        .arg("--unix")
        .arg(&sock)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .context("spawn proxy")?;
    child.stdin.take().context("stdin")?.write_all(policy_json.as_bytes())?;
    let mut line = String::new();
    BufReader::new(child.stdout.take().context("stdout")?).read_line(&mut line)?;
    anyhow::ensure!(line == "READY\n", "first line was {line:?}");
    Ok(Proxy { child, sock, _dir: dir })
}

async fn echo_upstream() -> Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                while let Ok(n) = s.read(&mut buf).await {
                    if n == 0 || s.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    Ok(port)
}

/// Raise the soft `RLIMIT_NOFILE` to `want`. `false` when the hard limit is lower.
fn raise_nofile(want: u64) -> bool {
    use rustix::process::{Resource, Rlimit, getrlimit, setrlimit};
    let limit = getrlimit(Resource::Nofile);
    if limit.current.is_some_and(|c| c >= want) {
        return true;
    }
    if limit.maximum.is_some_and(|m| m < want) {
        return false;
    }
    setrlimit(
        Resource::Nofile,
        Rlimit {
            current: Some(want),
            maximum: limit.maximum,
        },
    )
    .is_ok()
}

fn policy_for(host: &str, port: u16) -> String {
    format!(r#"{{"rules":[{{"host":"{host}","port":{port}}}]}}"#)
}

async fn connect(sock: &Path) -> Result<UnixStream> {
    Ok(UnixStream::connect(sock).await?)
}

async fn read_to_end(s: &mut UnixStream) -> Result<String> {
    let mut out = Vec::new();
    timeout(Duration::from_secs(5), s.read_to_end(&mut out))
        .await
        .context("read timed out")??;
    Ok(String::from_utf8_lossy(&out).into_owned())
}

#[tokio::test]
async fn an_allowed_tunnel_round_trips_bytes_including_those_sent_with_the_head() -> Result<()> {
    let port = echo_upstream().await?;
    let proxy = start(&policy_for("127.0.0.1", port))?;
    let mut s = connect(&proxy.sock).await?;
    s.write_all(format!("CONNECT 127.0.0.1:{port} HTTP/1.1\r\n\r\nearly").as_bytes())
        .await?;
    let mut buf = vec![0u8; 64];
    let mut got = Vec::new();
    while !got.windows(5).any(|w| w == b"early") {
        let n = timeout(Duration::from_secs(5), s.read(&mut buf))
            .await
            .context("timeout")??;
        anyhow::ensure!(n > 0, "closed early: {:?}", String::from_utf8_lossy(&got));
        got.extend_from_slice(&buf[..n]);
    }
    let text = String::from_utf8_lossy(&got);
    assert!(text.starts_with("HTTP/1.1 200"), "{text}");
    s.write_all(b"ping").await?;
    let mut echoed = [0u8; 4];
    timeout(Duration::from_secs(5), s.read_exact(&mut echoed))
        .await
        .context("timeout")??;
    assert_eq!(&echoed, b"ping");
    Ok(())
}

#[tokio::test]
async fn a_denied_target_gets_403_naming_it() -> Result<()> {
    let proxy = start(&policy_for("allowed.example", 443))?;
    let mut s = connect(&proxy.sock).await?;
    s.write_all(b"CONNECT evil.example:443 HTTP/1.1\r\n\r\n").await?;
    let text = read_to_end(&mut s).await?;
    assert!(text.starts_with("HTTP/1.1 403"), "{text}");
    assert!(text.contains("evil.example:443"), "{text}");
    Ok(())
}

#[tokio::test]
async fn a_non_connect_method_gets_405() -> Result<()> {
    let proxy = start(&policy_for("allowed.example", 443))?;
    let mut s = connect(&proxy.sock).await?;
    s.write_all(b"GET http://allowed.example/ HTTP/1.1\r\n\r\n").await?;
    assert!(read_to_end(&mut s).await?.starts_with("HTTP/1.1 405"));
    Ok(())
}

#[tokio::test]
async fn a_head_over_eight_kib_is_closed_unanswered() -> Result<()> {
    let proxy = start(&policy_for("allowed.example", 443))?;
    let mut s = connect(&proxy.sock).await?;
    // The proxy closes with bytes unread: Linux then resets the connection
    // where macOS gives a clean EOF. Either is "closed"; no answer may arrive.
    let _ = s.write_all(&vec![b'a'; 9 * 1024]).await;
    let mut out = Vec::new();
    let read = timeout(Duration::from_secs(5), s.read_to_end(&mut out))
        .await
        .context("read timed out")?;
    if let Err(e) = read {
        anyhow::ensure!(
            e.kind() == std::io::ErrorKind::ConnectionReset,
            "unexpected read error: {e}"
        );
    }
    assert!(out.is_empty(), "answered: {:?}", String::from_utf8_lossy(&out));
    Ok(())
}

#[tokio::test]
async fn a_head_that_never_completes_is_closed_at_the_deadline() -> Result<()> {
    let proxy = start(&policy_for("allowed.example", 443))?;
    let mut s = connect(&proxy.sock).await?;
    s.write_all(b"CONNECT allowed.exa").await?;
    let mut out = Vec::new();
    timeout(Duration::from_secs(15), s.read_to_end(&mut out))
        .await
        .context("not closed within 15s")??;
    assert!(out.is_empty());
    Ok(())
}

#[tokio::test]
async fn connection_257_is_closed_at_accept() -> Result<()> {
    // 256 held sockets, their proxy-side peers, and the listener need more
    // descriptors than a 256 soft limit gives. The proxy child inherits the raise.
    if !raise_nofile(1024) {
        eprintln!("skipped: the hard RLIMIT_NOFILE is below 1024");
        return Ok(());
    }
    let proxy = start(&policy_for("allowed.example", 443))?;
    // Idle connections hold a slot while the proxy waits for their head.
    let mut held = Vec::new();
    for _ in 0..256 {
        held.push(connect(&proxy.sock).await?);
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    let mut extra = connect(&proxy.sock).await?;
    assert_eq!(read_to_end(&mut extra).await?, "");
    // A held slot still works: it is answered, not dropped.
    held[0].write_all(b"GET / HTTP/1.1\r\n\r\n").await?;
    assert!(read_to_end(&mut held[0]).await?.starts_with("HTTP/1.1 405"));
    Ok(())
}

#[test]
fn a_malformed_policy_exits_without_ready() -> Result<()> {
    use std::io::Read;
    let dir = tempfile::tempdir()?;
    for bad in ["not json", r#"{"rules":[{"host":"a_b.example","port":443}]}"#] {
        let mut child = Command::new(env!("CARGO_BIN_EXE_sandy-egress-proxy"))
            .arg("--unix")
            .arg(dir.path().join("p.sock"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        child.stdin.take().context("stdin")?.write_all(bad.as_bytes())?;
        let mut out = String::new();
        child.stdout.take().context("stdout")?.read_to_string(&mut out)?;
        assert!(!child.wait()?.success(), "{bad}");
        assert!(!out.contains("READY"), "{bad}: {out:?}");
    }
    Ok(())
}
