//! `sandy-agent egress-relay --vsock-port <P> -- <rest>` (#402): the guest side
//! of the egress proxy (`docs/decisions/egress-proxy.md` decision 1).
//!
//! The guest has no NIC, so a client needs a local endpoint to reach the host
//! proxy. The relay binds `127.0.0.1:3128` before it starts `<rest>`, so no job
//! process can start before the listener exists. For each accepted connection it
//! opens one stream to the host and copies bytes both ways until either side
//! closes. It never parses HTTP: the host proxy is the only enforcement point, so
//! a root job that kills the relay or dials the host directly meets the same checks.
//!
//! `<rest>` runs as the relay's child with the proxy variables added, and the
//! relay exits with the child's status (`128 + signal` for a signal death), so the
//! console protocol's `exit=<n>` is unchanged.

#![cfg_attr(
    not(target_os = "linux"),
    allow(dead_code, reason = "the relay runs only in a Linux guest; tests drive the seam")
)]

use std::{
    ffi::OsString,
    future::Future,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    process::ExitStatus,
    sync::Arc,
    time::Duration,
};

use tokio::{
    io::{AsyncRead, AsyncWrite, copy_bidirectional},
    net::{TcpListener, TcpStream},
};

/// Where the relay listens, and what the proxy variables name.
pub const PROXY_ADDR: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 3128);

/// The vsock CID of the host proxy's side of the stream.
#[cfg_attr(
    not(target_os = "linux"),
    allow(dead_code, reason = "vsock is Linux-only; tests drive the seam")
)]
const HOST_CID: u32 = 2;

/// How the relay opens one stream to the host proxy. A seam so a test can
/// substitute a unix socket for vsock, which exists only in a Linux guest.
pub trait Connector: Send + Sync + 'static {
    /// One stream to the host proxy.
    type Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static;
    /// Open a new stream to the host proxy.
    fn connect(&self) -> impl Future<Output = io::Result<Self::Stream>> + Send;
}

/// The vsock connector: the host (CID 2) at the proxy's port.
#[cfg(target_os = "linux")]
pub struct VsockConnector {
    /// The host proxy's vsock port.
    pub port: u32,
}

#[cfg(target_os = "linux")]
impl Connector for VsockConnector {
    type Stream = tokio_vsock::VsockStream;

    async fn connect(&self) -> io::Result<Self::Stream> {
        tokio_vsock::VsockStream::connect(tokio_vsock::VsockAddr::new(HOST_CID, self.port)).await
    }
}

const USAGE: &str = "usage: sandy-agent egress-relay --vsock-port PORT -- <rest> [args...]";

/// Parse `--vsock-port PORT -- <rest> [args...]` (the arguments after `egress-relay`).
pub fn parse_args(args: &[OsString]) -> Result<(u32, Vec<OsString>), String> {
    let (flag, rest) = args.split_first().ok_or(USAGE)?;
    if flag != "--vsock-port" {
        return Err(USAGE.to_string());
    }
    let (port, rest) = rest.split_first().ok_or(USAGE)?;
    // u32::MAX is VMADDR_PORT_ANY: it is not a port the host proxy can listen on.
    let port = port
        .to_str()
        .and_then(|p| p.parse::<u32>().ok())
        .filter(|&p| p != u32::MAX)
        .ok_or_else(|| format!("--vsock-port needs a port number below {}; {USAGE}", u32::MAX))?;
    match rest.split_first() {
        Some((dashdash, job)) if dashdash == "--" && !job.is_empty() => Ok((port, job.to_vec())),
        _ => Err(USAGE.to_string()),
    }
}

/// The variables a client needs to use the relay. Both cases are set because curl
/// honours only the lowercase `http_proxy`. `ALL_PROXY` is not set. `NO_PROXY`
/// keeps loopback traffic inside the guest.
#[must_use]
pub fn proxy_env(addr: SocketAddr) -> [(&'static str, String); 6] {
    let url = format!("http://{addr}");
    let no_proxy = "localhost,127.0.0.1,::1".to_string();
    [
        ("HTTPS_PROXY", url.clone()),
        ("https_proxy", url.clone()),
        ("HTTP_PROXY", url.clone()),
        ("http_proxy", url),
        ("NO_PROXY", no_proxy.clone()),
        ("no_proxy", no_proxy),
    ]
}

/// The `egress-relay` entry point: bind, start `<rest>`, relay until it exits, and
/// exit with its status. A usage or bind failure aborts like any agent-internal
/// failure, so the backend reports an infra fault, never a job exit code.
#[cfg(target_os = "linux")]
pub fn cli(args: &[OsString]) -> std::process::ExitCode {
    let (port, rest) = parse_args(args).unwrap_or_else(|usage| crate::fail(&usage));
    // Bound here, before the runtime starts the child: no job process can run first.
    let std_listener = std::net::TcpListener::bind(PROXY_ADDR)
        .and_then(|l| l.set_nonblocking(true).map(|()| l))
        .unwrap_or_else(|e| crate::fail(&format!("binding {PROXY_ADDR} for the egress relay: {e}")));
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|e| crate::fail(&format!("starting the runtime: {e}")));
    let result = runtime.block_on(async {
        let listener = TcpListener::from_std(std_listener)?;
        run(listener, Arc::new(VsockConnector { port }), &rest).await
    });
    match result {
        Ok(status) => std::process::ExitCode::from(crate::exit_code(status)),
        Err(e) => crate::fail(&format!("running the egress relay's command: {e}")),
    }
}

/// vsock exists only inside a Linux guest.
#[cfg(not(target_os = "linux"))]
pub fn cli(args: &[OsString]) -> std::process::ExitCode {
    let (port, _rest) = parse_args(args).unwrap_or_else(|usage| crate::fail(&usage));
    crate::fail(&format!(
        "--vsock-port {port}: vsock is only available inside a Linux guest"
    ))
}

/// Accept connections on `listener` and relay each to a fresh stream from
/// `connector`. Runs until its task is dropped.
pub async fn serve<C: Connector>(listener: TcpListener, connector: Arc<C>) {
    loop {
        match listener.accept().await {
            Ok((client, _)) => {
                tokio::spawn(relay_one(client, Arc::clone(&connector)));
            }
            Err(e) => {
                // EMFILE and friends are not a listener failure: stop serving and every
                // tunnel dies with it. Log, back off, and keep going.
                eprintln!("sandy-agent: egress-relay accept failed: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

/// Relay one client. An upstream connect failure closes this connection only.
async fn relay_one<C: Connector>(mut client: TcpStream, connector: Arc<C>) {
    let mut upstream = match connector.connect().await {
        Ok(upstream) => upstream,
        Err(e) => {
            eprintln!("sandy-agent: egress-relay cannot reach the host proxy: {e}");
            return;
        }
    };
    // Copies both ways, and half-closes the far side when one side reaches EOF.
    if let Err(e) = copy_bidirectional(&mut client, &mut upstream).await {
        eprintln!("sandy-agent: egress-relay connection ended: {e}");
    }
}

/// Start `rest` as a child with the proxy variables, serve `listener` while it
/// runs, and return its status. `listener` is already bound, so the child can
/// connect to it as its first action.
///
/// # Errors
/// An I/O error starting or waiting for the child.
pub async fn run<C: Connector>(listener: TcpListener, connector: Arc<C>, rest: &[OsString]) -> io::Result<ExitStatus> {
    let (program, args) = rest
        .split_first()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "empty command"))?;
    let mut command = tokio::process::Command::new(program);
    command.args(args).kill_on_drop(true);
    for (name, value) in proxy_env(listener.local_addr()?) {
        command.env(name, value);
    }
    let mut child = command.spawn()?;
    let server = tokio::spawn(serve(listener, connector));
    let status = child.wait().await;
    server.abort();
    status
}

#[cfg(test)]
mod tests {
    use std::{
        os::unix::process::ExitStatusExt,
        sync::atomic::{AtomicUsize, Ordering},
    };

    use anyhow::Context;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{UnixListener, UnixStream},
    };

    use super::*;

    /// Connects to a unix socket in place of the host's vsock.
    struct UnixConnector(std::path::PathBuf);

    impl Connector for UnixConnector {
        type Stream = UnixStream;

        async fn connect(&self) -> io::Result<UnixStream> {
            UnixStream::connect(&self.0).await
        }
    }

    /// Fails the first `failures` connects, then behaves like [`UnixConnector`].
    struct FlakyConnector {
        inner: UnixConnector,
        failures: usize,
        calls: AtomicUsize,
    }

    impl Connector for FlakyConnector {
        type Stream = UnixStream;

        async fn connect(&self) -> io::Result<UnixStream> {
            if self.calls.fetch_add(1, Ordering::SeqCst) < self.failures {
                return Err(io::Error::new(io::ErrorKind::ConnectionRefused, "scripted failure"));
            }
            self.inner.connect().await
        }
    }

    fn args(items: &[&str]) -> Vec<OsString> {
        items.iter().map(OsString::from).collect()
    }

    async fn loopback() -> anyhow::Result<TcpListener> {
        TcpListener::bind("127.0.0.1:0").await.context("bind a test relay port")
    }

    #[test]
    fn the_args_parse_into_a_port_and_the_rest() {
        assert_eq!(
            parse_args(&args(&["--vsock-port", "5001", "--", "sh", "-c", "true"])),
            Ok((5001, args(&["sh", "-c", "true"])))
        );
    }

    #[test]
    fn malformed_args_are_refused() {
        for bad in [
            &[][..],
            &["--vsock-port"],
            &["--vsock-port", "x", "--", "sh"],
            &["--vsock-port", "4294967295", "--", "sh"],
            &["--vsock-port", "5001"],
            &["--vsock-port", "5001", "--"],
            &["--vsock-port", "5001", "sh"],
            &["--vsock-listen", "5001", "--", "sh"],
        ] {
            assert!(parse_args(&args(bad)).is_err(), "{bad:?} must be refused");
        }
    }

    /// The six variables with their exact values, and no `ALL_PROXY`.
    #[test]
    fn the_proxy_variables_carry_the_exact_values() {
        let env = proxy_env(PROXY_ADDR);
        let url = "http://127.0.0.1:3128";
        let no_proxy = "localhost,127.0.0.1,::1";
        assert_eq!(
            env.iter().map(|(n, v)| (*n, v.as_str())).collect::<Vec<_>>(),
            vec![
                ("HTTPS_PROXY", url),
                ("https_proxy", url),
                ("HTTP_PROXY", url),
                ("http_proxy", url),
                ("NO_PROXY", no_proxy),
                ("no_proxy", no_proxy),
            ]
        );
        assert!(env.iter().all(|(n, _)| !n.eq_ignore_ascii_case("ALL_PROXY")));
    }

    /// The child sees those variables in its real environment, and the relay adds no `ALL_PROXY`.
    #[tokio::test]
    async fn the_child_environment_carries_the_proxy_variables() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let out = dir.path().join("env.txt");
        let listener = loopback().await?;
        let url = format!("http://{}", listener.local_addr()?);
        let connector = Arc::new(UnixConnector(dir.path().join("unused.sock")));
        let script = format!("env > {}", out.display());
        let status = run(listener, connector, &args(&["sh", "-c", &script])).await?;
        anyhow::ensure!(status.success(), "child failed: {status:?}");
        let env = std::fs::read_to_string(&out)?;
        for name in ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"] {
            assert!(env.contains(&format!("{name}={url}\n")), "{name} missing from:\n{env}");
        }
        for name in ["NO_PROXY", "no_proxy"] {
            assert!(
                env.contains(&format!("{name}=localhost,127.0.0.1,::1\n")),
                "{name} missing from:\n{env}"
            );
        }
        // The relay never adds `ALL_PROXY`: the child has it only if this process did.
        assert_eq!(
            env.lines().any(|l| l.starts_with("ALL_PROXY=")),
            std::env::var_os("ALL_PROXY").is_some()
        );
        Ok(())
    }

    /// The listener exists before the child starts: connecting is the child's first action.
    #[tokio::test]
    async fn the_listener_is_bound_before_the_child_starts() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let listener = loopback().await?;
        let port = listener.local_addr()?.port();
        let connector = Arc::new(UnixConnector(dir.path().join("unused.sock")));
        let script = format!("exec 3<>/dev/tcp/127.0.0.1/{port}");
        let status = run(listener, connector, &args(&["bash", "-c", &script])).await?;
        assert!(status.success(), "the child could not connect first thing: {status:?}");
        Ok(())
    }

    /// Bytes reach the upstream unchanged and the reply comes back, across a half-close:
    /// the upstream sees EOF only because the client's `shutdown` was forwarded.
    #[tokio::test]
    async fn bytes_cross_both_ways_including_a_half_close() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let sock = dir.path().join("upstream.sock");
        let upstream = UnixListener::bind(&sock)?;
        let upstream_task = tokio::spawn(async move {
            let (mut s, _) = upstream.accept().await?;
            let mut got = Vec::new();
            s.read_to_end(&mut got).await?; // returns only once the client's half-close arrives
            s.write_all(&got.iter().rev().copied().collect::<Vec<u8>>()).await?;
            s.shutdown().await?;
            io::Result::Ok(got)
        });

        let listener = loopback().await?;
        let addr = listener.local_addr()?;
        let relay = tokio::spawn(run(
            listener,
            Arc::new(UnixConnector(sock)),
            args(&["sleep", "30"]).leak(),
        ));

        let mut client = TcpStream::connect(addr).await?;
        let payload: Vec<u8> = (0..=255u8).cycle().take(100_000).collect();
        client.write_all(&payload).await?;
        client.shutdown().await?;
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).await?;

        assert_eq!(
            upstream_task.await??,
            payload,
            "the upstream must see the bytes unchanged"
        );
        assert_eq!(reply, payload.iter().rev().copied().collect::<Vec<u8>>());
        relay.abort();
        Ok(())
    }

    /// The relay's status is the child's: 0, a nonzero code, and a signal death.
    #[tokio::test]
    async fn the_relay_status_is_the_childs() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        for (script, expected) in [("exit 0", 0u8), ("exit 7", 7), ("kill -9 $$", 137)] {
            let connector = Arc::new(UnixConnector(dir.path().join("unused.sock")));
            let status = run(loopback().await?, connector, &args(&["sh", "-c", script])).await?;
            assert_eq!(crate::exit_code(status), expected, "{script}");
        }
        let signalled = run(
            loopback().await?,
            Arc::new(UnixConnector(dir.path().join("unused.sock"))),
            &args(&["sh", "-c", "kill -9 $$"]),
        )
        .await?;
        assert_eq!(signalled.signal(), Some(9));
        Ok(())
    }

    /// An upstream connect failure closes that one client and the relay keeps serving.
    #[tokio::test]
    async fn an_upstream_connect_failure_closes_only_that_client() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let sock = dir.path().join("upstream.sock");
        let upstream = UnixListener::bind(&sock)?;
        tokio::spawn(async move {
            while let Ok((mut s, _)) = upstream.accept().await {
                let mut got = Vec::new();
                let _ = s.read_to_end(&mut got).await;
                let _ = s.write_all(b"served").await;
            }
        });
        let connector = Arc::new(FlakyConnector {
            inner: UnixConnector(sock),
            failures: 1,
            calls: AtomicUsize::new(0),
        });
        let listener = loopback().await?;
        let addr = listener.local_addr()?;
        let relay = tokio::spawn(run(listener, connector, args(&["sleep", "30"]).leak()));

        // The first client's upstream connect fails: it is closed with no data.
        let mut first = TcpStream::connect(addr).await?;
        let mut sink = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), first.read_to_end(&mut sink))
            .await
            .context("the failed client was not closed")??;
        assert!(sink.is_empty());

        // The relay is still serving: the second client goes through.
        let mut second = TcpStream::connect(addr).await?;
        second.shutdown().await?;
        let mut reply = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), second.read_to_end(&mut reply))
            .await
            .context("the second client got no reply")??;
        assert_eq!(reply, b"served");
        relay.abort();
        Ok(())
    }
}
