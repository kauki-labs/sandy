//! `sandy-agent port-relay --vsock-port <P> --to <127.0.0.1:T>` (#590): the guest half of the host-side
//! bridge to a guest service port.
//!
//! The service (for example `t3 serve`) listens on guest loopback, which the host cannot reach. The relay listens
//! on vsock port `P` and, for each connection from the host, dials `127.0.0.1:T` and copies bytes both ways. It
//! parses nothing: the host bridge owns TLS and auth. It admits only the host (CID 2), so a guest-local process on
//! vsock loopback, or another guest, cannot use it. This is the egress relay run in the other direction
//! (`docs/decisions/egress-proxy.md` decision 1).

#![cfg_attr(
    not(target_os = "linux"),
    allow(dead_code, reason = "the relay runs only in a Linux guest; tests drive the seam")
)]

use std::{
    ffi::OsString,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use sandy_api::agent::PORT_RELAY_READY;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, split},
    net::TcpStream,
    sync::Semaphore,
    time::{Instant, timeout},
};

use crate::link_source::{Acceptor, HOST_CID};

const USAGE: &str = "usage: sandy-agent port-relay --vsock-port PORT --to 127.0.0.1:PORT";

/// Parse `--vsock-port PORT --to ADDR` (the arguments after `port-relay`). The target must be an IPv4 loopback
/// address with a real port: the relay never forwards off the guest's loopback.
pub fn parse_args(args: &[OsString]) -> Result<(u32, SocketAddr), String> {
    let [port_flag, port, to_flag, target] = args else {
        return Err(USAGE.to_string());
    };
    if port_flag != "--vsock-port" || to_flag != "--to" {
        return Err(USAGE.to_string());
    }
    // u32::MAX is VMADDR_PORT_ANY: the kernel would bind some other port, and the host could never reach the relay.
    let port = port
        .to_str()
        .and_then(|p| p.parse::<u32>().ok())
        .filter(|&p| p != u32::MAX)
        .ok_or_else(|| format!("--vsock-port needs a port number below {}; {USAGE}", u32::MAX))?;
    let target = target
        .to_str()
        .and_then(|t| t.parse::<SocketAddr>().ok())
        .filter(|t| t.ip() == IpAddr::V4(Ipv4Addr::LOCALHOST) && t.port() != 0)
        .ok_or_else(|| format!("--to needs a 127.0.0.1 address with a port; {USAGE}"))?;
    Ok((port, target))
}

/// The most host connections relayed at once. Over the cap a connection is closed unanswered, so a flood from the
/// host cannot exhaust the relay's descriptors or the service's.
pub const MAX_CONNECTIONS: usize = 256;

/// How long one dial to the target may take. Loopback answers at once, so a longer wait means the service's accept
/// backlog is full, and the connection is closed instead of holding a task and a descriptor for minutes.
const DIAL_TIMEOUT: Duration = Duration::from_secs(5);

/// How long a connection may carry no byte in either direction before it is closed. Without it a peer that sends
/// the ready byte and then goes silent pins a slot and two descriptors for good, and enough of them refuse everyone.
/// Fifteen minutes is far above a websocket's keepalive interval.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(15 * 60);

/// Accept connections on `acceptor` and relay each host connection to `target`. Runs until its task is dropped.
pub async fn serve<A>(acceptor: A, target: SocketAddr)
where
    A: Acceptor + Send + 'static,
    A::Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    serve_with_cap(acceptor, target, MAX_CONNECTIONS, IDLE_TIMEOUT).await;
}

/// [`serve`] with an explicit cap on concurrent connections and an idle limit per connection.
///
/// A peer that is not the host is closed at once and the target is never dialed for it, so a guest-local process
/// on vsock loopback cannot use the relay. Each connection runs in its own task, so a long-lived one (a websocket)
/// does not block the next.
pub async fn serve_with_cap<A>(mut acceptor: A, target: SocketAddr, cap: usize, idle: Duration)
where
    A: Acceptor + Send + 'static,
    A::Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let slots = Arc::new(Semaphore::new(cap));
    loop {
        match acceptor.accept().await {
            Ok((stream, HOST_CID)) => {
                let Ok(slot) = Arc::clone(&slots).try_acquire_owned() else {
                    drop(stream);
                    eprintln!("sandy-agent: port-relay is at its {cap} connection cap; closed a connection");
                    continue;
                };
                tokio::spawn(async move {
                    relay_one(stream, target, idle).await;
                    drop(slot);
                });
            }
            Ok((stream, cid)) => {
                drop(stream);
                eprintln!("sandy-agent: port-relay refused a connection from vsock cid {cid}");
            }
            Err(e) => {
                eprintln!("sandy-agent: port-relay accept failed: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

/// Relay one host connection. A target that is down closes this connection only.
async fn relay_one<S>(mut host: S, target: SocketAddr, idle: Duration)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut service = match timeout(DIAL_TIMEOUT, TcpStream::connect(target)).await {
        Ok(Ok(service)) => service,
        Ok(Err(e)) => {
            eprintln!("sandy-agent: port-relay cannot reach {target}: {e}");
            return;
        }
        Err(_) => {
            eprintln!("sandy-agent: port-relay timed out dialing {target}");
            return;
        }
    };
    // Small interactive frames (a websocket) must not wait on Nagle.
    let _ = service.set_nodelay(true);
    // Tell the host the service is there before any data moves: its dial counts as successful only on this byte.
    if let Err(e) = host.write_all(&[PORT_RELAY_READY]).await {
        eprintln!("sandy-agent: port-relay could not announce readiness: {e}");
        return;
    }
    if let Err(e) = copy_until_idle(host, service, idle).await
        && e.kind() != io::ErrorKind::ConnectionReset
    {
        eprintln!("sandy-agent: port-relay connection ended: {e}");
    }
}

/// Copy both ways, half-closing the far side when one side reaches EOF, until both directions end or neither
/// moves a byte for `idle` ([`io::ErrorKind::TimedOut`]). A quiet direction alone is not idle: a download with no
/// upload keeps the connection open.
async fn copy_until_idle<A, B>(a: A, b: B, idle: Duration) -> io::Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let start = Instant::now();
    let last = AtomicU64::new(0);
    let (a_read, a_write) = split(a);
    let (b_read, b_write) = split(b);
    let (up, down) = tokio::join!(
        pump(a_read, b_write, start, &last, idle),
        pump(b_read, a_write, start, &last, idle)
    );
    up.and(down)
}

/// One direction of [`copy_until_idle`]. A read that times out is idle only if the other direction also moved
/// nothing for `idle`; the shared `last` holds the millisecond of the latest byte either way.
async fn pump<R, W>(mut from: R, mut to: W, start: Instant, last: &AtomicU64, idle: Duration) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let idle_ms = u64::try_from(idle.as_millis()).unwrap_or(u64::MAX);
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        match timeout(idle, from.read(&mut buf)).await {
            Ok(Ok(0)) => return to.shutdown().await,
            Ok(Ok(n)) => {
                to.write_all(&buf[..n]).await?;
                last.store(elapsed_ms(start), Ordering::Relaxed);
            }
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                if elapsed_ms(start).saturating_sub(last.load(Ordering::Relaxed)) >= idle_ms {
                    return Err(io::Error::new(io::ErrorKind::TimedOut, "connection idle"));
                }
            }
        }
    }
}

fn elapsed_ms(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// The `port-relay` entry point: bind the vsock listener, then relay until killed. A usage or bind failure aborts
/// like any agent-internal failure, so the backend reports an infra fault.
#[cfg(target_os = "linux")]
pub fn cli(args: &[OsString]) -> std::process::ExitCode {
    let (port, target) = parse_args(args).unwrap_or_else(|usage| crate::fail(&usage));
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|e| crate::fail(&format!("starting the runtime: {e}")));
    runtime.block_on(async {
        let acceptor = crate::link_source::VsockAcceptor::bind(port)
            .unwrap_or_else(|e| crate::fail(&format!("binding vsock port {port} for the port relay: {e}")));
        serve(acceptor, target).await;
    });
    std::process::ExitCode::SUCCESS
}

/// vsock exists only inside a Linux guest.
#[cfg(not(target_os = "linux"))]
pub fn cli(args: &[OsString]) -> std::process::ExitCode {
    let (port, _target) = parse_args(args).unwrap_or_else(|usage| crate::fail(&usage));
    crate::fail(&format!(
        "port-relay --vsock-port {port}: vsock is only available inside a Linux guest"
    ))
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        net::Ipv4Addr,
        sync::{Arc, Mutex},
        time::Duration,
    };

    use anyhow::Context;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt, DuplexStream, duplex},
        net::TcpListener,
        time::timeout,
    };

    use super::*;
    use crate::link_source::HOST_CID;

    const WAIT: Duration = Duration::from_secs(5);

    fn args(list: &[&str]) -> Vec<OsString> {
        list.iter().map(OsString::from).collect()
    }

    /// An acceptor that yields scripted `(stream, cid)` pairs, then never yields again.
    struct Script(Arc<Mutex<VecDeque<(DuplexStream, u32)>>>);

    impl Acceptor for Script {
        type Stream = DuplexStream;

        async fn accept(&mut self) -> std::io::Result<(Self::Stream, u32)> {
            loop {
                let next = self
                    .0
                    .lock()
                    .map_err(|_| std::io::Error::other("poisoned"))?
                    .pop_front();
                match next {
                    Some(item) => return Ok(item),
                    None => tokio::time::sleep(Duration::from_millis(10)).await,
                }
            }
        }
    }

    /// A connection as the host would open it: the guest side goes to the acceptor, the host side to the test.
    fn connection(queue: &Arc<Mutex<VecDeque<(DuplexStream, u32)>>>, cid: u32) -> anyhow::Result<DuplexStream> {
        let (guest, host) = duplex(4096);
        queue
            .lock()
            .map_err(|_| anyhow::anyhow!("poisoned"))?
            .push_back((guest, cid));
        Ok(host)
    }

    /// A loopback echo server. Returns its address and a count of accepted connections.
    async fn echo_target() -> anyhow::Result<(SocketAddr, Arc<Mutex<u32>>)> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.context("bind echo")?;
        let addr = listener.local_addr()?;
        let accepted = Arc::new(Mutex::new(0u32));
        let count = Arc::clone(&accepted);
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                if let Ok(mut n) = count.lock() {
                    *n += 1;
                }
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    while let Ok(n) = socket.read(&mut buf).await {
                        if n == 0 || socket.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
        Ok((addr, accepted))
    }

    /// A connection the relay accepted and connected to the service: it announces itself with the ready byte, then
    /// echoes. A host dial that merely connected (vfkit's proxy does this before the guest listens) never sees it.
    async fn served(host: &mut DuplexStream, word: &[u8]) -> anyhow::Result<bool> {
        let mut ready = [0u8; 1];
        match timeout(WAIT, host.read_exact(&mut ready)).await {
            Ok(Ok(_)) if ready[0] == PORT_RELAY_READY => echoes(host, word).await,
            _ => Ok(false),
        }
    }

    async fn echoes(host: &mut DuplexStream, word: &[u8]) -> anyhow::Result<bool> {
        host.write_all(word).await?;
        let mut got = vec![0u8; word.len()];
        match timeout(WAIT, host.read_exact(&mut got)).await {
            Ok(Ok(_)) => Ok(got == word),
            _ => Ok(false),
        }
    }

    /// The relay's job: bytes from the host reach the loopback service and its answer comes back.
    #[tokio::test]
    async fn a_host_connection_is_spliced_to_the_target() -> anyhow::Result<()> {
        let (target, _) = echo_target().await?;
        let queue = Arc::new(Mutex::new(VecDeque::new()));
        let mut host = connection(&queue, HOST_CID)?;
        let relay = tokio::spawn(serve(Script(Arc::clone(&queue)), target));

        assert!(
            served(&mut host, b"ping").await?,
            "the echo must come back through the relay"
        );
        relay.abort();
        Ok(())
    }

    /// The "second environment cannot reach this port" row: a peer that is not the host is closed unanswered and
    /// never causes a dial to the service, whichever non-host CID it reports (0, the loopback CID 1, a guest, the
    /// maximum). The host connection behind each is still served, and the target saw exactly that one dial.
    #[tokio::test]
    async fn a_peer_that_is_not_the_host_is_closed_and_never_dials_the_target() -> anyhow::Result<()> {
        let (target, accepted) = echo_target().await?;
        let queue = Arc::new(Mutex::new(VecDeque::new()));
        let mut intruders = Vec::new();
        for cid in [0, 1, HOST_CID + 1, u32::MAX] {
            intruders.push(connection(&queue, cid)?);
        }
        let relay = tokio::spawn(serve(Script(Arc::clone(&queue)), target));

        for (i, intruder) in intruders.iter_mut().enumerate() {
            let mut buf = [0u8; 1];
            let closed = timeout(WAIT, intruder.read(&mut buf))
                .await
                .with_context(|| format!("intruder {i} read timed out"))?;
            assert!(
                matches!(closed, Ok(0) | Err(_)),
                "a non-host peer must be closed, got {closed:?}"
            );
        }
        let mut host = connection(&queue, HOST_CID)?;
        assert!(
            served(&mut host, b"after").await?,
            "the host is still served after refusals"
        );
        assert_eq!(
            *accepted.lock().map_err(|_| anyhow::anyhow!("poisoned"))?,
            1,
            "only the host connection may dial the target"
        );
        relay.abort();
        Ok(())
    }

    /// A long-lived connection (t3 holds a websocket) must not block a second one.
    #[tokio::test]
    async fn connections_are_served_concurrently() -> anyhow::Result<()> {
        let (target, _) = echo_target().await?;
        let queue = Arc::new(Mutex::new(VecDeque::new()));
        let mut first = connection(&queue, HOST_CID)?;
        let mut second = connection(&queue, HOST_CID)?;
        let relay = tokio::spawn(serve(Script(Arc::clone(&queue)), target));

        assert!(served(&mut first, b"one").await?, "first connection");
        assert!(
            served(&mut second, b"two").await?,
            "second connection while the first is open"
        );
        assert!(echoes(&mut first, b"again").await?, "first connection still open");
        relay.abort();
        Ok(())
    }

    /// A service that is down closes that connection only: the relay keeps accepting, and once the service is up
    /// the next connection is served through the same relay.
    #[tokio::test]
    async fn an_unreachable_target_closes_only_that_connection() -> anyhow::Result<()> {
        let dead = {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
            listener.local_addr()?
        };
        let queue = Arc::new(Mutex::new(VecDeque::new()));
        let mut first = connection(&queue, HOST_CID)?;
        let relay = tokio::spawn(serve(Script(Arc::clone(&queue)), dead));

        let mut buf = [0u8; 1];
        let closed = timeout(WAIT, first.read(&mut buf)).await.context("read timed out")?;
        assert!(
            matches!(closed, Ok(0) | Err(_)),
            "a dead target must close the connection, got {closed:?}"
        );

        // The service comes up on the same port; a later connection works through the same relay.
        let listener = TcpListener::bind(dead).await.context("rebind the target port")?;
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 64];
                    while let Ok(n) = socket.read(&mut buf).await {
                        if n == 0 || socket.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
        let mut second = connection(&queue, HOST_CID)?;
        assert!(
            served(&mut second, b"up").await?,
            "the relay must serve after one failed dial"
        );
        relay.abort();
        Ok(())
    }

    /// The cap bounds concurrent connections: with one allowed, a second host connection is closed unanswered while
    /// the first is open, and is served once the first closes.
    #[tokio::test]
    async fn connections_beyond_the_cap_are_closed() -> anyhow::Result<()> {
        let (target, _) = echo_target().await?;
        let queue = Arc::new(Mutex::new(VecDeque::new()));
        let mut first = connection(&queue, HOST_CID)?;
        let relay = tokio::spawn(serve_with_cap(Script(Arc::clone(&queue)), target, 1, IDLE_TIMEOUT));
        assert!(served(&mut first, b"one").await?, "the first connection is served");

        let mut second = connection(&queue, HOST_CID)?;
        let mut buf = [0u8; 1];
        let closed = timeout(WAIT, second.read(&mut buf))
            .await
            .context("over-cap read timed out")?;
        assert!(
            matches!(closed, Ok(0) | Err(_)),
            "an over-cap connection must be closed, got {closed:?}"
        );

        drop(first);
        tokio::time::sleep(Duration::from_millis(200)).await;
        let mut third = connection(&queue, HOST_CID)?;
        assert!(
            served(&mut third, b"three").await?,
            "a slot freed by a closed connection is reusable"
        );
        relay.abort();
        Ok(())
    }

    /// A silent connection must not hold a slot forever: a host process that sends nothing after the ready byte,
    /// against a service that also stays silent, is closed once the idle limit passes, and its slot is reusable.
    #[tokio::test]
    async fn a_silent_connection_is_closed_after_the_idle_limit() -> anyhow::Result<()> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .context("bind silent")?;
        let target = listener.local_addr()?;
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((socket, _)) = listener.accept().await {
                held.push(socket);
            }
        });
        let queue = Arc::new(Mutex::new(VecDeque::new()));
        let mut host = connection(&queue, HOST_CID)?;
        let relay = tokio::spawn(serve_with_cap(
            Script(Arc::clone(&queue)),
            target,
            1,
            Duration::from_millis(300),
        ));
        let mut ready = [0u8; 1];
        timeout(WAIT, host.read_exact(&mut ready))
            .await
            .context("ready byte")??;

        let mut byte = [0u8; 1];
        let closed = timeout(WAIT, host.read(&mut byte))
            .await
            .context("a silent connection was never closed")?;
        assert!(
            matches!(closed, Ok(0) | Err(_)),
            "a silent connection must be closed, got {closed:?}"
        );

        let mut next = connection(&queue, HOST_CID)?;
        let mut ready = [0u8; 1];
        timeout(WAIT, next.read_exact(&mut ready))
            .await
            .context("the freed slot was not reusable")??;
        relay.abort();
        Ok(())
    }

    /// Traffic in either direction counts as activity: a connection that keeps talking outlives the idle limit.
    #[tokio::test]
    async fn a_connection_with_traffic_outlives_the_idle_limit() -> anyhow::Result<()> {
        let (target, _) = echo_target().await?;
        let queue = Arc::new(Mutex::new(VecDeque::new()));
        let mut host = connection(&queue, HOST_CID)?;
        let relay = tokio::spawn(serve_with_cap(
            Script(Arc::clone(&queue)),
            target,
            4,
            Duration::from_millis(400),
        ));
        assert!(served(&mut host, b"0").await?, "the first echo comes back");
        for i in 1..=6u8 {
            tokio::time::sleep(Duration::from_millis(150)).await;
            assert!(
                echoes(&mut host, &[b'0' + i]).await?,
                "an active connection must stay open past the idle limit"
            );
        }
        relay.abort();
        Ok(())
    }

    #[test]
    fn the_arguments_name_a_port_and_a_loopback_target() {
        let parsed = parse_args(&args(&["--vsock-port", "5100", "--to", "127.0.0.1:3773"]));
        assert_eq!(parsed, Ok((5100, SocketAddr::from((Ipv4Addr::LOCALHOST, 3773)))));
    }

    #[test]
    fn a_bad_argument_list_is_refused() {
        for bad in [
            &["--vsock-port", "5100"][..],
            &["--to", "127.0.0.1:3773"][..],
            &["--vsock-port", "x", "--to", "127.0.0.1:3773"][..],
            // u32::MAX is VMADDR_PORT_ANY: the kernel would bind some other port.
            &["--vsock-port", "4294967295", "--to", "127.0.0.1:3773"][..],
            // The relay never forwards off the guest's loopback.
            &["--vsock-port", "5100", "--to", "10.0.0.5:3773"][..],
            &["--vsock-port", "5100", "--to", "0.0.0.0:3773"][..],
            &["--vsock-port", "5100", "--to", "[::1]:3773"][..],
            &["--vsock-port", "5100", "--to", "127.0.0.1:0"][..],
            &["--vsock-port", "5100", "--to", "127.0.0.2:3773"][..],
            &["--vsock-port", "5100", "--to", "[::ffff:127.0.0.1]:3773"][..],
            &["--to", "127.0.0.1:3773", "--vsock-port", "5100"][..],
            &["--vsock-port", "5100", "--to", "127.0.0.1:3773", "extra"][..],
        ] {
            assert!(parse_args(&args(bad)).is_err(), "{bad:?} must be refused");
        }
    }
}
