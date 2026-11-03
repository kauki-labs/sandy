//! The host half of the service bridge (#590): a loopback listener that splices each accepted connection to a
//! stream from a [`Dialer`].
//!
//! The guest service (for example `t3 serve`) listens on guest loopback, and `sandy-agent port-relay` exposes it on
//! a vsock port (`docs/decisions/agent-fabric.md` decision 10a). A [`Dialer`] opens one stream to that relay: over
//! vhost-vsock on qemu, over a unix socket on vfkit. The bridge owns the host side: it binds `127.0.0.1` on an
//! ephemeral port, reports the address (the endpoint `Probe::Ready` carries), caps concurrent connections, retries
//! a dial for a short window while the relay comes up, and, when shut down or dropped, closes every live connection
//! and stops listening. That last part is how a stopped environment refuses connections.
//!
//! A connected stream does not mean the guest is ready (vfkit's proxy accepts before the guest listens, and the
//! relay accepts before it dials the service), so the bridge counts a dial as successful only after it has read
//! [`PORT_RELAY_READY`], and does not forward that byte.
//!
//! The bridge parses nothing and adds no TLS or auth. Any local user can connect to a loopback port, so until the
//! owner decides the exposure (`docs/decisions/agent-fabric.md` decision 10b) it is a development aid for a
//! single-user host: the service authenticates its own clients (t3's pairing token), and tailnet exposure is the
//! host's job (`tailscale serve`).
//! It must run inside a tokio runtime.

use std::{
    future::Future,
    io,
    net::{Ipv4Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use sandy_api::agent::PORT_RELAY_READY;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, split},
    net::{TcpListener, TcpStream},
    sync::{Semaphore, oneshot},
    task::{JoinHandle, JoinSet},
    time::{Instant, sleep, timeout},
};

/// One dial attempt, readiness byte included, may not take longer than this. The window bounds the retries, not
/// a single hung attempt.
const DIAL_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(5);

/// Opens one stream to the guest relay.
pub trait Dialer: Send + Sync + 'static {
    /// One stream to the guest relay.
    type Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static;

    /// Open a new stream to the guest relay. Return as soon as the stream is connected: the bridge itself waits for
    /// the relay's [`PORT_RELAY_READY`] byte.
    fn dial(&self) -> impl Future<Output = io::Result<Self::Stream>> + Send;
}

/// How a [`Bridge`] limits and retries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BridgeConfig {
    /// The most connections relayed at once, from 1 to [`Semaphore::MAX_PERMITS`]. A client over the cap is closed
    /// unanswered. A client waiting in its dial window holds a slot.
    pub max_connections: usize,
    /// How long a failing dial is retried before the client's connection is closed. Zero means one attempt. The
    /// window is measured between attempts, and one attempt can take up to 5 s (a hung dial or a guest that never
    /// sends the ready byte), so a client can wait up to the window plus 5 s.
    pub dial_window: Duration,
    /// The pause between dial attempts inside the window.
    pub dial_retry_interval: Duration,
    /// How long a client may stay silent before the bridge closes it without dialing. The bridge dials the guest
    /// relay only after the client's first byte, so a connection that sends nothing costs no relay slot and no dial.
    pub first_byte_timeout: Duration,
    /// How long a relayed connection may carry no byte in either direction before the bridge closes it. A guest
    /// that sends the ready byte and then goes silent would otherwise pin a slot and two descriptors for good. A
    /// quiet direction alone is not idle, so a long download or an idle upload keeps the connection open.
    pub idle_timeout: Duration,
}

impl Default for BridgeConfig {
    fn default() -> Self {
        Self {
            // Each relayed connection holds two descriptors, and macOS's default soft limit is 256.
            max_connections: 64,
            dial_window: Duration::from_secs(10),
            dial_retry_interval: Duration::from_millis(200),
            first_byte_timeout: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(15 * 60),
        }
    }
}

/// A running bridge. Dropping it closes it.
#[must_use = "dropping the bridge closes it"]
#[derive(Debug)]
pub struct Bridge {
    addr: SocketAddr,
    stop: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<()>>,
}

impl Bridge {
    /// Bind `127.0.0.1` on an ephemeral port and start relaying to `dialer`.
    ///
    /// # Errors
    /// [`io::ErrorKind::InvalidInput`] when `config.max_connections` is 0 or above [`Semaphore::MAX_PERMITS`]
    /// (a bridge that can never serve is an error here, not a silent refusal of every client), and the bind error.
    pub async fn start<D: Dialer>(dialer: D, config: BridgeConfig) -> io::Result<Self> {
        if config.max_connections == 0 || config.max_connections > Semaphore::MAX_PERMITS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "max_connections must be between 1 and {}, got {}",
                    Semaphore::MAX_PERMITS,
                    config.max_connections
                ),
            ));
        }
        if config.idle_timeout.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "idle_timeout must be non-zero: zero would close every connection at once",
            ));
        }
        if !config.dial_window.is_zero() && config.dial_retry_interval.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "dial_retry_interval must be above zero when dial_window is, or a failing dial would spin",
            ));
        }
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let addr = listener.local_addr()?;
        let (stop, stopped) = oneshot::channel();
        let task = tokio::spawn(accept_loop(listener, Arc::new(dialer), config, stopped));
        Ok(Self {
            addr,
            stop: Some(stop),
            task: Some(task),
        })
    }

    /// The loopback address clients connect to. It is the literal `127.0.0.1:<port>`: a caller that rewrites it to
    /// `localhost` can resolve `[::1]` and reach whatever else listens on that port.
    #[must_use]
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Stop listening and close every live connection, including a client still waiting in its dial window.
    /// Returns once the listener is closed and every connection task has ended, so nothing is forwarded after it.
    pub async fn shutdown(mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }
}

impl Drop for Bridge {
    /// Signals the same stop as [`Bridge::shutdown`] and returns at once: the listener and the connections close a
    /// moment later, when the bridge's task runs. Call `shutdown` where the close must be complete.
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }
}

/// Accept clients until `stopped` fires (or its sender is dropped), then close the listener and end every relayed
/// connection before returning.
async fn accept_loop<D: Dialer>(
    listener: TcpListener,
    dialer: Arc<D>,
    config: BridgeConfig,
    mut stopped: oneshot::Receiver<()>,
) {
    let slots = Arc::new(Semaphore::new(config.max_connections));
    let mut live = JoinSet::new();
    loop {
        // Reap finished connections so the set does not grow with every client ever served.
        while live.try_join_next().is_some() {}
        let client = tokio::select! {
            _ = &mut stopped => break,
            accepted = listener.accept() => match accepted {
                Ok((client, _)) => client,
                Err(e) => {
                    tracing::warn!(%e, "the bridge could not accept a client");
                    // EMFILE and friends are not a listener failure: back off and keep serving.
                    sleep(Duration::from_millis(100)).await;
                    continue;
                }
            },
        };
        let Ok(slot) = Arc::clone(&slots).try_acquire_owned() else {
            drop(client);
            tracing::debug!(
                cap = config.max_connections,
                "the bridge is at its connection cap; closed a client"
            );
            continue;
        };
        // Small interactive frames (a websocket) must not wait on Nagle.
        let _ = client.set_nodelay(true);
        let dialer = Arc::clone(&dialer);
        live.spawn(async move {
            relay_one(client, &*dialer, config).await;
            drop(slot);
        });
    }
    drop(listener);
    live.shutdown().await;
}

/// Relay one client: dial the guest relay inside the window, then copy both ways until either side closes. A dial
/// that never succeeds closes this client only.
async fn relay_one<D: Dialer>(client: TcpStream, dialer: &D, config: BridgeConfig) {
    // Dial only after the client's first byte: a connection that sends nothing then costs no relay slot and no dial.
    // `peek` leaves the byte in the socket for the copy to forward.
    let mut first = [0u8; 1];
    match timeout(config.first_byte_timeout, client.peek(&mut first)).await {
        Ok(Ok(n)) if n > 0 => {}
        _ => {
            tracing::debug!("the bridge closed a client that sent no first byte");
            return;
        }
    }
    let Some(guest) = dial_within_window(dialer, &config).await else {
        tracing::debug!("the bridge gave up dialing the guest relay");
        return;
    };
    let _ = copy_until_idle(client, guest, config.idle_timeout).await;
}

/// Copy both ways, half-closing the far side when one side reaches EOF, until both directions end or neither
/// moves a byte for `idle` ([`io::ErrorKind::TimedOut`]).
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

/// Dial until the guest relay answers with [`PORT_RELAY_READY`], or the window ends.
async fn dial_within_window<D: Dialer>(dialer: &D, config: &BridgeConfig) -> Option<D::Stream> {
    let started = Instant::now();
    loop {
        if let Ok(Ok(stream)) = timeout(DIAL_ATTEMPT_TIMEOUT, dial_ready(dialer)).await {
            return Some(stream);
        }
        if started.elapsed().saturating_add(config.dial_retry_interval) >= config.dial_window {
            return None;
        }
        sleep(config.dial_retry_interval).await;
    }
}

/// One attempt: connect, then wait for the ready byte. Anything else, or a close before it, is a failed attempt.
async fn dial_ready<D: Dialer>(dialer: &D) -> io::Result<D::Stream> {
    let mut stream = dialer.dial().await?;
    let mut ready = [0u8; 1];
    stream.read_exact(&mut ready).await?;
    if ready[0] == PORT_RELAY_READY {
        Ok(stream)
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the guest relay did not announce readiness",
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::Ipv4Addr,
        sync::{
            Arc,
            atomic::{AtomicU32, Ordering},
        },
    };

    use anyhow::Context;
    use sandy_api::agent::PORT_RELAY_READY;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        time::timeout,
    };

    use super::*;

    const WAIT: Duration = Duration::from_secs(5);

    /// A loopback echo server standing in for the guest relay.
    async fn echo_guest() -> anyhow::Result<SocketAddr> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.context("bind echo")?;
        let addr = listener.local_addr()?;
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                tokio::spawn(async move {
                    if socket.write_all(&[PORT_RELAY_READY]).await.is_err() {
                        return;
                    }
                    let mut buf = [0u8; 1024];
                    while let Ok(n) = socket.read(&mut buf).await {
                        if n == 0 || socket.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
        Ok(addr)
    }

    /// A guest that accepts and closes at once for its first `close_first` connections (what vfkit's proxy does
    /// before the guest listens, or the relay when its service is down), then behaves like [`echo_guest`]. Returns
    /// its address and a count of accepted connections.
    async fn flaky_guest(close_first: u32) -> anyhow::Result<(SocketAddr, Arc<AtomicU32>)> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .context("bind flaky guest")?;
        let addr = listener.local_addr()?;
        let accepted = Arc::new(AtomicU32::new(0));
        let count = Arc::clone(&accepted);
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                if count.fetch_add(1, Ordering::SeqCst) < close_first {
                    drop(socket);
                    continue;
                }
                tokio::spawn(async move {
                    if socket.write_all(&[PORT_RELAY_READY]).await.is_err() {
                        return;
                    }
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

    /// True when the peer closed within 100 ms: non-blocking reads see EOF without any await. Used right after
    /// `shutdown().await`, where "eventually closed" (the 5 s `closed_unanswered`) is not good enough. Linux
    /// loopback delivers the FIN inside `close()`, so the first read already sees it; macOS delivers it a moment
    /// later, hence the short bound instead of a single read.
    fn already_closed(client: TcpStream) -> anyhow::Result<bool> {
        let client = client.into_std()?;
        client.set_nonblocking(true)?;
        let mut buf = [0u8; 1];
        for _ in 0..10 {
            if matches!(std::io::Read::read(&mut &client, &mut buf), Ok(0))
                || matches!(std::io::Read::read(&mut &client, &mut buf), Err(e) if e.kind() == io::ErrorKind::ConnectionReset)
            {
                return Ok(true);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        Ok(false)
    }

    /// Dials a TCP address, after failing `failures` times first, and counts every attempt.
    struct TcpDialer {
        target: SocketAddr,
        failures: u32,
        attempts: Arc<AtomicU32>,
    }

    impl TcpDialer {
        fn new(target: SocketAddr) -> (Self, Arc<AtomicU32>) {
            Self::failing(target, 0)
        }

        fn failing(target: SocketAddr, failures: u32) -> (Self, Arc<AtomicU32>) {
            let attempts = Arc::new(AtomicU32::new(0));
            (
                Self {
                    target,
                    failures,
                    attempts: Arc::clone(&attempts),
                },
                attempts,
            )
        }
    }

    impl Dialer for TcpDialer {
        type Stream = TcpStream;

        async fn dial(&self) -> io::Result<TcpStream> {
            if self.attempts.fetch_add(1, Ordering::SeqCst) < self.failures {
                return Err(io::Error::from(io::ErrorKind::ConnectionRefused));
            }
            TcpStream::connect(self.target).await
        }
    }

    fn config(max_connections: usize, window_ms: u64) -> BridgeConfig {
        BridgeConfig {
            max_connections,
            dial_window: Duration::from_millis(window_ms),
            dial_retry_interval: Duration::from_millis(20),
            first_byte_timeout: Duration::from_secs(5),
            idle_timeout: Duration::from_secs(60),
        }
    }

    async fn echoes(client: &mut TcpStream, word: &[u8]) -> bool {
        if client.write_all(word).await.is_err() {
            return false;
        }
        let mut got = vec![0u8; word.len()];
        matches!(timeout(WAIT, client.read_exact(&mut got)).await, Ok(Ok(_))) && got == word
    }

    /// True when the peer closes without sending a byte.
    async fn closed_unanswered(client: &mut TcpStream) -> anyhow::Result<bool> {
        // The bridge dials only after the client's first byte.
        let _ = client.write_all(b"x").await;
        let mut buf = [0u8; 1];
        let read = timeout(WAIT, client.read(&mut buf)).await.context("read timed out")?;
        Ok(matches!(read, Ok(0) | Err(_)))
    }

    /// The bridge's job: a client on the loopback address reaches the guest through the dialer.
    #[tokio::test]
    async fn a_client_is_spliced_to_the_dialed_stream() -> anyhow::Result<()> {
        let (dialer, _) = TcpDialer::new(echo_guest().await?);
        let bridge = Bridge::start(dialer, config(8, 0)).await?;
        let mut client = TcpStream::connect(bridge.addr()).await?;
        assert!(
            echoes(&mut client, b"ping").await,
            "the echo must come back through the bridge"
        );
        Ok(())
    }

    /// The bridge is reachable from the host only: it binds the IPv4 loopback address, never a wildcard.
    #[tokio::test]
    async fn the_bridge_listens_on_the_loopback_address_only() -> anyhow::Result<()> {
        let (dialer, _) = TcpDialer::new(echo_guest().await?);
        let bridge = Bridge::start(dialer, config(8, 0)).await?;
        assert_eq!(bridge.addr().ip(), std::net::IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_ne!(bridge.addr().port(), 0, "an ephemeral port is bound and reported");
        Ok(())
    }

    /// A dial that fails closes that client only; the bridge keeps serving the next one.
    #[tokio::test]
    async fn a_failed_dial_closes_that_client_and_the_bridge_keeps_serving() -> anyhow::Result<()> {
        let (dialer, attempts) = TcpDialer::failing(echo_guest().await?, 1);
        let bridge = Bridge::start(dialer, config(8, 0)).await?;

        let mut first = TcpStream::connect(bridge.addr()).await?;
        assert!(closed_unanswered(&mut first).await?, "a failed dial closes the client");
        let mut second = TcpStream::connect(bridge.addr()).await?;
        assert!(echoes(&mut second, b"ok").await, "the next client is served");
        assert_eq!(
            attempts.load(Ordering::SeqCst),
            2,
            "one attempt per client when the window is zero"
        );
        Ok(())
    }

    /// While the relay comes up the dial fails; inside the window it is retried and the client is served.
    #[tokio::test]
    async fn a_dial_that_fails_at_first_is_retried_inside_the_window() -> anyhow::Result<()> {
        let (dialer, attempts) = TcpDialer::failing(echo_guest().await?, 3);
        let bridge = Bridge::start(dialer, config(8, 2_000)).await?;
        let mut client = TcpStream::connect(bridge.addr()).await?;
        assert!(
            echoes(&mut client, b"late").await,
            "the client is served once the dial succeeds"
        );
        assert_eq!(attempts.load(Ordering::SeqCst), 4, "three failures then one success");
        Ok(())
    }

    /// A dial that never succeeds is given up after the window, so a dead relay cannot hold a client forever.
    #[tokio::test]
    async fn a_dial_that_keeps_failing_is_given_up_after_the_window() -> anyhow::Result<()> {
        let (dialer, attempts) = TcpDialer::failing(echo_guest().await?, u32::MAX);
        let bridge = Bridge::start(dialer, config(8, 150)).await?;
        let mut client = TcpStream::connect(bridge.addr()).await?;
        assert!(
            closed_unanswered(&mut client).await?,
            "the client is closed once the window ends"
        );
        let made = attempts.load(Ordering::SeqCst);
        assert!(
            (2..=20).contains(&made),
            "retried inside the window, not forever: {made} attempts"
        );
        Ok(())
    }

    /// The cap bounds concurrent connections: over it a client is closed unanswered, and a freed slot is reusable.
    #[tokio::test]
    async fn connections_beyond_the_cap_are_closed() -> anyhow::Result<()> {
        let (dialer, _) = TcpDialer::new(echo_guest().await?);
        let bridge = Bridge::start(dialer, config(1, 0)).await?;

        let mut first = TcpStream::connect(bridge.addr()).await?;
        assert!(echoes(&mut first, b"one").await, "the first connection is served");
        let mut second = TcpStream::connect(bridge.addr()).await?;
        assert!(
            closed_unanswered(&mut second).await?,
            "an over-cap connection is closed"
        );

        drop(first);
        // The slot frees when the first connection's task ends; poll for it instead of guessing a delay.
        let mut third = TcpStream::connect(bridge.addr()).await?;
        for _ in 0..50 {
            third = TcpStream::connect(bridge.addr()).await?;
            third.write_all(b"x").await?;
            let mut byte = [0u8; 1];
            if matches!(
                timeout(Duration::from_millis(100), third.read(&mut byte)).await,
                Ok(Ok(1))
            ) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(
            echoes(&mut third, b"three").await,
            "a slot freed by a closed connection is reusable"
        );
        Ok(())
    }

    /// "A stopped environment refuses connections": shutdown closes live connections and stops listening.
    #[tokio::test]
    async fn shutdown_closes_live_connections_and_refuses_new_ones() -> anyhow::Result<()> {
        let (dialer, _) = TcpDialer::new(echo_guest().await?);
        let bridge = Bridge::start(dialer, config(8, 0)).await?;
        let addr = bridge.addr();
        let mut live = TcpStream::connect(addr).await?;
        assert!(echoes(&mut live, b"live").await, "the connection works before shutdown");

        bridge.shutdown().await;

        assert!(closed_unanswered(&mut live).await?, "shutdown closes a live connection");
        assert!(
            TcpStream::connect(addr).await.is_err(),
            "a new connection is refused after shutdown"
        );
        Ok(())
    }

    /// Dropping the bridge closes it the same way, so a forgotten shutdown cannot leave a port open.
    #[tokio::test]
    async fn dropping_the_bridge_closes_it_too() -> anyhow::Result<()> {
        let (dialer, _) = TcpDialer::new(echo_guest().await?);
        let bridge = Bridge::start(dialer, config(8, 0)).await?;
        let addr = bridge.addr();
        let mut live = TcpStream::connect(addr).await?;
        assert!(echoes(&mut live, b"live").await, "the connection works before the drop");

        drop(bridge);

        assert!(closed_unanswered(&mut live).await?, "a drop closes a live connection");
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(TcpStream::connect(addr).await.is_err(), "a drop stops listening");
        Ok(())
    }

    /// A dial that connects but never announces readiness (vfkit's proxy before the guest listens) is a failed
    /// dial: it is retried inside the window and the client is closed when the window ends.
    #[tokio::test]
    async fn a_dial_that_connects_but_never_announces_readiness_is_retried_then_closed() -> anyhow::Result<()> {
        let (guest, accepted) = flaky_guest(u32::MAX).await?;
        let (dialer, _) = TcpDialer::new(guest);
        let bridge = Bridge::start(dialer, config(8, 150)).await?;
        let mut client = TcpStream::connect(bridge.addr()).await?;
        assert!(
            closed_unanswered(&mut client).await?,
            "the client is closed once the window ends"
        );
        let made = accepted.load(Ordering::SeqCst);
        assert!(
            (2..=20).contains(&made),
            "retried inside the window, not forever: {made} dials"
        );
        Ok(())
    }

    /// The same guest comes up after a few early connects: the client is served once the ready byte arrives, and
    /// the ready byte itself is not forwarded to the client.
    #[tokio::test]
    async fn a_dial_is_retried_until_the_ready_byte_arrives() -> anyhow::Result<()> {
        let (guest, accepted) = flaky_guest(3).await?;
        let (dialer, _) = TcpDialer::new(guest);
        let bridge = Bridge::start(dialer, config(8, 2_000)).await?;
        let mut client = TcpStream::connect(bridge.addr()).await?;
        assert!(
            echoes(&mut client, b"late").await,
            "served once ready, with no stray ready byte"
        );
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            4,
            "three early closes, then the ready one"
        );
        Ok(())
    }

    /// `shutdown` returns only after every live connection is closed, so a restart or reuse that relies on it
    /// cannot see a late byte forwarded. Run multi-threaded: a connection task on another worker finishes its poll
    /// before it is cancelled, and a current-thread runtime hides that.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn shutdown_has_closed_every_connection_when_it_returns() -> anyhow::Result<()> {
        let (dialer, _) = TcpDialer::new(echo_guest().await?);
        let bridge = Bridge::start(dialer, config(8, 0)).await?;
        let mut live = TcpStream::connect(bridge.addr()).await?;
        assert!(echoes(&mut live, b"live").await, "the connection works before shutdown");

        bridge.shutdown().await;

        assert!(already_closed(live)?, "no live connection may outlive shutdown");
        Ok(())
    }

    /// A client still waiting inside its dial window is closed by shutdown too.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn shutdown_closes_a_client_waiting_in_its_dial_window() -> anyhow::Result<()> {
        let (guest, _) = flaky_guest(u32::MAX).await?;
        let (dialer, _) = TcpDialer::new(guest);
        let bridge = Bridge::start(dialer, config(8, 5_000)).await?;
        let mut waiting = TcpStream::connect(bridge.addr()).await?;
        waiting.write_all(b"x").await?;
        tokio::time::sleep(Duration::from_millis(100)).await;

        bridge.shutdown().await;

        assert!(
            already_closed(waiting)?,
            "a client in its dial window is closed by shutdown"
        );
        Ok(())
    }

    /// A config that can never serve is an error at `start`, not a bridge that silently refuses everyone.
    #[tokio::test]
    async fn a_config_that_cannot_serve_is_refused_at_start() -> anyhow::Result<()> {
        let (guest, _) = flaky_guest(0).await?;
        for max in [0, usize::MAX] {
            let (dialer, _) = TcpDialer::new(guest);
            let started = Bridge::start(dialer, config(max, 0)).await;
            assert!(
                matches!(&started, Err(e) if e.kind() == io::ErrorKind::InvalidInput),
                "max_connections {max} must be refused, got {started:?}"
            );
        }
        Ok(())
    }

    /// A client that sends nothing costs no dial and no relay slot: the bridge dials only after the first byte, and
    /// closes a silent client when `first_byte_timeout` passes. A client that does send is served as usual.
    #[tokio::test]
    async fn a_client_that_sends_nothing_causes_no_dial_and_is_closed_after_the_first_byte_timeout()
    -> anyhow::Result<()> {
        let (guest, accepted) = flaky_guest(0).await?;
        let (dialer, attempts) = TcpDialer::new(guest);
        let config = BridgeConfig {
            first_byte_timeout: Duration::from_millis(150),
            ..config(8, 0)
        };
        let bridge = Bridge::start(dialer, config).await?;

        let mut silent = TcpStream::connect(bridge.addr()).await?;
        let mut byte = [0u8; 1];
        let closed = timeout(WAIT, silent.read(&mut byte))
            .await
            .context("a silent client was never closed")?;
        assert!(
            matches!(closed, Ok(0) | Err(_)),
            "a silent client must be closed, got {closed:?}"
        );
        assert_eq!(
            attempts.load(Ordering::SeqCst),
            0,
            "no dial for a client that sent nothing"
        );
        assert_eq!(accepted.load(Ordering::SeqCst), 0, "the guest relay saw no connection");

        let mut talker = TcpStream::connect(bridge.addr()).await?;
        assert!(echoes(&mut talker, b"hi").await, "a client that sends is served");
        Ok(())
    }

    /// A guest that announces readiness and then goes silent must not hold a slot for good.
    #[tokio::test]
    async fn a_silent_relayed_connection_is_closed_after_the_idle_timeout() -> anyhow::Result<()> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .context("bind silent guest")?;
        let guest = listener.local_addr()?;
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((mut socket, _)) = listener.accept().await {
                let _ = socket.write_all(&[PORT_RELAY_READY]).await;
                held.push(socket);
            }
        });
        let (dialer, _) = TcpDialer::new(guest);
        let config = BridgeConfig {
            idle_timeout: Duration::from_millis(300),
            ..config(1, 0)
        };
        let bridge = Bridge::start(dialer, config).await?;

        let mut client = TcpStream::connect(bridge.addr()).await?;
        client.write_all(b"x").await?;
        let mut byte = [0u8; 1];
        let closed = timeout(WAIT, client.read(&mut byte))
            .await
            .context("a silent relayed connection was never closed")?;
        assert!(
            matches!(closed, Ok(0) | Err(_)),
            "a silent connection must be closed, got {closed:?}"
        );
        Ok(())
    }

    /// Traffic in either direction is activity: a connection that keeps talking outlives the idle timeout.
    #[tokio::test]
    async fn a_connection_with_traffic_outlives_the_idle_timeout() -> anyhow::Result<()> {
        let guest = echo_guest().await?;
        let (dialer, _) = TcpDialer::new(guest);
        let config = BridgeConfig {
            idle_timeout: Duration::from_millis(400),
            ..config(4, 0)
        };
        let bridge = Bridge::start(dialer, config).await?;
        let mut client = TcpStream::connect(bridge.addr()).await?;
        for i in 0..6u8 {
            assert!(
                echoes(&mut client, &[b'a' + i]).await,
                "an active connection must stay open past the idle timeout"
            );
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
        Ok(())
    }

    /// A zero idle timeout would close every connection at once, so it is an error at `start`.
    #[tokio::test]
    async fn a_zero_idle_timeout_is_refused_at_start() -> anyhow::Result<()> {
        let (guest, _) = flaky_guest(0).await?;
        let (dialer, _) = TcpDialer::new(guest);
        let zero = BridgeConfig {
            idle_timeout: Duration::ZERO,
            ..config(8, 0)
        };
        let refused = Bridge::start(dialer, zero).await;
        assert!(
            matches!(&refused, Err(e) if e.kind() == io::ErrorKind::InvalidInput),
            "a zero idle timeout must be refused, got {refused:?}"
        );
        Ok(())
    }

    /// A retry interval of zero with a non-zero window would spin against an instantly failing dialer, so it is an
    /// error at `start`. A zero window never retries, so a zero interval is harmless there.
    #[tokio::test]
    async fn a_zero_retry_interval_with_a_window_is_refused_at_start() -> anyhow::Result<()> {
        let (guest, _) = flaky_guest(0).await?;
        let spinning = BridgeConfig {
            dial_window: Duration::from_secs(1),
            dial_retry_interval: Duration::ZERO,
            ..config(8, 0)
        };
        let (dialer, _) = TcpDialer::new(guest);
        let refused = Bridge::start(dialer, spinning).await;
        assert!(
            matches!(&refused, Err(e) if e.kind() == io::ErrorKind::InvalidInput),
            "a zero interval with a window must be refused, got {refused:?}"
        );
        let one_shot = BridgeConfig {
            dial_window: Duration::ZERO,
            dial_retry_interval: Duration::ZERO,
            ..config(8, 0)
        };
        let (dialer, _) = TcpDialer::new(guest);
        assert!(
            Bridge::start(dialer, one_shot).await.is_ok(),
            "a zero window and interval is one attempt"
        );
        Ok(())
    }

    /// The largest permit count the semaphore allows is accepted and one more is refused.
    #[tokio::test]
    async fn the_largest_permit_count_is_accepted_and_one_more_is_refused() -> anyhow::Result<()> {
        let (guest, _) = flaky_guest(0).await?;
        let (dialer, _) = TcpDialer::new(guest);
        assert!(Bridge::start(dialer, config(Semaphore::MAX_PERMITS, 0)).await.is_ok());
        let (dialer, _) = TcpDialer::new(guest);
        let refused = Bridge::start(dialer, config(Semaphore::MAX_PERMITS + 1, 0)).await;
        assert!(
            matches!(&refused, Err(e) if e.kind() == io::ErrorKind::InvalidInput),
            "MAX_PERMITS + 1 must be refused, got {refused:?}"
        );
        Ok(())
    }
}
