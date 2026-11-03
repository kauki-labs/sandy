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
//! The bridge parses nothing and adds no TLS or auth. Tailnet exposure is the host's job (`tailscale serve`), and the
//! service authenticates its own clients (t3's pairing token).

use std::{future::Future, io, net::SocketAddr, time::Duration};

use tokio::{
    io::{AsyncRead, AsyncWrite},
    task::JoinHandle,
};

/// Opens one stream to the guest relay.
pub trait Dialer: Send + Sync + 'static {
    /// One stream to the guest relay.
    type Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static;

    /// Open a new stream to the guest relay.
    fn dial(&self) -> impl Future<Output = io::Result<Self::Stream>> + Send;
}

/// How a [`Bridge`] limits and retries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BridgeConfig {
    /// The most connections relayed at once. A connection over the cap is closed unanswered.
    pub max_connections: usize,
    /// How long a failing dial is retried before the client's connection is closed. Zero means one attempt.
    pub dial_window: Duration,
    /// The pause between dial attempts inside the window.
    pub dial_retry_interval: Duration,
}

impl Default for BridgeConfig {
    fn default() -> Self {
        Self {
            max_connections: 256,
            dial_window: Duration::from_secs(10),
            dial_retry_interval: Duration::from_millis(200),
        }
    }
}

/// A running bridge. Dropping it closes it.
#[derive(Debug)]
pub struct Bridge {
    addr: SocketAddr,
    task: Option<JoinHandle<()>>,
}

impl Bridge {
    /// Bind `127.0.0.1` on an ephemeral port and start relaying to `dialer`.
    ///
    /// # Errors
    /// Returns the bind error.
    pub async fn start<D: Dialer>(_dialer: D, _config: BridgeConfig) -> io::Result<Self> {
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
        let addr = listener.local_addr()?;
        let task = tokio::spawn(async move {
            let _listener = listener;
            std::future::pending::<()>().await;
        });
        Ok(Self { addr, task: Some(task) })
    }

    /// The loopback address clients connect to.
    #[must_use]
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Stop listening and close every live connection. Returns once they are closed.
    pub async fn shutdown(mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
            let _ = task.await;
        }
    }
}

impl Drop for Bridge {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
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
        tokio::time::sleep(Duration::from_millis(200)).await;
        let mut third = TcpStream::connect(bridge.addr()).await?;
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
}
