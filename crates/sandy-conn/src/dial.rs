//! The [`Dialer`]s the host bridge uses to reach `sandy-agent port-relay` in a guest (#590).
//!
//! - [`UnixDialer`] connects to a unix socket. vfkit exposes a guest vsock port to the host as one: the
//!   `virtio-vsock,port=P,socketURL=<path>,connect` device makes vfkit own the socket, so the path exists from the
//!   moment vfkit runs, and a connect succeeds before the guest listens. The bridge's ready byte covers that gap.
//! - `VsockDialer` (Linux only) connects to `<guest CID>:<port>` over vhost-vsock, which is how qemu's host reaches
//!   a guest.
//!
//! Neither opens a stream the bridge trusts until the relay has announced readiness (see [`crate::bridge`]).

use std::{io, path::PathBuf};

use tokio::net::UnixStream;

use crate::bridge::Dialer;

/// Dials a unix socket.
#[derive(Debug, Clone)]
pub struct UnixDialer {
    path: PathBuf,
}

impl UnixDialer {
    /// A dialer for the unix socket at `path`.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

impl Dialer for UnixDialer {
    type Stream = UnixStream;

    async fn dial(&self) -> io::Result<UnixStream> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("not implemented: {}", self.path.display()),
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use anyhow::Context;
    use sandy_api::agent::PORT_RELAY_READY;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpStream, UnixListener},
        time::timeout,
    };

    use super::*;
    use crate::bridge::{Bridge, BridgeConfig};

    const WAIT: Duration = Duration::from_secs(5);

    fn config(window_ms: u64) -> BridgeConfig {
        BridgeConfig {
            max_connections: 8,
            dial_window: Duration::from_millis(window_ms),
            dial_retry_interval: Duration::from_millis(20),
        }
    }

    /// A unix-socket stand-in for the guest relay: announces readiness, then echoes.
    fn serve_relay(listener: UnixListener) {
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
    }

    async fn echoes(client: &mut TcpStream, word: &[u8]) -> bool {
        if client.write_all(word).await.is_err() {
            return false;
        }
        let mut got = vec![0u8; word.len()];
        matches!(timeout(WAIT, client.read_exact(&mut got)).await, Ok(Ok(_))) && got == word
    }

    /// The vfkit path: a client on the bridge's loopback address reaches the guest relay through its unix socket.
    #[tokio::test]
    async fn a_client_reaches_the_relay_through_a_unix_socket() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("relay.sock");
        serve_relay(UnixListener::bind(&path).context("bind relay socket")?);

        let bridge = Bridge::start(UnixDialer::new(&path), config(0)).await?;
        let mut client = TcpStream::connect(bridge.addr()).await?;
        assert!(echoes(&mut client, b"ping").await, "the echo must come back through the unix socket");
        Ok(())
    }

    /// The socket is not there yet when the first client arrives (the guest is still booting): the dial is
    /// retried inside the window, and the client is served once the relay is listening.
    #[tokio::test]
    async fn a_socket_that_appears_later_is_dialed_inside_the_window() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("relay.sock");

        let bridge = Bridge::start(UnixDialer::new(&path), config(3_000)).await?;
        let mut client = TcpStream::connect(bridge.addr()).await?;

        tokio::time::sleep(Duration::from_millis(200)).await;
        serve_relay(UnixListener::bind(&path).context("bind relay socket late")?);

        assert!(echoes(&mut client, b"late").await, "the client waiting in its window is served");
        Ok(())
    }

    /// A socket path with nothing behind it is a failed dial: the client is closed, and the bridge keeps serving.
    #[tokio::test]
    async fn a_missing_socket_closes_the_client_and_the_bridge_keeps_serving() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("relay.sock");

        let bridge = Bridge::start(UnixDialer::new(&path), config(0)).await?;
        let mut first = TcpStream::connect(bridge.addr()).await?;
        let mut byte = [0u8; 1];
        let closed = timeout(WAIT, first.read(&mut byte)).await.context("read timed out")?;
        assert!(matches!(closed, Ok(0) | Err(_)), "a missing socket must close the client, got {closed:?}");

        serve_relay(UnixListener::bind(&path).context("bind relay socket")?);
        let mut second = TcpStream::connect(bridge.addr()).await?;
        assert!(echoes(&mut second, b"ok").await, "the bridge serves once the socket exists");
        Ok(())
    }
}
