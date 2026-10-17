//! The one stream transport sandyd's control RPC (and, later, cross-machine
//! channel delivery) ride: UDS (local) → vsock (VM guest) → TCP/QUIC-over-mesh
//! (cross-machine), per epic #205's B6. Each tier produces the same thing — an
//! ordered, duplex byte stream ([`Conn`]) — so `sandy-control-proto`'s
//! length-prefixed framing rides any of them unchanged; swapping tiers is an
//! address choice, never a protocol change.
//!
//! Step-1 (this crate's current state): UDS only. vsock and TCP/QUIC-over-mesh
//! land as [`ConnAddr`] grows variants and [`connect`]/[`listen`] grow match
//! arms, not as a redesign.

use std::path::{Path, PathBuf};

use tokio::net::{UnixListener, UnixStream};

/// An address to [`connect`] to or [`listen`] on, naming a tier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnAddr {
    /// A Unix domain socket path (step-1, local).
    Uds(PathBuf),
}

/// A connection failure: dialing, accepting, or binding.
#[derive(Debug, thiserror::Error)]
pub enum ConnError {
    /// The underlying I/O failed.
    #[error("connection I/O: {0}")]
    Io(#[from] std::io::Error),
}

/// An ordered, duplex byte stream — what `sandy-control-proto`'s
/// length-prefixed framing (`write_frame`/`read_frame`) rides directly,
/// whichever tier produced it. A blanket impl: any type that is already
/// `AsyncRead + AsyncWrite + Send + Unpin` (every tokio stream type) gets this
/// for free.
pub trait Conn: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin> Conn for T {}

/// Dial `addr`, returning a duplex stream once connected.
///
/// # Errors
/// [`ConnError::Io`] if the dial fails (no listener, permission denied, …).
pub async fn connect(addr: &ConnAddr) -> Result<Box<dyn Conn>, ConnError> {
    match addr {
        ConnAddr::Uds(path) => Ok(Box::new(UnixStream::connect(path).await?)),
    }
}

/// Accepts incoming connections on whatever [`listen`] bound.
pub struct Listener(ListenerInner);

enum ListenerInner {
    Uds(UnixListener),
}

impl Listener {
    /// Accept the next incoming connection.
    ///
    /// # Errors
    /// [`ConnError::Io`] if accepting fails.
    pub async fn accept(&self) -> Result<Box<dyn Conn>, ConnError> {
        match &self.0 {
            ListenerInner::Uds(listener) => {
                let (stream, _addr) = listener.accept().await?;
                Ok(Box::new(stream))
            }
        }
    }
}

/// Bind `addr`, returning a [`Listener`] ready to [`Listener::accept`].
///
/// For a UDS path left behind by a crashed prior listener (a real socket file
/// with nothing behind it — a well-known UDS footgun absent from TCP, which
/// has no filesystem footprint), this detects staleness by probing with a
/// connect and removes the orphan before (re)binding. A path where something
/// is genuinely still listening is never touched — [`ConnError::Io`]
/// propagates instead, so a second `sandyd` instance can't silently steal the
/// first's socket.
///
/// # Errors
/// [`ConnError::Io`] if binding fails: another listener genuinely holds the
/// path, or the path is otherwise inaccessible (permissions, missing parent
/// directory, …).
pub async fn listen(addr: &ConnAddr) -> Result<Listener, ConnError> {
    match addr {
        ConnAddr::Uds(path) => Ok(Listener(ListenerInner::Uds(bind_uds(path).await?))),
    }
}

async fn bind_uds(path: &Path) -> Result<UnixListener, ConnError> {
    match UnixListener::bind(path) {
        Ok(listener) => Ok(listener),
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
            if UnixStream::connect(path).await.is_ok() {
                // Something answered: a real listener holds this path.
                return Err(ConnError::Io(e));
            }
            // Nothing answered: an orphaned socket file from a prior process
            // that never cleaned up after itself (a crash, a kill -9). Remove
            // it and bind fresh — safe specifically because the connect probe
            // just proved nothing live is behind it.
            std::fs::remove_file(path)?;
            Ok(UnixListener::bind(path)?)
        }
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Context;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    fn uds_path(dir: &tempfile::TempDir) -> ConnAddr {
        ConnAddr::Uds(dir.path().join("sandy-conn-test.sock"))
    }

    #[tokio::test]
    async fn connect_and_accept_round_trip_bytes() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let addr = uds_path(&dir);
        let listener = listen(&addr).await.context("listen")?;

        let (accepted, mut dialed) = tokio::try_join!(listener.accept(), connect(&addr))?;
        let mut accepted = accepted;

        dialed.write_all(b"hello").await.context("write")?;
        dialed.flush().await?;
        let mut buf = [0u8; 5];
        accepted.read_exact(&mut buf).await.context("read")?;
        assert_eq!(&buf, b"hello");
        Ok(())
    }

    #[tokio::test]
    async fn connecting_with_nothing_listening_fails_cleanly() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        // Never listened on: no socket file exists at all.
        let addr = ConnAddr::Uds(dir.path().join("nobody-home.sock"));

        assert!(
            connect(&addr).await.is_err(),
            "dialing a non-existent socket must error, not hang"
        );
        Ok(())
    }

    #[tokio::test]
    async fn listening_on_a_path_still_in_use_fails_without_stealing_it() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let addr = uds_path(&dir);
        let first = listen(&addr).await.context("first listen")?;

        assert!(
            listen(&addr).await.is_err(),
            "a second listener on a path a live one still holds must not silently take over"
        );

        // The first listener is still the real one: a connect against it must
        // still work, proving it wasn't disturbed by the failed second attempt.
        let (_accepted, _dialed) = tokio::try_join!(first.accept(), connect(&addr))?;
        Ok(())
    }

    /// The actual design claim: `sandy-control-proto`'s length-prefixed
    /// framing (the control RPC's wire format) rides a `sandy-conn`
    /// connection unchanged, not just "some type that happens to implement
    /// AsyncRead/AsyncWrite in isolation."
    #[tokio::test]
    async fn control_proto_framing_rides_a_conn_end_to_end() -> anyhow::Result<()> {
        use sandy_control_proto::{ControlRequest, ListRequest, control_request, read_frame, write_frame};

        let dir = tempfile::tempdir()?;
        let addr = uds_path(&dir);
        let listener = listen(&addr).await.context("listen")?;

        let (mut server, mut client) = tokio::try_join!(listener.accept(), connect(&addr))?;

        let request = ControlRequest {
            request_id: 42,
            op: Some(control_request::Op::List(ListRequest {})),
        };
        write_frame(&mut client, &request).await.context("write_frame")?;

        let received: ControlRequest = read_frame(&mut server)
            .await
            .context("read_frame")?
            .context("connection closed before a frame arrived")?;
        assert_eq!(received, request);
        Ok(())
    }

    #[tokio::test]
    async fn listening_on_a_path_orphaned_by_a_dead_process_recovers() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let addr = uds_path(&dir);

        // Simulate a crashed prior sandyd: a listener existed, bound the
        // path, and was dropped without ever removing the socket file (a
        // real `UnixListener` does NOT clean up its own path on Drop).
        let orphan = listen(&addr).await.context("orphaned listen")?;
        drop(orphan);
        assert!(
            dir.path().join("sandy-conn-test.sock").exists(),
            "dropping a UnixListener leaves its socket file behind — the premise this test needs"
        );

        // A fresh listen() on the same path must detect the orphan (nothing
        // answers a connect probe) and recover, not propagate AddrInUse.
        let recovered = listen(&addr)
            .await
            .context("recovered listen should succeed, not propagate AddrInUse")?;
        let (_accepted, _dialed) = tokio::try_join!(recovered.accept(), connect(&addr))?;
        Ok(())
    }
}
