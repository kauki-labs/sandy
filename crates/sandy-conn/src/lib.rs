//! The one stream transport sandyd's control RPC (and, later, cross-machine
//! channel delivery) ride: UDS (local) → vsock (VM guest) → TCP/QUIC-over-mesh
//! (cross-machine), per epic #205's B6. Each tier produces the same thing — an
//! ordered, duplex byte stream ([`Conn`]) — so `sandy-control-proto`'s
//! length-prefixed framing rides any of them unchanged; swapping tiers is an
//! address choice, never a protocol change.
//!
//! Current state: UDS and the TCP/mesh tier (#159). vsock is parked (no
//! consumer yet; #216's agent-link relay covers the cross-machine dispatch
//! case this crate originally scoped vsock for). QUIC-over-mesh lands as
//! [`ConnAddr`] grows a variant and [`connect`]/[`listen`] grow a match arm,
//! not as a redesign.

use std::{
    net::SocketAddr,
    os::unix::fs::FileTypeExt,
    path::{Path, PathBuf},
};

use tokio::net::{TcpListener, TcpStream, UnixListener, UnixStream};

/// An address to [`connect`] to or [`listen`] on, naming a tier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnAddr {
    /// A Unix domain socket path (step-1, local).
    Uds(PathBuf),
    /// A TCP socket address — the mesh tier (#159): the hosts are already on
    /// the Headscale/Netbird mesh, so a plain TCP dial to the peer's mesh IP
    /// is the whole "cross-machine" step, with WireGuard's own
    /// authentication and encryption as the trust boundary for whatever
    /// protocol rides this connection (no additional mTLS layer for step-1).
    Tcp(SocketAddr),
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
        ConnAddr::Tcp(socket_addr) => Ok(Box::new(TcpStream::connect(socket_addr).await?)),
    }
}

/// An accepted connection's peer identity, tagged by the tier it arrived on.
///
/// Not `Option<SocketAddr>`: each tier's own peer-auth check needs its own
/// identity kind — a mesh IP for TCP, a CID for vsock (parked, no variant
/// yet), a peer uid for UDS (no consumer needs it yet, so [`PeerAddr::Uds`]
/// carries nothing rather than guessing a shape nobody's checked against). A
/// lossy `Option<SocketAddr>` would force every non-TCP tier's real identity
/// into `None`, which a caller could too easily mistake for "no peer to
/// check" instead of "this tier's identity isn't `SocketAddr`-shaped."
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerAddr {
    /// A UDS peer carries no identity here yet (no consumer checks it); add
    /// a credential (peer uid) when one does, rather than reusing this
    /// variant to mean something it doesn't check today.
    Uds,
    /// The dialing peer's socket address, as the kernel reports it to
    /// `accept(2)` — on a mesh connection, this is the peer's mesh IP,
    /// authenticated by WireGuard underneath (see [`ConnAddr::Tcp`]).
    Tcp(SocketAddr),
}

/// Accepts incoming connections on whatever [`listen`] bound.
pub struct Listener(ListenerInner);

enum ListenerInner {
    Uds(UnixListener),
    Tcp(TcpListener),
}

impl Listener {
    /// Accept the next incoming connection, with the peer's identity on
    /// whatever tier this listener is.
    ///
    /// # Errors
    /// [`ConnError::Io`] if accepting fails.
    pub async fn accept(&self) -> Result<(Box<dyn Conn>, PeerAddr), ConnError> {
        match &self.0 {
            ListenerInner::Uds(listener) => {
                let (stream, _addr) = listener.accept().await?;
                Ok((Box::new(stream), PeerAddr::Uds))
            }
            ListenerInner::Tcp(listener) => {
                let (stream, addr) = listener.accept().await?;
                Ok((Box::new(stream), PeerAddr::Tcp(addr)))
            }
        }
    }

    /// The address actually bound — the OS-assigned port when [`listen`] was
    /// given port 0, as every test here does to avoid a fixed, collidable
    /// port. UDS has no socket address of this kind.
    ///
    /// # Errors
    /// [`ConnError::Io`] on the UDS tier, or if the underlying query fails.
    pub fn local_addr(&self) -> Result<SocketAddr, ConnError> {
        match &self.0 {
            ListenerInner::Uds(_) => Err(ConnError::Io(std::io::Error::other(
                "a UDS listener has no SocketAddr; local_addr is TCP-only",
            ))),
            ListenerInner::Tcp(listener) => Ok(listener.local_addr()?),
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
        ConnAddr::Tcp(socket_addr) => Ok(Listener(ListenerInner::Tcp(TcpListener::bind(socket_addr).await?))),
    }
}

async fn bind_uds(path: &Path) -> Result<UnixListener, ConnError> {
    // The whole check-probe-maybe-remove-bind sequence must be atomic across
    // every caller — same process or a different one — or two callers racing
    // to recover the same orphaned path can both conclude "stale" and
    // interleave a remove_file against the socket the other just bound. An
    // flock on a sibling lockfile serializes it, same pattern as
    // sandy::journal's job locks: not the socket path itself, since recovery
    // unlinks and rebinds that path, which a lock ON it wouldn't survive.
    let lock_path = lock_file_path(path);
    let _lock = tokio::task::spawn_blocking(move || -> std::io::Result<std::fs::File> {
        use std::os::unix::fs::OpenOptionsExt;
        // mode(0o600): a world-readable lockfile lets another local user open
        // it and take LOCK_EX, blocking every future listen() here (CWE-59,
        // availability, not data exposure — the file holds no content).
        // NOFOLLOW: refuse a symlink planted at the lockfile path for the
        // same reason the socket path itself is checked above.
        let file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(&lock_path)?;
        fs2::FileExt::lock_exclusive(&file)?;
        Ok(file)
    })
    .await
    .map_err(std::io::Error::other)??;

    bind_uds_locked(path).await
    // _lock drops here, releasing the flock — held only for this function's
    // duration, not the listener's whole lifetime.
}

fn lock_file_path(socket_path: &Path) -> PathBuf {
    let mut lock_path = socket_path.as_os_str().to_owned();
    lock_path.push(".lock");
    PathBuf::from(lock_path)
}

async fn bind_uds_locked(path: &Path) -> Result<UnixListener, ConnError> {
    // Checked before the first bind attempt at all, not only inside AddrInUse
    // recovery below: AF_UNIX `bind()` follows a symlink at the target path,
    // so an attacker who pre-plants one at a predictable socket path (e.g.
    // $XDG_RUNTIME_DIR/sandyd.sock) could redirect the real socket wherever
    // the link points. Refuse outright rather than silently following it.
    if is_symlink(path) {
        return Err(ConnError::Io(std::io::Error::other(format!(
            "refusing to bind through a symlink at {}",
            path.display()
        ))));
    }
    match bind_uds_0600(path) {
        Ok(listener) => Ok(listener),
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
            // Only a real UDS at this path is even eligible for orphan
            // recovery: a plain file (or anything else) left at the
            // configured path also makes bind() fail with AddrInUse, and
            // deleting an unrelated file just because it occupies this path
            // would be a worse bug than the one being guarded against.
            if !is_socket(path) {
                return Err(ConnError::Io(e));
            }
            match UnixStream::connect(path).await {
                // Answered (even if it then closes immediately): a real
                // listener holds this path.
                Ok(_) => Err(ConnError::Io(e)),
                // Refused specifically is the proof an orphan needs: the
                // socket file exists but nothing is listening behind it. Any
                // OTHER probe failure (permission denied, …) is inconclusive,
                // not proof of staleness, and must not trigger a delete.
                Err(probe_err) if probe_err.kind() == std::io::ErrorKind::ConnectionRefused => {
                    // Re-verified immediately before acting, not just relying
                    // on the check above: narrows, but doesn't eliminate
                    // (a true atomic remove-iff-still-this-exact-inode needs a
                    // heavier primitive than remove_file), the window between
                    // concluding "orphan" and acting on that conclusion.
                    if !is_socket(path) {
                        return Err(ConnError::Io(e));
                    }
                    std::fs::remove_file(path)?;
                    Ok(bind_uds_0600(path)?)
                }
                Err(_) => Err(ConnError::Io(e)),
            }
        }
        Err(e) => Err(e.into()),
    }
}

/// `path`'s own file type is a symlink. `symlink_metadata`, unlike `metadata`,
/// does not follow the link, so this reports the link itself, not its target.
fn is_symlink(path: &Path) -> bool {
    std::fs::symlink_metadata(path)
        .map(|metadata| metadata.file_type().is_symlink())
        .unwrap_or(false)
}

/// `path` exists and its own file type is a Unix domain socket.
fn is_socket(path: &Path) -> bool {
    std::fs::symlink_metadata(path)
        .map(|metadata| metadata.file_type().is_socket())
        .unwrap_or(false)
}

/// Binds a Unix listener at `path` with mode 0600, set at creation rather
/// than via a `chmod` afterward, which would leave a window where the socket
/// exists under the ambient (often far more permissive) umask. `bind(2)` on
/// an AF_UNIX socket takes no mode parameter of its own; the kernel applies
/// the umask exactly as it would for a new file. This brackets the one
/// `bind` syscall with a tightened umask and restores the original
/// immediately after. The umask is process-wide, not scoped to this call, so
/// unrelated file creation elsewhere in the process during this one syscall
/// would transiently see the tightened mask too: a narrow, single-syscall
/// window, and the standard, accepted tradeoff for a mode-at-creation UDS
/// bind (there is no race-free alternative without a mode parameter on bind
/// itself).
fn bind_uds_0600(path: &Path) -> std::io::Result<UnixListener> {
    use rustix::{fs::Mode, process::umask};
    let previous = umask(Mode::from_raw_mode(0o177));
    let bound = std::os::unix::net::UnixListener::bind(path);
    umask(previous);
    let std_listener = bound?;
    std_listener.set_nonblocking(true)?;
    UnixListener::from_std(std_listener)
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
    async fn tcp_connect_and_accept_round_trip_bytes() -> anyhow::Result<()> {
        let addr = ConnAddr::Tcp("127.0.0.1:0".parse()?);
        let listener = listen(&addr).await.context("listen")?;
        let bound = ConnAddr::Tcp(listener.local_addr().context("local_addr")?);

        let ((accepted, peer), mut dialed) = tokio::try_join!(listener.accept(), connect(&bound))?;
        match peer {
            PeerAddr::Tcp(addr) => assert_eq!(addr.ip(), "127.0.0.1".parse::<std::net::IpAddr>()?),
            other => panic!("expected PeerAddr::Tcp, got {other:?}"),
        }
        let mut accepted = accepted;

        dialed.write_all(b"hello").await.context("write")?;
        dialed.flush().await?;
        let mut buf = [0u8; 5];
        accepted.read_exact(&mut buf).await.context("read")?;
        assert_eq!(&buf, b"hello");
        Ok(())
    }

    /// Precise version of the assertion above: the accepted `PeerAddr` must be
    /// exactly the dialing side's own bound address (ip *and* port), not just
    /// the right IP. Dials with a raw `TcpStream` directly (not `connect()`,
    /// which returns `Box<dyn Conn>` with no `local_addr()`) so the dialer's
    /// own address is available to compare against.
    #[tokio::test]
    async fn tcp_accept_reports_exactly_the_dialers_bound_address() -> anyhow::Result<()> {
        let listener = listen(&ConnAddr::Tcp("127.0.0.1:0".parse()?)).await.context("listen")?;
        let bound = listener.local_addr().context("local_addr")?;

        let (accept_result, dial_result) = tokio::join!(listener.accept(), tokio::net::TcpStream::connect(bound));
        let (_accepted, peer) = accept_result?;
        let dialed = dial_result.context("dial")?;
        let dialer_addr = dialed.local_addr().context("dialed.local_addr")?;

        assert_eq!(
            peer,
            PeerAddr::Tcp(dialer_addr),
            "the accepted peer must match the dialer's own bound address exactly"
        );
        Ok(())
    }

    #[tokio::test]
    async fn tcp_connecting_with_nothing_listening_fails_cleanly() -> anyhow::Result<()> {
        // Port 0 never has a real listener behind it as a dial target; a
        // closed, unused high port stands in for "nothing there."
        let addr = ConnAddr::Tcp("127.0.0.1:1".parse()?);
        assert!(
            connect(&addr).await.is_err(),
            "dialing a port nothing listens on must error, not hang"
        );
        Ok(())
    }

    #[tokio::test]
    async fn tcp_binding_port_zero_picks_a_free_ephemeral_port() -> anyhow::Result<()> {
        let addr = ConnAddr::Tcp("127.0.0.1:0".parse()?);
        let listener = listen(&addr).await.context("listen")?;
        assert_ne!(
            listener.local_addr().context("local_addr")?.port(),
            0,
            "the OS must assign a real port, not echo back 0"
        );
        Ok(())
    }

    #[tokio::test]
    async fn connect_and_accept_round_trip_bytes() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let addr = uds_path(&dir);
        let listener = listen(&addr).await.context("listen")?;

        let ((accepted, peer), mut dialed) = tokio::try_join!(listener.accept(), connect(&addr))?;
        assert_eq!(peer, PeerAddr::Uds, "a UDS peer carries no address, step-1");
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

        let ((mut server, _peer), mut client) = tokio::try_join!(listener.accept(), connect(&addr))?;

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

    #[tokio::test]
    async fn a_file_occupying_the_path_is_never_deleted() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("sandy-conn-test.sock");
        std::fs::write(&path, b"not a socket")?;

        assert!(
            listen(&ConnAddr::Uds(path.clone())).await.is_err(),
            "a plain file at the configured path must not be mistaken for an orphaned socket"
        );
        assert!(path.exists(), "the unrelated file must survive untouched");
        Ok(())
    }

    /// The fix for a real TOCTOU CodeRabbit found on #223: a bare re-probe
    /// before `remove_file` doesn't close the window between two callers
    /// recovering the same orphan concurrently. A test that just races two
    /// `tokio::spawn`ed `listen()` calls against each other and checks
    /// "exactly one wins" does NOT reliably prove this: tried first,
    /// confirmed by mutation that it passed 5/5 runs with the lock entirely
    /// removed, because without an explicit forced overlap the two tasks tend
    /// not to actually interleave inside the narrow vulnerable window —
    /// each one's recovery (self-correctingly) completes before the other
    /// starts, so "exactly one wins" holds either way. Same category of
    /// honesty issue as #106/#184's concurrency fixes (#213 tracks a general
    /// harness for this).
    ///
    /// This instead proves the mechanism directly and deterministically: an
    /// externally-held flock on the lockfile `bind_uds` uses must make
    /// `listen()` block until released, not race past it. That's the one
    /// fact the whole fix depends on — if flock itself correctly serializes
    /// (a well-established kernel guarantee, not in question), and `listen()`
    /// correctly waits on it (this test), then no two real callers — same
    /// process or different ones — can ever interleave the vulnerable
    /// section, regardless of timing.
    #[tokio::test]
    async fn bind_uds_waits_for_a_lockfile_held_by_someone_else() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let addr = uds_path(&dir);
        let ConnAddr::Uds(socket_path) = &addr else {
            unreachable!("uds_path always builds a ConnAddr::Uds")
        };
        let socket_path = socket_path.clone();

        // Hold the lock externally, simulating another caller mid-recovery.
        let lock_file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(lock_file_path(&socket_path))
            .context("open lockfile")?;
        fs2::FileExt::lock_exclusive(&lock_file).context("acquire the external lock")?;

        let listen_task = tokio::spawn(async move { listen(&addr).await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(
            !listen_task.is_finished(),
            "listen() must block while the lockfile is held elsewhere, not race past it"
        );

        fs2::FileExt::unlock(&lock_file).context("release the external lock")?;
        let result = tokio::time::timeout(std::time::Duration::from_secs(2), listen_task)
            .await
            .context("listen() did not proceed once the lock was released")?
            .context("listen task panicked")?;
        assert!(result.is_ok(), "a fresh path should bind cleanly once the lock clears");
        Ok(())
    }

    #[tokio::test]
    async fn a_bound_socket_is_mode_0600() -> anyhow::Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir()?;
        let addr = uds_path(&dir);
        // Not manipulated here: the process umask is global, and tests run
        // concurrently in the same process, so forcing it in one test would
        // race every other test's bind. bind_uds_0600 brackets its own umask
        // internally around the single bind syscall, which is what's under
        // test regardless of whatever the ambient umask happens to be.
        let _listener = listen(&addr).await.context("listen")?;

        let ConnAddr::Uds(path) = &addr else {
            unreachable!("uds_path always builds a ConnAddr::Uds")
        };
        let mode = std::fs::metadata(path)?.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "socket mode must be 0600, set at creation");
        Ok(())
    }

    #[tokio::test]
    async fn the_lockfile_is_mode_0600() -> anyhow::Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir()?;
        let addr = uds_path(&dir);
        let ConnAddr::Uds(socket_path) = &addr else {
            unreachable!("uds_path always builds a ConnAddr::Uds")
        };
        let socket_path = socket_path.clone();
        let _listener = listen(&addr).await.context("listen")?;

        let mode = std::fs::metadata(lock_file_path(&socket_path))?.permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "a world-readable lockfile lets another user block our flock (CWE-59)"
        );
        Ok(())
    }

    #[tokio::test]
    async fn listening_through_a_symlink_is_refused() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let real_target = dir.path().join("elsewhere.sock");
        let link_path = dir.path().join("sandy-conn-test.sock");
        std::os::unix::fs::symlink(&real_target, &link_path).context("create symlink")?;

        assert!(
            listen(&ConnAddr::Uds(link_path.clone())).await.is_err(),
            "binding through a symlink must be refused, not silently followed"
        );
        assert!(
            !real_target.exists(),
            "a refused bind must never create anything at the symlink's target"
        );
        Ok(())
    }
}
