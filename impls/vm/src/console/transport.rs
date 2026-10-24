//! The console transport split (host).
//!
//! The sentinel [`Protocol`](super::protocol::Protocol) is transport-agnostic;
//! this module supplies the byte channel it drives. There are two, selected by
//! platform:
//!
//! - **[`PipeTransport`]** — the Linux/qemu path: a Unix-domain socket to qemu's serial chardev. The backend owns the
//!   spawn and connects the socket; the transport is built over it with [`PipeTransport::new`].
//! - **[`PtyTransport`]** — the macOS/vfkit path: a pseudo-terminal, allocated through the safe `portable-pty` wrapper
//!   (chosen over `nix::pty` for its cross-platform surface) so no `unsafe` block is needed (INV-SAFE). It spawns the
//!   guest (vfkit) onto the slave and drains the master on a background thread so reads honor a deadline.
//!
//! Both carry a read deadline (the run budget), so a silent guest surfaces as
//! `Ok(0)` and resolves through the protocol's timeout path. The real boot over
//! each is tier-3 (host), proven by a live `sandy run` (#26), not a sandbox test.

use std::{
    io::{ErrorKind, Read, Write},
    path::Path,
    sync::mpsc,
    thread,
    time::Duration,
};

use sandy::BackendError;
pub use sandy_api::console::{ReadEvent, Transport};

/// The Linux/qemu pipe transport: the guest serial console on a byte channel.
///
/// Holds the two halves of the guest's serial console as boxed byte streams. The
/// backend owns the process spawn and the channel (a Unix-domain socket to qemu's
/// serial chardev) and builds the transport over it with [`PipeTransport::new`];
/// the transport only drives the sentinel protocol.
pub struct PipeTransport {
    /// The readable half of the guest serial console.
    reader: Box<dyn Read + Send>,
    /// The writable half of the guest serial console.
    writer: Box<dyn Write + Send>,
}

impl std::fmt::Debug for PipeTransport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("PipeTransport").finish_non_exhaustive()
    }
}

impl PipeTransport {
    /// Build a pipe transport over an already-connected byte channel — the
    /// backend's socket to the spawned hypervisor's serial chardev. The backend
    /// owns the process spawn and the channel; the transport only drives the
    /// sentinel protocol over it.
    ///
    /// The `reader` should carry a short read timeout — a poll quantum, not the
    /// run's deadline (#185): a timed-out read reports [`ReadEvent::Idle`], real
    /// EOF reports [`ReadEvent::Closed`], and the driver (`run_console`) is the
    /// one place that decides what either means against the live `RunControl`.
    #[must_use]
    pub fn new(reader: Box<dyn Read + Send>, writer: Box<dyn Write + Send>) -> Self {
        Self { reader, writer }
    }
}

impl Transport for PipeTransport {
    fn read(&mut self, buf: &mut [u8]) -> Result<ReadEvent, BackendError> {
        match self.reader.read(buf) {
            Ok(0) => Ok(ReadEvent::Closed),
            Ok(read) => Ok(ReadEvent::Data(read)),
            // The poll quantum elapsed with nothing to read; the console may
            // still be alive. Distinct from a real EOF (#185) so the driver can
            // poll a live cancellation/deadline signal without mistaking a quiet
            // guest for a closed one.
            Err(err) if matches!(err.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => Ok(ReadEvent::Idle),
            Err(err) => Err(BackendError::Transport(format!("pipe read: {err}"))),
        }
    }

    fn write(&mut self, bytes: &[u8]) -> Result<(), BackendError> {
        self.writer
            .write_all(bytes)
            .and_then(|()| self.writer.flush())
            .map_err(|err| BackendError::Transport(format!("pipe write: {err}")))
    }
}

/// The macOS/vfkit PTY transport: the guest console on a pseudo-terminal.
///
/// The PTY is allocated through `portable-pty` (a safe wrapper), so the
/// transport carries no `unsafe` block (INV-SAFE). The vfkit guest is attached
/// to the slave side by the host spawn wiring (#26); the master's reader/writer
/// drive the sentinel protocol.
pub struct PtyTransport {
    /// Keeps the PTY master alive for the transport's lifetime (the writer and the
    /// reader thread are clones of it).
    _master: Box<dyn portable_pty::MasterPty + Send>,
    /// The PTY slave, consumed by [`PtyTransport::spawn`] (which drops it so the
    /// master sees EOF once the guest exits). `None` after a spawn.
    slave: Option<Box<dyn portable_pty::SlavePty + Send>>,
    /// Chunks drained from the PTY master by a background reader thread. Reading
    /// through a channel lets [`Transport::read`] honor a deadline — the PTY
    /// master exposes no read-timeout API the way a socket does.
    rx: mpsc::Receiver<Vec<u8>>,
    /// Bytes received from the channel but not yet handed to the caller.
    pending: Vec<u8>,
    /// How long [`Transport::read`] waits for a chunk before reporting
    /// [`ReadEvent::Idle`] — a poll quantum, not the run deadline (#185); set by
    /// the backend via [`PtyTransport::set_read_timeout`].
    read_budget: Duration,
    /// Writer over the PTY master (guest stdin — the injected command frame).
    writer: Box<dyn Write + Send>,
    /// The guest process (e.g. `vfkit`) spawned onto the slave, owned so teardown
    /// can signal it. `None` until [`PtyTransport::spawn`] is called.
    child: Option<Box<dyn portable_pty::Child + Send + Sync>>,
}

impl std::fmt::Debug for PtyTransport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("PtyTransport").finish_non_exhaustive()
    }
}

impl PtyTransport {
    /// Allocate a PTY and attach it to the guest console.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError::Transport`] if the PTY cannot be allocated or its
    /// reader/writer handles cannot be cloned.
    pub fn open() -> Result<Self, BackendError> {
        let pair = portable_pty::native_pty_system()
            .openpty(portable_pty::PtySize::default())
            .map_err(|err| BackendError::Transport(format!("pty openpty: {err}")))?;
        let mut reader = pair
            .master
            .try_clone_reader()
            .map_err(|err| BackendError::Transport(format!("pty reader: {err}")))?;
        let writer = pair
            .master
            .take_writer()
            .map_err(|err| BackendError::Transport(format!("pty writer: {err}")))?;

        // Drain the master on a thread so `read` can time out on a silent guest
        // (the master has no read-timeout API). The thread ends on EOF or once the
        // receiver is dropped (transport teardown).
        let (tx, rx) = mpsc::channel::<Vec<u8>>();
        thread::spawn(move || {
            let mut buf = [0u8; 4096];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) => break,
                    Ok(read) => {
                        if tx.send(buf[..read].to_vec()).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        Ok(Self {
            _master: pair.master,
            slave: Some(pair.slave),
            rx,
            pending: Vec::new(),
            // `PtyTransport` and `run_console` are both public: a caller that
            // omits `set_read_timeout` must still get a safe poll quantum, not
            // a multi-minute block that could silently delay cancellation or
            // deadline handling (every real in-tree caller sets this
            // explicitly before driving the console, but the default itself
            // must not be a footgun).
            read_budget: super::POLL_QUANTUM,
            writer,
            child: None,
        })
    }

    /// Set how long [`Transport::read`] waits for guest output before reporting
    /// [`ReadEvent::Idle`] — a poll quantum, not the run's timeout (#185): the
    /// driver (`run_console`) checks the live `RunControl` and the phase
    /// deadline itself on every idle tick.
    pub fn set_read_timeout(&mut self, budget: Duration) {
        self.read_budget = budget;
    }

    /// Spawn `program` with `args` attached to the PTY slave, so the guest console
    /// (vfkit's `virtio-serial,stdio`) is bound to this PTY and the master drives
    /// the sentinel protocol. Returns the child pid. The child is owned by the
    /// transport and torn down by [`PtyTransport::shutdown`].
    ///
    /// The parent's slave handle is dropped once the child holds it, so the master
    /// reader sees EOF when the guest exits (otherwise an open slave would keep the
    /// master readable forever and a dead guest would hang the driver).
    ///
    /// # Errors
    ///
    /// Returns [`BackendError::Spawn`] if the slave was already consumed or the
    /// process cannot be launched on it.
    pub fn spawn(&mut self, program: &Path, args: &[String]) -> Result<u32, BackendError> {
        let slave = self
            .slave
            .take()
            .ok_or_else(|| BackendError::Spawn("pty slave already consumed".to_string()))?;
        let mut builder = portable_pty::CommandBuilder::new(program);
        for arg in args {
            builder.arg(arg);
        }
        let child = slave
            .spawn_command(builder)
            .map_err(|err| BackendError::Spawn(format!("spawn {} on pty: {err}", program.display())))?;
        drop(slave);
        let pid = child.process_id().unwrap_or(0);
        self.child = Some(child);
        Ok(pid)
    }

    /// Kill and reap the spawned child, if any. Best-effort — the child may have
    /// already exited.
    pub fn shutdown(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl Transport for PtyTransport {
    fn read(&mut self, buf: &mut [u8]) -> Result<ReadEvent, BackendError> {
        if self.pending.is_empty() {
            match self.rx.recv_timeout(self.read_budget) {
                Ok(chunk) => self.pending = chunk,
                // The poll quantum elapsed with nothing to read; the console may
                // still be alive (#185) — distinct from the channel disconnecting
                // below, which means the reader thread hit real EOF for good.
                Err(mpsc::RecvTimeoutError::Timeout) => return Ok(ReadEvent::Idle),
                // The reader thread exited (the guest's EOF or its own read
                // fault): no further bytes will ever arrive.
                Err(mpsc::RecvTimeoutError::Disconnected) => return Ok(ReadEvent::Closed),
            }
        }
        let take = buf.len().min(self.pending.len());
        buf[..take].copy_from_slice(&self.pending[..take]);
        self.pending.drain(..take);
        Ok(ReadEvent::Data(take))
    }

    fn write(&mut self, bytes: &[u8]) -> Result<(), BackendError> {
        self.writer
            .write_all(bytes)
            .and_then(|()| self.writer.flush())
            .map_err(|err| BackendError::Transport(format!("pty write: {err}")))
    }
}

#[cfg(test)]
mod tests {
    //! Tier-2 (pipe transport) and tier-3 (real boots) live here.
    //!
    //! Tier-2 drives [`PipeTransport`] against a fake serial subprocess that
    //! echoes the sentinel protocol, asserting a clean capture + parsed
    //! [`Outcome`](sandy::Outcome). It is `#[ignore]`d because it
    //! spawns a subprocess and touches real pipe fds — out of the sandbox's
    //! tier-1 budget, run on the host (#26).
    //!
    //! Tier-3 — real boots, PTY on an Apple-silicon host and a pipe on a Linux node, proving the
    //! four distinct outcomes reproduce on both transports — is host-gated and
    //! not expressed as a sandbox test at all (INV-S9: never counted green from
    //! a fake). It binds into `cargo test --test live_boot` (#26).
    use super::*;

    /// A silent PTY (no guest spawned, no output) must have `read` report
    /// [`ReadEvent::Idle`] after the poll quantum — not block forever, and not
    /// be mistaken for a closed console (#185: the driver treats `Idle` and
    /// `Closed` very differently). Regression for the vfkit hang a real boot
    /// exposed (#26).
    #[test]
    fn pty_transport_read_times_out_on_a_silent_console() -> Result<(), BackendError> {
        let mut transport = PtyTransport::open()?;
        transport.set_read_timeout(std::time::Duration::from_millis(100));
        let mut buf = [0u8; 16];
        let event = transport.read(&mut buf)?;
        assert_eq!(
            event,
            ReadEvent::Idle,
            "a silent PTY must time out to Idle, not block or close"
        );
        Ok(())
    }

    /// Once the child spawned on the PTY exits, the master reader thread hits a
    /// real EOF and `read` reports [`ReadEvent::Closed`] — not another `Idle`
    /// forever (#185: a driver that only ever saw `Idle` would spin reading a
    /// dead console instead of resolving the run).
    #[test]
    fn pty_transport_read_reports_closed_once_the_child_exits() -> Result<(), BackendError> {
        let mut transport = PtyTransport::open()?;
        transport.set_read_timeout(Duration::from_millis(100));
        transport.spawn(Path::new("/bin/sh"), &["-c".to_string(), "exit 0".to_string()])?;

        let mut buf = [0u8; 64];
        let closed = (0..50).any(|_| matches!(transport.read(&mut buf), Ok(ReadEvent::Closed)));
        assert!(
            closed,
            "the transport must report Closed once the child exits, not loop as Idle forever"
        );
        Ok(())
    }

    /// The pipe transport drives the protocol over any byte channel; an in-memory
    /// pair stands in for the hypervisor's serial socket. The real boot over a
    /// Unix socket to qemu is tier-3 (host), proven by a live `sandy run` (#26).
    #[test]
    fn pipe_transport_reads_and_writes_over_a_channel() -> Result<(), BackendError> {
        let reader = Box::new(std::io::Cursor::new(b"guest-says-hi".to_vec()));
        let writer: Box<dyn Write + Send> = Box::new(Vec::new());
        let mut transport = PipeTransport::new(reader, writer);

        let mut buf = [0u8; 32];
        let event = transport.read(&mut buf)?;
        let ReadEvent::Data(read) = event else {
            panic!("expected Data, got {event:?}");
        };
        assert_eq!(&buf[..read], b"guest-says-hi");
        transport.write(b"cmd")?;
        Ok(())
    }

    /// #185 regression: a quiet-but-still-open channel reports `Idle`, not
    /// `Closed` — only an actual EOF (the write end closing) reports `Closed`.
    /// Before the fix both collapsed into `Ok(0)`, which only worked because
    /// the read timeout was the whole run budget; polling on a short interval
    /// would have ended the run on the first quiet tick.
    #[test]
    fn pipe_transport_distinguishes_idle_from_closed() -> anyhow::Result<()> {
        use anyhow::Context as _;

        let (mut their_end, our_end) = std::os::unix::net::UnixStream::pair().context("create a socket pair")?;
        our_end
            .set_read_timeout(Some(Duration::from_millis(50)))
            .context("set read timeout")?;
        let reader = our_end.try_clone().context("clone socket")?;
        let mut transport = PipeTransport::new(Box::new(reader), Box::new(our_end));

        let mut buf = [0u8; 16];
        assert_eq!(
            transport.read(&mut buf)?,
            ReadEvent::Idle,
            "nothing sent yet, the channel is still open"
        );

        use std::io::Write as _;
        their_end.write_all(b"hi").context("write to the pair")?;
        assert_eq!(transport.read(&mut buf)?, ReadEvent::Data(2));

        drop(their_end);
        assert_eq!(
            transport.read(&mut buf)?,
            ReadEvent::Closed,
            "the write end closed; no further bytes will ever arrive"
        );
        Ok(())
    }
}
