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

use crate::backend::BackendError;

/// A byte-level console channel to a guest.
///
/// The read/write split is deliberately minimal — the [`Protocol`] does all the
/// framing — so a pipe, a PTY, or a test fixture can stand in interchangeably.
///
/// [`Protocol`]: super::protocol::Protocol
pub trait Transport {
    /// Read whatever console bytes are currently available into `buf`, blocking
    /// up to the caller's deadline, and return the number read. `Ok(0)` means
    /// the console closed (EOF).
    ///
    /// # Errors
    ///
    /// Returns [`BackendError::Transport`] if the underlying channel faults.
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, BackendError>;

    /// Write all of `bytes` to the guest console (the injected command frame).
    ///
    /// # Errors
    ///
    /// Returns [`BackendError::Transport`] if the write cannot be completed.
    fn write(&mut self, bytes: &[u8]) -> Result<(), BackendError>;
}

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
    /// The `reader` should carry a read timeout matching the run's deadline: a
    /// timed-out read is reported as `Ok(0)` (see [`Transport::read`]), which the
    /// driver treats as the deadline elapsing rather than a fault.
    #[must_use]
    pub fn new(reader: Box<dyn Read + Send>, writer: Box<dyn Write + Send>) -> Self {
        Self { reader, writer }
    }
}

impl Transport for PipeTransport {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, BackendError> {
        match self.reader.read(buf) {
            Ok(read) => Ok(read),
            // A read timeout (the channel carries the run deadline) or EOF is
            // reported as `Ok(0)`: the driver resolves it through the protocol's
            // own timeout path, never as a fabricated transport fault.
            Err(err) if matches!(err.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => Ok(0),
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
    /// How long [`Transport::read`] waits for a chunk before reporting `Ok(0)`
    /// (the run deadline); set by the backend via [`PtyTransport::set_read_timeout`].
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
            // A generous default until the backend sets the run's budget.
            read_budget: Duration::from_secs(300),
            writer,
            child: None,
        })
    }

    /// Set how long [`Transport::read`] waits for guest output before reporting
    /// the deadline (`Ok(0)`). The backend sets this to the run's timeout so a
    /// silent guest resolves through the protocol's timeout path.
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
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, BackendError> {
        if self.pending.is_empty() {
            match self.rx.recv_timeout(self.read_budget) {
                Ok(chunk) => self.pending = chunk,
                // A timeout (the deadline elapsed) or a disconnected channel (the
                // reader thread hit EOF — the guest exited) is reported as `Ok(0)`;
                // the driver resolves it through the protocol's own timeout path,
                // never as a fabricated fault.
                Err(_) => return Ok(0),
            }
        }
        let take = buf.len().min(self.pending.len());
        buf[..take].copy_from_slice(&self.pending[..take]);
        self.pending.drain(..take);
        Ok(take)
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
    //! [`Outcome`](crate::backend::Outcome). It is `#[ignore]`d because it
    //! spawns a subprocess and touches real pipe fds — out of the sandbox's
    //! tier-1 budget, run on the host (#26).
    //!
    //! Tier-3 — real boots, PTY on an M2 and a pipe on a Linux node, proving the
    //! four distinct outcomes reproduce on both transports — is host-gated and
    //! not expressed as a sandbox test at all (INV-S9: never counted green from
    //! a fake). It binds into `cargo test --test live_boot` (#26).
    use super::*;

    /// A silent PTY (no guest spawned, no output) must have `read` return `Ok(0)`
    /// after the budget — the deadline path — rather than blocking forever.
    /// Regression for the vfkit hang a real boot exposed (#26).
    #[test]
    fn pty_transport_read_times_out_on_a_silent_console() -> Result<(), BackendError> {
        let mut transport = PtyTransport::open()?;
        transport.set_read_timeout(std::time::Duration::from_millis(100));
        let mut buf = [0u8; 16];
        let read = transport.read(&mut buf)?;
        assert_eq!(read, 0, "a silent PTY must time out to Ok(0), not block");
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
        let read = transport.read(&mut buf)?;
        assert_eq!(&buf[..read], b"guest-says-hi");
        transport.write(b"cmd")?;
        Ok(())
    }
}
