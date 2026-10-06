//! The console transport split (tier-2 / host).
//!
//! The sentinel [`Protocol`](super::protocol::Protocol) is transport-agnostic;
//! this module supplies the byte channel it drives. There are two, selected by
//! platform:
//!
//! - **[`PipeTransport`]** — a plain pipe to the guest's serial console, the Linux/qemu path (proven on ws01: an ~8s
//!   clean boot).
//! - **[`PtyTransport`]** — a pseudo-terminal, the macOS/vfkit path. The real implementation will go through a safe PTY
//!   wrapper (`portable-pty`, chosen over `nix::pty` for its cross-platform surface) so no `unsafe` block is needed
//!   (INV-SAFE).
//!
//! Both are skeletons here: the real fd work is tier-2/host and binds into #26.
//! Only the [`Transport`] seam is pinned so [`run_console`](super::run_console)
//! and the backends can be written against it now.

use std::io::{Read, Write};

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

/// The Linux/qemu pipe transport: the guest serial console on a plain pipe.
///
/// Holds the two halves of the guest's serial console as boxed byte streams.
/// The host wiring that spawns qemu and hands over its console fds lands in #26;
/// [`connect`](PipeTransport::connect) therefore reports host-deferral rather
/// than fabricating a channel to a guest that has not been spawned.
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
    /// Open the pipe transport over an already-spawned guest's console fds.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError::Transport`]: the console fds are supplied by the
    /// qemu-spawn host wiring (#26), which is not wired into the sandbox build.
    pub fn connect() -> Result<Self, BackendError> {
        Err(BackendError::Transport(
            "pipe transport requires the guest serial-console fds from the qemu spawn (host-wired in #26)".to_string(),
        ))
    }
}

impl Transport for PipeTransport {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, BackendError> {
        self.reader
            .read(buf)
            .map_err(|err| BackendError::Transport(format!("pipe read: {err}")))
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
    /// Keeps the allocated PTY pair alive for the lifetime of the transport.
    _pair: portable_pty::PtyPair,
    /// Reader over the PTY master (guest stdout).
    reader: Box<dyn Read + Send>,
    /// Writer over the PTY master (guest stdin — the injected command frame).
    writer: Box<dyn Write + Send>,
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
        let reader = pair
            .master
            .try_clone_reader()
            .map_err(|err| BackendError::Transport(format!("pty reader: {err}")))?;
        let writer = pair
            .master
            .take_writer()
            .map_err(|err| BackendError::Transport(format!("pty writer: {err}")))?;
        Ok(Self {
            _pair: pair,
            reader,
            writer,
        })
    }
}

impl Transport for PtyTransport {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, BackendError> {
        self.reader
            .read(buf)
            .map_err(|err| BackendError::Transport(format!("pty read: {err}")))
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
    //! a fake). It binds into `cargo test --test phase_a` (#26).
    use super::*;

    /// Tier-2: a fake serial subprocess speaks the sentinel protocol over a
    /// pipe; [`PipeTransport`] + [`run_console`](crate::console::run_console)
    /// must produce a clean, parsed outcome. Ignored: host-gated (spawns a
    /// subprocess, real fds). RED until the pipe transport is implemented.
    #[test]
    #[ignore = "tier-2: spawns a fake-serial subprocess over real pipe fds; host-gated (#26)"]
    fn pipe_transport_against_fake_serial() {
        let mut transport = PipeTransport::connect().expect("connect pipe transport");
        // The fake-serial fixture + run_console wiring is filled in at the host
        // tier; constructing the transport already exercises the seam.
        let mut sink = [0u8; 64];
        let _ = transport.read(&mut sink);
    }
}
