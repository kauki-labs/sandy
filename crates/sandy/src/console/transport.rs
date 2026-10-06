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
#[derive(Debug)]
pub struct PipeTransport;

impl PipeTransport {
    /// Open the pipe transport over an already-spawned guest's console fds.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError::Transport`] if the console fds cannot be set up.
    pub fn connect() -> Result<Self, BackendError> {
        todo!("open the qemu serial pipe (tier-2/host)")
    }
}

impl Transport for PipeTransport {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, BackendError> {
        let _ = buf;
        todo!("read from the serial pipe")
    }

    fn write(&mut self, bytes: &[u8]) -> Result<(), BackendError> {
        let _ = bytes;
        todo!("write to the serial pipe")
    }
}

/// The macOS/vfkit PTY transport: the guest console on a pseudo-terminal.
///
/// The real build allocates the PTY through `portable-pty` (a safe wrapper), so
/// the transport carries no `unsafe` block (INV-SAFE).
#[derive(Debug)]
pub struct PtyTransport;

impl PtyTransport {
    /// Allocate a PTY and attach it to the guest console.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError::Transport`] if the PTY cannot be allocated.
    pub fn open() -> Result<Self, BackendError> {
        todo!("allocate a PTY via portable-pty and attach the guest console (tier-2/host)")
    }
}

impl Transport for PtyTransport {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, BackendError> {
        let _ = buf;
        todo!("read from the PTY master")
    }

    fn write(&mut self, bytes: &[u8]) -> Result<(), BackendError> {
        let _ = bytes;
        todo!("write to the PTY master")
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
