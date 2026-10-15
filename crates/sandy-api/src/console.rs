//! The console transport seam: a byte-level channel to a guest.

use crate::backend::BackendError;

/// A byte-level console channel to a guest.
///
/// The read/write split is deliberately minimal — the protocol does all the
/// framing — so a pipe, a PTY, or a test fixture can stand in interchangeably.
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
