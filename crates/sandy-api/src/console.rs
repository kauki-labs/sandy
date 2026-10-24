//! The console transport seam: a byte-level channel to a guest.

use crate::backend::BackendError;

/// What one [`Transport::read`] call observed.
///
/// Splitting "nothing yet" from "gone for good" (#185) is what lets a driver
/// poll a live cancellation/deadline signal on a short interval without a
/// quiet-but-still-booting guest being mistaken for a closed console: before
/// this, both cases collapsed into `Ok(0)`, which only worked because the
/// read's own timeout was set to the whole run budget (one blocking call per
/// phase, never polled in between).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadEvent {
    /// `n` bytes were read into the caller's buffer.
    Data(usize),
    /// No bytes arrived within this call's own poll window; the console may
    /// still be alive.
    Idle,
    /// The console closed: no further bytes will ever arrive.
    Closed,
}

/// A byte-level console channel to a guest.
///
/// The read/write split is deliberately minimal — the protocol does all the
/// framing — so a pipe, a PTY, or a test fixture can stand in interchangeably.
pub trait Transport {
    /// Read whatever console bytes are currently available into `buf`,
    /// blocking up to the implementation's own short poll window (never the
    /// whole run budget — see [`ReadEvent::Idle`]), and report what happened.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError::Transport`] if the underlying channel faults.
    fn read(&mut self, buf: &mut [u8]) -> Result<ReadEvent, BackendError>;

    /// Write all of `bytes` to the guest console (the injected command frame).
    ///
    /// # Errors
    ///
    /// Returns [`BackendError::Transport`] if the write cannot be completed.
    fn write(&mut self, bytes: &[u8]) -> Result<(), BackendError>;
}
