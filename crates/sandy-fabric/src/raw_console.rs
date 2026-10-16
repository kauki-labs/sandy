//! The raw-console seam (spec §3.2): the break-glass fallback for a dead agent
//! or a broken boot, reaching a sandbox's console directly instead of through
//! its agent.
//!
//! Distinct from [`sandy_api::console::Transport`]: that one is the VM backend's
//! existing byte-level driver for the job-dispatch console protocol (serial
//! `ttyS0`/`hvc0`), already built and used on the run path. This seam is the
//! OPERATOR-facing escape hatch when the agent itself is unreachable — a
//! different caller, a different lifecycle, reusing the same mechanism once a
//! VM-backed impl wires it (see [`status`](RawConsole::status)'s doc).
//!
//! Honest-gate requirement: an impl with no real console to offer (the local
//! process backend has none — a bare process has no serial line) MUST report
//! [`ConsoleStatus::Unavailable`] and fail `read`/`write` with
//! [`ConsoleError::Unavailable`], never silently succeed as a no-op. A silent
//! no-op break-glass is indistinguishable from a working one until an operator
//! needs it and it isn't there.

/// Whether a [`RawConsole`] can actually reach a sandbox right now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsoleStatus {
    /// A real console is reachable.
    Available,
    /// No console is reachable. The string is the diagnostic reason (e.g. "no
    /// serial console on the process backend").
    Unavailable(String),
}

/// A raw-console failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConsoleError {
    /// This impl has no console to offer right now ([`ConsoleStatus::Unavailable`]).
    #[error("console unavailable: {0}")]
    Unavailable(String),
    /// The underlying channel faulted.
    #[error("console I/O: {0}")]
    Io(String),
}

/// A byte-level break-glass path to a sandbox, bypassing its agent.
///
/// `read`/`write` mirror [`sandy_api::console::Transport`]'s minimal read/write
/// split; the protocol on top is a caller concern. An impl reporting
/// [`ConsoleStatus::Unavailable`] from [`status`](RawConsole::status) MUST also
/// fail every `read`/`write` with [`ConsoleError::Unavailable`] — the two must
/// never disagree, or a caller that only checks one of them gets a false signal.
pub trait RawConsole: Send + Sync {
    /// Whether this console path can reach a sandbox right now.
    fn status(&self) -> ConsoleStatus;

    /// Read whatever console bytes are currently available into `buf`, and
    /// return the number read. `Ok(0)` means the console closed (EOF).
    ///
    /// # Errors
    /// [`ConsoleError::Unavailable`] when [`status`](RawConsole::status) is
    /// [`ConsoleStatus::Unavailable`]; [`ConsoleError::Io`] if the channel faults.
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, ConsoleError>;

    /// Write `bytes` to the sandbox's console.
    ///
    /// # Errors
    /// [`ConsoleError::Unavailable`] when [`status`](RawConsole::status) is
    /// [`ConsoleStatus::Unavailable`]; [`ConsoleError::Io`] if the write cannot
    /// be completed.
    fn write(&mut self, bytes: &[u8]) -> Result<(), ConsoleError>;
}
