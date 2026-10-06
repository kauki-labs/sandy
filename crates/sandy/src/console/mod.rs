//! The native console driver (Block 33): boot → inject → capture → teardown.
//!
//! This is the Rust port of nix-vm's `vm-console-run.py`, shared by both native
//! backends (#32/#35). It is split into two seams:
//!
//! - [`protocol`] — the transport-agnostic sentinel state machine (pure, tier-1): fed `&[u8]` chunks, it detects the
//!   boot-ready marker, injects the base64-wrapped command, captures the bytes between the unique per-run sentinels,
//!   parses the trailing `exit=<n>`, and produces the pinned [`Outcome`](crate::backend::Outcome).
//! - [`transport`] — the platform byte channel the machine drives: a pipe on Linux/qemu, a PTY on macOS/vfkit.
//!
//! [`run_console`] wires a [`Transport`] to a [`Protocol`]. The emitted
//! [`Outcome`](crate::backend::Outcome) is the pinned `snake_case` record reused
//! from [`crate::backend`] (INV-8), with the four outcomes kept distinct and
//! `guest_exit` never fabricated (INV-OUTCOME).

mod protocol;
mod transport;

pub use protocol::{Markers, Protocol, ProtocolStep, TimeoutPolicy, parse_exit};
pub use transport::{PipeTransport, PtyTransport, Transport};

use crate::backend::{Outcome, RunSpec};

/// Run one job over `transport` using the sentinel [`Protocol`], returning the
/// physical [`Outcome`](crate::backend::Outcome).
///
/// Derives the per-phase [`TimeoutPolicy`] from `spec.timeout_secs`, then loops:
/// read a chunk, [`feed`](Protocol::feed) it, write any
/// [`Inject`](ProtocolStep::Inject) bytes, and call
/// [`on_timeout`](Protocol::on_timeout) when
/// [`current_deadline`](Protocol::current_deadline) elapses, until the machine
/// is [`Done`](ProtocolStep::Done). A [`BackendError::Protocol`] or
/// transport fault is mapped into the `transport_error` field of the returned
/// outcome rather than fabricating `guest_exit` (INV-OUTCOME).
///
/// [`BackendError::Protocol`]: crate::backend::BackendError::Protocol
#[must_use]
pub fn run_console<T: Transport + ?Sized>(transport: &mut T, spec: &RunSpec<'_>, markers: &Markers) -> Outcome {
    let _ = (transport, spec, markers);
    todo!("drive transport<->protocol to a terminal Outcome")
}
