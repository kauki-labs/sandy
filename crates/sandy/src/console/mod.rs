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

use std::time::Instant;

pub use protocol::{Markers, Protocol, ProtocolStep, TimeoutPolicy, parse_exit};
pub use transport::{PipeTransport, PtyTransport, Transport};

use crate::backend::{BackendError, Outcome, RunSpec};

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
    let mut protocol =
        Protocol::new(markers.clone(), TimeoutPolicy::from_secs(spec.timeout_secs)).with_command(spec.command);
    let mut buf = [0u8; 4096];
    // Tracks whether the ready marker was seen, so a late protocol/transport
    // fault is reported with the boot state we actually observed rather than a
    // fabricated one.
    let mut booted = false;
    // Start of the current phase's budget; reset when the command is injected.
    let mut phase_start = Instant::now();

    loop {
        if let Some(result) = protocol.outcome() {
            return finalize(result, booted);
        }
        if phase_start.elapsed() >= protocol.current_deadline() {
            protocol.on_timeout();
            continue;
        }
        match transport.read(&mut buf) {
            Ok(0) => {
                // The console closed before a terminal state: let the timeout
                // path resolve it (booted:false, or timed_out:true post-inject).
                protocol.on_timeout();
            }
            Ok(read) => match protocol.feed(&buf[..read]) {
                ProtocolStep::Inject(frame) => {
                    booted = true;
                    phase_start = Instant::now();
                    if let Err(err) = transport.write(&frame) {
                        return transport_fault(err, booted);
                    }
                }
                ProtocolStep::NeedMore | ProtocolStep::Done => {}
            },
            Err(err) => return transport_fault(err, booted),
        }
    }
}

/// Collapse a terminal protocol result into the physical [`Outcome`]. A
/// [`BackendError`] (a garbled frame) becomes `transport_error` with no
/// fabricated `guest_exit` (INV-OUTCOME).
fn finalize(result: Result<Outcome, BackendError>, booted: bool) -> Outcome {
    match result {
        Ok(outcome) => outcome,
        Err(err) => transport_fault(err, booted),
    }
}

/// Map an infra fault into the `transport_error` field, preserving the observed
/// boot state and never inventing an exit code.
fn transport_fault(err: BackendError, booted: bool) -> Outcome {
    Outcome {
        booted,
        guest_exit: None,
        transport_error: Some(err.to_string()),
        timed_out: false,
    }
}
