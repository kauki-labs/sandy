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
    // A bounded tail of everything read from the console, so a boot that never
    // reaches the command is still diagnosable (the console is otherwise lost).
    let mut console = ConsoleTail::new();
    // Start of the current phase's budget; reset when the command is injected.
    let mut phase_start = Instant::now();

    loop {
        if let Some(result) = protocol.outcome() {
            return finalize(result, booted, console.into_string());
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
            Ok(read) => {
                console.push(&buf[..read]);
                match protocol.feed(&buf[..read]) {
                    ProtocolStep::Inject(frame) => {
                        booted = true;
                        phase_start = Instant::now();
                        if let Err(err) = transport.write(&frame) {
                            return transport_fault(err, booted, console.into_string());
                        }
                    }
                    ProtocolStep::NeedMore | ProtocolStep::Done => {}
                }
            }
            Err(err) => return transport_fault(err, booted, console.into_string()),
        }
    }
}

/// The last [`ConsoleTail::CAP`] bytes read from the console, as a rolling buffer:
/// a long-running job can print more than fits, and only the tail is kept for
/// diagnostics.
struct ConsoleTail {
    bytes: Vec<u8>,
}

impl ConsoleTail {
    /// Keep up to 64 KiB of console tail.
    const CAP: usize = 64 * 1024;

    fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    fn push(&mut self, chunk: &[u8]) {
        self.bytes.extend_from_slice(chunk);
        if self.bytes.len() > Self::CAP {
            let excess = self.bytes.len() - Self::CAP;
            self.bytes.drain(..excess);
        }
    }

    fn into_string(self) -> String {
        String::from_utf8_lossy(&self.bytes).into_owned()
    }
}

/// Collapse a terminal protocol result into the physical [`Outcome`], attaching the
/// captured `console`. A [`BackendError`] (a garbled frame) becomes
/// `transport_error` with no fabricated `guest_exit` (INV-OUTCOME).
fn finalize(result: Result<Outcome, BackendError>, booted: bool, console: String) -> Outcome {
    match result {
        Ok(mut outcome) => {
            outcome.console = console;
            outcome
        }
        Err(err) => transport_fault(err, booted, console),
    }
}

/// Map an infra fault into the `transport_error` field, preserving the observed
/// boot state and the captured console, and never inventing an exit code.
fn transport_fault(err: BackendError, booted: bool, console: String) -> Outcome {
    Outcome {
        booted,
        guest_exit: None,
        transport_error: Some(err.to_string()),
        timed_out: false,
        console,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The console tail keeps only the last `CAP` bytes: an overlong stream is
    /// bounded, and the retained text is the tail (the end of the boot/run).
    #[test]
    fn console_tail_keeps_the_last_cap_bytes() {
        let mut tail = ConsoleTail::new();
        tail.push(&vec![b'x'; ConsoleTail::CAP]);
        tail.push(b"END");
        let out = tail.into_string();
        assert_eq!(out.len(), ConsoleTail::CAP, "the tail is bounded to CAP bytes");
        assert!(out.ends_with("END"), "the retained bytes are the tail, not the head");
    }

    /// A short stream is kept whole and decoded lossily.
    #[test]
    fn console_tail_keeps_a_short_stream_whole() {
        let mut tail = ConsoleTail::new();
        tail.push(b"boot log\n");
        assert_eq!(tail.into_string(), "boot log\n");
    }
}
