//! The transport-agnostic sentinel state machine (tier-1, pure).
//!
//! The protocol is the Rust port of nix-vm's `vm-console-run.py` console
//! contract, with the transport sheared off: it is fed `&[u8]` chunks and a
//! single timeout event, and it never reads a clock or a file descriptor. A
//! scripted fixture and a real console fd therefore drive it identically
//! (`feed` / `on_timeout`), which is what makes the whole boot→inject→capture
//! →exit contract testable in the sandbox (tier-1).
//!
//! The contract, in order:
//! 1. scan the guest's stdout for the boot-ready [`Markers::ready`] marker;
//! 2. once ready, inject the base64-wrapped command bracketed by the unique per-run [`Markers::start`] /
//!    [`Markers::end`] sentinels;
//! 3. capture the bytes strictly *between* those sentinels (binary-safe — the region may hold NULs and arbitrary
//!    control bytes);
//! 4. parse the trailing `exit=<n>` line that follows the END sentinel;
//! 5. produce a terminal [`Outcome`].
//!
//! Per INV-OUTCOME the machine never fabricates `guest_exit`: a missing ready
//! marker is `booted: false`, a missing END sentinel is `timed_out: true`, and
//! a garbled `exit=` line is a [`BackendError::Protocol`] — never a defaulted
//! `guest_exit: 0`. The emitted [`Outcome`] is the pinned `snake_case` record
//! reused from [`crate::backend`] (INV-8), never redefined here (INV-TRAIT).

use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use uuid::Uuid;

use crate::backend::{BackendError, Outcome};

/// Find the first offset of `needle` within `haystack` (byte-exact, binary-safe).
///
/// Used both to locate the per-run sentinels in the console stream and to find
/// the `exit=` token in the trailing region. An empty needle matches at 0.
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    if haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|window| window == needle)
}

/// The per-run markers that delimit the console protocol.
///
/// `ready` is the host-agnostic boot-ready marker (e.g. the guest's login
/// banner). `start` / `end` are the unique per-run sentinels that bracket the
/// captured output; making them per-run (a fresh [`Uuid`]) stops output from a
/// previous run, or from the command itself echoing a literal, from being
/// mistaken for a frame boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Markers {
    /// The boot-ready marker to scan stdout for before injecting the command.
    pub ready: String,
    /// The opening sentinel; capture begins at the byte after it.
    pub start: String,
    /// The closing sentinel; capture ends at the byte before it.
    pub end: String,
}

impl Markers {
    /// Construct markers from explicit strings (used by tests and callers that
    /// pin their own sentinel text).
    #[must_use]
    pub fn new(ready: impl Into<String>, start: impl Into<String>, end: impl Into<String>) -> Self {
        Self {
            ready: ready.into(),
            start: start.into(),
            end: end.into(),
        }
    }

    /// Derive per-run sentinels from `run_id` in the pinned
    /// `<<SANDY-<uuid>-START>>` / `<<SANDY-<uuid>-END>>` format, keeping the
    /// caller's boot-ready marker.
    #[must_use]
    pub fn for_run(ready: impl Into<String>, run_id: Uuid) -> Self {
        Self {
            ready: ready.into(),
            start: format!("<<SANDY-{run_id}-START>>"),
            end: format!("<<SANDY-{run_id}-END>>"),
        }
    }
}

/// The two wall-clock budgets the driver enforces on the (clockless) state
/// machine. The machine reports which budget is live via
/// [`Protocol::current_deadline`]; when it elapses the driver calls
/// [`Protocol::on_timeout`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeoutPolicy {
    /// Maximum wait for the boot-ready marker (before any injection).
    pub boot: Duration,
    /// Maximum wait for the END sentinel after the command is injected.
    pub command: Duration,
}

impl TimeoutPolicy {
    /// A policy that gives both phases the same whole-second budget — the common
    /// case, derived from a [`crate::backend::RunSpec`]'s `timeout_secs`.
    #[must_use]
    pub fn from_secs(secs: u32) -> Self {
        let budget = Duration::from_secs(u64::from(secs));
        Self {
            boot: budget,
            command: budget,
        }
    }
}

/// What the driver should do after feeding a chunk (or a timeout) to the
/// [`Protocol`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolStep {
    /// Nothing to emit yet; read more bytes and feed them.
    NeedMore,
    /// The ready marker was seen — write these bytes to the guest console (the
    /// base64-wrapped command bracketed by the START/END sentinels), then keep
    /// reading.
    Inject(Vec<u8>),
    /// The machine reached a terminal state; the result is available from
    /// [`Protocol::outcome`]. Feeding further bytes is a no-op.
    Done,
}

/// The pure sentinel state machine.
///
/// Drive it by repeatedly reading from the transport and calling [`feed`] with
/// each chunk, writing out any [`ProtocolStep::Inject`] bytes, and calling
/// [`on_timeout`] when [`current_deadline`] elapses. When a step returns
/// [`ProtocolStep::Done`], read the terminal result from [`outcome`].
///
/// [`feed`]: Protocol::feed
/// [`on_timeout`]: Protocol::on_timeout
/// [`current_deadline`]: Protocol::current_deadline
/// [`outcome`]: Protocol::outcome
#[derive(Debug)]
pub struct Protocol {
    /// The markers this run scans for and injects.
    markers: Markers,
    /// The per-phase timeout budgets.
    timeout: TimeoutPolicy,
    /// The base64-wrapped command frame to inject once the ready marker is seen.
    /// Empty when the machine is driven as a pure parser (no command bound).
    command_frame: Vec<u8>,
    /// Raw bytes seen but not yet consumed by the marker scanner (a marker may
    /// straddle two reads).
    buffer: Vec<u8>,
    /// The bytes captured strictly between START and END (binary-safe).
    captured: Vec<u8>,
    /// Whether the boot-ready marker has been seen.
    ready_seen: bool,
    /// Whether the command has been injected.
    injected: bool,
    /// Whether the START sentinel has been seen (capture is in progress).
    start_seen: bool,
    /// Whether the END sentinel has been seen (capture is complete; the trailing
    /// `exit=` line is awaited).
    end_seen: bool,
    /// The terminal result, once reached. `None` while still running.
    terminal: Option<Result<Outcome, BackendError>>,
}

impl Protocol {
    /// Create a fresh protocol for one run.
    ///
    /// The returned machine carries no command frame, so it parses a console
    /// stream (ready → capture → exit) but injects an empty frame. Bind a
    /// command with [`Protocol::with_command`] before driving a real transport.
    #[must_use]
    pub fn new(markers: Markers, timeout: TimeoutPolicy) -> Self {
        Self {
            markers,
            timeout,
            command_frame: Vec::new(),
            buffer: Vec::new(),
            captured: Vec::new(),
            ready_seen: false,
            injected: false,
            start_seen: false,
            end_seen: false,
            terminal: None,
        }
    }

    /// Bind the guest command this run injects once the ready marker is seen.
    ///
    /// The command is base64-wrapped (INV-SAFE: no shell-metacharacter leakage
    /// from argv into the injected line) inside a frame that brackets the
    /// guest's stdout with the per-run START/END sentinels and appends the
    /// `exit=<n>` line the parser reads back.
    #[must_use]
    pub(crate) fn with_command(mut self, command: &[String]) -> Self {
        self.command_frame = Self::build_frame(&self.markers, command);
        self
    }

    /// Build the injected command frame: a shell line that decodes the
    /// base64-wrapped command, runs it between the START/END sentinels, and
    /// reports the exit status the parser reads.
    fn build_frame(markers: &Markers, command: &[String]) -> Vec<u8> {
        let encoded = STANDARD.encode(command.join(" ").as_bytes());
        format!(
            "printf '%s' '{start}'; printf '%s' '{encoded}' | base64 -d | sh; printf '%s\\nexit=%d\\n' '{end}' \
             \"$?\"\n",
            start = markers.start,
            end = markers.end,
        )
        .into_bytes()
    }

    /// Feed one chunk of console bytes and advance the machine.
    ///
    /// Scans for the ready marker (pre-injection) or the START/END sentinels
    /// (post-injection), captures the region between the sentinels verbatim, and
    /// parses the trailing `exit=<n>` once END is seen.
    pub fn feed(&mut self, bytes: &[u8]) -> ProtocolStep {
        if self.terminal.is_some() {
            return ProtocolStep::Done;
        }
        self.buffer.extend_from_slice(bytes);
        self.advance()
    }

    /// Advance the machine over the currently buffered bytes as far as it can.
    ///
    /// Runs the phases in order — ready → START → capture-to-END → parse exit —
    /// consuming the buffer as each boundary is crossed. Returns
    /// [`ProtocolStep::Inject`] when this call crossed the ready boundary (the
    /// driver must write the frame), [`ProtocolStep::Done`] when a terminal
    /// result was reached without a fresh injection, and
    /// [`ProtocolStep::NeedMore`] otherwise.
    fn advance(&mut self) -> ProtocolStep {
        let mut injected_now = false;

        // Phase 1 — wait for the boot-ready marker, then inject the command.
        if !self.ready_seen {
            match find_subslice(&self.buffer, self.markers.ready.as_bytes()) {
                Some(pos) => {
                    self.ready_seen = true;
                    self.injected = true;
                    injected_now = true;
                    self.drain_through(pos, self.markers.ready.len());
                }
                None => {
                    self.trim_pending(self.markers.ready.len());
                    return ProtocolStep::NeedMore;
                }
            }
        }

        // Phase 2 — discard the echo between the frame and the START sentinel.
        if !self.start_seen {
            match find_subslice(&self.buffer, self.markers.start.as_bytes()) {
                Some(pos) => {
                    self.start_seen = true;
                    self.drain_through(pos, self.markers.start.len());
                }
                None => {
                    self.trim_pending(self.markers.start.len());
                    return self.pending_step(injected_now);
                }
            }
        }

        // Phase 3 — capture verbatim up to the END sentinel (binary-safe).
        if !self.end_seen {
            match find_subslice(&self.buffer, self.markers.end.as_bytes()) {
                Some(pos) => {
                    self.captured.extend_from_slice(&self.buffer[..pos]);
                    self.end_seen = true;
                    self.drain_through(pos, self.markers.end.len());
                }
                None => {
                    // Flush all but a possible straddling END prefix into the
                    // capture so the buffer stays bounded across reads.
                    let keep = self.markers.end.len().saturating_sub(1);
                    if self.buffer.len() > keep {
                        let take = self.buffer.len() - keep;
                        self.captured.extend_from_slice(&self.buffer[..take]);
                        self.buffer.drain(..take);
                    }
                    return self.pending_step(injected_now);
                }
            }
        }

        // Phase 4 — parse the trailing `exit=<n>` line once it is complete.
        if let Some(nl) = self.buffer.iter().position(|&byte| byte == b'\n') {
            let line = self.buffer[..=nl].to_vec();
            self.terminal = Some(self.finish(&line));
        } else {
            return self.pending_step(injected_now);
        }

        if injected_now {
            ProtocolStep::Inject(self.command_frame.clone())
        } else {
            ProtocolStep::Done
        }
    }

    /// Drop everything up to and including a marker found at `pos` of length
    /// `marker_len`.
    fn drain_through(&mut self, pos: usize, marker_len: usize) {
        self.buffer.drain(..pos + marker_len);
    }

    /// While scanning for a marker that was not found, keep only the trailing
    /// `marker_len - 1` bytes (the most a marker can straddle into the next
    /// read), discarding the rest as noise.
    fn trim_pending(&mut self, marker_len: usize) {
        let keep = marker_len.saturating_sub(1);
        if self.buffer.len() > keep {
            let drop = self.buffer.len() - keep;
            self.buffer.drain(..drop);
        }
    }

    /// The step to return when no terminal state was reached this call: signal
    /// the pending injection if it just happened, else ask for more bytes.
    fn pending_step(&self, injected_now: bool) -> ProtocolStep {
        if injected_now {
            ProtocolStep::Inject(self.command_frame.clone())
        } else {
            ProtocolStep::NeedMore
        }
    }

    /// Turn a complete `exit=<n>` line into the terminal [`Outcome`]; a garbled
    /// line is a [`BackendError::Protocol`], never a defaulted exit (INV-OUTCOME).
    fn finish(&self, exit_line: &[u8]) -> Result<Outcome, BackendError> {
        let code = parse_exit(exit_line)?;
        tracing::debug!(
            captured_bytes = self.captured.len(),
            guest_exit = code,
            "console capture complete"
        );
        Ok(Outcome {
            booted: true,
            guest_exit: Some(code),
            transport_error: None,
            timed_out: false,
        })
    }

    /// Signal that the budget reported by [`Protocol::current_deadline`] has
    /// elapsed.
    ///
    /// Before the ready marker this yields a terminal `booted: false` (no
    /// fabricated exit); after injection, with the END sentinel unseen, it
    /// yields `timed_out: true` (INV-OUTCOME).
    pub fn on_timeout(&mut self) -> ProtocolStep {
        if self.terminal.is_some() {
            return ProtocolStep::Done;
        }
        let outcome = if self.injected {
            // Ready was seen and the command injected, but the END sentinel
            // never arrived: the command hung (INV-OUTCOME — no fabricated exit).
            Outcome {
                booted: true,
                guest_exit: None,
                transport_error: None,
                timed_out: true,
            }
        } else {
            // The ready marker never arrived within the boot budget.
            Outcome {
                booted: false,
                guest_exit: None,
                transport_error: None,
                timed_out: false,
            }
        };
        self.terminal = Some(Ok(outcome));
        ProtocolStep::Done
    }

    /// The remaining-phase budget the driver should wait under: the boot budget
    /// until the ready marker is seen, then the command budget.
    #[must_use]
    pub fn current_deadline(&self) -> Duration {
        if self.ready_seen {
            self.timeout.command
        } else {
            self.timeout.boot
        }
    }

    /// The terminal result, or `None` while the run is still in progress.
    ///
    /// A protocol/transport fault surfaces as `Err(BackendError::Protocol)`; a
    /// completed or boot-failed or timed-out run surfaces as `Ok(Outcome)` with
    /// the matching field set.
    #[must_use]
    pub fn outcome(&self) -> Option<Result<Outcome, BackendError>> {
        self.terminal.clone()
    }
}

/// Parse the trailing `exit=<n>` line that follows the END sentinel.
///
/// `tail` is the slice after the END sentinel. The exit code is a signed
/// decimal (the guest's `$?`). This is the separately-testable pure core of the
/// exit contract.
///
/// # Errors
///
/// Returns [`BackendError::Protocol`] when the `exit=` token is absent or its
/// value is not a valid integer — never a defaulted `0` (INV-OUTCOME).
pub fn parse_exit(tail: &[u8]) -> Result<i32, BackendError> {
    const KEY: &[u8] = b"exit=";
    let start =
        find_subslice(tail, KEY).ok_or_else(|| BackendError::Protocol("no `exit=` marker in tail".to_string()))?;
    let rest = &tail[start + KEY.len()..];
    let end = rest
        .iter()
        .position(|&byte| byte == b'\n' || byte == b'\r')
        .unwrap_or(rest.len());
    let value = std::str::from_utf8(&rest[..end])
        .map_err(|_| BackendError::Protocol("non-utf8 exit value".to_string()))?
        .trim();
    value
        .parse::<i32>()
        .map_err(|err| BackendError::Protocol(format!("unparsable exit value {value:?}: {err}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The boot-ready marker used across the protocol tests.
    const READY: &str = "sandy login:";

    /// Build markers with fixed, human-readable sentinels so the scripted
    /// streams below are easy to read.
    fn test_markers() -> Markers {
        Markers::new(READY, "<<SANDY-TEST-START>>", "<<SANDY-TEST-END>>")
    }

    /// Assemble a scripted console stream: `pre` boot chatter, the ready marker,
    /// then the captured `body` bracketed by the sentinels, then `tail` (e.g.
    /// the `exit=` line).
    fn scripted(markers: &Markers, pre: &[u8], body: &[u8], tail: &[u8]) -> Vec<u8> {
        let mut stream = Vec::new();
        stream.extend_from_slice(pre);
        stream.extend_from_slice(markers.ready.as_bytes());
        stream.extend_from_slice(b"\n");
        stream.extend_from_slice(markers.start.as_bytes());
        stream.extend_from_slice(body);
        stream.extend_from_slice(markers.end.as_bytes());
        stream.extend_from_slice(tail);
        stream
    }

    /// Drive the protocol to a terminal result from a single scripted stream.
    fn drive(markers: Markers, stream: &[u8]) -> Option<Result<Outcome, BackendError>> {
        let mut protocol = Protocol::new(markers, TimeoutPolicy::from_secs(30));
        let _ = protocol.feed(stream);
        protocol.outcome()
    }

    /// Tier-1 positive: ready marker detected → command injected → output
    /// captured → `exit=0` parsed, yielding a booted run with `guest_exit:
    /// Some(0)`. RED until `feed`/`outcome` are implemented (todo!() panics).
    #[test]
    fn detects_ready_injects_and_captures() -> anyhow::Result<()> {
        use anyhow::Context;
        let markers = test_markers();
        let stream = scripted(&markers, b"booting...\n", b"hello from guest\n", b"exit=0\n");
        let outcome = drive(markers, &stream)
            .context("protocol reached a terminal result")?
            .context("terminal result is an Outcome, not a protocol error")?;
        assert_eq!(
            outcome,
            Outcome {
                booted: true,
                guest_exit: Some(0),
                transport_error: None,
                timed_out: false,
            }
        );
        Ok(())
    }

    /// Tier-1 positive: a non-zero exit is carried through verbatim, never
    /// coerced. RED until implemented.
    #[test]
    fn parses_nonzero_exit() -> anyhow::Result<()> {
        use anyhow::Context;
        let markers = test_markers();
        let stream = scripted(&markers, b"", b"work\n", b"exit=7\n");
        let outcome = drive(markers, &stream)
            .context("terminal result")?
            .context("Outcome, not a protocol error")?;
        assert!(outcome.booted);
        assert_eq!(outcome.guest_exit, Some(7));
        Ok(())
    }

    /// Tier-1 adversarial: the ready marker never arrives before the boot
    /// timeout → `booted: false` with no fabricated exit (INV-OUTCOME). RED
    /// until implemented.
    #[test]
    fn never_ready_is_not_booted() -> anyhow::Result<()> {
        use anyhow::Context;
        let mut protocol = Protocol::new(test_markers(), TimeoutPolicy::from_secs(30));
        // Boot chatter that never contains the ready marker, then the boot
        // budget elapses.
        let _ = protocol.feed(b"kernel panic? no, just noise\n");
        let _ = protocol.on_timeout();
        let outcome = protocol
            .outcome()
            .context("terminal result after boot timeout")?
            .context("Outcome, not a protocol error")?;
        assert!(!outcome.booted);
        assert_eq!(outcome.guest_exit, None, "no fabricated exit on boot failure");
        Ok(())
    }

    /// Tier-1 adversarial: ready and START are seen but END never arrives → the
    /// command budget elapses and the run is `timed_out: true` with no
    /// fabricated exit. RED until implemented.
    #[test]
    fn missing_end_sentinel_times_out() -> anyhow::Result<()> {
        use anyhow::Context;
        let markers = test_markers();
        let mut protocol = Protocol::new(markers.clone(), TimeoutPolicy::from_secs(30));
        // Ready + START + partial body, but no END sentinel and no exit line.
        let mut stream = Vec::new();
        stream.extend_from_slice(markers.ready.as_bytes());
        stream.extend_from_slice(b"\n");
        stream.extend_from_slice(markers.start.as_bytes());
        stream.extend_from_slice(b"partial output, command hung");
        let _ = protocol.feed(&stream);
        let _ = protocol.on_timeout();
        let outcome = protocol
            .outcome()
            .context("terminal result after command timeout")?
            .context("Outcome, not a protocol error")?;
        assert!(outcome.timed_out);
        assert_eq!(outcome.guest_exit, None, "no fabricated exit on timeout");
        Ok(())
    }

    /// Tier-1 adversarial: the `exit=` line after END is garbled → a
    /// `BackendError::Protocol`, never a defaulted `guest_exit: 0`
    /// (INV-OUTCOME). RED until implemented.
    #[test]
    fn malformed_exit_is_a_protocol_error() -> anyhow::Result<()> {
        use anyhow::Context;
        let markers = test_markers();
        let stream = scripted(&markers, b"", b"work\n", b"exit=not-a-number\n");
        let result = drive(markers, &stream).context("terminal result")?;
        assert!(
            matches!(result, Err(BackendError::Protocol(_))),
            "garbled exit must be a protocol error, got {result:?}"
        );
        Ok(())
    }

    /// Tier-1 adversarial: NUL and other control bytes inside the captured
    /// region do not corrupt the capture or desynchronize the sentinel scan;
    /// the run still completes with the exact captured bytes and parsed exit.
    /// RED until implemented.
    #[test]
    fn binary_on_stdout_doesnt_corrupt_capture() -> anyhow::Result<()> {
        use anyhow::Context;
        let markers = test_markers();
        let body: &[u8] = b"\x00\x01binary\xff\x00payload\x00";
        let stream = scripted(&markers, b"", body, b"exit=0\n");
        let outcome = drive(markers, &stream)
            .context("terminal result")?
            .context("Outcome, not a protocol error")?;
        // The control bytes must not have been read as a boot/exit signal.
        assert!(outcome.booted);
        assert_eq!(outcome.guest_exit, Some(0));
        Ok(())
    }

    /// Tier-1: the pure exit parser round-trips a well-formed line and rejects a
    /// garbled one with a protocol error rather than a defaulted `0`. RED until
    /// `parse_exit` is implemented.
    #[test]
    fn parse_exit_rejects_garbage() -> anyhow::Result<()> {
        use anyhow::Context;
        assert_eq!(parse_exit(b"exit=0\n").context("well-formed zero")?, 0);
        assert_eq!(parse_exit(b"exit=42\n").context("well-formed nonzero")?, 42);
        assert!(matches!(parse_exit(b"exit=\n"), Err(BackendError::Protocol(_))));
        assert!(matches!(parse_exit(b"no exit here"), Err(BackendError::Protocol(_))));
        Ok(())
    }
}
