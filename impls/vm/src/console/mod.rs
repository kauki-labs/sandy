//! The native console driver (Block 33): boot → inject → capture → teardown.
//!
//! This is the Rust port of nix-vm's `vm-console-run.py`, shared by both native
//! backends (#32/#35). It is split into two seams:
//!
//! - [`protocol`] — the transport-agnostic sentinel state machine (pure, tier-1): fed `&[u8]` chunks, it detects the
//!   boot-ready marker, injects the base64-wrapped command, captures the bytes between the unique per-run sentinels,
//!   parses the trailing `exit=<n>`, and produces the pinned [`Outcome`](sandy::Outcome).
//! - [`transport`] — the platform byte channel the machine drives: a pipe on Linux/qemu, a PTY on macOS/vfkit.
//!
//! [`run_console`] wires a [`Transport`] to a [`Protocol`]. The emitted
//! [`Outcome`](sandy::Outcome) is the pinned `snake_case` record reused
//! from [`sandy`] (INV-8), with the four outcomes kept distinct and
//! `guest_exit` never fabricated (INV-OUTCOME).

mod protocol;
mod transport;

use std::time::{Duration, Instant};

pub use protocol::{Markers, Protocol, ProtocolStep, TimeoutPolicy, parse_exit};
use sandy::{BackendError, Outcome, RunControl, RunSpec};
pub use transport::{PipeTransport, PtyTransport, ReadEvent, Transport};

/// How long a transport's own `read` blocks before reporting
/// [`ReadEvent::Idle`] (#185). Short enough that cancellation and a live
/// deadline move (an attach-state suspend/reinstate, #340) are noticed
/// promptly; long enough not to spin the console socket/PTY needlessly over a
/// run that can last minutes.
pub(crate) const POLL_QUANTUM: Duration = Duration::from_millis(250);

/// Run one job over `transport` using the sentinel [`Protocol`], returning the
/// physical [`Outcome`](sandy::Outcome).
///
/// Derives the per-phase [`TimeoutPolicy`] from `spec.timeout_secs`, then loops:
/// read a chunk, [`feed`](Protocol::feed) it, write any
/// [`Inject`](ProtocolStep::Inject) bytes, and call
/// [`on_timeout`](Protocol::on_timeout) when the phase budget elapses OR
/// `spec.control` says to stop ([`RunControl::is_cancelled`], or its live
/// deadline passing — #340/#185), until the machine is
/// [`Done`](ProtocolStep::Done). A [`BackendError::Protocol`] or transport
/// fault is mapped into the `transport_error` field of the returned outcome
/// rather than fabricating `guest_exit` (INV-OUTCOME).
///
/// [`BackendError::Protocol`]: sandy::BackendError::Protocol
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
    // `spec.control`'s own deadline as observed when this run started: as long
    // as nothing outside this call has moved it, `phase_start`/`current_deadline`
    // above stay authoritative (today's boot-then-command budget shape,
    // unchanged). The moment something moves it — an attach-state
    // suspend/reinstate (#340) — the live value takes over instead.
    let initial_deadline = spec.control.deadline();

    loop {
        if let Some(result) = protocol.outcome() {
            return finalize(result, booted, console.into_string());
        }
        if control_demands_stop(spec.control, initial_deadline, phase_start, protocol.current_deadline()) {
            protocol.on_timeout();
            continue;
        }
        match transport.read(&mut buf) {
            Ok(ReadEvent::Closed) => {
                // The console closed before a terminal state: let the timeout
                // path resolve it (booted:false, or timed_out:true post-inject).
                protocol.on_timeout();
            }
            Ok(ReadEvent::Idle) => {
                // Nothing arrived within this poll window; loop around so the
                // control/deadline check above runs again promptly (#185).
            }
            Ok(ReadEvent::Data(read)) => {
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

/// Whether the driver should treat the current phase's budget as exhausted.
///
/// `daemon cancel` always does. Otherwise `spec.control`'s live deadline is
/// authoritative once something has moved it away from the value it carried
/// when this run started — a suspended deadline (`None`) never times out, and
/// a reinstated one (e.g. a post-detach grace period) is checked directly; the
/// original per-phase [`TimeoutPolicy`] budget governs until then, so a run
/// nothing ever touches keeps today's boot-then-command shape unchanged.
fn control_demands_stop(
    control: &RunControl,
    initial_deadline: Option<Instant>,
    phase_start: Instant,
    phase_budget: Duration,
) -> bool {
    if control.is_cancelled() {
        return true;
    }
    match control.deadline() {
        None => false,
        Some(deadline) if Some(deadline) == initial_deadline => phase_start.elapsed() >= phase_budget,
        Some(_) => control.timed_out(),
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
    use sandy::Grants;

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

    /// A [`Transport`] whose `read` behaves the way the real ones do after
    /// #185: every call returns within `quantum`, as [`ReadEvent::Idle`]
    /// unless a scheduled chunk's wall-clock offset (from this transport's own
    /// construction) has arrived, or the schedule is exhausted (then `Closed`
    /// if configured, else `Idle` forever). Driving `run_console` against real
    /// elapsed time — not a mocked clock — is what makes a timing regression
    /// (a deadline/cancel check that only runs once before a long blocking
    /// read) show up as a genuine failure rather than passing by accident.
    struct ScriptedTransport {
        start: Instant,
        schedule: std::collections::VecDeque<(Duration, Vec<u8>)>,
        quantum: Duration,
        eof_when_exhausted: bool,
    }

    impl ScriptedTransport {
        fn new(quantum: Duration) -> Self {
            Self {
                start: Instant::now(),
                schedule: std::collections::VecDeque::new(),
                quantum,
                eof_when_exhausted: false,
            }
        }

        /// Schedule `bytes` to become readable `at` after this transport's own
        /// construction (not after the previous step — an absolute offset, so
        /// the schedule reads as a timeline).
        fn deliver_at(mut self, at: Duration, bytes: impl Into<Vec<u8>>) -> Self {
            self.schedule.push_back((at, bytes.into()));
            self
        }

        /// Report [`ReadEvent::Closed`] once the schedule is exhausted, instead
        /// of `Idle` forever.
        fn then_close(mut self) -> Self {
            self.eof_when_exhausted = true;
            self
        }
    }

    impl Transport for ScriptedTransport {
        fn read(&mut self, buf: &mut [u8]) -> Result<ReadEvent, BackendError> {
            std::thread::sleep(self.quantum);
            let due = self.schedule.front().is_some_and(|(at, _)| self.start.elapsed() >= *at);
            if due {
                let (_, bytes) = self.schedule.pop_front().expect("front just checked Some");
                let n = bytes.len().min(buf.len());
                buf[..n].copy_from_slice(&bytes[..n]);
                return Ok(ReadEvent::Data(n));
            }
            if self.schedule.is_empty() && self.eof_when_exhausted {
                return Ok(ReadEvent::Closed);
            }
            Ok(ReadEvent::Idle)
        }

        fn write(&mut self, _bytes: &[u8]) -> Result<(), BackendError> {
            Ok(())
        }
    }

    fn test_markers() -> Markers {
        Markers::new("SANDY-READY", "<<SANDY-TEST-START>>", "<<SANDY-TEST-END>>")
    }

    fn no_grants() -> Grants {
        Grants {
            secrets: false,
            agent: false,
            shares: false,
        }
    }

    fn control_spec<'a>(
        command: &'a [String],
        grants: &'a Grants,
        control: &'a RunControl,
        timeout_secs: u32,
    ) -> RunSpec<'a> {
        RunSpec {
            template: "demo",
            command,
            inputs: &[],
            outputs: &[],
            secrets: &[],
            env: &[],
            cpu: None,
            mem: None,
            timeout_secs,
            grants,
            outcome_file: None,
            secret_dir: None,
            control,
        }
    }

    /// A completed run's scripted "guest" bytes: the START/END sentinels
    /// bracketing a trivial body, followed by `exit=0`.
    fn command_frame(markers: &Markers, body: &str) -> Vec<u8> {
        format!("{}{body}{}exit=0\n", markers.start, markers.end).into_bytes()
    }

    /// Regression guard (#185): a run whose control nothing ever touches keeps
    /// today's shape exactly — boot and command phases each get their own full
    /// `timeout_secs` budget. Boot takes 0.3s, the command another 0.3s, both
    /// comfortably inside a 1s-per-phase budget, over a transport that only
    /// ever reports `Idle` in between (never one long blocking read).
    #[test]
    fn an_untouched_control_keeps_the_existing_boot_then_command_budget() {
        let markers = test_markers();
        let command = [String::from("true")];
        let grants = no_grants();
        let control = RunControl::with_timeout_secs(1);
        let spec = control_spec(&command, &grants, &control, 1);
        let mut transport = ScriptedTransport::new(Duration::from_millis(20))
            .deliver_at(Duration::from_millis(300), format!("{}\n", markers.ready))
            .deliver_at(Duration::from_millis(600), command_frame(&markers, "ok\n"));

        let outcome = run_console(&mut transport, &spec, &markers);

        assert!(
            !outcome.timed_out,
            "each phase stayed within its own 1s budget: {outcome:?}"
        );
        assert_eq!(outcome.guest_exit, Some(0), "console: {}", outcome.console);
    }

    /// The actual deliverable (#185, mirroring the process backend's own
    /// #340 test): suspending the control's deadline before the run lets the
    /// command phase survive well past its original 1s budget, proving
    /// `run_console` reads `spec.control` live rather than only the static
    /// per-phase `TimeoutPolicy`.
    #[test]
    fn suspending_the_control_survives_past_the_command_phases_original_budget() {
        let markers = test_markers();
        let command = [String::from("true")];
        let grants = no_grants();
        let control = RunControl::with_timeout_secs(1);
        control.suspend_deadline();
        let spec = control_spec(&command, &grants, &control, 1);
        let mut transport = ScriptedTransport::new(Duration::from_millis(20))
            .deliver_at(Duration::from_millis(100), format!("{}\n", markers.ready))
            .deliver_at(Duration::from_millis(2_000), command_frame(&markers, "ok\n"));

        let outcome = run_console(&mut transport, &spec, &markers);

        assert!(
            !outcome.timed_out,
            "a suspended deadline must not time out, even ~2x past the original 1s command budget: {outcome:?}"
        );
        assert_eq!(outcome.guest_exit, Some(0), "console: {}", outcome.console);
    }

    /// Suspending the deadline must not make a genuinely closed console hang
    /// forever: `Closed` resolves through the timeout path unconditionally,
    /// independent of the live control.
    #[test]
    fn a_suspended_deadline_still_resolves_on_a_closed_console() {
        let markers = test_markers();
        let command = [String::from("true")];
        let grants = no_grants();
        let control = RunControl::with_timeout_secs(1);
        control.suspend_deadline();
        let spec = control_spec(&command, &grants, &control, 1);
        let mut transport = ScriptedTransport::new(Duration::from_millis(20)).then_close();

        let start = Instant::now();
        let outcome = run_console(&mut transport, &spec, &markers);

        assert!(
            !outcome.booted,
            "the console closed before the ready marker ever appeared: {outcome:?}"
        );
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "a closed console must resolve promptly even while the deadline is suspended"
        );
    }

    /// `daemon cancel` (#185): cancelling a running command ends it promptly
    /// and is reported the same way a timeout is (matching the process
    /// backend's own precedent), well before the 60s budget either phase
    /// carries.
    #[test]
    fn cancelling_the_control_ends_a_running_command_before_its_timeout() {
        let markers = test_markers();
        let command = [String::from("true")];
        let grants = no_grants();
        let control = RunControl::with_timeout_secs(60);
        let spec = control_spec(&command, &grants, &control, 60);
        let mut transport = ScriptedTransport::new(Duration::from_millis(20))
            .deliver_at(Duration::from_millis(50), format!("{}\n", markers.ready));

        let start = Instant::now();
        let outcome = std::thread::scope(|scope| {
            let handle = scope.spawn(|| run_console(&mut transport, &spec, &markers));
            std::thread::sleep(Duration::from_millis(300));
            control.cancel();
            handle.join().expect("run_console thread panicked")
        });

        assert!(
            outcome.timed_out,
            "a cancelled run is reported the same way a timeout is: {outcome:?}"
        );
        assert!(
            outcome.booted,
            "the ready marker was seen before cancellation: {outcome:?}"
        );
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "cancellation must end the run promptly, not wait anywhere near the 60s budget"
        );
    }

    /// Cancelling before the guest ever boots resolves through the same path a
    /// natural boot timeout would (`booted: false`), just promptly rather than
    /// after the full boot budget.
    #[test]
    fn cancelling_the_control_during_boot_resolves_as_not_booted() {
        let markers = test_markers();
        let command = [String::from("true")];
        let grants = no_grants();
        let control = RunControl::with_timeout_secs(60);
        let spec = control_spec(&command, &grants, &control, 60);
        let mut transport = ScriptedTransport::new(Duration::from_millis(20));

        let start = Instant::now();
        let outcome = std::thread::scope(|scope| {
            let handle = scope.spawn(|| run_console(&mut transport, &spec, &markers));
            std::thread::sleep(Duration::from_millis(300));
            control.cancel();
            handle.join().expect("run_console thread panicked")
        });

        assert!(!outcome.booted, "the ready marker never arrived: {outcome:?}");
        assert!(
            !outcome.timed_out,
            "a boot-phase stop is reported as not-booted, not timed_out: {outcome:?}"
        );
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "cancellation must end the run promptly, not wait anywhere near the 60s boot budget"
        );
    }
}
