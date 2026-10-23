//! `sandy daemon attach`'s interactive bridge (#327, ssh-style terminal
//! handling since epic #340 phase 3): once the control connection's `Attach`
//! request succeeds, redeem its cap on `sandyd`'s separate attach data-plane
//! socket (`sandy_control_proto::attach_socket_path`, `docs/decisions/
//! sandyd.md` §1 keeps the control RPC itself pure request/response — this
//! never rides that connection) and bridge the local terminal's stdin/stdout
//! to it: fully raw mode while a real terminal is attached (piped stdin, the
//! ordinary case under test automation, bridges unmodified), local `SIGWINCH`
//! posted as `Resize`, until the ssh-style `~.` escape sequence (right after
//! a newline — see [`EscapeDetector`]; a real Ctrl-D now reaches the guest as
//! EOF, since shells and TUIs both need that), the connection closing, or the
//! job reaching a terminal status (polled on the now-otherwise-idle control
//! connection, which stays open for exactly this).
//!
//! Detaching never touches the job itself: it only closes this attach
//! connection. Re-attaching later is a fresh `sandy daemon attach` invocation
//! — a fresh control-RPC `Attach` call, a fresh CF-H-1 session — but it still
//! gets a post-capable cap for the original submitter: `daemon submit`
//! persists the durable `attach_token` `Submit` hands back
//! ([`persist_attach_token`]), keyed by job id, under the same staging base
//! `$SANDY_SOCK`'s own directory lives in; `daemon attach` reads it back
//! ([`read_attach_token`]) and presents it, which `Attach`'s handler checks
//! independently of (in addition to) the per-connection `session_matches`.

use std::io::IsTerminal as _;

use sandy_fabric_local::{
    agent::{TTY_STDERR, TTY_STDIN, TTY_STDOUT},
    link::{LinkError, LinkFrame, read_frame, write_frame},
};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt as _};

/// The largest chunk read from local stdin per posted frame.
const STDIN_CHUNK: usize = 4096;

/// The owned, `0700` directory every job's durable attach token is staged
/// under (#327) — a sibling of `sandyd`'s own owned subdir, same validated
/// staging base (`sandy_fsutil::ensure_sandy_staging_base`) the control
/// socket's default path already lives under, never inside `sandyd`'s own
/// directory (a different owner's state, kept separate).
const ATTACH_TOKEN_DIR_NAME: &str = "sandy-cli-attach-tokens";

/// Persist `token` (`SubmitResponse.attach_token`) for `job_id` (#327), so a
/// LATER, separate `sandy daemon attach` invocation can read it back and
/// present it — the durable credential that survives this process exiting,
/// unlike CF-H-1's per-connection `session`. A no-op if `token` is empty
/// (the daemon's own best-effort RNG/store-write fallback — see
/// `handler::handle`'s Submit arm — already means this job has no durable
/// token; nothing to persist).
///
/// Best-effort: a failure here is logged to stderr, never fails the Submit
/// itself — the job already submitted successfully; losing the convenience
/// of a later post-capable re-attach is not a reason to report the whole
/// command as failed.
pub fn persist_attach_token(job_id: &str, token: &[u8]) {
    if token.is_empty() {
        return;
    }
    if let Err(e) = try_persist_attach_token(job_id, token) {
        eprintln!("sandy: could not persist the attach token for job {job_id}: {e}");
    }
}

fn try_persist_attach_token(job_id: &str, token: &[u8]) -> Result<(), sandy_fsutil::FsError> {
    let base = sandy_fsutil::ensure_sandy_staging_base()?;
    let dir = sandy_fsutil::OwnedDir::open_or_create(&base.join(ATTACH_TOKEN_DIR_NAME))?;
    dir.write_secret(job_id, token)?;
    Ok(())
}

/// Read back `job_id`'s durable attach token, if [`persist_attach_token`]
/// ever wrote one. `None` on ANY failure (missing file, a tampered/unsafe
/// directory, an unreadable staging base) — never an error that would block
/// `daemon attach` itself; the caller falls back to presenting no token,
/// which `Attach`'s handler already treats as "fall back to
/// `session_matches`" rather than a hard refusal.
#[must_use]
pub fn read_attach_token(job_id: &str) -> Option<Vec<u8>> {
    let base = sandy_fsutil::ensure_sandy_staging_base().ok()?;
    let dir = sandy_fsutil::OwnedDir::open(&base.join(ATTACH_TOKEN_DIR_NAME)).ok()?;
    std::fs::read(dir.path().join(job_id)).ok()
}

/// Writes a delivered [`ArchivePayload`] to the current directory as
/// `<job_id>-transcript.log` and prints its path — the same user-facing
/// shape `sandy run --out` already gives for a local job's collected
/// outputs, sourced here from the one built-in transcript rather than a
/// generic outputs directory (epic #340 phase 3). Best-effort: a write
/// failure is reported but never turns an otherwise-successful attach into
/// a failing command — the job already ran to completion.
pub fn write_archive(job_id: &str, archive: &ArchivePayload) {
    match create_archive_file(std::path::Path::new("."), job_id) {
        Ok((mut file, path)) => {
            use std::io::Write as _;
            match file.write_all(&archive.bytes) {
                Ok(()) => println!(
                    "sandy: wrote {} bytes of archived transcript ({}) to {}",
                    archive.bytes.len(),
                    archive.content_type,
                    path.display()
                ),
                Err(e) => eprintln!(
                    "sandy: could not write the archived transcript to {}: {e}",
                    path.display()
                ),
            }
        }
        Err(e) => eprintln!("sandy: could not create a file for the archived transcript: {e}"),
    }
}

/// Creates `<dir>/<job_id>-transcript.log` (or, if that name is already
/// taken, the first free `<dir>/<job_id>-transcript-N.log`) exclusively and
/// `0600` (CodeRabbit findings on #347): `create_new` means this never
/// silently truncates a prior archive sitting at the same path, and setting
/// the mode on the `OpenOptions` itself — not a separate `chmod` after the
/// fact — means no window where the file briefly exists at a looser
/// (umask-determined) mode. A transcript can carry sensitive job output, so
/// it's private from the first byte, not readable-then-restricted.
///
/// Takes `dir` explicitly rather than resolving against the process's
/// current directory (CodeRabbit finding on this PR): a test that needs an
/// isolated destination passes its own tempdir instead of mutating the
/// whole process's cwd via `std::env::set_current_dir`, which would race
/// every other test running in the same process under a parallel test
/// runner that doesn't give each test its own process.
fn create_archive_file(dir: &std::path::Path, job_id: &str) -> std::io::Result<(std::fs::File, std::path::PathBuf)> {
    use std::os::unix::fs::OpenOptionsExt as _;

    const MAX_ATTEMPTS: u32 = 1000;
    for suffix in 0..MAX_ATTEMPTS {
        let path = if suffix == 0 {
            dir.join(format!("{job_id}-transcript.log"))
        } else {
            dir.join(format!("{job_id}-transcript-{suffix}.log"))
        };
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
        {
            Ok(file) => return Ok((file, path)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::other(format!(
        "no free transcript filename for job {job_id} after {MAX_ATTEMPTS} attempts"
    )))
}

/// The outcome of feeding one byte through [`EscapeDetector`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EscapeOutcome {
    /// Forward this byte as ordinary input.
    Forward(u8),
    /// A previously withheld `~` turned out not to start a real escape
    /// (the byte after it was neither `.` nor `~`) — forward both, in order.
    ForwardTwo(u8, u8),
    /// A possible escape is in progress; nothing to forward yet.
    Hold,
    /// `~.` right after a newline: detach.
    Detach,
}

/// SSH's own escape-sequence rule (`~.` right after a newline detaches;
/// `~~` right after a newline forwards one literal `~`; a `~` anywhere else,
/// or `~` not followed by `.`/`~`, is ordinary input) — needed because raw
/// mode means Ctrl-D now reaches the guest as real EOF (shells and TUIs both
/// rely on that), so detach can no longer be a single raw byte.
///
/// Session start counts as "just after a newline" (matching ssh: you can
/// detach immediately upon attaching, before typing anything else).
struct EscapeDetector {
    at_line_start: bool,
    pending_tilde: bool,
}

impl EscapeDetector {
    fn new() -> Self {
        Self {
            at_line_start: true,
            pending_tilde: false,
        }
    }

    fn feed(&mut self, byte: u8) -> EscapeOutcome {
        if self.pending_tilde {
            self.pending_tilde = false;
            return match byte {
                b'.' => {
                    self.at_line_start = false;
                    EscapeOutcome::Detach
                }
                b'~' => {
                    self.at_line_start = false;
                    EscapeOutcome::Forward(b'~')
                }
                other => {
                    self.at_line_start = is_line_terminator(other);
                    EscapeOutcome::ForwardTwo(b'~', other)
                }
            };
        }
        if self.at_line_start && byte == b'~' {
            self.pending_tilde = true;
            self.at_line_start = false;
            return EscapeOutcome::Hold;
        }
        self.at_line_start = is_line_terminator(byte);
        EscapeOutcome::Forward(byte)
    }
}

/// A raw-mode terminal's Enter key sends a literal `\r` (`ICRNL`, which would
/// normally translate it to `\n`, is disabled by `make_raw()` along with the
/// rest of raw mode) — the same CR-vs-LF distinction this whole epic started
/// from (#340's context). The escape detector must treat either as
/// "line start," or a real user pressing Enter before `~.` would never
/// actually trigger detach outside of synthetic `\n`-only test input.
fn is_line_terminator(byte: u8) -> bool {
    byte == b'\n' || byte == b'\r'
}

/// Puts the real stdin fd into raw mode for the duration of this guard
/// (`Drop` restores the original termios) — a no-op if stdin is not a real
/// terminal (piped stdin, e.g. under test automation), since there is no
/// terminal discipline to change in the first place.
///
/// Output stays fully raw too (no local `OPOST`/`ONLCR` reset): the guest's
/// real PTY (epic #340 phase 1) now owns terminal semantics end to end, so
/// re-mangling output locally would corrupt a full-screen app's own cursor
/// control. This process's own status lines print with an explicit `\r\n`
/// instead of relying on local output processing — see [`print_status`].
struct RawMode {
    original: Option<rustix::termios::Termios>,
}

impl RawMode {
    fn enable() -> Self {
        if !std::io::stdin().is_terminal() {
            return Self { original: None };
        }
        let Ok(original) = rustix::termios::tcgetattr(std::io::stdin()) else {
            // A tty by `IsTerminal`'s own check, yet tcgetattr refused —
            // treat as "not actually controllable" rather than failing the
            // whole attach over terminal cosmetics.
            return Self { original: None };
        };
        let mut raw = original.clone();
        raw.make_raw();
        if rustix::termios::tcsetattr(std::io::stdin(), rustix::termios::OptionalActions::Flush, &raw).is_err() {
            return Self { original: None };
        }
        Self {
            original: Some(original),
        }
    }
}

/// Prints a local status line under raw mode, where bare `\n` no longer
/// returns to column 0 (no local `OPOST`/`ONLCR`) — an explicit `\r\n`
/// instead, flushed immediately since nothing else flushes stderr for us.
fn print_status(line: &str) {
    use std::io::Write as _;
    let mut stderr = std::io::stderr();
    let _ = write!(stderr, "{line}\r\n");
    let _ = stderr.flush();
}

/// The local terminal's current size (`cols`, `rows`), or `None` if stdin
/// isn't a real terminal or the ioctl fails — sent on `Join` so the first
/// PTY sized for this connection doesn't need a separate round trip, and
/// again on every `SIGWINCH` ([`spawn_resize_watcher`]).
#[must_use]
pub fn window_size() -> Option<(u16, u16)> {
    if !std::io::stdin().is_terminal() {
        return None;
    }
    let winsize = rustix::termios::tcgetwinsize(std::io::stdin()).ok()?;
    Some((winsize.ws_col, winsize.ws_row))
}

/// Watches local `SIGWINCH` and reports the new size each time — a no-op
/// receiver (never produces anything) if stdin isn't a real terminal, since
/// there's no local resize to watch for under test automation.
fn spawn_resize_watcher() -> tokio::sync::mpsc::Receiver<(u16, u16)> {
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    if std::io::stdin().is_terminal() {
        tokio::spawn(async move {
            let Ok(mut signals) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change()) else {
                return;
            };
            loop {
                if signals.recv().await.is_none() {
                    return;
                }
                let Some(size) = window_size() else { continue };
                if tx.send(size).await.is_err() {
                    return;
                }
            }
        });
    }
    rx
}

impl Drop for RawMode {
    fn drop(&mut self) {
        if let Some(original) = self.original.take() {
            let _ = rustix::termios::tcsetattr(std::io::stdin(), rustix::termios::OptionalActions::Flush, &original);
        }
    }
}

/// Reads local stdin on its own blocking OS thread (never a tokio task):
/// `tokio::io::stdin()`'s own docs warn a blocked read on it cannot be
/// cancelled, which would otherwise hang this process's runtime shutdown
/// until the user next presses a key. A `std::thread` reading real stdin has
/// the identical "parked in the kernel read call" property, but nothing here
/// ever needs to cancel it — it's left to end on its own (process exit drops
/// it) once [`run_interactive`] itself has already returned.
fn spawn_stdin_reader() -> tokio::sync::mpsc::Receiver<Vec<u8>> {
    let (tx, rx) = tokio::sync::mpsc::channel(8);
    std::thread::spawn(move || {
        use std::io::Read as _;
        let mut stdin = std::io::stdin();
        let mut buf = vec![0_u8; STDIN_CHUNK];
        loop {
            match stdin.read(&mut buf) {
                Ok(0) => return, // real EOF (piped stdin, no tty)
                Ok(n) => {
                    if tx.blocking_send(buf[..n].to_vec()).is_err() {
                        return; // the receiving end dropped; nothing left to feed
                    }
                }
                Err(_) => return,
            }
        }
    });
    rx
}

/// A one-shot transcript delivered via `LinkFrame::Archive` at job end
/// (epic #340 phase 3), decoded and handed back to the caller — this module
/// bridges the terminal, it doesn't know the job id needed to name a
/// sensible local file, so the caller (which does) writes it out.
pub struct ArchivePayload {
    /// The content type the agent tagged the transcript with.
    pub content_type: String,
    /// The decoded transcript bytes.
    pub bytes: Vec<u8>,
}

/// Bridge `read_half`/`write_half` — `sandyd`'s attach data-plane connection,
/// already past its `Join`/`Joined` handshake — to the local terminal: local
/// stdin -> posted `TTY_STDIN`, delivered `TTY_STDOUT`/`TTY_STDERR` -> local
/// stdout, local `SIGWINCH` -> posted `Resize`, until local EOF (a real
/// Ctrl-D now reaches the guest, per [`RawMode`]'s doc comment), the ssh-style
/// `~.` escape sequence ([`EscapeDetector`]), the connection closing, or
/// `status_watch` reports the job reached a terminal state. Returns any
/// `Archive` frame the daemon delivered along the way.
///
/// # Errors
/// An I/O fault reading or writing the connection or the local terminal.
pub async fn run_interactive<R, W>(
    read_half: R,
    write_half: W,
    status_watch: Option<tokio::sync::oneshot::Receiver<String>>,
) -> std::io::Result<Option<ArchivePayload>>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let _raw_mode = RawMode::enable();
    run_interactive_inner(
        read_half,
        write_half,
        status_watch,
        spawn_stdin_reader(),
        spawn_resize_watcher(),
    )
    .await
}

/// The bounded window [`drain_for_archive`] waits in, once the job's status
/// poll reports a terminal state, for a trailing `Archive` frame that might
/// still be in flight on the data plane.
const ARCHIVE_DRAIN_BUDGET: std::time::Duration = std::time::Duration::from_secs(2);

/// One `read_frame` result, as forwarded by [`spawn_frame_reader`]'s
/// background task.
type FrameResult = Result<Option<LinkFrame>, LinkError>;

/// Spawns a task that owns `read_half` exclusively and loops `read_frame` on
/// it, forwarding each result to the returned channel — so nothing outside
/// this task ever cancels a `read_frame` call mid-read (CodeRabbit finding on
/// this PR): `read_frame` reads its length prefix and body in multiple steps
/// into local buffers with no state that survives across calls, so racing it
/// directly in a `tokio::select!` (the original, pre-#340 shape) meant a
/// `status`/`detach` win while a read was already in progress silently
/// discarded whatever bytes it had already pulled off the stream —
/// permanently desyncing anything read after, exactly what
/// [`drain_for_archive`] depends on not happening. `mpsc::Receiver::recv` is
/// cancel-safe (a message already sent is never lost by a cancelled `recv`),
/// so `run_interactive_inner`'s own `select!` only ever races "has the next
/// COMPLETE frame arrived," never a read in progress.
///
/// Ends (and drops its sender) once `read_frame` itself ends — a clean close
/// (`Ok(None)`) or a fault (`Err`) — after forwarding that final result; a
/// `recv()` after the channel closes returns `None`.
fn spawn_frame_reader<R>(mut read_half: R) -> tokio::sync::mpsc::Receiver<FrameResult>
where
    R: AsyncRead + Unpin + Send + 'static,
{
    let (tx, rx) = tokio::sync::mpsc::channel(1);
    tokio::spawn(async move {
        loop {
            let frame = read_frame(&mut read_half).await;
            let is_end = matches!(frame, Ok(None) | Err(_));
            if tx.send(frame).await.is_err() {
                return; // the receiver dropped; nothing left to feed
            }
            if is_end {
                return;
            }
        }
    });
    rx
}

/// Reads further frames off `frame_rx` for up to [`ARCHIVE_DRAIN_BUDGET`],
/// looking only for a trailing `LinkFrame::Archive` — called once the job's
/// status poll already reports a terminal state, since that poll and the
/// agent's own archive send are two independent races (CodeRabbit finding on
/// this PR): "terminal state observed" doesn't guarantee the transcript
/// already arrived. Stops early on a clean close, a fault, or the channel
/// closing (nothing more to drain either way); anything other than `Archive`
/// is ignored and does not reset the budget. Never fails
/// `run_interactive_inner` itself — worst case, the caller just doesn't get a
/// transcript this time.
async fn drain_for_archive(
    frame_rx: &mut tokio::sync::mpsc::Receiver<FrameResult>,
    archive: &mut Option<ArchivePayload>,
) {
    let deadline = tokio::time::Instant::now() + ARCHIVE_DRAIN_BUDGET;
    while archive.is_none() {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return;
        }
        let Ok(frame) = tokio::time::timeout(remaining, frame_rx.recv()).await else {
            return; // drain budget exhausted
        };
        match frame {
            Some(Ok(Some(LinkFrame::Archive { content_type, payload }))) => {
                if let Ok(bytes) = hex::decode(&payload) {
                    *archive = Some(ArchivePayload { content_type, bytes });
                }
                return;
            }
            Some(Ok(Some(_))) => {} // ignore anything else during the drain window
            Some(Ok(None)) | Some(Err(_)) | None => return, // clean close, fault, or channel closed
        }
    }
}

/// [`run_interactive`]'s bridge loop, taking its stdin and resize feeds as
/// `mpsc::Receiver`s instead of reading the real terminal/signals — so a
/// test can drive it with synthetic chunks (`tokio::io::duplex` standing in
/// for the connection) without a tty. Split out for exactly that reason;
/// production code has only the one caller above.
async fn run_interactive_inner<R, W>(
    read_half: R,
    write_half: W,
    mut status_watch: Option<tokio::sync::oneshot::Receiver<String>>,
    mut stdin_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    mut resize_rx: tokio::sync::mpsc::Receiver<(u16, u16)>,
) -> std::io::Result<Option<ArchivePayload>>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let mut frame_rx = spawn_frame_reader(read_half);
    let write_half = std::sync::Arc::new(tokio::sync::Mutex::new(write_half));
    // The escape sequence (or piped EOF under test automation) must
    // explicitly signal detachment, distinct from the stdin task simply
    // ending (dropping this without firing it) — a `Notify` latches the
    // signal (`notify_one` stores a permit even if nothing is `.await`ing
    // yet), unlike a oneshot, which would need re-creating per loop
    // iteration and would fire `Err` on a dropped sender, conflating
    // "detach" with "the stdin task ended."
    let detach = std::sync::Arc::new(tokio::sync::Notify::new());
    let stdin_task = {
        let write_half = std::sync::Arc::clone(&write_half);
        let detach = std::sync::Arc::clone(&detach);
        tokio::spawn(async move {
            let mut detector = EscapeDetector::new();
            while let Some(chunk) = stdin_rx.recv().await {
                let mut to_post = Vec::with_capacity(chunk.len());
                let mut should_detach = false;
                for byte in chunk {
                    match detector.feed(byte) {
                        EscapeOutcome::Forward(b) => to_post.push(b),
                        EscapeOutcome::ForwardTwo(a, b) => {
                            to_post.push(a);
                            to_post.push(b);
                        }
                        EscapeOutcome::Hold => {}
                        EscapeOutcome::Detach => {
                            should_detach = true;
                            break;
                        }
                    }
                }
                if !to_post.is_empty() {
                    let frame = LinkFrame::Post {
                        content_type: TTY_STDIN.to_string(),
                        payload: hex::encode(&to_post),
                        channel: None,
                    };
                    if write_frame(&mut *write_half.lock().await, &frame).await.is_err() {
                        return;
                    }
                }
                if should_detach {
                    detach.notify_one();
                    return;
                }
            }
            // Piped stdin reached real EOF — NOT a detach signal (the
            // persisted-token test relies on this: it closes stdin before
            // the echo arrives, and must keep reading deliveries after).
        })
    };
    let resize_task = {
        let write_half = std::sync::Arc::clone(&write_half);
        tokio::spawn(async move {
            while let Some((cols, rows)) = resize_rx.recv().await {
                let frame = LinkFrame::Resize { cols, rows };
                if write_frame(&mut *write_half.lock().await, &frame).await.is_err() {
                    return;
                }
            }
        })
    };

    let mut stdout = tokio::io::stdout();
    let mut archive = None;
    let result = loop {
        let delivered = if let Some(watch) = status_watch.as_mut() {
            tokio::select! {
                frame = frame_rx.recv() => frame.unwrap_or(Ok(None)),
                status = watch => {
                    if let Ok(status) = status {
                        print_status(&format!("sandy: job reached a terminal state ({status}); detaching"));
                    }
                    // The status poll and the agent's own Archive send are
                    // two independent races (CodeRabbit finding on this PR)
                    // — "terminal state observed" doesn't guarantee the
                    // transcript already arrived on the data plane. Give it
                    // a short bounded window before giving up on it.
                    drain_for_archive(&mut frame_rx, &mut archive).await;
                    break Ok(());
                }
                // A manual detach ends the bridge immediately, with no
                // archive drain: the job is still running (detaching never
                // touches it), so there is no trailing transcript to wait
                // for yet.
                () = detach.notified() => break Ok(()),
            }
        } else {
            tokio::select! {
                frame = frame_rx.recv() => frame.unwrap_or(Ok(None)),
                () = detach.notified() => break Ok(()),
            }
        };
        match delivered {
            Ok(Some(LinkFrame::Deliver {
                content_type, payload, ..
            })) if content_type == TTY_STDOUT || content_type == TTY_STDERR => {
                let Ok(bytes) = hex::decode(&payload) else {
                    break Err(std::io::Error::other("delivered frame payload was not valid hex"));
                };
                if let Err(e) = stdout.write_all(&bytes).await {
                    break Err(e);
                }
                if let Err(e) = stdout.flush().await {
                    break Err(e);
                }
            }
            Ok(Some(LinkFrame::Archive { content_type, payload })) => {
                let Ok(bytes) = hex::decode(&payload) else {
                    break Err(std::io::Error::other("archive frame payload was not valid hex"));
                };
                archive = Some(ArchivePayload { content_type, bytes });
            }
            Ok(Some(LinkFrame::Refused { reason })) => {
                print_status(&format!("sandy: {reason}"));
            }
            Ok(Some(_other)) => {
                // Anything else on this wire would be a protocol violation
                // from `sandyd`'s side; surfaced, not silently ignored, but
                // not fatal to an otherwise-working bridge either.
                print_status("sandy: attach: unexpected frame from the daemon");
            }
            Ok(None) => break Ok(()), // clean close
            Err(e) => break Err(std::io::Error::other(e)),
        }
    };

    stdin_task.abort();
    resize_task.abort();
    result.map(|()| archive)
}

/// Poll `job_id`'s status on `control_connection` (the control-RPC connection
/// `Attach` already succeeded on, left open — the data plane is a SEPARATE
/// connection, so this one is otherwise idle) every `interval`, sending its
/// name once the job reaches a terminal state (anything but
/// `Pending`/`Running`), so [`run_interactive`] can end the bridge and report
/// it. Silently stops (never sends) if the connection faults; the relay's own
/// EOF/fault handling is what ends the bridge in that case.
#[must_use]
pub fn spawn_status_watch(
    mut control_connection: tokio::net::UnixStream,
    job_id: String,
    interval: std::time::Duration,
) -> tokio::sync::oneshot::Receiver<String> {
    use sandy_control_proto::{JobStatus, StatusRequest, control_request, control_response};

    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let mut request_id = 1_u64;
        loop {
            tokio::time::sleep(interval).await;
            request_id += 1;
            let Ok(response) = sandy_control_proto::client::call(
                &mut control_connection,
                request_id,
                control_request::Op::Status(StatusRequest { job_id: job_id.clone() }),
            )
            .await
            else {
                return;
            };
            let Some(control_response::Result::Status(status)) = response.result else {
                return;
            };
            let parsed = JobStatus::try_from(status.status).unwrap_or(JobStatus::Unspecified);
            if !matches!(parsed, JobStatus::Pending | JobStatus::Running) {
                let _ = tx.send(parsed.as_str_name().to_owned());
                return;
            }
        }
    });
    rx
}

#[cfg(test)]
mod tests {
    use anyhow::Context as _;

    use super::*;

    /// A job id unique enough that two test runs (even concurrent ones on
    /// the same machine, since this touches the real shared staging base —
    /// there is no override hook for it) never collide, and distinctive
    /// enough to spot if it ever leaked into a real deployment's directory.
    fn test_job_id(case: &str) -> String {
        format!("sandy-cli-attach-test-{case}-{}", uuid::Uuid::new_v4())
    }

    /// Removes this test's own token file so a run never leaves state behind
    /// in the real shared staging base.
    struct CleanupToken(String);
    impl Drop for CleanupToken {
        fn drop(&mut self) {
            if let Ok(base) = sandy_fsutil::ensure_sandy_staging_base() {
                let _ = std::fs::remove_file(base.join(ATTACH_TOKEN_DIR_NAME).join(&self.0));
            }
        }
    }

    #[test]
    fn a_persisted_attach_token_round_trips() {
        let job_id = test_job_id("round-trip");
        let _cleanup = CleanupToken(job_id.clone());
        let token = b"a-token-worth-of-bytes".to_vec();

        persist_attach_token(&job_id, &token);

        assert_eq!(read_attach_token(&job_id), Some(token));
    }

    /// Adversarial: a job id with no persisted token reads back `None`, not
    /// an error or a fabricated empty token.
    #[test]
    fn an_unpersisted_job_id_reads_back_none() {
        let job_id = test_job_id("never-persisted");
        assert_eq!(read_attach_token(&job_id), None);
    }

    /// `persist_attach_token` is a no-op for an empty token (the daemon's own
    /// best-effort RNG/store-write fallback) — never writes an empty file a
    /// later read could confuse with "no token at all" being handled some
    /// other way.
    #[test]
    fn persisting_an_empty_token_is_a_no_op() {
        let job_id = test_job_id("empty-token");
        persist_attach_token(&job_id, &[]);
        assert_eq!(read_attach_token(&job_id), None);
    }

    /// Regression (CodeRabbit finding on this PR): `create_archive_file`
    /// must write `0600`, never a looser umask-determined mode — a
    /// transcript can carry sensitive job output. Passes the tempdir
    /// directly rather than mutating the process's cwd (a second CodeRabbit
    /// finding on this same PR: `std::env::set_current_dir` affects the
    /// whole process, racing every other test under a parallel test runner
    /// that doesn't give each test its own process).
    #[test]
    fn a_created_archive_file_is_mode_0600() -> anyhow::Result<()> {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().context("tempdir")?;

        let (file, _path) = create_archive_file(dir.path(), "mode-test-job").context("create archive file")?;
        let mode = file.metadata().context("stat the created file")?.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "expected 0600, got {mode:o}");
        Ok(())
    }

    /// Regression, the other half of the same finding: a pre-existing file
    /// at the expected path must never be silently truncated — a second
    /// `create_archive_file` call for the same job id falls back to a
    /// numbered suffix instead, and the original file's content survives.
    #[test]
    fn a_conflicting_archive_filename_falls_back_without_clobbering() -> anyhow::Result<()> {
        let dir = tempfile::tempdir().context("tempdir")?;

        let (mut first_file, first_path) =
            create_archive_file(dir.path(), "conflict-test-job").context("create the first archive file")?;
        {
            use std::io::Write as _;
            first_file
                .write_all(b"first transcript")
                .context("write the first file's content")?;
        }

        let (_second_file, second_path) =
            create_archive_file(dir.path(), "conflict-test-job").context("create the second archive file")?;
        assert_ne!(
            first_path, second_path,
            "a conflicting filename must fall back to a different path, not reuse the first"
        );

        let first_content = std::fs::read(&first_path).context("read back the first file")?;
        assert_eq!(
            first_content, b"first transcript",
            "the first file's content must survive the second create_archive_file call untouched"
        );
        Ok(())
    }

    /// A bridge test's standard "no real signal/terminal" resize feed — a
    /// channel with its sender already dropped, so `recv()` returns `None`
    /// immediately and the resize task exits cleanly, exactly like a
    /// non-terminal stdin under test automation ([`spawn_resize_watcher`]'s
    /// own no-op case).
    fn no_resize_feed() -> tokio::sync::mpsc::Receiver<(u16, u16)> {
        let (_tx, rx) = tokio::sync::mpsc::channel(1);
        rx
    }

    /// Epic #340 phase 3: a real Ctrl-D now reaches the guest (real EOF for
    /// shells and TUIs), so it must NOT detach by itself — only the ssh-style
    /// `~.` sequence, right after a newline, does.
    #[tokio::test]
    async fn newline_then_tilde_dot_detaches_promptly() -> anyhow::Result<()> {
        let (conn_read, _conn_read_peer) = tokio::io::duplex(4096);
        let (conn_write, _conn_write_peer) = tokio::io::duplex(4096);
        let (stdin_tx, stdin_rx) = tokio::sync::mpsc::channel(8);

        let task = tokio::spawn(run_interactive_inner(
            conn_read,
            conn_write,
            None,
            stdin_rx,
            no_resize_feed(),
        ));
        // Session start counts as "just after a newline" — detach fires
        // without needing a real newline byte first.
        stdin_tx.send(b"~.".to_vec()).await.context("feed ~.")?;

        let outcome = tokio::time::timeout(std::time::Duration::from_secs(2), task)
            .await
            .context("run_interactive_inner did not return after ~.")?
            .context("run_interactive_inner task panicked")?;
        outcome.context("run_interactive_inner returned an error")?;
        Ok(())
    }

    /// Regression, the other half of the same finding: piped-stdin EOF (the
    /// stdin task's `mpsc::Receiver` closing with no escape sequence ever
    /// seen) must NOT detach — `a_separate_attach_process_gets_post_rights_via_the_persisted_token`
    /// (`live_attach.rs`) depends on exactly this: it closes stdin before the
    /// echo arrives and still expects the bridge to keep running. Proven
    /// here by closing the stdin channel immediately and asserting the loop
    /// is still running a bit later, then closing the connection to let it
    /// end cleanly.
    #[tokio::test]
    async fn piped_stdin_eof_does_not_detach() -> anyhow::Result<()> {
        let (conn_read, conn_read_peer) = tokio::io::duplex(4096);
        let (conn_write, _conn_write_peer) = tokio::io::duplex(4096);
        let (stdin_tx, stdin_rx) = tokio::sync::mpsc::channel(8);
        drop(stdin_tx); // real EOF, no escape sequence ever sent

        let mut task = tokio::spawn(run_interactive_inner(
            conn_read,
            conn_write,
            None,
            stdin_rx,
            no_resize_feed(),
        ));

        let still_running = tokio::time::timeout(std::time::Duration::from_millis(200), &mut task).await;
        assert!(
            still_running.is_err(),
            "piped stdin EOF must not end the bridge on its own"
        );

        drop(conn_read_peer); // clean close of the connection: the real way this bridge ends here
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(2), task)
            .await
            .context("run_interactive_inner did not end after the connection closed")?
            .context("run_interactive_inner task panicked")?;
        outcome.context("run_interactive_inner returned an error")?;
        Ok(())
    }

    /// Regression (CodeRabbit finding on this PR): the job-status poll and
    /// the agent's own `Archive` send are two independent races — observing
    /// a terminal state does not guarantee the transcript already arrived.
    /// Fires the terminal-state signal FIRST, then writes the `Archive`
    /// frame onto the connection shortly after, and asserts it still gets
    /// captured rather than lost to an immediate break.
    #[tokio::test]
    async fn an_archive_arriving_shortly_after_terminal_status_is_still_captured() -> anyhow::Result<()> {
        let (conn_read, mut conn_read_peer) = tokio::io::duplex(4096);
        let (conn_write, _conn_write_peer) = tokio::io::duplex(4096);
        let (_stdin_tx, stdin_rx) = tokio::sync::mpsc::channel(8);
        let (status_tx, status_rx) = tokio::sync::oneshot::channel();

        let task = tokio::spawn(run_interactive_inner(
            conn_read,
            conn_write,
            Some(status_rx),
            stdin_rx,
            no_resize_feed(),
        ));

        status_tx
            .send("JOB_STATUS_SUCCEEDED".to_owned())
            .map_err(|_| anyhow::anyhow!("send status"))?;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let archive_frame = LinkFrame::Archive {
            content_type: "text/plain".to_owned(),
            payload: hex::encode(b"transcript bytes"),
        };
        write_frame(&mut conn_read_peer, &archive_frame)
            .await
            .context("write the archive frame")?;

        let outcome = tokio::time::timeout(ARCHIVE_DRAIN_BUDGET + std::time::Duration::from_secs(1), task)
            .await
            .context("run_interactive_inner did not return")?
            .context("run_interactive_inner task panicked")?
            .context("run_interactive_inner returned an error")?;

        let archive = outcome.context("expected an archive payload to have been captured")?;
        assert_eq!(archive.bytes, b"transcript bytes");
        assert_eq!(archive.content_type, "text/plain");
        Ok(())
    }

    /// Regression (CodeRabbit "Heavy lift" finding on this PR): the original
    /// shape raced a bare `read_frame(&mut read_half)` directly inside the
    /// `select!` against `status`/`detach`. `read_frame` reads its length
    /// prefix and body across multiple `.await` points with no state
    /// surviving between them — if `status` won while a read had already
    /// consumed PART of a frame (e.g. the length prefix, with the body still
    /// in flight), `tokio::select!` drops that `read_frame` future, and
    /// whatever bytes it had already pulled off the stream were gone for
    /// good: the next `read_frame` call (inside `drain_for_archive`) would
    /// start reading mid-frame, desynced, and silently fail to decode the
    /// Archive transcript. [`spawn_frame_reader`]'s background task fixes
    /// this by giving `read_frame` exclusive, uninterrupted ownership of the
    /// stream.
    ///
    /// Reproduces the exact race: manually writes a REAL `Archive` frame's
    /// raw wire bytes (length prefix + JSON body, matching `write_frame`'s
    /// own format) split across two separate writes, with `status` resolving
    /// in the gap between them — so if the old bug were still present, the
    /// `read_frame` in flight at that moment would be cancelled mid-body and
    /// the transcript lost.
    #[tokio::test]
    async fn an_archive_frame_split_across_two_writes_with_status_in_the_gap_is_still_captured() -> anyhow::Result<()> {
        let (conn_read, mut conn_read_peer) = tokio::io::duplex(4096);
        let (conn_write, _conn_write_peer) = tokio::io::duplex(4096);
        let (_stdin_tx, stdin_rx) = tokio::sync::mpsc::channel(8);
        let (status_tx, status_rx) = tokio::sync::oneshot::channel();

        let task = tokio::spawn(run_interactive_inner(
            conn_read,
            conn_write,
            Some(status_rx),
            stdin_rx,
            no_resize_feed(),
        ));

        // Build the Archive frame's raw wire bytes by hand (length prefix +
        // JSON body), the same format `write_frame` itself produces — so
        // this test controls exactly where the split falls, something
        // `write_frame`'s own single `write_all` call can't do.
        let archive_frame = LinkFrame::Archive {
            content_type: "text/plain".to_owned(),
            payload: hex::encode(b"split transcript bytes"),
        };
        let body = serde_json::to_vec(&archive_frame).context("encode the archive frame")?;
        let len = u32::try_from(body.len()).context("frame body length")?.to_be_bytes();
        let mut wire = Vec::with_capacity(4 + body.len());
        wire.extend_from_slice(&len);
        wire.extend_from_slice(&body);

        // Split WITHIN the body, well past the length prefix, so the real
        // bug's failure mode (a read already past the 4-byte length and
        // partway into `read_exact`-ing the body) is what's under test, not
        // just a split at the length/body boundary.
        let split_at = 4 + (body.len() / 2);
        let (first_half, second_half) = wire.split_at(split_at);

        use tokio::io::AsyncWriteExt as _;
        conn_read_peer
            .write_all(first_half)
            .await
            .context("write the first half of the split frame")?;
        conn_read_peer.flush().await.context("flush the first half")?;

        // `status` resolves while the second half is still unsent — the
        // in-flight `read_frame` (inside spawn_frame_reader's task) is
        // mid-body at exactly this moment.
        status_tx
            .send("JOB_STATUS_SUCCEEDED".to_owned())
            .map_err(|_| anyhow::anyhow!("send status"))?;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        conn_read_peer
            .write_all(second_half)
            .await
            .context("write the second half of the split frame")?;
        conn_read_peer.flush().await.context("flush the second half")?;

        let outcome = tokio::time::timeout(ARCHIVE_DRAIN_BUDGET + std::time::Duration::from_secs(1), task)
            .await
            .context("run_interactive_inner did not return")?
            .context("run_interactive_inner task panicked")?
            .context("run_interactive_inner returned an error")?;

        let archive =
            outcome.context("expected the archive payload to survive status resolving mid-read of the split frame")?;
        assert_eq!(archive.bytes, b"split transcript bytes");
        assert_eq!(archive.content_type, "text/plain");
        Ok(())
    }

    /// [`EscapeDetector`] unit tests — the state machine directly, no
    /// bridge/tokio involved. These are the real acceptance bar for the
    /// ssh-style escape rule (#340 phase 3's own stated requirement).
    mod escape_detector {
        use super::{EscapeDetector, EscapeOutcome};

        /// Feeds `bytes` through a fresh detector, returning the forwarded
        /// bytes and whether detach fired (and at which index, if so,
        /// stopping there — matches the real stdin task's own behavior).
        fn run(bytes: &[u8]) -> (Vec<u8>, bool) {
            let mut detector = EscapeDetector::new();
            let mut forwarded = Vec::new();
            for &byte in bytes {
                match detector.feed(byte) {
                    EscapeOutcome::Forward(b) => forwarded.push(b),
                    EscapeOutcome::ForwardTwo(a, b) => {
                        forwarded.push(a);
                        forwarded.push(b);
                    }
                    EscapeOutcome::Hold => {}
                    EscapeOutcome::Detach => return (forwarded, true),
                }
            }
            (forwarded, false)
        }

        #[test]
        fn tilde_dot_at_session_start_detaches() {
            let (forwarded, detached) = run(b"~.");
            assert!(detached);
            assert_eq!(forwarded, b"");
        }

        #[test]
        fn tilde_dot_right_after_a_newline_detaches() {
            let (forwarded, detached) = run(b"echo hi\n~.");
            assert!(detached);
            assert_eq!(forwarded, b"echo hi\n");
        }

        /// Regression (CodeRabbit finding on this PR): a real raw-mode
        /// terminal's Enter key sends `\r`, not `\n` (`ICRNL` is disabled by
        /// raw mode, same CR-vs-LF distinction this whole epic started
        /// from) — `~.` must still detach right after a bare `\r`, not just
        /// the synthetic `\n` every other test here uses.
        #[test]
        fn tilde_dot_right_after_a_carriage_return_detaches() {
            let (forwarded, detached) = run(b"echo hi\r~.");
            assert!(detached);
            assert_eq!(forwarded, b"echo hi\r");
        }

        /// Adversarial: `~.` typed in the MIDDLE of a line (not right after
        /// a newline) must pass through as ordinary input, never detach.
        #[test]
        fn tilde_dot_mid_line_is_ordinary_input() {
            let (forwarded, detached) = run(b"echo ~.\n");
            assert!(!detached);
            assert_eq!(forwarded, b"echo ~.\n");
        }

        /// `~~` right after a newline forwards one literal `~` — ssh's own
        /// escape-the-escape rule — rather than eating real input.
        #[test]
        fn tilde_tilde_after_a_newline_forwards_one_literal_tilde() {
            let (forwarded, detached) = run(b"~~ not an escape\n");
            assert!(!detached);
            assert_eq!(forwarded, b"~ not an escape\n");
        }

        /// A `~` right after a newline, followed by something other than
        /// `.`/`~`, isn't an escape at all — both bytes are forwarded.
        #[test]
        fn tilde_followed_by_an_ordinary_byte_forwards_both() {
            let (forwarded, detached) = run(b"~x\n");
            assert!(!detached);
            assert_eq!(forwarded, b"~x\n");
        }

        /// A multi-line session: `~.` only detaches right after a newline,
        /// not just because one appeared earlier in the stream.
        #[test]
        fn only_the_newline_immediately_before_tilde_dot_counts() {
            let (forwarded, detached) = run(b"echo hi\necho ~.there\n");
            assert!(!detached);
            assert_eq!(forwarded, b"echo hi\necho ~.there\n");
        }
    }
}
