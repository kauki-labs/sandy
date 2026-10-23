//! `sandy daemon attach`'s interactive bridge (#327): once the control
//! connection's `Attach` request succeeds, redeem its cap on `sandyd`'s
//! separate attach data-plane socket (`sandy_control_proto::attach_socket_path`,
//! `docs/decisions/sandyd.md` §1 keeps the control RPC itself pure
//! request/response — this never rides that connection) and bridge the local
//! terminal's stdin/stdout to it: raw mode while a real terminal is attached
//! (piped stdin, the ordinary case under test automation, bridges
//! unmodified), until local Ctrl-D/EOF, the connection closing, or the job
//! reaching a terminal status (polled on the now-otherwise-idle control
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
    link::{LinkFrame, read_frame, write_frame},
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
    match create_archive_file(job_id) {
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

/// Creates `<job_id>-transcript.log` (or, if that name is already taken, the
/// first free `<job_id>-transcript-N.log`) exclusively and `0600` (CodeRabbit
/// findings on #347): `create_new` means this never silently truncates a
/// prior archive sitting at the same path, and setting the mode on the
/// `OpenOptions` itself — not a separate `chmod` after the fact — means no
/// window where the file briefly exists at a looser (umask-determined) mode.
/// A transcript can carry sensitive job output, so it's private from the
/// first byte, not readable-then-restricted.
fn create_archive_file(job_id: &str) -> std::io::Result<(std::fs::File, std::path::PathBuf)> {
    use std::os::unix::fs::OpenOptionsExt as _;

    const MAX_ATTEMPTS: u32 = 1000;
    for suffix in 0..MAX_ATTEMPTS {
        let path = if suffix == 0 {
            std::path::PathBuf::from(format!("{job_id}-transcript.log"))
        } else {
            std::path::PathBuf::from(format!("{job_id}-transcript-{suffix}.log"))
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
/// `cfmakeraw` clears `OPOST`, which would also mangle output this process
/// itself prints (not just what it relays) by turning every bare `\n` into a
/// staircase; `output_modes` is set back to `OPOST | ONLCR` right after, so
/// local output stays normal while input discipline goes raw.
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
        raw.output_modes = rustix::termios::OutputModes::OPOST | rustix::termios::OutputModes::ONLCR;
        if rustix::termios::tcsetattr(std::io::stdin(), rustix::termios::OptionalActions::Flush, &raw).is_err() {
            return Self { original: None };
        }
        Self {
            original: Some(original),
        }
    }
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

/// Bridge `read_half`/`write_half` — `sandyd`'s attach data-plane connection,
/// already past its `Join`/`Joined` handshake — to the local terminal: local
/// stdin -> posted `TTY_STDIN`, delivered `TTY_STDOUT`/`TTY_STDERR` -> local
/// stdout, until local Ctrl-D/EOF, the connection closing, or
/// `status_watch` reports the job reached a terminal state.
///
/// # Errors
/// An I/O fault reading or writing the connection or the local terminal.
pub async fn run_interactive<R, W>(
    read_half: R,
    write_half: W,
    status_watch: Option<tokio::sync::oneshot::Receiver<String>>,
) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let _raw_mode = RawMode::enable();
    run_interactive_inner(read_half, write_half, status_watch, spawn_stdin_reader()).await
}

/// The bounded window [`drain_for_archive`] waits in, once the job's status
/// poll reports a terminal state, for a trailing `Archive` frame that might
/// still be in flight on the data plane.
const ARCHIVE_DRAIN_BUDGET: std::time::Duration = std::time::Duration::from_secs(2);

/// Reads further frames off `read_half` for up to [`ARCHIVE_DRAIN_BUDGET`],
/// looking only for a trailing `LinkFrame::Archive` — called once the job's
/// status poll already reports a terminal state, since that poll and the
/// agent's own archive send are two independent races (CodeRabbit finding on
/// this PR): "terminal state observed" doesn't guarantee the transcript
/// already arrived. Stops early on a clean close or an I/O fault (nothing
/// more to drain either way); anything other than `Archive` is ignored and
/// does not reset the budget. Never fails `run_interactive_inner` itself —
/// worst case, the caller just doesn't get a transcript this time.
async fn drain_for_archive<R>(read_half: &mut R, archive: &mut Option<ArchivePayload>)
where
    R: AsyncRead + Unpin,
{
    let deadline = tokio::time::Instant::now() + ARCHIVE_DRAIN_BUDGET;
    while archive.is_none() {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return;
        }
        let Ok(frame) = tokio::time::timeout(remaining, read_frame(read_half)).await else {
            return; // drain budget exhausted
        };
        match frame {
            Ok(Some(LinkFrame::Archive { content_type, payload })) => {
                if let Ok(bytes) = hex::decode(&payload) {
                    *archive = Some(ArchivePayload { content_type, bytes });
                }
                return;
            }
            Ok(Some(_)) => {}            // ignore anything else during the drain window
            Ok(None) | Err(_) => return, // clean close, or a fault — nothing more to drain
        }
    }
}

/// [`run_interactive`]'s bridge loop, taking its stdin and resize feeds as
/// `mpsc::Receiver`s instead of reading the real terminal/signals — so a
/// test can drive it with synthetic chunks (`tokio::io::duplex` standing in
/// for the connection) without a tty. Split out for exactly that reason;
/// production code has only the one caller above.
async fn run_interactive_inner<R, W>(
    mut read_half: R,
    write_half: W,
    mut status_watch: Option<tokio::sync::oneshot::Receiver<String>>,
    mut stdin_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let write_half = std::sync::Arc::new(tokio::sync::Mutex::new(write_half));
    // Ctrl-D must explicitly signal detachment, distinct from the stdin task
    // simply ending on piped EOF (dropping this without firing it) — a
    // `Notify` latches the signal (`notify_one` stores a permit even if
    // nothing is `.await`ing yet), unlike a oneshot, which would need
    // re-creating per loop iteration and would fire `Err` on a dropped
    // sender, conflating "detach" with "the stdin task ended."
    let detach = std::sync::Arc::new(tokio::sync::Notify::new());
    let stdin_task = {
        let write_half = std::sync::Arc::clone(&write_half);
        let detach = std::sync::Arc::clone(&detach);
        tokio::spawn(async move {
            while let Some(chunk) = stdin_rx.recv().await {
                let ctrl_d_at = chunk.iter().position(|&b| b == CTRL_D);
                let (before, ctrl_d) = match ctrl_d_at {
                    Some(i) => (&chunk[..i], true),
                    None => (&chunk[..], false),
                };
                if !before.is_empty() {
                    let frame = LinkFrame::Post {
                        content_type: TTY_STDIN.to_string(),
                        payload: hex::encode(before),
                        channel: None,
                    };
                    if write_frame(&mut *write_half.lock().await, &frame).await.is_err() {
                        return;
                    }
                }
                if ctrl_d {
                    detach.notify_one(); // Ctrl-D: tell the main loop to detach
                    return;
                }
            }
            // Piped stdin reached real EOF — NOT a detach signal (the
            // persisted-token test relies on this: it closes stdin before
            // the echo arrives, and must keep reading deliveries after).
        })
    };

    let mut stdout = tokio::io::stdout();
    let result = loop {
        let delivered = if let Some(watch) = status_watch.as_mut() {
            tokio::select! {
                frame = read_frame(&mut read_half) => frame,
                status = watch => {
                    if let Ok(status) = status {
                        println!("sandy: job reached a terminal state ({status}); detaching");
                    }
                    // The status poll and the agent's own Archive send are
                    // two independent races (CodeRabbit finding on this PR)
                    // — "terminal state observed" doesn't guarantee the
                    // transcript already arrived on the data plane. Give it
                    // a short bounded window before giving up on it.
                    drain_for_archive(&mut read_half, &mut archive).await;
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
                frame = read_frame(&mut read_half) => frame,
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
            Ok(Some(LinkFrame::Refused { reason })) => {
                eprintln!("sandy: {reason}");
            }
            Ok(Some(_other)) => {
                // Anything else on this wire would be a protocol violation
                // from `sandyd`'s side; surfaced, not silently ignored, but
                // not fatal to an otherwise-working bridge either.
                eprintln!("sandy: attach: unexpected frame from the daemon");
            }
            Ok(None) => break Ok(()), // clean close
            Err(e) => break Err(std::io::Error::other(e)),
        }
    };

    stdin_task.abort();
    result
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
    /// transcript can carry sensitive job output. Checked via the mode bits
    /// cargo-nextest's one-process-per-test isolation makes a `set_current_dir`
    /// test safe here (unlike plain `cargo test`'s shared-process model).
    #[test]
    fn a_created_archive_file_is_mode_0600() -> anyhow::Result<()> {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().context("tempdir")?;
        std::env::set_current_dir(dir.path()).context("set cwd")?;

        let (file, _path) = create_archive_file("mode-test-job").context("create archive file")?;
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
        std::env::set_current_dir(dir.path()).context("set cwd")?;

        let (mut first_file, first_path) =
            create_archive_file("conflict-test-job").context("create the first archive file")?;
        {
            use std::io::Write as _;
            first_file
                .write_all(b"first transcript")
                .context("write the first file's content")?;
        }

        let (_second_file, second_path) =
            create_archive_file("conflict-test-job").context("create the second archive file")?;
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
    ///
    /// Regression (CodeRabbit finding on this PR): Ctrl-D used to just end
    /// the stdin task, never signaling the main `select!` loop — the bridge
    /// then kept blocking on `read_frame` until the connection closed or
    /// `status_watch` fired, so an operator in a real terminal had no way to
    /// detach. Drives [`run_interactive_inner`] directly (no real tty/stdin
    /// needed) and asserts it returns promptly once Ctrl-D is fed in.
    #[tokio::test]
    async fn ctrl_d_detaches_promptly() -> anyhow::Result<()> {
        let (conn_read, _conn_read_peer) = tokio::io::duplex(4096);
        let (conn_write, _conn_write_peer) = tokio::io::duplex(4096);
        let (stdin_tx, stdin_rx) = tokio::sync::mpsc::channel(8);

        let task = tokio::spawn(run_interactive_inner(conn_read, conn_write, None, stdin_rx));
        stdin_tx.send(vec![b'a', CTRL_D]).await.context("feed Ctrl-D")?;

        let outcome = tokio::time::timeout(std::time::Duration::from_secs(2), task)
            .await
            .context("run_interactive_inner did not return after Ctrl-D")?
            .context("run_interactive_inner task panicked")?;
        outcome.context("run_interactive_inner returned an error")?;
        Ok(())
    }

    /// Regression, the other half of the same finding: piped-stdin EOF (the
    /// stdin task's `mpsc::Receiver` closing with no Ctrl-D byte ever seen)
    /// must NOT detach — `a_separate_attach_process_gets_post_rights_via_the_persisted_token`
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
        drop(stdin_tx); // real EOF, no Ctrl-D byte ever sent

        let mut task = tokio::spawn(run_interactive_inner(conn_read, conn_write, None, stdin_rx));

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
