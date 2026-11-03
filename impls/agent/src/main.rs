//! `sandy-agent`: the sandbox agent as its own OS process (#216).
//!
//! Usage: `sandy-agent [--vsock-listen PORT] -- <job> [args...]`. The process
//! backend launches it with its agent link on stdin
//! (`sandy_fabric::capauth::AGENT_LINK_FD`, fd 0); in a VM guest it listens on a
//! vsock port and takes the host's connection as the link
//! ([`link_source`], #238). The
//! agent bootstraps over the link ([`LinkAgent::bootstrap`]: the cap is the
//! first frame, read once and presented back to the relay), then runs the job
//! as its child and bridges the job's stdio to the channel.
//!
//! The job never inherits the link: the agent keeps a close-on-exec duplicate,
//! points its own stdin at `/dev/null`, and gives the job fresh pipes. It
//! inherits the agent's environment unchanged, which is the backend's.
//!
//! The job's result reaches the backend as the link's last frame
//! ([`LinkAgent::report_exit`]): its exit code, `128 + signal` for a signal
//! death. The relay passes it on, and the backend takes the job's exit only
//! from there, never from this process's status, which a wrapper or the job
//! itself could change. An agent that fails, panics, or is killed reports
//! nothing, and the run is an infra fault (INV-11). The agent also exits with
//! the job's code, and aborts on an internal failure, for whoever runs it by
//! hand.

use std::{
    ffi::OsString,
    io::Write,
    os::{fd::AsFd, unix::process::ExitStatusExt},
    process::{ExitCode, ExitStatus},
    sync::Arc,
    time::Duration,
};

use sandy_fabric_local::agent::{ARCHIVE_TRANSCRIPT, LinkAgent};
use tokio::io::{AsyncRead, AsyncWrite};

/// How long [`serve`] waits for the archived transcript to reach the relay
/// before giving up on it and moving on to report the job's exit regardless
/// (CodeRabbit on #345) — generous for even a large (line-capped) transcript
/// over a healthy link, short enough that a stuck peer doesn't stall exit
/// reporting for long.
const ARCHIVE_SEND_TIMEOUT: Duration = Duration::from_secs(10);

/// [`sandy_guest_template::manifest::default_history_lines`]'s own value,
/// mirrored here rather than pulled in as a dependency just for one constant
/// (`sandy-agent` otherwise has no reason to depend on the manifest crate):
/// the line bound a job gets when the submitter never configured one, and
/// what [`configured_history_lines`] falls back to on a missing or malformed
/// `SANDY_HISTORY_LINES`.
const DEFAULT_HISTORY_LINES: u32 = 10_000;

/// The env var `history_lines_env` (`sandy-host-executor/src/dispatch.rs`)
/// sets on `RunSpec.env` for a flake/v1 (VM) dispatch (epic #340 phase 6).
/// Read directly from this process's own environment rather than threaded
/// through as a CLI arg: `ProcessBackend` already overlays `spec.env` onto
/// the `sandy-agent` child it spawns (`impls/local/src/process.rs`), which
/// is the carrier this reads from, proven directly by
/// `agent_process.rs::a_configured_history_lines_env_value_bounds_the_captured_console`.
///
/// The VM backends forward `SANDY_HISTORY_LINES` from `RunSpec.env` to this agent (#398); the
/// process-backend/`argv/v1` branch passes `env: &[]`, since that manifest has no `history_lines`
/// field, so it gets [`DEFAULT_HISTORY_LINES`].
fn configured_history_lines() -> u32 {
    parse_history_lines(std::env::var("SANDY_HISTORY_LINES").ok())
}

/// The actual parsing, split out from [`configured_history_lines`] so it's
/// testable as a pure function: this crate forbids `unsafe_code`
/// (workspace lint), and mutating process env (`std::env::set_var`) from a
/// test is unsafe as of Rust 2024 — reading real process env is for
/// [`configured_history_lines`] alone, never a test.
fn parse_history_lines(raw: Option<String>) -> u32 {
    match raw {
        Some(v) => v.parse().unwrap_or_else(|e| {
            eprintln!("sandy-agent: SANDY_HISTORY_LINES={v:?} is not a valid u32 ({e}); using the default");
            DEFAULT_HISTORY_LINES
        }),
        None => DEFAULT_HISTORY_LINES,
    }
}

/// The largest an archived transcript can be once hex-encoded (2x) and
/// wrapped in a `LinkFrame::Archive`'s own JSON envelope, while still fitting
/// under [`sandy_fabric_local::link::MAX_FRAME`] (1 MiB) in one frame —
/// there is no chunking: `Archive` is defined as one frame, sent once. A
/// generous fixed reserve covers the envelope's `content_type` field and
/// JSON punctuation, which is tiny and constant regardless of transcript
/// size.
///
/// A job's *configured* line bound (`history_lines`, default 10,000) can
/// still exceed this in bytes if its lines run long — this is the safety net
/// under that case, not a replacement for it: [`read_tail_lines`] applies the
/// line bound first, and only falls back to trimming further by bytes (from
/// the same end) if the line-capped result still doesn't fit.
const ARCHIVE_BYTE_CEILING: usize = (sandy_fabric_local::link::MAX_FRAME - 4096) / 2;

/// Read at most the last `max_lines` lines of `path` (`pipe-pane`'s
/// transcript — an append-only file independent of tmux's own
/// `history-limit`, which only bounds a live client's in-memory scrollback,
/// so a long-running job's log can grow far past any configured line bound),
/// then, only if that's still more than `max_bytes`, trim further to the
/// last `max_bytes` of it.
///
/// Scans the file backward in fixed-size chunks rather than reading it whole
/// — a file with billions of lines (or none at all, one giant line) cannot
/// make this allocate proportionally to the job's entire output.
async fn read_tail_lines(path: &std::path::Path, max_lines: u32, max_bytes: usize) -> std::io::Result<Vec<u8>> {
    use tokio::io::{AsyncReadExt, AsyncSeekExt};
    const CHUNK: u64 = 64 * 1024;
    if max_lines == 0 {
        return Ok(Vec::new());
    }
    // However generous `max_lines` is, never scan back further than a small
    // multiple of the byte ceiling: a file with no newlines at all (or far
    // too few to ever satisfy `max_lines`) would otherwise make this read
    // the whole, potentially unbounded file.
    let scan_ceiling = (max_bytes as u64).saturating_mul(4).max(CHUNK);

    let mut file = tokio::fs::File::open(path).await?;
    let len = file.metadata().await?.len();
    let mut pos = len;
    let mut buf: Vec<u8> = Vec::new();
    let mut newlines: u32 = 0;

    while pos > 0 {
        let read_len = CHUNK.min(pos);
        pos -= read_len;
        file.seek(std::io::SeekFrom::Start(pos)).await?;
        let mut chunk = vec![0_u8; read_len as usize];
        file.read_exact(&mut chunk).await?;
        newlines += u32::try_from(bytecount_newlines(&chunk)).unwrap_or(u32::MAX);
        chunk.extend_from_slice(&buf);
        buf = chunk;
        // Strictly more than `max_lines`, not `>=`: with exactly `max_lines`
        // newlines in `buf`, the bytes before the first one could still be a
        // partial line split by this chunk boundary, and there would be no
        // further newline left to anchor trimming it off — one extra
        // newline guarantees a real boundary to cut at.
        if pos == 0 || newlines > max_lines || len - pos >= scan_ceiling {
            break;
        }
    }

    // Keep only the last `max_lines` complete lines. This also drops a
    // leading partial line when the scan stopped mid-chunk (one `pipe-pane`
    // flush can split a chunk mid-line) — it's always among the
    // `lines_in_buf - max_lines` lines counted from the front, so dropping
    // that many throws it away along with the genuinely excess whole lines,
    // whether or not the scan happened to also reach the true start of the
    // file in the same chunk.
    let lines_in_buf = u32::try_from(bytecount_newlines(&buf)).unwrap_or(u32::MAX);
    if lines_in_buf > max_lines {
        let mut remaining_to_drop = lines_in_buf - max_lines;
        if let Some(cut) = buf.iter().position(|&b| {
            if b == b'\n' {
                remaining_to_drop -= 1;
                remaining_to_drop == 0
            } else {
                false
            }
        }) {
            buf.drain(..=cut);
        }
    }

    if buf.len() > max_bytes {
        let start = buf.len() - max_bytes;
        buf.drain(..start);
    }
    Ok(buf)
}

fn bytecount_newlines(buf: &[u8]) -> usize {
    buf.iter().filter(|&&b| b == b'\n').count()
}

mod egress_relay;
mod link_source;
mod peer;
mod service;
mod tmux_pty;

use link_source::LinkSource;
use tmux_pty::TmuxJob;

fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    // `sandy-agent peer …` is the job's helper for its peer channels (#238).
    if args.first().is_some_and(|first| first == "peer") {
        return peer::cli(&args[1..]);
    }
    // `sandy-agent egress-relay …` wraps the job in the guest-side egress relay (#402).
    if args.first().is_some_and(|first| first == "egress-relay") {
        return egress_relay::cli(&args[1..]);
    }
    let (source, job) = match link_source::parse_args(args) {
        Ok(parsed) => parsed,
        Err(usage) => fail(&usage),
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(runtime) => runtime,
        Err(e) => fail(&format!("starting the runtime: {e}")),
    };
    match runtime.block_on(run(source, job)) {
        Ok(status) => ExitCode::from(exit_code(status)),
        Err(e) => fail(&e),
    }
}

/// An agent-internal failure: say why on stderr, then end with `SIGABRT` so the
/// backend reports an infra fault, never a job exit code.
fn fail(why: &str) -> ! {
    eprintln!("sandy-agent: {why}");
    std::process::abort();
}

/// Take the link from `source`, then [`serve`] the job over it.
async fn run(source: LinkSource, job: Vec<OsString>) -> Result<ExitStatus, String> {
    harden();
    match source {
        LinkSource::Stdin => {
            let link = claim_link().map_err(|e| format!("claiming the agent link on stdin: {e}"))?;
            serve(link, job).await
        }
        LinkSource::Vsock(port) => serve(accept_vsock_link(port).await?, job).await,
    }
}

/// Listen on vsock `port` and take the host's connection as the link; the
/// listener is closed before this returns.
#[cfg(target_os = "linux")]
async fn accept_vsock_link(port: u32) -> Result<tokio_vsock::VsockStream, String> {
    let listener =
        link_source::VsockAcceptor::bind(port).map_err(|e| format!("listening on vsock port {port}: {e}"))?;
    let mut link = link_source::accept_host(listener)
        .await
        .map_err(|e| format!("accepting the host's agent link on vsock port {port}: {e}"))?;
    // Tell the host the stream reached the agent, not only the hypervisor's
    // vsock proxy, before the relay writes the cap.
    tokio::io::AsyncWriteExt::write_all(&mut link, &[sandy_api::agent::AGENT_LINK_READY])
        .await
        .map_err(|e| format!("acknowledging the host's agent link: {e}"))?;
    Ok(link)
}

/// vsock exists only inside a Linux guest.
#[cfg(not(target_os = "linux"))]
async fn accept_vsock_link(port: u32) -> Result<tokio::net::UnixStream, String> {
    Err(format!(
        "--vsock-listen {port}: vsock is only available inside a Linux guest"
    ))
}

/// Bootstrap over `link`, run the job as this process's child, and bridge its
/// stdio until it exits.
async fn serve<L>(link: L, job: Vec<OsString>) -> Result<ExitStatus, String>
where
    L: AsyncRead + AsyncWrite + Send + 'static,
{
    let agent = Arc::new(
        LinkAgent::bootstrap(link)
            .await
            .map_err(|e| format!("bootstrap: {e}"))?,
    );

    // Peer channels (#238): serve them to the job on a socket in a private dir.
    let peer_dir = match agent.peers() {
        [] => None,
        _ => Some(peer::start(&agent).map_err(|e| format!("starting the peer socket: {e}"))?),
    };
    // Removed on every path out, a failed bridge included.
    let _peer_dir_cleanup = peer_dir.clone().map(RemoveDirOnDrop);

    if job.is_empty() {
        return Err("empty job argv".to_string());
    }
    // #340 phase 1: the job runs inside a detached tmux session behind a real
    // PTY, not as this process's own direct child over three pipes — see
    // `tmux_pty`'s module doc for why (TUI/line-discipline support, and
    // surviving independent of any one attach connection).
    let peer_socket = peer_dir.as_deref().map(|dir| dir.join(peer::SOCKET_NAME));
    let peer_env = peer_socket.as_deref().map(|socket| (peer::PEER_SOCKET_ENV, socket));
    // #340 phase 6/item 3: the submitter's configured scrollback/transcript
    // line bound (or the manifest default), read once and reused for both
    // the live tmux session's own `history-limit` and the archived
    // transcript's cap below.
    let history_lines = configured_history_lines();
    // #589: a declared service reports readiness from its health probe, never from console text. Parsed
    // before the job starts so a mangled spec refuses the run instead of skipping the probe.
    let service = service::from_env()?;
    let tmux_job =
        TmuxJob::start(&job, peer_env, history_lines).map_err(|e| format!("starting the tmux job session: {e}"))?;
    let readiness = service.map(|spec| service::spawn_readiness(Arc::clone(&agent), spec.probe));
    let (pty_read, pty_write, resizer, mut attach_child) = tmux_job
        .open_attach()
        .map_err(|e| format!("opening the attach pty: {e}"))?;

    // #340 phase 2: a `Join`'s initial size and every later `Resize` frame
    // both arrive on this one queue (`attach_relay.rs` posts the connection's
    // initial size as an ordinary resize right after the join succeeds, so
    // there's no separate "initial size" case to handle here) — drain it for
    // the bridge's whole lifetime, applying each to the real pty. Queued,
    // not dropped, by `take_resizes`'s own contract, so nothing here is lost
    // even if this task is briefly behind; `abort()` below ends it the
    // moment the bridge itself does, since a resize for an attach that's
    // already gone has nothing left to apply to.
    let resize_task = agent.take_resizes().map(|mut resizes| {
        tokio::spawn(async move {
            while let Some((cols, rows)) = resizes.recv().await {
                if let Err(e) = resizer.resize(cols, rows) {
                    eprintln!("sandy-agent: applying a terminal resize ({cols}x{rows}): {e}");
                }
            }
        })
    });

    // `serve_tty`/`bridge_tty` only returns once `pty_read` hits EOF — but
    // with `remain-on-exit on` (needed so a fast job's pane survives long
    // enough to even be usable, see `tmux_pty`'s own doc), the attach
    // client's pty does NOT reach EOF just because the job inside finished:
    // the dead pane stays visible, still attached. Awaiting the bridge
    // sequentially before checking the sentinel would therefore hang
    // forever. Instead: run the bridge in the background, wait for the
    // job's REAL exit via the sentinel (independent of the bridge), then
    // kill the session — which disconnects the attach client and is what
    // actually drives the bridge's pty to EOF so it can return.
    // No `Tee` to `to_stdout` here (unlike the old pipe-based version): a
    // fast job can leave the live attach stream showing tmux's own
    // escape-sequence-laden "dead pane" redraw instead of (or alongside) the
    // job's real output, which once mixed into the backend's `console`
    // capture occasionally produced a garbled fragment downstream code
    // mistook for real content (confirmed: an intermittent false positive in
    // `the_job_environment_carries_no_link_or_cap`, gone once this stopped).
    // The pipe-pane transcript dumped to stdout below is the sole, reliable
    // source for `console` now; this only affects that non-interactive
    // capture, not the live TTY_STDOUT channel a real attached viewer sees
    // (posted independently, inside `bridge_tty` itself).
    let bridge_agent = Arc::clone(&agent);
    let bridge_task =
        tokio::spawn(async move { bridge_agent.serve_tty(pty_read, tokio::io::empty(), pty_write).await });

    let exit = match tmux_job.wait_for_exit().await {
        Ok(exit) => exit,
        Err(e) => {
            tmux_job.kill();
            let _ = attach_child.kill();
            bridge_task.abort();
            if let Some(resize_task) = resize_task {
                resize_task.abort();
            }
            return Err(format!("reading the job's real exit code: {e}"));
        }
    };
    // The session persists independent of any one attach connection by
    // design (#340) — this kill ends THIS bridge's attach, not the job
    // (already finished) or (in a later phase) any other concurrent attach.
    tmux_job.kill();
    let _ = attach_child.wait();
    if let Some(resize_task) = resize_task {
        resize_task.abort();
    }

    match bridge_task.await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(format!("bridging the job's stdio: {e}")),
        Err(e) => return Err(format!("the stdio bridge task panicked: {e}")),
    }
    // The exit is the link's last frame: end the probe (finishing a verdict write already begun, never
    // tearing it) before anything else is written.
    if let Some(readiness) = readiness {
        readiness.finish().await?;
    }

    // The live attach bridge above only reliably carries output for a job
    // that's still running by the time `tmux attach` connects — a fast,
    // non-interactive job (confirmed with plain `ls`/`env`-style jobs, which
    // exit before the attach can connect at all) races it, and tmux's
    // `remain-on-exit` death notice then replaces the screen the attach sees
    // instead of replaying anything from before the attach existed. The
    // backend's own `console` capture (what every non-interactive caller
    // reads today, unaware this is now tmux-backed) still needs to be
    // complete regardless of job speed — `pipe-pane`'s transcript, started
    // before any attach at session creation, is exactly the race-free source
    // for that: write it to this process's own stdout now, which
    // `ProcessBackend` already captures as `Outcome::console`. This never
    // touches the live TTY_STDOUT channel itself (only the bridge above
    // posts to that), so a genuinely attached viewer sees no duplicate.
    //
    // The same transcript is also the epic #340 phase 2 archive: sent once,
    // best-effort, to the orchestrator-side channel.
    //
    // `send_archive` and `report_exit` share the link's one write mutex, and
    // a stuck peer (stopped reading) would otherwise block `write_all`
    // forever — but a `tokio::time::timeout` around the write itself is NOT
    // a safe fix (CodeRabbit on #345, confirmed): `write_frame` is a length
    // prefix, then a body, then a flush; cancelling the future mid-write
    // doesn't un-send bytes already handed to the kernel, so a timeout can
    // leave a real, still-open connection holding a genuinely torn frame —
    // structurally different from an ordinary write I/O error (a broken
    // connection, which `report_exit`'s own next write would immediately
    // and safely re-fail on too). Writing `report_exit`'s `Exit` frame on a
    // connection left mid-frame this way doesn't fail cleanly: the relay
    // reads the Exit's bytes as a continued (corrupted) Archive body and
    // fails with a decode error, losing the exit report as collateral
    // damage — worse than the plain timeout this was meant to bound.
    //
    // So: an ordinary send failure (the write completed enough to observe a
    // real I/O error) is safe to continue past, same as before — but a
    // timeout must NOT be followed by `report_exit` over the same link.
    // `LinkFrame::Exit`'s own absence already means "the agent failed"
    // (INV-11); failing here cleanly, before writing anything more, is
    // exactly that contract, not a new failure mode.
    match read_tail_lines(tmux_job.log_path(), history_lines, ARCHIVE_BYTE_CEILING).await {
        Ok(transcript) => {
            to_stdout(&transcript);
            match tokio::time::timeout(ARCHIVE_SEND_TIMEOUT, agent.send_archive(ARCHIVE_TRANSCRIPT, transcript)).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => eprintln!("sandy-agent: sending the archived transcript: {e}"),
                Err(_elapsed) => {
                    return Err(format!(
                        "sending the archived transcript timed out after {ARCHIVE_SEND_TIMEOUT:?}; the link may be \
                         mid-frame, so the job's exit cannot be safely reported over it"
                    ));
                }
            }
        }
        Err(e) => eprintln!("sandy-agent: reading the archived transcript: {e}"),
    }

    agent
        .report_exit(exit)
        .await
        .map_err(|e| format!("reporting the job's exit: {e}"))?;
    Ok(ExitStatus::from_raw(exit << 8))
}

/// Removes the peer socket's private dir when dropped.
struct RemoveDirOnDrop(std::path::PathBuf);

impl Drop for RemoveDirOnDrop {
    fn drop(&mut self) {
        if let Err(e) = std::fs::remove_dir_all(&self.0) {
            eprintln!("sandy-agent: removing the peer socket dir: {e}");
        }
    }
}

/// Keep the cap out of reach of the same-uid job where the platform allows:
/// on Linux, a non-dumpable process writes no core dump and cannot be
/// ptrace-attached or have its memory read by an unprivileged peer.
fn harden() {
    #[cfg(target_os = "linux")]
    if let Err(e) = rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable) {
        eprintln!("sandy-agent: could not mark the agent non-dumpable: {e}");
    }
}

/// Take the agent link off stdin: keep a close-on-exec duplicate, then point fd
/// 0 at `/dev/null` so no copy without close-on-exec is left to inherit.
fn claim_link() -> std::io::Result<tokio::net::UnixStream> {
    let link = std::io::stdin().as_fd().try_clone_to_owned()?;
    let null = std::fs::File::open("/dev/null")?;
    rustix::stdio::dup2_stdin(&null)?;
    let link = std::os::unix::net::UnixStream::from(link);
    link.set_nonblocking(true)?;
    tokio::net::UnixStream::from_std(link)
}

/// The job's exit as this process's exit code: its code, or `128 + signal`.
fn exit_code(status: ExitStatus) -> u8 {
    let code = status
        .code()
        .or_else(|| status.signal().map(|sig| 128 + sig))
        .unwrap_or(1);
    u8::try_from(code & 0xff).unwrap_or(1)
}

fn to_stdout(bytes: &[u8]) {
    let mut out = std::io::stdout().lock();
    let _ = out.write_all(bytes).and_then(|()| out.flush());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_signal_death_maps_to_128_plus_the_signal() {
        assert_eq!(exit_code(ExitStatus::from_raw(7 << 8)), 7);
        assert_eq!(exit_code(ExitStatus::from_raw(9)), 137, "SIGKILL");
    }

    #[test]
    fn an_absent_history_lines_value_falls_back_to_the_default() {
        assert_eq!(parse_history_lines(None), DEFAULT_HISTORY_LINES);
    }

    #[test]
    fn a_valid_history_lines_value_is_used_verbatim() {
        assert_eq!(parse_history_lines(Some("42".to_string())), 42);
    }

    #[test]
    fn a_malformed_history_lines_value_falls_back_to_the_default() {
        assert_eq!(
            parse_history_lines(Some("not-a-number".to_string())),
            DEFAULT_HISTORY_LINES
        );
    }

    /// Pins [`ARCHIVE_BYTE_CEILING`] against [`sandy_fabric_local::link::MAX_FRAME`]
    /// directly, rather than trusting the arithmetic in its doc comment: a
    /// real `Archive` frame carrying exactly the ceiling must still encode
    /// under the wire limit once hex-encoded and wrapped in its JSON
    /// envelope.
    #[tokio::test]
    async fn an_archive_at_the_byte_ceiling_still_fits_in_one_wire_frame() -> Result<(), Box<dyn std::error::Error>> {
        use sandy_fabric_local::link::{LinkFrame, write_frame};
        let frame = LinkFrame::Archive {
            content_type: ARCHIVE_TRANSCRIPT.to_string(),
            payload: hex::encode(vec![b'x'; ARCHIVE_BYTE_CEILING]),
        };
        let (mut sink, _keep_open) = tokio::io::duplex(sandy_fabric_local::link::MAX_FRAME + 4096);
        write_frame(&mut sink, &frame).await?;
        Ok(())
    }

    async fn write_lines(dir: &tempfile::TempDir, lines: &[&str]) -> std::io::Result<std::path::PathBuf> {
        let path = dir.path().join("transcript.log");
        let mut content = lines.join("\n");
        content.push('\n');
        tokio::fs::write(&path, content).await?;
        Ok(path)
    }

    #[tokio::test]
    async fn fewer_lines_than_the_cap_are_returned_whole() -> std::io::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = write_lines(&dir, &["one", "two", "three"]).await?;
        let tail = read_tail_lines(&path, 10, 1024).await?;
        assert_eq!(String::from_utf8_lossy(&tail), "one\ntwo\nthree\n");
        Ok(())
    }

    #[tokio::test]
    async fn more_lines_than_the_cap_keep_only_the_newest() -> std::io::Result<()> {
        let dir = tempfile::tempdir()?;
        let lines: Vec<String> = (0..20).map(|n| format!("line{n}")).collect();
        let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
        let path = write_lines(&dir, &refs).await?;
        let tail = read_tail_lines(&path, 3, 1024).await?;
        assert_eq!(String::from_utf8_lossy(&tail), "line17\nline18\nline19\n");
        Ok(())
    }

    #[tokio::test]
    async fn a_zero_line_cap_returns_nothing() -> std::io::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = write_lines(&dir, &["one", "two"]).await?;
        let tail = read_tail_lines(&path, 0, 1024).await?;
        assert!(tail.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn a_line_cap_spanning_more_than_one_scan_chunk_still_keeps_only_the_newest() -> std::io::Result<()> {
        let dir = tempfile::tempdir()?;
        // Each line is ~11 bytes; keeping the last 10,000 of 20,000 such
        // lines needs well over one 64 KiB backward-scan chunk, so this
        // exercises the multi-chunk path (a single chunk's own newline count
        // alone would already satisfy a smaller cap, as in the other test).
        let lines: Vec<String> = (0..20_000).map(|n| format!("line{n:06}")).collect();
        let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
        let path = write_lines(&dir, &refs).await?;
        let tail = read_tail_lines(&path, 10_000, 1_000_000).await?;
        let text = String::from_utf8_lossy(&tail);
        assert_eq!(text.lines().count(), 10_000, "got {} lines", text.lines().count());
        assert_eq!(text.lines().next(), Some("line010000"));
        assert_eq!(text.lines().last(), Some("line019999"));
        Ok(())
    }

    /// A regression for an off-by-one where the scan could stop with
    /// exactly `max_lines` newlines in the buffer while the bytes before the
    /// first one were still a partial line split by the chunk boundary —
    /// with no further newline left to anchor trimming it off, it leaked
    /// into the result as a corrupted "line". `max_lines = 6554` is chosen
    /// so the last 64 KiB scan chunk holds exactly 6,554 newlines: 6,553
    /// whole lines plus a 6-byte partial fragment (`"03446\n"`, missing its
    /// `line` prefix) that itself ends in a newline.
    #[tokio::test]
    async fn a_result_landing_on_exactly_max_lines_newlines_still_drops_the_leading_partial_line() -> std::io::Result<()>
    {
        let dir = tempfile::tempdir()?;
        let lines: Vec<String> = (0..10_000).map(|n| format!("line{n:05}")).collect();
        let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
        let path = write_lines(&dir, &refs).await?;
        let tail = read_tail_lines(&path, 6554, 1_000_000).await?;
        let text = String::from_utf8_lossy(&tail);
        assert_eq!(
            text.lines().next(),
            Some("line03446"),
            "the leading fragment must be dropped, not kept as a corrupted first line: {text:?}"
        );
        assert_eq!(text.lines().count(), 6554, "got {} lines", text.lines().count());
        Ok(())
    }

    #[tokio::test]
    async fn a_line_capped_result_still_over_the_byte_ceiling_is_trimmed_further() -> std::io::Result<()> {
        let dir = tempfile::tempdir()?;
        let long_lines = ["a".repeat(100), "b".repeat(100), "c".repeat(100)];
        let refs: Vec<&str> = long_lines.iter().map(String::as_str).collect();
        let path = write_lines(&dir, &refs).await?;
        // All 3 lines fit the line cap, but not the tiny byte ceiling.
        let tail = read_tail_lines(&path, 10, 50).await?;
        assert!(
            tail.len() <= 50,
            "got {} bytes: {:?}",
            tail.len(),
            String::from_utf8_lossy(&tail)
        );
        assert!(
            !tail.contains(&b'a') && !tail.contains(&b'b'),
            "the byte trim must keep the tail (most recent) end, not the oldest lines: {:?}",
            String::from_utf8_lossy(&tail)
        );
        Ok(())
    }
}
