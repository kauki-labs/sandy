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

/// The largest tail of the `pipe-pane` transcript either `to_stdout` or
/// `send_archive` ever reads (CodeRabbit on #345), regardless of the file's
/// real size: `pipe-pane` is an append-only file independent of tmux's own
/// `history-limit` (that one only bounds the in-memory scrollback a client
/// sees), so a long-running, chatty job's log can grow far past any
/// configured line bound. Stays comfortably under
/// [`sandy_fabric_local::link::MAX_FRAME`] (1 MiB) even after this gets
/// hex-encoded (2x) and wrapped in a `LinkFrame::Archive`'s own JSON
/// envelope — the tail, not the head, since the most recent output (and the
/// exit marker `wait_for_exit` already found in it) is what both consumers
/// actually need.
const CONSOLE_TAIL_CAP: u64 = 256 * 1024;

/// Read at most the last `cap` bytes of `path`, without ever loading more
/// than that into memory regardless of the file's real size.
async fn read_tail(path: &std::path::Path, cap: u64) -> std::io::Result<Vec<u8>> {
    use tokio::io::{AsyncReadExt, AsyncSeekExt};
    let mut file = tokio::fs::File::open(path).await?;
    let len = file.metadata().await?.len();
    if len > cap {
        file.seek(std::io::SeekFrom::Start(len - cap)).await?;
    }
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).await?;
    Ok(buf)
}

mod link_source;
mod peer;
mod tmux_pty;

use link_source::LinkSource;
use tmux_pty::TmuxJob;

fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    // `sandy-agent peer …` is the job's helper for its peer channels (#238).
    if args.first().is_some_and(|first| first == "peer") {
        return peer::cli(&args[1..]);
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
    let tmux_job = TmuxJob::start(&job, peer_env).map_err(|e| format!("starting the tmux job session: {e}"))?;
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
    match read_tail(tmux_job.log_path(), CONSOLE_TAIL_CAP).await {
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
}
