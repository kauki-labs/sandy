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
    pin::Pin,
    process::{ExitCode, ExitStatus, Stdio},
    sync::Arc,
    task::{Context, Poll},
};

use sandy_fabric_local::agent::LinkAgent;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

mod link_source;
mod peer;

use link_source::LinkSource;

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

    let (program, args) = job.split_first().ok_or("empty job argv")?;
    let mut command = tokio::process::Command::new(program);
    if let Some(dir) = &peer_dir {
        command.env(peer::PEER_SOCKET_ENV, dir.join(peer::SOCKET_NAME));
    }
    let mut child = command
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| format!("spawning the job {}: {e}", program.to_string_lossy()))?;
    let (Some(stdin), Some(stdout), Some(stderr)) = (child.stdin.take(), child.stdout.take(), child.stderr.take())
    else {
        return Err("the job's stdio pipes were not created".to_string());
    };

    // Tee the job's output to this process's own stdio as well, so the backend's
    // console capture still carries it.
    let bridged = agent
        .serve_tty(Tee::new(stdout, to_stdout), Tee::new(stderr, to_stderr), stdin)
        .await;
    if let Err(e) = bridged {
        let _ = child.start_kill();
        let _ = child.wait().await;
        return Err(format!("bridging the job's stdio: {e}"));
    }
    let status = child.wait().await.map_err(|e| format!("waiting on the job: {e}"))?;
    if let Some(dir) = &peer_dir
        && let Err(e) = std::fs::remove_dir_all(dir)
    {
        eprintln!("sandy-agent: removing the peer socket dir: {e}");
    }
    agent
        .report_exit(i32::from(exit_code(status)))
        .await
        .map_err(|e| format!("reporting the job's exit: {e}"))?;
    Ok(status)
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

fn to_stderr(bytes: &[u8]) {
    let _ = std::io::stderr().lock().write_all(bytes);
}

/// An [`AsyncRead`] that copies every chunk it yields to `sink`.
struct Tee<R> {
    inner: R,
    sink: fn(&[u8]),
}

impl<R> Tee<R> {
    fn new(inner: R, sink: fn(&[u8])) -> Self {
        Self { inner, sink }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for Tee<R> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let polled = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = polled {
            (self.sink)(&buf.filled()[before..]);
        }
        polled
    }
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
