//! The VM side of the guest agent (#238): the command that launches the
//! image's `sandy-agent` inside the guest, and the host's connector for its
//! vsock link.
//!
//! The host connects to the guest agent, never the other way round, so the
//! relay only ever dials its own VM. The guest agent only listens once the
//! console has launched it, and a hypervisor's vsock proxy (vfkit) accepts the
//! host's socket before it dials the guest, so the connector retries until the
//! agent acknowledges the stream with [`AGENT_LINK_READY`]. Only then does the
//! relay get the stream and write the cap.

use std::{
    io::{self, Read},
    os::fd::OwnedFd,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use sandy::{BackendError, Outcome};
use sandy_api::agent::{AGENT_LINK_READY, AgentLaunch, AgentReport, AgentVerdict};

/// Agent mode: how long after the guest finishes to wait for the relay's
/// verdict (as on the process backend, it follows the link closing at once).
const VERDICT_GRACE: Duration = Duration::from_secs(10);

/// The first retry delay; it doubles up to [`MAX_BACKOFF`].
const FIRST_BACKOFF: Duration = Duration::from_millis(50);
/// The longest wait between connection attempts.
const MAX_BACKOFF: Duration = Duration::from_millis(500);
/// How long one attempt waits for the agent's ready byte.
const READY_WAIT: Duration = Duration::from_secs(2);

/// The shell command the console injects in agent mode: the image's agent,
/// listening on `port`, running the job as `sh -c <job>` so the job keeps the
/// shell semantics a plain console run gives `command.join(" ")`.
pub(crate) fn agent_shell_command(program: &Path, port: u32, job: &[String]) -> String {
    format!(
        "{} --vsock-listen {port} -- sh -c {}",
        sh_quote(&program.to_string_lossy()),
        sh_quote(&job.join(" "))
    )
}

/// `s` as one single-quoted POSIX shell word.
fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// A connected stream that can wait a bounded time for its first byte.
pub(crate) trait LinkStream: Read + Into<OwnedFd> + Send + 'static {
    /// Bound the next read.
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;
}

impl LinkStream for std::os::unix::net::UnixStream {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        std::os::unix::net::UnixStream::set_read_timeout(self, timeout)
    }
}

#[cfg(target_os = "linux")]
impl LinkStream for vsock::VsockStream {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        vsock::VsockStream::set_read_timeout(self, timeout)
    }
}

/// Connect with `connect` until the guest agent acknowledges with
/// [`AGENT_LINK_READY`], then return the stream as an fd for the relay.
///
/// A refused or dropped attempt, or one that sends anything else, is retried
/// with backoff.
///
/// # Errors
/// `TimedOut` once `deadline` passes, or `Interrupted` once `stop` is set (the
/// guest finished without the agent connecting), naming the last failure.
pub(crate) fn connect_agent_link<S: LinkStream>(
    mut connect: impl FnMut() -> io::Result<S>,
    deadline: Instant,
    stop: &AtomicBool,
) -> io::Result<OwnedFd> {
    let mut backoff = FIRST_BACKOFF;
    let mut last = "no attempt made".to_string();
    loop {
        if stop.load(Ordering::SeqCst) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                format!("the run ended before the guest agent took its link (last: {last})"),
            ));
        }
        let now = Instant::now();
        if now >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("the guest agent never took its link (last: {last})"),
            ));
        }
        match connect().and_then(|stream| acknowledged(stream, READY_WAIT.min(deadline - now))) {
            Ok(Some(fd)) => return Ok(fd),
            Ok(None) => last = "the stream closed or sent something else".to_string(),
            Err(e) => last = e.to_string(),
        }
        std::thread::sleep(backoff.min(deadline.saturating_duration_since(Instant::now())));
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}

/// The stream as an fd if its first byte is [`AGENT_LINK_READY`] within `wait`;
/// `None` if it closed or sent anything else.
fn acknowledged<S: LinkStream>(mut stream: S, wait: Duration) -> io::Result<Option<OwnedFd>> {
    stream.set_read_timeout(Some(wait.max(Duration::from_millis(1))))?;
    let mut byte = [0_u8; 1];
    match stream.read(&mut byte) {
        Ok(1) if byte[0] == AGENT_LINK_READY => {
            stream.set_read_timeout(None)?;
            Ok(Some(stream.into()))
        }
        Ok(_) => Ok(None),
        Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Start the thread that connects to the guest agent and hands the link to
/// `launch.on_link`. Returns the receiver for the run's verdict.
pub(crate) fn spawn_connector<S, C>(
    launch: &AgentLaunch,
    connect: C,
    box_id: &str,
    deadline: Instant,
    stop: Arc<AtomicBool>,
) -> (std::sync::mpsc::Receiver<AgentVerdict>, std::thread::JoinHandle<bool>)
where
    S: LinkStream,
    C: FnMut() -> io::Result<S> + Send + 'static,
{
    let (report, verdict) = AgentReport::channel();
    let (on_link, box_id) = (Arc::clone(&launch.on_link), box_id.to_string());
    // Returns whether the link was handed to the relay.
    let thread = std::thread::spawn(move || {
        match connect_agent_link(connect, deadline, &stop) {
            Ok(link) => {
                // A panic drops the report unresolved: the run is an infra fault.
                let handed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| on_link(&box_id, link, report)));
                if handed.is_err() {
                    tracing::warn!(box_id, "the agent link handler (on_link) panicked");
                }
                // A panicking handler did not take the link, even if it kept the fd.
                handed.is_ok()
            }
            Err(err) => {
                report.agent_failed(format!("could not reach the guest agent: {err}"));
                false
            }
        }
    });
    (verdict, thread)
}

/// Agent mode: the job's exit comes only from the relay's verdict, never from
/// the console's `exit=` (INV-11).
///
/// A booted guest whose agent never took its link (`linked` false) is an infra
/// fault, even when the console then timed out: the job never started, so the
/// timeout is not the job's. Otherwise a run that did not complete keeps its
/// timeout or transport fault, with no exit.
pub(crate) fn agent_outcome(
    mut outcome: Outcome,
    verdict: &std::sync::mpsc::Receiver<AgentVerdict>,
    job: &str,
    linked: bool,
) -> Result<Outcome, BackendError> {
    if outcome.booted && !linked {
        let why = match verdict.try_recv() {
            Ok(AgentVerdict::AgentFailed(why)) => why,
            _ => "the link was never handed to the relay".to_string(),
        };
        return Err(BackendError::Spawn(format!(
            "the guest agent never took its link for `{job}`: {why}"
        )));
    }
    if !outcome.booted || outcome.timed_out || outcome.transport_error.is_some() {
        outcome.guest_exit = None;
        return Ok(outcome);
    }
    match verdict.recv_timeout(VERDICT_GRACE) {
        Ok(AgentVerdict::JobExited(code)) => {
            outcome.guest_exit = Some(code);
            Ok(outcome)
        }
        Ok(AgentVerdict::AgentFailed(why)) => Err(BackendError::Spawn(format!(
            "the sandbox agent failed for `{job}`: {why}"
        ))),
        Err(_) => Err(BackendError::Spawn(format!(
            "the sandbox agent's relay reported no verdict for `{job}`"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::Write,
        os::unix::net::{UnixListener, UnixStream},
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        thread,
    };

    use super::*;

    #[test]
    fn the_agent_command_quotes_the_job_for_the_guest_shell() {
        let command = agent_shell_command(
            Path::new("/nix/store/abc-sandy-agent/bin/sandy-agent"),
            5000,
            &["echo".to_string(), "it's".to_string(), "$HOME".to_string()],
        );
        assert_eq!(
            command,
            r#"'/nix/store/abc-sandy-agent/bin/sandy-agent' --vsock-listen 5000 -- sh -c 'echo it'\''s $HOME'"#
        );
    }

    /// A listener that closes the first `drops` connections at once (the guest
    /// not listening yet, as vfkit's proxy does), sends `wrong` bytes on the
    /// next one if set, then acknowledges like the agent.
    fn agent_after(
        drops: usize,
        wrong: Option<u8>,
    ) -> anyhow::Result<(tempfile::TempDir, std::path::PathBuf, Arc<AtomicUsize>)> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("agent.sock");
        let listener = UnixListener::bind(&path)?;
        let accepted = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&accepted);
        thread::spawn(move || {
            for (n, conn) in listener.incoming().enumerate() {
                let Ok(mut conn) = conn else { return };
                seen.fetch_add(1, Ordering::SeqCst);
                if n < drops {
                    continue;
                }
                if n == drops
                    && let Some(byte) = wrong
                {
                    let _ = conn.write_all(&[byte]);
                    continue;
                }
                let _ = conn.write_all(&[AGENT_LINK_READY]);
                thread::sleep(Duration::from_millis(200));
                return;
            }
        });
        Ok((dir, path, accepted))
    }

    #[test]
    fn retries_until_the_agent_acknowledges_the_link() -> anyhow::Result<()> {
        let (_dir, path, accepted) = agent_after(2, Some(b'x'))?;
        let stop = AtomicBool::new(false);
        let deadline = Instant::now() + Duration::from_secs(10);
        connect_agent_link(|| UnixStream::connect(&path), deadline, &stop)?;
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            4,
            "two drops and a wrong byte are retried; the fourth connection is the link"
        );
        Ok(())
    }

    #[test]
    fn gives_up_at_the_deadline_without_a_link() -> anyhow::Result<()> {
        let (_dir, path, _) = agent_after(usize::MAX, None)?;
        let stop = AtomicBool::new(false);
        let started = Instant::now();
        let err = connect_agent_link(
            || UnixStream::connect(&path),
            started + Duration::from_millis(400),
            &stop,
        )
        .expect_err("no acknowledgement must not yield a link");
        assert_eq!(err.kind(), io::ErrorKind::TimedOut, "got {err}");
        assert!(started.elapsed() < Duration::from_secs(3), "bounded by the deadline");
        Ok(())
    }

    #[test]
    fn stops_promptly_when_the_run_is_over() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let missing = dir.path().join("never.sock");
        let stop = AtomicBool::new(true);
        let err = connect_agent_link(
            || UnixStream::connect(&missing),
            Instant::now() + Duration::from_secs(30),
            &stop,
        )
        .expect_err("a stopped run must not keep connecting");
        assert_eq!(err.kind(), io::ErrorKind::Interrupted, "got {err}");
        Ok(())
    }
}
