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
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

use sandy_api::agent::AGENT_LINK_READY;

/// The first retry delay; it doubles up to [`MAX_BACKOFF`].
const FIRST_BACKOFF: Duration = Duration::from_millis(50);
/// The longest wait between connection attempts.
const MAX_BACKOFF: Duration = Duration::from_millis(500);
/// How long one attempt waits for the agent's ready byte.
const READY_WAIT: Duration = Duration::from_secs(2);

/// The shell command the console injects in agent mode: the image's agent,
/// listening on `port`, running the job as `sh -c <job>` so the job keeps the
/// shell semantics a plain console run gives `command.join(" ")`.
pub(crate) fn agent_shell_command(_program: &Path, _port: u32, _job: &[String]) -> String {
    String::new()
}

/// A connected stream that can wait a bounded time for its first byte.
pub(crate) trait LinkStream: Read + Into<OwnedFd> {
    /// Bound the next read.
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;
}

impl LinkStream for std::os::unix::net::UnixStream {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        std::os::unix::net::UnixStream::set_read_timeout(self, timeout)
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
    _connect: impl FnMut() -> io::Result<S>,
    _deadline: Instant,
    _stop: &AtomicBool,
) -> io::Result<OwnedFd> {
    let _ = (
        AGENT_LINK_READY,
        FIRST_BACKOFF,
        MAX_BACKOFF,
        READY_WAIT,
        Ordering::SeqCst,
    );
    Err(io::Error::other("not implemented"))
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
