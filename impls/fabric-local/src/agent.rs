//! The sandbox agent (spec §3.2, issue #109): the per-sandbox gateway and
//! channel-membership unit. "Getting inside" a sandbox goes through the agent.
//!
//! [`SandboxAgent::bootstrap`] reads the orchestrator-channel cap exactly once
//! from the consumed-once handoff the executor launched it with
//! ([`AGENT_CAP_FD`](sandy_fabric::capauth::AGENT_CAP_FD) — never a staged file,
//! which would leak into the job's exported environment, see `docs/decisions/`
//! and #177) and joins with it. [`SandboxAgent::serve_tty`] then bridges the
//! job's stdio to Tty traffic on that channel until the job exits.
//!
//! Cap-scope enforcement (observe vs interact) is never duplicated here: a
//! member without `post` rights is rejected by [`Channel::post`] before an
//! envelope is ever stored, so there is nothing for this bridge to forward in
//! the first place — the agent inherits the channel's own boundedness rather
//! than re-checking it.
//!
//! [`UnavailableConsole`] is the process backend's honest
//! [`RawConsole`](sandy_fabric::raw_console::RawConsole) stub: a bare process has
//! no serial console to break glass to, so it reports
//! [`ConsoleStatus::Unavailable`](sandy_fabric::raw_console::ConsoleStatus::Unavailable)
//! and fails every `read`/`write`, never silently no-ops. The real console
//! fallback (`sandy_api::console::Transport`, already built for the VM run path)
//! wires in once a VM-backed agent exists; not this PR's scope.

use std::sync::Arc;

use futures_util::StreamExt;
use sandy_fabric::{
    capauth::{CapAuthority, decode_cap},
    channel_backend::ChannelBackend,
    raw_console::{ConsoleError, ConsoleStatus, RawConsole},
};
use sandy_proto::{MessageType, Tty};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::channel::{Channel, ChannelError, MembershipId};

/// `content_type` for a Tty envelope carrying orchestrator-to-sandbox input.
pub const TTY_STDIN: &str = "application/vnd.sandy.tty.stdin";
/// `content_type` for a Tty envelope carrying the job's stdout.
pub const TTY_STDOUT: &str = "application/vnd.sandy.tty.stdout";
/// `content_type` for a Tty envelope carrying the job's stderr.
pub const TTY_STDERR: &str = "application/vnd.sandy.tty.stderr";

/// Bytes read per TTY chunk.
const TTY_CHUNK: usize = 4096;

/// A sandbox agent failure.
#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    /// The bootstrap cap handoff could not be read to EOF.
    #[error("reading the bootstrap cap: {0}")]
    BootstrapRead(#[source] std::io::Error),
    /// The bootstrap handoff's bytes are not a validly encoded cap.
    #[error("decoding the bootstrap cap: {0}")]
    BootstrapDecode(#[from] sandy_fabric::capauth::CapCodecError),
    /// A channel operation failed: the bootstrap cap was rejected at `join`
    /// (forged, expired, wrong channel, …), or a later `post`/`subscribe` failed
    /// (e.g. the membership was revoked since bootstrap).
    #[error("channel: {0}")]
    Channel(#[from] ChannelError),
    /// The job's stdio faulted while bridging TTY traffic.
    #[error("TTY stdio: {0}")]
    Stdio(#[source] std::io::Error),
}

/// The per-sandbox gateway: holds the orchestrator-channel membership this
/// sandbox bootstrapped with, and bridges the job's stdio to Tty traffic on it.
///
/// Holds a shared [`Channel`] handle (the all-local MVP's channels live
/// in-process, per the spec's "sandboxes as plain processes, channels in
/// memory" step-1 scope) rather than owning it outright, so the same channel
/// instance's membership and backend are visible to both the agent and whatever
/// in-process orchestrator-side code posts/subscribes alongside it.
pub struct SandboxAgent<B, A> {
    channel: Arc<Channel<B, A>>,
    membership: MembershipId,
}

impl<B: ChannelBackend + 'static, A: CapAuthority + 'static> SandboxAgent<B, A> {
    /// Read the bootstrap cap from `cap_handoff` to EOF, decode it, and join
    /// `channel` with it. `cap_handoff` is read exactly once and dropped before
    /// this returns — the consumed-once pipe/fd convention
    /// ([`AGENT_CAP_FD`](sandy_fabric::capauth::AGENT_CAP_FD)): never re-read,
    /// never staged to disk.
    ///
    /// # Errors
    /// [`AgentError::BootstrapRead`] if `cap_handoff` cannot be read to EOF,
    /// [`AgentError::BootstrapDecode`] if the bytes aren't a validly encoded
    /// [`Cap`](sandy_fabric::capauth::Cap), [`AgentError::Channel`] if the decoded
    /// cap fails [`CapAuthority::verify`] or scopes to a different channel.
    pub fn bootstrap(channel: Arc<Channel<B, A>>, mut cap_handoff: impl std::io::Read) -> Result<Self, AgentError> {
        let mut bytes = Vec::new();
        cap_handoff.read_to_end(&mut bytes).map_err(AgentError::BootstrapRead)?;
        drop(cap_handoff);
        let cap = decode_cap(&bytes)?;
        let membership = channel.join(&cap)?;
        Ok(Self { channel, membership })
    }

    /// This sandbox's membership on its orchestrator channel.
    #[must_use]
    pub fn membership(&self) -> &MembershipId {
        &self.membership
    }

    /// Bridge the job's stdio to Tty envelopes on the orchestrator channel until
    /// `job_stdout` hits EOF (the job exited): the job's stdout becomes
    /// [`TTY_STDOUT`] posts, its stderr becomes [`TTY_STDERR`] posts, and
    /// [`TTY_STDIN`] posts arriving on the channel are written to `job_stdin`.
    /// The inbound (channel → job) and stderr sides both run as background
    /// tasks, aborted once the outbound stdout side ends — `job_stdout` is the
    /// one signal this treats as "the job exited" (a process that closes
    /// stdout but leaks stderr open would otherwise never let this return).
    ///
    /// # Errors
    /// [`AgentError::Channel`] if this membership can no longer subscribe (e.g.
    /// revoked since `bootstrap`); [`AgentError::Stdio`] if reading `job_stdout`
    /// faults; whatever [`Channel::post`] returns if a stdout post itself fails.
    pub async fn serve_tty(
        &self,
        mut job_stdout: impl AsyncRead + Unpin + Send + 'static,
        job_stderr: impl AsyncRead + Unpin + Send + 'static,
        mut job_stdin: impl AsyncWrite + Unpin + Send + 'static,
    ) -> Result<(), AgentError> {
        let inbound_stream = self.channel.subscribe(&self.membership)?;
        let inbound = tokio::spawn(async move {
            let mut inbound_stream = std::pin::pin!(inbound_stream);
            loop {
                let env = match inbound_stream.next().await {
                    Some(Ok(env)) => env,
                    Some(Err(e)) => {
                        tracing::warn!(error = %e, "TTY inbound stream faulted; stdin bridge stopped");
                        break;
                    }
                    None => break,
                };
                if !matches!(env.message_type, Some(MessageType::Tty(_))) || env.content_type != TTY_STDIN {
                    continue;
                }
                if let Err(e) = job_stdin.write_all(&env.payload).await {
                    tracing::warn!(error = %e, "writing to job stdin failed; stdin bridge stopped");
                    break;
                }
            }
        });

        let stderr = tokio::spawn(forward_tty(
            Arc::clone(&self.channel),
            self.membership.clone(),
            job_stderr,
            TTY_STDERR,
        ));

        let mut buf = [0_u8; TTY_CHUNK];
        let result = loop {
            match job_stdout.read(&mut buf).await {
                Ok(0) => break Ok(()),
                Ok(n) => {
                    if let Err(e) = self
                        .channel
                        .post(
                            &self.membership,
                            Some(MessageType::Tty(Tty {})),
                            TTY_STDOUT,
                            buf[..n].to_vec(),
                        )
                        .await
                    {
                        break Err(e.into());
                    }
                }
                Err(e) => break Err(AgentError::Stdio(e)),
            }
        };
        inbound.abort();
        // Let the stderr side flush what the job wrote before exiting (a job
        // typically writes its crash/error message to stderr right before
        // closing stdout) rather than dropping it immediately; bounded so a job
        // that leaks stderr open cannot hang serve_tty.
        let stderr_abort = stderr.abort_handle();
        if tokio::time::timeout(STDERR_DRAIN, stderr).await.is_err() {
            stderr_abort.abort();
        }
        result
    }
}

/// Upper bound on draining the stderr bridge after `job_stdout` reaches EOF.
const STDERR_DRAIN: std::time::Duration = std::time::Duration::from_millis(500);

/// Forward `reader` to the channel as `content_type`-tagged Tty posts until EOF
/// or a post fails. Used for the stderr side, which (unlike stdout) is not the
/// signal `serve_tty` waits on to decide the job has exited.
async fn forward_tty<B: ChannelBackend + 'static, A: CapAuthority + 'static>(
    channel: Arc<Channel<B, A>>,
    membership: MembershipId,
    mut reader: impl AsyncRead + Unpin + Send,
    content_type: &'static str,
) {
    let mut buf = [0_u8; TTY_CHUNK];
    loop {
        let n = match reader.read(&mut buf).await {
            Ok(n) => n,
            Err(e) => {
                tracing::warn!(error = %e, content_type, "TTY forward read failed; bridge stopped");
                return;
            }
        };
        if n == 0 {
            return;
        }
        if let Err(e) = channel
            .post(
                &membership,
                Some(MessageType::Tty(Tty {})),
                content_type,
                buf[..n].to_vec(),
            )
            .await
        {
            tracing::warn!(error = %e, content_type, "TTY forward post failed; bridge stopped");
            return;
        }
    }
}

/// The process backend's honest [`RawConsole`] stub: a bare process has no
/// serial console, so this reports [`ConsoleStatus::Unavailable`] and refuses
/// every `read`/`write` with [`ConsoleError::Unavailable`] rather than a silent
/// no-op — a working break-glass path and an absent one must never look the
/// same to a caller that only checks the return value of a call.
#[derive(Debug, Clone, Default)]
pub struct UnavailableConsole;

impl UnavailableConsole {
    const REASON: &'static str = "no serial console on the process backend";
}

impl RawConsole for UnavailableConsole {
    fn status(&self) -> ConsoleStatus {
        ConsoleStatus::Unavailable(Self::REASON.to_owned())
    }

    fn read(&mut self, _buf: &mut [u8]) -> Result<usize, ConsoleError> {
        Err(ConsoleError::Unavailable(Self::REASON.to_owned()))
    }

    fn write(&mut self, _bytes: &[u8]) -> Result<(), ConsoleError> {
        Err(ConsoleError::Unavailable(Self::REASON.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use std::{io::Cursor, time::Duration};

    use anyhow::Context;
    use sandy_fabric::{
        capauth::{Cap, CapError, CapRights, CapScope, encode_cap},
        types::{ChannelId, PeerId},
    };
    use tokio::time::{Duration as TokioDuration, timeout};

    use super::*;
    use crate::{capauth::LocalCapAuthority, inmem::InMem};

    const CHANNEL: &str = "orchestrator";

    fn rights(post: bool, read: bool, invite: bool) -> CapRights {
        CapRights { post, read, invite }
    }

    fn scope(peer: &str, rights: CapRights) -> CapScope {
        CapScope {
            peer: PeerId::from(peer),
            channel: ChannelId::from(CHANNEL),
            rights,
            expires_at: None,
        }
    }

    /// A fresh channel plus two caps minted against its own authority BEFORE
    /// the authority moves into the `Channel` (it has no handle left to mint
    /// with afterward): one for the agent under test, one for a separate
    /// in-process "orchestrator side" test helper that posts/subscribes on the
    /// same channel. `agent_cap` carries `invite` rights so tests can derive a
    /// third party's cap from it via `Channel::invite`.
    async fn new_channel_and_caps() -> anyhow::Result<(Arc<Channel<InMem, LocalCapAuthority>>, Cap, Cap)> {
        let authority = LocalCapAuthority::new(Duration::from_secs(3600))?;
        let agent_cap = authority.mint(scope("agent", rights(true, true, true)))?;
        let orchestrator_cap = authority.mint(scope("orchestrator", rights(true, true, false)))?;
        let channel = Channel::new(ChannelId::from(CHANNEL), InMem::default(), authority).await?;
        Ok((Arc::new(channel), agent_cap, orchestrator_cap))
    }

    #[tokio::test]
    async fn bootstrap_decodes_and_joins_with_the_handed_off_cap() -> anyhow::Result<()> {
        let (channel, agent_cap, _) = new_channel_and_caps().await?;
        let bytes = encode_cap(&agent_cap)?;

        let agent = SandboxAgent::bootstrap(Arc::clone(&channel), Cursor::new(bytes))?;

        // Prove it actually joined (not just decoded): the membership can post.
        channel
            .post(
                agent.membership(),
                Some(MessageType::Tty(Tty {})),
                TTY_STDOUT,
                b"ok".to_vec(),
            )
            .await
            .context("joined membership must be able to post")?;
        Ok(())
    }

    /// `SandboxAgent` holds a `Channel`, which holds a `Cap` whose `Debug`
    /// deliberately redacts its proof — threading that through would need
    /// `Debug` bounds nobody else wants, so a bootstrap failure is asserted by
    /// matching the `Err` arm directly rather than `expect_err`.
    fn assert_bootstrap_fails<T>(result: Result<T, AgentError>, msg: &str, matches: impl FnOnce(&AgentError) -> bool) {
        match result {
            Ok(_) => panic!("{msg}"),
            Err(e) => assert!(matches(&e), "{msg}: got {e:?}"),
        }
    }

    #[tokio::test]
    async fn bootstrap_rejects_undecodable_bytes() -> anyhow::Result<()> {
        let (channel, ..) = new_channel_and_caps().await.context("setup")?;
        let result = SandboxAgent::bootstrap(channel, Cursor::new(b"not a cap".to_vec()));
        assert_bootstrap_fails(result, "garbage bytes must not bootstrap", |e| {
            matches!(e, AgentError::BootstrapDecode(_))
        });
        Ok(())
    }

    #[tokio::test]
    async fn bootstrap_rejects_a_cap_from_a_different_authority() -> anyhow::Result<()> {
        let (channel, ..) = new_channel_and_caps().await?;
        let foreign_authority = LocalCapAuthority::new(Duration::from_secs(3600))?;
        let foreign_cap = foreign_authority.mint(scope("agent", rights(true, true, false)))?;
        let bytes = encode_cap(&foreign_cap)?;

        let result = SandboxAgent::bootstrap(channel, Cursor::new(bytes));
        assert_bootstrap_fails(result, "a foreign cap must not join", |e| {
            matches!(e, AgentError::Channel(ChannelError::Cap(CapError::Forged)))
        });
        Ok(())
    }

    #[tokio::test]
    async fn bootstrap_rejects_a_cap_scoped_to_a_different_channel() -> anyhow::Result<()> {
        let authority = LocalCapAuthority::new(Duration::from_secs(3600))?;
        let wrong_channel_cap = authority.mint(CapScope {
            peer: PeerId::from("agent"),
            channel: ChannelId::from("some-other-channel"),
            rights: rights(true, true, false),
            expires_at: None,
        })?;
        let channel = Arc::new(Channel::new(ChannelId::from(CHANNEL), InMem::default(), authority).await?);
        let bytes = encode_cap(&wrong_channel_cap)?;

        let result = SandboxAgent::bootstrap(channel, Cursor::new(bytes));
        assert_bootstrap_fails(result, "a wrong-channel cap must not join", |e| {
            matches!(e, AgentError::Channel(ChannelError::WrongChannel))
        });
        Ok(())
    }

    #[tokio::test]
    async fn serve_tty_bridges_job_stdio_to_the_channel_in_both_directions() -> anyhow::Result<()> {
        let (channel, agent_cap, orchestrator_cap) = new_channel_and_caps().await?;
        let agent = SandboxAgent::bootstrap(Arc::clone(&channel), Cursor::new(encode_cap(&agent_cap)?))?;
        let orchestrator = channel.join(&orchestrator_cap)?;

        let (job_stdout_agent, mut job_stdout_test) = tokio::io::duplex(1024);
        let (job_stderr_agent, mut job_stderr_test) = tokio::io::duplex(1024);
        let (job_stdin_agent, mut job_stdin_test) = tokio::io::duplex(1024);

        // Subscribe before posting, so the orchestrator-side stream sees the
        // stdout frame whichever order the two tasks happen to run in.
        let mut orchestrator_stream = std::pin::pin!(channel.subscribe(&orchestrator)?);

        let serving = tokio::spawn(async move {
            agent
                .serve_tty(job_stdout_agent, job_stderr_agent, job_stdin_agent)
                .await
        });

        // Orchestrator -> job: a stdin frame must reach the job's stdin pipe.
        channel
            .post(
                &orchestrator,
                Some(MessageType::Tty(Tty {})),
                TTY_STDIN,
                b"hello-job\n".to_vec(),
            )
            .await?;
        let mut stdin_buf = [0_u8; 16];
        let n = timeout(TokioDuration::from_secs(5), job_stdin_test.read(&mut stdin_buf)).await??;
        assert_eq!(&stdin_buf[..n], b"hello-job\n", "the stdin frame did not reach the job");

        // Job -> orchestrator: the job's stdout must become a TTY_STDOUT post.
        // The channel carries both directions, so the orchestrator's own just-
        // posted stdin frame arrives on this same stream first (replayed from
        // sequence 0) — a real consumer filters by content_type too.
        job_stdout_test.write_all(b"job-said-hi\n").await?;
        let env = loop {
            let env = timeout(TokioDuration::from_secs(5), orchestrator_stream.next())
                .await?
                .context("stream ended before the stdout frame arrived")??;
            if env.content_type == TTY_STDOUT {
                break env;
            }
        };
        assert!(matches!(env.message_type, Some(MessageType::Tty(_))));
        assert_eq!(env.payload, b"job-said-hi\n");

        // Job's stderr -> orchestrator too, tagged distinctly from stdout.
        job_stderr_test.write_all(b"job-warned\n").await?;
        let env = loop {
            let env = timeout(TokioDuration::from_secs(5), orchestrator_stream.next())
                .await?
                .context("stream ended before the stderr frame arrived")??;
            if env.content_type == TTY_STDERR {
                break env;
            }
        };
        assert_eq!(env.payload, b"job-warned\n");

        // EOF both the job's stdout and stderr (the job exits): serve_tty must
        // return promptly rather than sitting out the stderr-drain timeout.
        job_stdout_test.shutdown().await?;
        job_stderr_test.shutdown().await?;
        timeout(TokioDuration::from_secs(5), serving).await???;
        Ok(())
    }

    /// Adversarial (#109): an observe-only membership cannot inject input. The
    /// agent never duplicates this check — `Channel::post` refuses it before an
    /// envelope is ever stored — so this proves the integration doesn't
    /// accidentally bypass that by, say, forwarding every post regardless of who
    /// made it.
    #[tokio::test]
    async fn an_observe_only_membership_cannot_inject_stdin() -> anyhow::Result<()> {
        let (channel, agent_cap, _) = new_channel_and_caps().await?;
        let agent = SandboxAgent::bootstrap(Arc::clone(&channel), Cursor::new(encode_cap(&agent_cap)?))?;

        // A third party with read-only rights on the SAME channel: wrong rights,
        // not a wrong cap, so this isolates the rights check specifically. The
        // channel's own authority already moved in, so minting a sibling cap
        // from outside isn't possible — `invite`, attenuated from the agent's
        // own cap down to read-only, is the channel's own path for this and
        // doubles as proof that `invite` only narrows, never widens.
        let eavesdropper_cap = channel.invite(agent.membership(), rights(false, true, false))?;
        let eavesdropper = channel.join(&eavesdropper_cap)?;

        let (job_stdout_agent, _job_stdout_test) = tokio::io::duplex(1024);
        let (job_stderr_agent, _job_stderr_test) = tokio::io::duplex(1024);
        let (job_stdin_agent, mut job_stdin_test) = tokio::io::duplex(1024);
        let serving = tokio::spawn(async move {
            agent
                .serve_tty(job_stdout_agent, job_stderr_agent, job_stdin_agent)
                .await
        });

        let err = channel
            .post(
                &eavesdropper,
                Some(MessageType::Tty(Tty {})),
                TTY_STDIN,
                b"evil".to_vec(),
            )
            .await
            .expect_err("a read-only membership must not be able to post");
        assert!(matches!(err, ChannelError::InsufficientRights("post")), "got {err:?}");

        // Nothing must have reached the job's stdin: the rejected post was never
        // stored, so the bridge had nothing to forward.
        let mut buf = [0_u8; 16];
        let raced = timeout(TokioDuration::from_millis(200), job_stdin_test.read(&mut buf)).await;
        assert!(raced.is_err(), "the rejected post reached the job's stdin anyway");

        drop(job_stdin_test);
        serving.abort();
        Ok(())
    }

    #[test]
    fn unavailable_console_reports_unavailable_and_refuses_read_write() {
        let mut console = UnavailableConsole;
        assert!(matches!(console.status(), ConsoleStatus::Unavailable(_)));
        let mut buf = [0_u8; 8];
        assert!(
            matches!(console.read(&mut buf), Err(ConsoleError::Unavailable(_))),
            "a status of Unavailable must not silently succeed on read"
        );
        assert!(
            matches!(console.write(b"x"), Err(ConsoleError::Unavailable(_))),
            "a status of Unavailable must not silently succeed on write"
        );
    }
}
