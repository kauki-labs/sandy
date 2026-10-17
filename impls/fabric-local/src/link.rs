//! The agent link (#216): the byte stream between a sandbox agent running as
//! its own OS process and the orchestrator-side relay that holds its channel.
//!
//! The agent cannot host the channel itself: verifying a cap needs the
//! authority's key, and an agent holding that key could mint its own caps
//! (`docs/decisions/agent-fabric.md` §8). So the [`Channel`] stays with the
//! orchestrator, and [`serve_agent_link`] relays for exactly one agent over a
//! private link the executor created ([`AGENT_LINK_FD`](sandy_fabric::capauth::AGENT_LINK_FD)).
//!
//! The protocol, length-prefixed JSON frames ([`LinkFrame`]):
//!
//! 1. The relay sends the bootstrap cap as the first frame. The agent reads it exactly once (the consumed-once handoff)
//!    and never stores it.
//! 2. The agent presents it back in `Join`; the relay runs [`Channel::join`], so a forged, expired, or wrong-channel
//!    cap is refused there. One `Join` per link: a second is refused and the membership is unchanged.
//! 3. The agent posts `TTY_STDOUT`/`TTY_STDERR` only; the relay forwards `TTY_STDIN` traffic on the channel to the
//!    agent as `Deliver`.

use std::sync::Arc;

use futures_util::StreamExt;
use sandy_fabric::{
    capauth::{Cap, CapAuthority, CapCodecError},
    channel_backend::ChannelBackend,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::channel::{Channel, ChannelError};

/// The largest frame either side accepts. A length prefix above it is refused
/// before anything is allocated, so a hostile peer cannot make the other side
/// reserve an arbitrary buffer.
pub const MAX_FRAME: usize = 1 << 20;

/// One frame on the agent link. Byte fields are hex.
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LinkFrame {
    /// Relay to agent, first frame only: the encoded bootstrap cap.
    Cap {
        /// The hex of `encode_cap`.
        cap: String,
    },
    /// Agent to relay: join the channel with this cap.
    Join {
        /// The hex of `encode_cap`.
        cap: String,
    },
    /// Relay to agent: the join succeeded.
    Joined,
    /// Relay to agent: the join (or a repeated join) was refused.
    Refused {
        /// Why, for the agent's diagnostics. Never carries the cap.
        reason: String,
    },
    /// Agent to relay: post job output on the channel.
    Post {
        /// `TTY_STDOUT` or `TTY_STDERR`; anything else is refused.
        content_type: String,
        /// The hex of the bytes.
        payload: String,
    },
    /// Relay to agent: input for the job.
    Deliver {
        /// `TTY_STDIN`.
        content_type: String,
        /// The hex of the bytes.
        payload: String,
    },
}

impl LinkFrame {
    /// The frame's kind, for errors and logs.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Cap { .. } => "cap",
            Self::Join { .. } => "join",
            Self::Joined => "joined",
            Self::Refused { .. } => "refused",
            Self::Post { .. } => "post",
            Self::Deliver { .. } => "deliver",
        }
    }
}

/// Redacts the cap in `Cap` and `Join`, so a logged frame never carries it.
impl std::fmt::Debug for LinkFrame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cap { .. } | Self::Join { .. } => write!(f, "LinkFrame::{}(<redacted>)", self.kind()),
            Self::Joined => f.write_str("LinkFrame::Joined"),
            Self::Refused { reason } => write!(f, "LinkFrame::Refused({reason:?})"),
            Self::Post { content_type, payload } | Self::Deliver { content_type, payload } => write!(
                f,
                "LinkFrame::{}({content_type}, {} bytes)",
                self.kind(),
                payload.len() / 2
            ),
        }
    }
}

/// An agent-link failure.
#[derive(Debug, thiserror::Error)]
pub enum LinkError {
    /// Reading or writing the link failed.
    #[error("link I/O: {0}")]
    Io(#[from] std::io::Error),
    /// A frame was malformed, oversized, or not allowed at this point.
    #[error("link protocol: {0}")]
    Protocol(String),
    /// The cap in a frame did not decode.
    #[error("link cap: {0}")]
    Cap(#[from] CapCodecError),
    /// The channel refused the join or a post.
    #[error("channel: {0}")]
    Channel(#[from] ChannelError),
}

/// Write one length-prefixed frame.
///
/// # Errors
/// [`LinkError::Io`] if the write fails, [`LinkError::Protocol`] if the frame
/// encodes above [`MAX_FRAME`].
pub async fn write_frame(_w: &mut (impl AsyncWrite + Unpin), _frame: &LinkFrame) -> Result<(), LinkError> {
    Err(LinkError::Protocol("not implemented".to_string()))
}

/// Read one length-prefixed frame; `None` on a clean EOF before a frame starts.
///
/// # Errors
/// [`LinkError::Io`] on a read fault or an EOF inside a frame,
/// [`LinkError::Protocol`] for a length above [`MAX_FRAME`] or bytes that are
/// not a [`LinkFrame`].
pub async fn read_frame(_r: &mut (impl AsyncRead + Unpin)) -> Result<Option<LinkFrame>, LinkError> {
    Err(LinkError::Protocol("not implemented".to_string()))
}

/// Relay one agent's link to `channel` until the agent closes it: hand over
/// `cap`, admit one `Join`, then carry its TTY traffic. The membership is left
/// when this returns.
///
/// # Errors
/// [`LinkError::Channel`] if the join is refused (the agent is told why first),
/// [`LinkError::Protocol`] if the agent sends a frame it may not, and
/// [`LinkError::Io`] if the link faults.
pub async fn serve_agent_link<B, A, L>(_channel: Arc<Channel<B, A>>, _cap: &Cap, _link: L) -> Result<(), LinkError>
where
    B: ChannelBackend + 'static,
    A: CapAuthority + 'static,
    L: AsyncRead + AsyncWrite + Send + 'static,
{
    Err(LinkError::Protocol("not implemented".to_string()))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use anyhow::Context;
    use sandy_fabric::{
        capauth::{CapRights, CapScope, encode_cap},
        types::{ChannelId, PeerId},
    };
    use sandy_proto::{MessageType, Tty};
    use tokio::time::timeout;

    use super::*;
    use crate::{
        agent::{AgentError, LinkAgent, TTY_STDERR, TTY_STDIN, TTY_STDOUT},
        capauth::LocalCapAuthority,
        inmem::InMem,
    };

    const CHANNEL: &str = "orchestrator";
    const WAIT: Duration = Duration::from_secs(5);

    fn scope(peer: &str, post: bool) -> CapScope {
        CapScope {
            peer: PeerId::from(peer),
            channel: ChannelId::from(CHANNEL),
            rights: CapRights {
                post,
                read: true,
                invite: false,
            },
            expires_at: None,
        }
    }

    type TestChannel = Arc<Channel<InMem, LocalCapAuthority>>;

    async fn channel_and_caps() -> anyhow::Result<(TestChannel, Cap, Cap)> {
        let authority = LocalCapAuthority::new(Duration::from_secs(3600))?;
        let agent_cap = authority.mint(scope("agent", true))?;
        let orchestrator_cap = authority.mint(scope("orchestrator", true))?;
        let channel = Channel::new(ChannelId::from(CHANNEL), InMem::default(), authority).await?;
        Ok((Arc::new(channel), agent_cap, orchestrator_cap))
    }

    #[tokio::test]
    async fn frames_round_trip_and_eof_before_a_frame_is_none() -> anyhow::Result<()> {
        let (mut a, mut b) = tokio::io::duplex(4096);
        let frame = LinkFrame::Post {
            content_type: TTY_STDOUT.to_string(),
            payload: hex::encode(b"hi"),
        };
        write_frame(&mut a, &frame).await?;
        drop(a);
        assert_eq!(read_frame(&mut b).await?, Some(frame));
        assert_eq!(read_frame(&mut b).await?, None, "a clean EOF is not an error");
        Ok(())
    }

    #[tokio::test]
    async fn an_oversized_length_prefix_is_refused() -> anyhow::Result<()> {
        let (mut a, mut b) = tokio::io::duplex(64);
        let too_big = u32::try_from(MAX_FRAME + 1)?;
        a.write_all(&too_big.to_be_bytes()).await?;
        let err = read_frame(&mut b)
            .await
            .expect_err("an oversized frame must be refused");
        assert!(
            matches!(err, LinkError::Protocol(ref m) if m.contains("too large")),
            "got {err:?}"
        );
        Ok(())
    }

    #[test]
    fn a_cap_bearing_frame_is_redacted_in_debug() {
        let secret = "deadbeefcafe".to_string();
        for frame in [
            LinkFrame::Cap { cap: secret.clone() },
            LinkFrame::Join { cap: secret.clone() },
        ] {
            let shown = format!("{frame:?}");
            assert!(!shown.contains(&secret), "the cap leaked into Debug: {shown}");
        }
    }

    /// End to end over the link: the agent bootstraps from the relay's cap frame,
    /// its job output reaches the channel, and channel stdin reaches the job.
    #[tokio::test]
    async fn a_linked_agent_bridges_tty_both_ways_through_the_relay() -> anyhow::Result<()> {
        let (channel, agent_cap, orchestrator_cap) = channel_and_caps().await?;
        let orchestrator = channel.join(&orchestrator_cap)?;
        let mut observed = std::pin::pin!(channel.subscribe(&orchestrator)?);

        let (agent_end, host_end) = tokio::io::duplex(64 * 1024);
        let relay = tokio::spawn({
            let channel = Arc::clone(&channel);
            async move { serve_agent_link(channel, &agent_cap, host_end).await }
        });
        let agent = timeout(WAIT, LinkAgent::bootstrap(agent_end)).await??;

        let (job_stdout_agent, mut job_stdout) = tokio::io::duplex(1024);
        let (job_stderr_agent, mut job_stderr) = tokio::io::duplex(1024);
        let (job_stdin_agent, mut job_stdin) = tokio::io::duplex(1024);
        let serving = tokio::spawn(async move {
            agent
                .serve_tty(job_stdout_agent, job_stderr_agent, job_stdin_agent)
                .await
        });

        channel
            .post(
                &orchestrator,
                Some(MessageType::Tty(Tty {})),
                TTY_STDIN,
                b"ping\n".to_vec(),
            )
            .await?;
        let mut buf = [0_u8; 16];
        let n = timeout(WAIT, job_stdin.read(&mut buf)).await??;
        assert_eq!(&buf[..n], b"ping\n", "channel stdin did not reach the job");

        job_stdout.write_all(b"pong\n").await?;
        job_stderr.write_all(b"warn\n").await?;
        let (mut saw_out, mut saw_err) = (false, false);
        while !(saw_out && saw_err) {
            let env = timeout(WAIT, observed.next())
                .await?
                .context("channel stream ended early")??;
            saw_out |= env.content_type == TTY_STDOUT && env.payload == b"pong\n";
            saw_err |= env.content_type == TTY_STDERR && env.payload == b"warn\n";
        }

        job_stdout.shutdown().await?;
        job_stderr.shutdown().await?;
        timeout(WAIT, serving).await???;
        drop(job_stdin);
        Ok(())
    }

    /// A cap from another authority is refused at `Join`: the agent never
    /// bootstraps, and the relay reports the forged cap.
    #[tokio::test]
    async fn a_forged_cap_is_refused_and_the_agent_never_bootstraps() -> anyhow::Result<()> {
        let (channel, ..) = channel_and_caps().await?;
        let foreign = LocalCapAuthority::new(Duration::from_secs(3600))?.mint(scope("agent", true))?;
        let (agent_end, host_end) = tokio::io::duplex(64 * 1024);
        let relay = tokio::spawn(async move { serve_agent_link(channel, &foreign, host_end).await });

        match timeout(WAIT, LinkAgent::bootstrap(agent_end)).await? {
            Ok(_) => panic!("a forged cap must not bootstrap"),
            Err(e) => assert!(matches!(e, AgentError::Refused(_)), "got {e:?}"),
        }
        let relayed = timeout(WAIT, relay).await??;
        assert!(
            matches!(relayed, Err(LinkError::Channel(ChannelError::Cap(_)))),
            "got {relayed:?}"
        );
        Ok(())
    }

    /// Drive the relay as a raw agent: read the cap frame, join with it.
    async fn joined_raw_agent(
        channel: TestChannel,
        cap: Cap,
    ) -> anyhow::Result<(tokio::io::DuplexStream, tokio::task::JoinHandle<Result<(), LinkError>>)> {
        let (mut agent_end, host_end) = tokio::io::duplex(64 * 1024);
        let relay = tokio::spawn(async move { serve_agent_link(channel, &cap, host_end).await });
        let Some(LinkFrame::Cap { cap }) = timeout(WAIT, read_frame(&mut agent_end)).await?? else {
            anyhow::bail!("the relay's first frame must be the cap");
        };
        write_frame(&mut agent_end, &LinkFrame::Join { cap }).await?;
        let joined = timeout(WAIT, read_frame(&mut agent_end)).await??;
        anyhow::ensure!(joined == Some(LinkFrame::Joined), "expected Joined, got {joined:?}");
        Ok((agent_end, relay))
    }

    #[tokio::test]
    async fn a_second_join_on_one_link_is_refused() -> anyhow::Result<()> {
        let (channel, agent_cap, _) = channel_and_caps().await?;
        let (mut agent_end, relay) = joined_raw_agent(channel, agent_cap.clone()).await?;

        write_frame(
            &mut agent_end,
            &LinkFrame::Join {
                cap: hex::encode(encode_cap(&agent_cap)?),
            },
        )
        .await?;
        let reply = timeout(WAIT, read_frame(&mut agent_end)).await??;
        assert!(matches!(reply, Some(LinkFrame::Refused { .. })), "got {reply:?}");

        drop(agent_end);
        timeout(WAIT, relay).await???;
        Ok(())
    }

    /// The agent may only post job output: a `TTY_STDIN` post (input to its own
    /// job, as if from the orchestrator) is refused and never stored.
    #[tokio::test]
    async fn the_relay_refuses_an_agent_posting_stdin() -> anyhow::Result<()> {
        let (channel, agent_cap, orchestrator_cap) = channel_and_caps().await?;
        let (mut agent_end, relay) = joined_raw_agent(Arc::clone(&channel), agent_cap).await?;

        write_frame(
            &mut agent_end,
            &LinkFrame::Post {
                content_type: TTY_STDIN.to_string(),
                payload: hex::encode(b"evil"),
            },
        )
        .await?;
        let relayed = timeout(WAIT, relay).await??;
        assert!(matches!(relayed, Err(LinkError::Protocol(_))), "got {relayed:?}");

        let orchestrator = channel.join(&orchestrator_cap)?;
        let mut stream = std::pin::pin!(channel.subscribe(&orchestrator)?);
        let stored = timeout(Duration::from_millis(200), stream.next()).await;
        assert!(stored.is_err(), "the refused post was stored: {stored:?}");
        Ok(())
    }
}
