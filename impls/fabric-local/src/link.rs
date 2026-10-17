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
    capauth::{Cap, CapAuthority, CapCodecError, decode_cap, encode_cap},
    channel_backend::ChannelBackend,
};
use sandy_proto::{MessageType, Tty};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::Mutex as AsyncMutex,
};

use crate::{
    agent::{TTY_STDERR, TTY_STDIN, TTY_STDOUT},
    channel::{Channel, ChannelError, MembershipId},
};

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
    /// Agent to relay, last frame: the job ran and exited with `code` (`128 +
    /// signal` for a signal death). Its absence means the agent failed.
    Exit {
        /// The job's exit code.
        code: i32,
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
            Self::Exit { .. } => "exit",
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
            Self::Exit { code } => write!(f, "LinkFrame::Exit({code})"),
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
pub async fn write_frame(w: &mut (impl AsyncWrite + Unpin), frame: &LinkFrame) -> Result<(), LinkError> {
    let body = serde_json::to_vec(frame).map_err(|e| LinkError::Protocol(format!("encode {}: {e}", frame.kind())))?;
    let len = u32::try_from(body.len())
        .ok()
        .filter(|&n| n as usize <= MAX_FRAME)
        .ok_or_else(|| LinkError::Protocol(format!("{} frame too large: {} bytes", frame.kind(), body.len())))?;
    w.write_all(&len.to_be_bytes()).await?;
    w.write_all(&body).await?;
    w.flush().await?;
    Ok(())
}

/// Read one length-prefixed frame; `None` on a clean EOF before a frame starts.
///
/// # Errors
/// [`LinkError::Io`] on a read fault or an EOF inside a frame,
/// [`LinkError::Protocol`] for a length above [`MAX_FRAME`] or bytes that are
/// not a [`LinkFrame`].
pub async fn read_frame(r: &mut (impl AsyncRead + Unpin)) -> Result<Option<LinkFrame>, LinkError> {
    let mut len = [0_u8; 4];
    let mut got = 0;
    while got < len.len() {
        let n = r.read(&mut len[got..]).await?;
        if n == 0 {
            if got == 0 {
                return Ok(None);
            }
            return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into());
        }
        got += n;
    }
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_FRAME {
        return Err(LinkError::Protocol(format!("frame too large: {len} bytes")));
    }
    let mut body = vec![0_u8; len];
    r.read_exact(&mut body).await?;
    serde_json::from_slice(&body)
        .map(Some)
        .map_err(|e| LinkError::Protocol(format!("malformed frame: {e}")))
}

/// Decode a hex field of a frame.
pub(crate) fn unhex(field: &str, what: &str) -> Result<Vec<u8>, LinkError> {
    hex::decode(field).map_err(|e| LinkError::Protocol(format!("{what} is not hex: {e}")))
}

/// Relay one agent's link to `channel` until the agent closes it: hand over
/// `cap`, admit one `Join`, then carry its TTY traffic. The membership is left
/// when this returns.
///
/// Returns the job's exit code from the agent's final `Exit` frame, or `None`
/// if the agent closed the link without one: it failed, so the job's result is
/// unknown and the run is an infra fault (INV-11).
///
/// # Errors
/// [`LinkError::Channel`] if the join is refused (the agent is told why first),
/// [`LinkError::Protocol`] if the agent sends a frame it may not, and
/// [`LinkError::Io`] if the link faults.
pub async fn serve_agent_link<B, A, L>(
    channel: Arc<Channel<B, A>>,
    cap: &Cap,
    link: L,
) -> Result<Option<i32>, LinkError>
where
    B: ChannelBackend + 'static,
    A: CapAuthority + 'static,
    L: AsyncRead + AsyncWrite + Send + 'static,
{
    let (mut rd, wr) = tokio::io::split(link);
    let wr = Arc::new(AsyncMutex::new(wr));

    write_frame(
        &mut *wr.lock().await,
        &LinkFrame::Cap {
            cap: hex::encode(encode_cap(cap)?),
        },
    )
    .await?;
    let presented = match read_frame(&mut rd).await? {
        Some(LinkFrame::Join { cap }) => decode_cap(&unhex(&cap, "the join cap")?)?,
        Some(other) => {
            return Err(LinkError::Protocol(format!(
                "expected join from the agent, got {}",
                other.kind()
            )));
        }
        None => {
            return Err(LinkError::Protocol(
                "the agent closed the link before joining".to_string(),
            ));
        }
    };
    let membership = match channel.join(&presented) {
        Ok(membership) => membership,
        Err(e) => {
            // Best effort: the agent may already be gone; the refusal is returned either way.
            let _ = write_frame(&mut *wr.lock().await, &LinkFrame::Refused { reason: e.to_string() }).await;
            return Err(e.into());
        }
    };
    write_frame(&mut *wr.lock().await, &LinkFrame::Joined).await?;

    let result = relay_joined(&channel, &membership, &mut rd, &wr).await;
    channel.leave(&membership);
    result.map(|()| None)
}

/// The joined phase of [`serve_agent_link`]: channel stdin out to the agent,
/// job output in from it, until the agent closes the link.
async fn relay_joined<B, A, R, W>(
    channel: &Arc<Channel<B, A>>,
    membership: &MembershipId,
    rd: &mut R,
    wr: &Arc<AsyncMutex<W>>,
) -> Result<(), LinkError>
where
    B: ChannelBackend + 'static,
    A: CapAuthority + 'static,
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let inbound = channel.subscribe(membership)?;
    let deliver = tokio::spawn({
        let wr = Arc::clone(wr);
        async move {
            let mut inbound = std::pin::pin!(inbound);
            while let Some(item) = inbound.next().await {
                let env = match item {
                    Ok(env) => env,
                    Err(e) => {
                        tracing::warn!(error = %e, "agent relay: channel stream faulted; stdin delivery stopped");
                        return;
                    }
                };
                if !matches!(env.message_type, Some(MessageType::Tty(_))) || env.content_type != TTY_STDIN {
                    continue;
                }
                let frame = LinkFrame::Deliver {
                    content_type: env.content_type,
                    payload: hex::encode(&env.payload),
                };
                if let Err(e) = write_frame(&mut *wr.lock().await, &frame).await {
                    tracing::warn!(error = %e, "agent relay: delivering stdin failed; stopped");
                    return;
                }
            }
        }
    });

    let result = loop {
        match read_frame(rd).await {
            Ok(None) => break Ok(()),
            Ok(Some(LinkFrame::Post { content_type, payload })) => {
                if content_type != TTY_STDOUT && content_type != TTY_STDERR {
                    break Err(LinkError::Protocol(format!("the agent may not post {content_type}")));
                }
                let bytes = match unhex(&payload, "a post payload") {
                    Ok(bytes) => bytes,
                    Err(e) => break Err(e),
                };
                if let Err(e) = channel
                    .post(membership, Some(MessageType::Tty(Tty {})), content_type, bytes)
                    .await
                {
                    break Err(e.into());
                }
            }
            Ok(Some(LinkFrame::Join { .. })) => {
                let refused = LinkFrame::Refused {
                    reason: "already joined; one membership per link".to_string(),
                };
                if let Err(e) = write_frame(&mut *wr.lock().await, &refused).await {
                    break Err(e);
                }
            }
            Ok(Some(other)) => {
                break Err(LinkError::Protocol(format!(
                    "unexpected {} frame from the agent",
                    other.kind()
                )));
            }
            Err(e) => break Err(e),
        }
    };
    deliver.abort();
    result
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use anyhow::Context;
    use sandy_fabric::{
        capauth::{CapRights, CapScope},
        types::{ChannelId, PeerId},
    };
    use tokio::time::timeout;

    use super::*;
    use crate::{
        agent::{AgentError, LinkAgent},
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
        // The agent is dropped with its serving task, closing the link: the
        // relay must then end cleanly and leave the membership.
        timeout(WAIT, relay).await???;
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
    ) -> anyhow::Result<(
        tokio::io::DuplexStream,
        tokio::task::JoinHandle<Result<Option<i32>, LinkError>>,
    )> {
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

    /// The relay reports the job's exit from the agent's last frame; without
    /// one the result is unknown (`None`), never a made-up exit code.
    #[tokio::test]
    async fn the_relay_returns_the_exit_the_agent_reports_and_none_without_one() -> anyhow::Result<()> {
        for report in [Some(7), None] {
            let (channel, agent_cap, _) = channel_and_caps().await?;
            let (agent_end, host_end) = tokio::io::duplex(64 * 1024);
            let relay = tokio::spawn(async move { serve_agent_link(channel, &agent_cap, host_end).await });
            let agent = timeout(WAIT, LinkAgent::bootstrap(agent_end)).await??;
            if let Some(code) = report {
                agent.report_exit(code).await?;
            }
            drop(agent);
            assert_eq!(timeout(WAIT, relay).await???, report, "reported {report:?}");
        }
        Ok(())
    }

    /// The relay admits only the cap it handed over: a peer presenting another
    /// valid cap (here the orchestrator's own) is refused, not joined as it.
    #[tokio::test]
    async fn a_join_with_a_cap_other_than_the_handed_one_is_refused() -> anyhow::Result<()> {
        let (channel, agent_cap, orchestrator_cap) = channel_and_caps().await?;
        let (mut agent_end, host_end) = tokio::io::duplex(64 * 1024);
        let relay = tokio::spawn(async move { serve_agent_link(channel, &agent_cap, host_end).await });
        let Some(LinkFrame::Cap { .. }) = timeout(WAIT, read_frame(&mut agent_end)).await?? else {
            anyhow::bail!("the relay's first frame must be the cap");
        };
        write_frame(
            &mut agent_end,
            &LinkFrame::Join {
                cap: hex::encode(sandy_fabric::capauth::encode_cap(&orchestrator_cap)?),
            },
        )
        .await?;
        let reply = timeout(WAIT, read_frame(&mut agent_end)).await??;
        assert!(matches!(reply, Some(LinkFrame::Refused { .. })), "got {reply:?}");
        assert!(
            timeout(WAIT, relay).await?.is_err(),
            "the relay must report the refusal"
        );
        Ok(())
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
