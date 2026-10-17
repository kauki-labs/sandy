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
use sandy_proto::{MessageType, PeerMsg, Tty};
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
    /// Relay to agent: a cap to join with. The first frame on the link carries
    /// the orchestrator-channel cap (`channel` absent) and how many peer-channel
    /// caps follow it, each in lockstep with its own `Join` (#238 slice 4).
    Cap {
        /// The hex of `encode_cap`.
        cap: String,
        /// The peer channel this cap is for; absent for the orchestrator channel.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        channel: Option<String>,
        /// On the first frame only: how many peer-channel caps follow.
        #[serde(default, skip_serializing_if = "is_zero")]
        peers: u32,
    },
    /// Agent to relay: join `channel` (the orchestrator channel when absent)
    /// with the cap this link handed over for it.
    Join {
        /// The hex of `encode_cap`.
        cap: String,
        /// The peer channel; absent for the orchestrator channel.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        channel: Option<String>,
    },
    /// Relay to agent: the join succeeded.
    Joined {
        /// The peer channel joined; absent for the orchestrator channel.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        channel: Option<String>,
    },
    /// Relay to agent: the join (or a repeated join) was refused.
    Refused {
        /// Why, for the agent's diagnostics. Never carries the cap.
        reason: String,
    },
    /// Agent to relay: post on a channel. On the orchestrator channel (`channel`
    /// absent) only job output, `TTY_STDOUT` or `TTY_STDERR`; on a peer channel
    /// this link joined, a peer message of any non-TTY content type.
    Post {
        /// The content type.
        content_type: String,
        /// The hex of the bytes.
        payload: String,
        /// The peer channel; absent for the orchestrator channel.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        channel: Option<String>,
    },
    /// Agent to relay, last frame: the job ran and exited with `code` (`128 +
    /// signal` for a signal death). Its absence means the agent failed.
    Exit {
        /// The job's exit code.
        code: i32,
    },
    /// Relay to agent: input for the job (`TTY_STDIN`, `channel` absent), or a
    /// message on a peer channel this link joined.
    Deliver {
        /// The content type.
        content_type: String,
        /// The hex of the bytes.
        payload: String,
        /// The peer channel; absent for the orchestrator channel.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        channel: Option<String>,
    },
}

impl LinkFrame {
    /// The frame's kind, for errors and logs.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Cap { .. } => "cap",
            Self::Join { .. } => "join",
            Self::Joined { .. } => "joined",
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
            Self::Joined { channel } => write!(f, "LinkFrame::Joined({channel:?})"),
            Self::Refused { reason } => write!(f, "LinkFrame::Refused({reason:?})"),
            Self::Exit { code } => write!(f, "LinkFrame::Exit({code})"),
            Self::Post {
                content_type, payload, ..
            }
            | Self::Deliver {
                content_type, payload, ..
            } => write!(
                f,
                "LinkFrame::{}({content_type}, {} bytes)",
                self.kind(),
                payload.len() / 2
            ),
        }
    }
}

/// `skip_serializing_if` helper: the first-frame-only `peers` count is omitted
/// when zero, so a link without peers keeps its exact wire form.
fn is_zero(n: &u32) -> bool {
    *n == 0
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
    serve_agent_link_with_peers(channel, cap, Vec::new(), link).await
}

/// A peer-channel membership the relay hands the agent at setup (#238 slice
/// 4): a channel this sandbox may talk to its peers on, and the cap minted for
/// it. Membership is fixed for the run in v1 (minted at dispatch).
pub struct PeerGrant<B, A> {
    /// The peer-group channel.
    pub channel: Arc<Channel<B, A>>,
    /// The agent's cap on it.
    pub cap: Cap,
}

/// [`serve_agent_link`] that also hands the agent `peers`, one membership per
/// peer channel. Each peer `Post` and `Deliver` is authorized against that
/// channel's own membership, never against holding the link.
///
/// # Errors
/// As [`serve_agent_link`]; a refused peer join fails the link.
pub async fn serve_agent_link_with_peers<B, A, L>(
    channel: Arc<Channel<B, A>>,
    cap: &Cap,
    peers: Vec<PeerGrant<B, A>>,
    link: L,
) -> Result<Option<i32>, LinkError>
where
    B: ChannelBackend + 'static,
    A: CapAuthority + 'static,
    L: AsyncRead + AsyncWrite + Send + 'static,
{
    let (mut rd, wr) = tokio::io::split(link);
    let wr = Arc::new(AsyncMutex::new(wr));

    let handed = hex::encode(encode_cap(cap)?);
    write_frame(
        &mut *wr.lock().await,
        &LinkFrame::Cap {
            cap: handed.clone(),
            channel: None,
            peers: u32::try_from(peers.len())
                .map_err(|_| LinkError::Protocol("too many peer channels for one link".to_string()))?,
        },
    )
    .await?;
    let presented = match read_frame(&mut rd).await? {
        Some(LinkFrame::Join { cap, channel: None }) => cap,
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
    // Admit only the cap this relay handed over: the peer may not join as anyone
    // else on this link, even with another valid cap.
    if presented != handed {
        let reason = "the join must present the cap this link handed over".to_string();
        let _ = write_frame(&mut *wr.lock().await, &LinkFrame::Refused { reason: reason.clone() }).await;
        return Err(LinkError::Protocol(reason));
    }
    let id = match channel.join(&decode_cap(&unhex(&presented, "the join cap")?)?) {
        Ok(id) => id,
        Err(e) => {
            // Best effort: the agent may already be gone; the refusal is returned either way.
            let _ = write_frame(&mut *wr.lock().await, &LinkFrame::Refused { reason: e.to_string() }).await;
            return Err(e.into());
        }
    };
    // From here on the guard leaves the membership and stops stdin delivery on
    // every path out, including this future being dropped.
    let mut membership = Joined {
        channel: Arc::clone(&channel),
        id,
        deliver: None,
    };
    write_frame(&mut *wr.lock().await, &LinkFrame::Joined { channel: None }).await?;

    // Each peer membership in lockstep: its cap, the agent's join for exactly
    // that channel with exactly that cap, then the verdict.
    let mut joined_peers = Vec::with_capacity(peers.len());
    for grant in peers {
        joined_peers.push(join_peer(grant, &mut rd, &wr).await?);
    }
    relay_joined(&mut membership, &mut joined_peers, &mut rd, &wr).await
}

/// Hand the agent one peer cap and admit its join, which must name that
/// channel and present exactly that cap.
async fn join_peer<B, A, R, W>(
    grant: PeerGrant<B, A>,
    rd: &mut R,
    wr: &Arc<AsyncMutex<W>>,
) -> Result<Joined<B, A>, LinkError>
where
    B: ChannelBackend + 'static,
    A: CapAuthority + 'static,
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let name = grant.channel.id().0.clone();
    let handed = hex::encode(encode_cap(&grant.cap)?);
    write_frame(
        &mut *wr.lock().await,
        &LinkFrame::Cap {
            cap: handed.clone(),
            channel: Some(name.clone()),
            peers: 0,
        },
    )
    .await?;
    let refuse = |reason: String| async {
        let _ = write_frame(&mut *wr.lock().await, &LinkFrame::Refused { reason: reason.clone() }).await;
        reason
    };
    match read_frame(rd).await? {
        Some(LinkFrame::Join { cap, channel }) if channel.as_deref() == Some(name.as_str()) && cap == handed => {}
        Some(LinkFrame::Join { .. }) => {
            let reason = refuse(format!(
                "the join for peer channel {name} must present the cap handed for it"
            ))
            .await;
            return Err(LinkError::Protocol(reason));
        }
        Some(other) => {
            return Err(LinkError::Protocol(format!(
                "expected the join for peer channel {name}, got {}",
                other.kind()
            )));
        }
        None => {
            return Err(LinkError::Protocol(format!(
                "the agent closed the link before joining peer channel {name}"
            )));
        }
    }
    let id = match grant.channel.join(&grant.cap) {
        Ok(id) => id,
        Err(e) => {
            refuse(e.to_string()).await;
            return Err(e.into());
        }
    };
    let membership = Joined {
        channel: grant.channel,
        id,
        deliver: None,
    };
    write_frame(&mut *wr.lock().await, &LinkFrame::Joined { channel: Some(name) }).await?;
    Ok(membership)
}

/// A joined agent's membership: leaving it, and aborting the stdin delivery
/// task, on drop.
struct Joined<B: ChannelBackend, A: CapAuthority> {
    channel: Arc<Channel<B, A>>,
    id: MembershipId,
    deliver: Option<tokio::task::AbortHandle>,
}

impl<B: ChannelBackend, A: CapAuthority> Drop for Joined<B, A> {
    fn drop(&mut self) {
        if let Some(deliver) = self.deliver.take() {
            deliver.abort();
        }
        self.channel.leave(&self.id);
    }
}

/// The joined phase of [`serve_agent_link`]: channel stdin out to the agent,
/// job output and the final exit in from it, until the agent closes the link.
async fn relay_joined<B, A, R, W>(
    membership: &mut Joined<B, A>,
    peers: &mut [Joined<B, A>],
    rd: &mut R,
    wr: &Arc<AsyncMutex<W>>,
) -> Result<Option<i32>, LinkError>
where
    B: ChannelBackend + 'static,
    A: CapAuthority + 'static,
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let inbound = membership.channel.subscribe(&membership.id)?;
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
                    channel: None,
                };
                if let Err(e) = write_frame(&mut *wr.lock().await, &frame).await {
                    tracing::warn!(error = %e, "agent relay: delivering stdin failed; stopped");
                    return;
                }
            }
        }
    });
    membership.deliver = Some(deliver.abort_handle());

    // Each peer channel delivers on its own membership's subscription, so only
    // channels this link joined can reach the agent.
    for peer in peers.iter_mut() {
        let inbound = peer.channel.subscribe(&peer.id)?;
        let name = peer.channel.id().0.clone();
        let deliver = tokio::spawn({
            let wr = Arc::clone(wr);
            async move {
                let mut inbound = std::pin::pin!(inbound);
                while let Some(item) = inbound.next().await {
                    let env = match item {
                        Ok(env) => env,
                        Err(e) => {
                            tracing::warn!(error = %e, channel = name, "agent relay: peer stream faulted; stopped");
                            return;
                        }
                    };
                    let frame = LinkFrame::Deliver {
                        content_type: env.content_type,
                        payload: hex::encode(&env.payload),
                        channel: Some(name.clone()),
                    };
                    if let Err(e) = write_frame(&mut *wr.lock().await, &frame).await {
                        tracing::warn!(error = %e, channel = name, "agent relay: peer delivery failed; stopped");
                        return;
                    }
                }
            }
        });
        peer.deliver = Some(deliver.abort_handle());
    }

    let mut exit = None;
    loop {
        match read_frame(rd).await? {
            None => return Ok(exit),
            Some(_) if exit.is_some() => {
                return Err(LinkError::Protocol(
                    "the agent sent a frame after reporting the job's exit".to_string(),
                ));
            }
            Some(LinkFrame::Post {
                content_type,
                payload,
                channel: None,
            }) => {
                if content_type != TTY_STDOUT && content_type != TTY_STDERR {
                    return Err(LinkError::Protocol(format!("the agent may not post {content_type}")));
                }
                let bytes = unhex(&payload, "a post payload")?;
                membership
                    .channel
                    .post(&membership.id, Some(MessageType::Tty(Tty {})), content_type, bytes)
                    .await?;
            }
            Some(LinkFrame::Post {
                content_type,
                payload,
                channel: Some(name),
            }) => {
                // Authorized against this channel's own membership, never against
                // holding the link: a channel this link did not join is refused.
                let Some(peer) = peers.iter().find(|p| p.channel.id().0 == name) else {
                    return Err(LinkError::Protocol(format!(
                        "the agent holds no membership on peer channel {name}"
                    )));
                };
                if [TTY_STDIN, TTY_STDOUT, TTY_STDERR].contains(&content_type.as_str()) {
                    return Err(LinkError::Protocol(format!(
                        "TTY traffic ({content_type}) belongs on the orchestrator channel, not peer channel {name}"
                    )));
                }
                let bytes = unhex(&payload, "a peer post payload")?;
                peer.channel
                    .post(&peer.id, Some(MessageType::PeerMsg(PeerMsg {})), content_type, bytes)
                    .await?;
            }
            Some(LinkFrame::Exit { code }) => exit = Some(code),
            Some(LinkFrame::Join { .. }) => {
                let refused = LinkFrame::Refused {
                    reason: "already joined; one membership per link".to_string(),
                };
                write_frame(&mut *wr.lock().await, &refused).await?;
            }
            Some(other) => {
                return Err(LinkError::Protocol(format!(
                    "unexpected {} frame from the agent",
                    other.kind()
                )));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use anyhow::Context;
    use sandy_fabric::{
        capauth::{CapRights, CapScope, encode_cap},
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
            channel: None,
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
            LinkFrame::Cap {
                cap: secret.clone(),
                channel: None,
                peers: 0,
            },
            LinkFrame::Join {
                cap: secret.clone(),
                channel: None,
            },
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

    /// A peer-group channel with the agent's cap and a sibling sandbox's cap on it.
    async fn peer_channel(id: &str) -> anyhow::Result<(TestChannel, Cap, Cap)> {
        let authority = LocalCapAuthority::new(Duration::from_secs(3600))?;
        let peer_scope = |peer: &str| CapScope {
            peer: PeerId::from(peer),
            channel: ChannelId::from(id),
            rights: CapRights {
                post: true,
                read: true,
                invite: false,
            },
            expires_at: None,
        };
        let agent_cap = authority.mint(peer_scope("agent"))?;
        let sibling_cap = authority.mint(peer_scope("sibling"))?;
        let channel = Channel::new(ChannelId::from(id), InMem::default(), authority).await?;
        Ok((Arc::new(channel), agent_cap, sibling_cap))
    }

    /// The next peer delivery on `inbox` for `channel`, skipping the agent's
    /// own echoes and other content.
    async fn next_peer(
        inbox: &mut tokio::sync::mpsc::Receiver<crate::agent::PeerDelivery>,
        payload: &[u8],
    ) -> anyhow::Result<crate::agent::PeerDelivery> {
        loop {
            let delivery = timeout(WAIT, inbox.recv()).await?.context("peer inbox closed")?;
            if delivery.payload == payload {
                return Ok(delivery);
            }
        }
    }

    /// #238 slice 4: the agent joins its peer channel at setup and exchanges
    /// messages with a sibling sandbox on it, alongside its orchestrator TTY.
    #[tokio::test]
    async fn an_agent_joins_its_peer_channel_and_exchanges_messages() -> anyhow::Result<()> {
        let (channel, agent_cap, _) = channel_and_caps().await?;
        let (group, agent_peer_cap, sibling_cap) = peer_channel("group-a").await?;
        let sibling = group.join(&sibling_cap)?;
        let mut sibling_view = std::pin::pin!(group.subscribe(&sibling)?);

        let (agent_end, host_end) = tokio::io::duplex(64 * 1024);
        let grants = vec![PeerGrant {
            channel: Arc::clone(&group),
            cap: agent_peer_cap,
        }];
        let relay =
            tokio::spawn(async move { serve_agent_link_with_peers(channel, &agent_cap, grants, host_end).await });
        let agent = timeout(WAIT, LinkAgent::bootstrap(agent_end)).await??;
        assert_eq!(agent.peers(), ["group-a".to_string()]);
        let mut inbox = agent.take_peer_inbox().context("the peer inbox is taken once")?;
        let agent = Arc::new(agent);

        let (stdout_agent, job_stdout) = tokio::io::duplex(1024);
        let (stderr_agent, job_stderr) = tokio::io::duplex(1024);
        let (stdin_agent, _job_stdin) = tokio::io::duplex(1024);
        let serving = tokio::spawn({
            let agent = Arc::clone(&agent);
            async move { agent.serve_tty(stdout_agent, stderr_agent, stdin_agent).await }
        });

        group
            .post(
                &sibling,
                Some(MessageType::PeerMsg(sandy_proto::PeerMsg {})),
                "application/json",
                b"from-sibling".to_vec(),
            )
            .await?;
        let got = next_peer(&mut inbox, b"from-sibling").await?;
        assert_eq!(
            (got.channel.as_str(), got.content_type.as_str()),
            ("group-a", "application/json")
        );

        agent
            .post_peer("group-a", "application/json", b"from-agent".to_vec())
            .await?;
        loop {
            let env = timeout(WAIT, sibling_view.next())
                .await?
                .context("group stream ended")??;
            if env.payload == b"from-agent" {
                assert!(matches!(env.message_type, Some(MessageType::PeerMsg(_))));
                break;
            }
        }

        drop((job_stdout, job_stderr));
        timeout(WAIT, serving).await???;
        drop(agent);
        timeout(WAIT, relay).await???;
        Ok(())
    }

    /// Overflow policy (#238, infra-f3): a full peer inbox drops the NEWEST
    /// delivery, so what the job reads is a gap-free, in-order prefix, and every
    /// drop is counted so a lost peer message is observable, never silent.
    #[tokio::test]
    async fn a_full_peer_inbox_drops_the_newest_and_counts_each_drop() -> anyhow::Result<()> {
        let (channel, agent_cap, _) = channel_and_caps().await?;
        let (group, agent_peer_cap, sibling_cap) = peer_channel("group-a").await?;
        let sibling = group.join(&sibling_cap)?;
        let (agent_end, host_end) = tokio::io::duplex(1 << 20);
        let grants = vec![PeerGrant {
            channel: Arc::clone(&group),
            cap: agent_peer_cap,
        }];
        let relay =
            tokio::spawn(async move { serve_agent_link_with_peers(channel, &agent_cap, grants, host_end).await });
        let agent = Arc::new(timeout(WAIT, LinkAgent::bootstrap(agent_end)).await??);
        let mut inbox = agent.take_peer_inbox().context("inbox")?;
        let (stdout_agent, job_stdout) = tokio::io::duplex(1024);
        let (stderr_agent, job_stderr) = tokio::io::duplex(1024);
        let (stdin_agent, _job_stdin) = tokio::io::duplex(1024);
        let serving = tokio::spawn({
            let agent = Arc::clone(&agent);
            async move { agent.serve_tty(stdout_agent, stderr_agent, stdin_agent).await }
        });

        let capacity = crate::agent::PEER_INBOX;
        let extra = 5;
        for n in 0..capacity + extra {
            group
                .post(
                    &sibling,
                    Some(MessageType::PeerMsg(sandy_proto::PeerMsg {})),
                    "text/plain",
                    format!("m{n}").into_bytes(),
                )
                .await?;
        }
        // Nothing reads the inbox until every delivery has been routed.
        let dropped = u64::try_from(extra)?;
        timeout(WAIT, async {
            while agent.peer_dropped() < dropped {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .context("the overflow was never counted")?;
        assert_eq!(agent.peer_dropped(), dropped, "exactly the overflow is dropped");
        for n in 0..capacity {
            let got = timeout(WAIT, inbox.recv()).await?.context("inbox closed")?;
            assert_eq!(
                got.payload,
                format!("m{n}").into_bytes(),
                "the kept messages are the oldest, in order"
            );
        }
        assert!(inbox.try_recv().is_err(), "nothing past the capacity was kept");

        drop((job_stdout, job_stderr));
        timeout(WAIT, serving).await???;
        drop(agent);
        timeout(WAIT, relay).await???;
        Ok(())
    }

    /// CodeRabbit on #246: a job that never reads its stdin must not stall the
    /// link reader, or peer deliveries would sit unrouted and uncounted.
    #[tokio::test]
    async fn a_job_that_never_reads_stdin_does_not_stall_peer_delivery() -> anyhow::Result<()> {
        let (channel, agent_cap, orchestrator_cap) = channel_and_caps().await?;
        let (group, agent_peer_cap, sibling_cap) = peer_channel("group-a").await?;
        let orchestrator = channel.join(&orchestrator_cap)?;
        let sibling = group.join(&sibling_cap)?;
        let (agent_end, host_end) = tokio::io::duplex(1 << 20);
        let grants = vec![PeerGrant {
            channel: Arc::clone(&group),
            cap: agent_peer_cap,
        }];
        let relay = tokio::spawn({
            let channel = Arc::clone(&channel);
            async move { serve_agent_link_with_peers(channel, &agent_cap, grants, host_end).await }
        });
        let agent = Arc::new(timeout(WAIT, LinkAgent::bootstrap(agent_end)).await??);
        let mut inbox = agent.take_peer_inbox().context("inbox")?;
        let (stdout_agent, job_stdout) = tokio::io::duplex(1024);
        let (stderr_agent, job_stderr) = tokio::io::duplex(1024);
        // A one-byte stdin pipe nobody reads: the first write fills it.
        let (stdin_agent, _never_read) = tokio::io::duplex(1);
        let serving = tokio::spawn({
            let agent = Arc::clone(&agent);
            async move { agent.serve_tty(stdout_agent, stderr_agent, stdin_agent).await }
        });

        channel
            .post(
                &orchestrator,
                Some(MessageType::Tty(Tty {})),
                TTY_STDIN,
                vec![b'x'; 64 * 1024],
            )
            .await?;
        tokio::time::sleep(Duration::from_millis(100)).await;
        group
            .post(
                &sibling,
                Some(MessageType::PeerMsg(sandy_proto::PeerMsg {})),
                "text/plain",
                b"still-routed".to_vec(),
            )
            .await?;
        let got = timeout(WAIT, inbox.recv())
            .await
            .context("the peer delivery was stalled behind the job's stdin")?
            .context("inbox closed")?;
        assert_eq!(got.payload, b"still-routed");

        drop((job_stdout, job_stderr));
        timeout(WAIT, serving).await???;
        drop(agent);
        timeout(WAIT, relay).await???;
        Ok(())
    }

    /// Run the relay with peer grants and drive it as a raw agent through the
    /// setup: the orchestrator join, then each peer join in lockstep.
    async fn raw_agent_with_peers(
        grants: Vec<PeerGrant<InMem, LocalCapAuthority>>,
    ) -> anyhow::Result<(
        tokio::io::DuplexStream,
        tokio::task::JoinHandle<Result<Option<i32>, LinkError>>,
    )> {
        let expected = u32::try_from(grants.len())?;
        let (channel, agent_cap, _) = channel_and_caps().await?;
        let (mut agent_end, host_end) = tokio::io::duplex(64 * 1024);
        let relay =
            tokio::spawn(async move { serve_agent_link_with_peers(channel, &agent_cap, grants, host_end).await });
        let Some(LinkFrame::Cap {
            cap,
            channel: None,
            peers,
        }) = timeout(WAIT, read_frame(&mut agent_end)).await??
        else {
            anyhow::bail!("the relay's first frame must be the orchestrator cap");
        };
        anyhow::ensure!(
            peers == expected,
            "the relay announced {peers} peer caps, expected {expected}"
        );
        write_frame(&mut agent_end, &LinkFrame::Join { cap, channel: None }).await?;
        anyhow::ensure!(
            timeout(WAIT, read_frame(&mut agent_end)).await?? == Some(LinkFrame::Joined { channel: None }),
            "the orchestrator join must succeed"
        );
        for _ in 0..peers {
            let Some(LinkFrame::Cap { cap, channel, .. }) = timeout(WAIT, read_frame(&mut agent_end)).await?? else {
                anyhow::bail!("expected a peer cap frame");
            };
            write_frame(
                &mut agent_end,
                &LinkFrame::Join {
                    cap,
                    channel: channel.clone(),
                },
            )
            .await?;
            let joined = timeout(WAIT, read_frame(&mut agent_end)).await??;
            anyhow::ensure!(
                joined == Some(LinkFrame::Joined { channel }),
                "peer join failed: {joined:?}"
            );
        }
        Ok((agent_end, relay))
    }

    /// Adversarial (infra-f3, post side): a link holding a cap for channel A
    /// cannot post to channel B, nor post TTY traffic on a peer channel; the
    /// relay ends and nothing is stored.
    #[tokio::test]
    async fn a_post_to_a_channel_the_link_did_not_join_is_refused() -> anyhow::Result<()> {
        let (group_a, agent_a, _) = peer_channel("group-a").await?;
        let (group_b, _, sibling_b) = peer_channel("group-b").await?;
        for (target, content_type) in [("group-b", "application/json"), ("group-a", TTY_STDOUT)] {
            let grants = vec![PeerGrant {
                channel: Arc::clone(&group_a),
                cap: agent_a.clone(),
            }];
            let (mut agent_end, relay) = raw_agent_with_peers(grants).await?;
            write_frame(
                &mut agent_end,
                &LinkFrame::Post {
                    content_type: content_type.to_string(),
                    payload: hex::encode(b"smuggled"),
                    channel: Some(target.to_string()),
                },
            )
            .await?;
            let relayed = timeout(WAIT, relay).await??;
            assert!(
                matches!(relayed, Err(LinkError::Protocol(_))),
                "{target}/{content_type}: got {relayed:?}"
            );
        }
        let observer = group_b.join(&sibling_b)?;
        let mut stream = std::pin::pin!(group_b.subscribe(&observer)?);
        let stored = timeout(Duration::from_millis(200), stream.next()).await;
        assert!(stored.is_err(), "the refused post reached channel B: {stored:?}");
        Ok(())
    }

    /// Adversarial (infra-f3, deliver side): traffic on a channel the link did
    /// not join never reaches the agent.
    #[tokio::test]
    async fn traffic_on_a_channel_the_link_did_not_join_never_reaches_the_agent() -> anyhow::Result<()> {
        let (group_a, agent_a, sibling_a) = peer_channel("group-a").await?;
        let (group_b, _, sibling_b) = peer_channel("group-b").await?;
        let grants = vec![PeerGrant {
            channel: Arc::clone(&group_a),
            cap: agent_a,
        }];
        let (mut agent_end, relay) = raw_agent_with_peers(grants).await?;

        let on_b = group_b.join(&sibling_b)?;
        group_b
            .post(
                &on_b,
                Some(MessageType::PeerMsg(sandy_proto::PeerMsg {})),
                "application/json",
                b"for-b-only".to_vec(),
            )
            .await?;
        let on_a = group_a.join(&sibling_a)?;
        group_a
            .post(
                &on_a,
                Some(MessageType::PeerMsg(sandy_proto::PeerMsg {})),
                "application/json",
                b"for-a".to_vec(),
            )
            .await?;

        let mut seen = Vec::new();
        while let Ok(Ok(Some(frame))) = timeout(Duration::from_millis(500), read_frame(&mut agent_end)).await {
            if let LinkFrame::Deliver { channel, payload, .. } = frame {
                seen.push((channel, unhex(&payload, "payload")?));
            }
        }
        assert!(
            seen.contains(&(Some("group-a".to_string()), b"for-a".to_vec())),
            "A's traffic must reach the agent: {seen:?}"
        );
        assert!(
            !seen
                .iter()
                .any(|(channel, payload)| channel.as_deref() == Some("group-b") || payload == b"for-b-only"),
            "B's traffic reached an agent that holds only A: {seen:?}"
        );
        drop(agent_end);
        timeout(WAIT, relay).await???;
        Ok(())
    }

    /// Adversarial (infra-f3, join side): a peer join must present exactly the
    /// cap handed over for that channel; another channel's cap, or the right cap
    /// under the wrong channel name, is refused.
    #[tokio::test]
    async fn a_peer_join_must_present_the_cap_handed_for_that_channel() -> anyhow::Result<()> {
        let (group_a, agent_a, _) = peer_channel("group-a").await?;
        let (_group_b, agent_b, _) = peer_channel("group-b").await?;
        let swapped_cap = hex::encode(encode_cap(&agent_b)?);
        for (join_cap, join_channel) in [(Some(swapped_cap), "group-a"), (None, "group-b")] {
            let (channel, agent_cap, _) = channel_and_caps().await?;
            let grants = vec![PeerGrant {
                channel: Arc::clone(&group_a),
                cap: agent_a.clone(),
            }];
            let (mut agent_end, host_end) = tokio::io::duplex(64 * 1024);
            let relay =
                tokio::spawn(async move { serve_agent_link_with_peers(channel, &agent_cap, grants, host_end).await });
            let Some(LinkFrame::Cap { cap, .. }) = timeout(WAIT, read_frame(&mut agent_end)).await?? else {
                anyhow::bail!("first frame must be a cap");
            };
            write_frame(&mut agent_end, &LinkFrame::Join { cap, channel: None }).await?;
            timeout(WAIT, read_frame(&mut agent_end)).await??;
            let Some(LinkFrame::Cap { cap: handed, .. }) = timeout(WAIT, read_frame(&mut agent_end)).await?? else {
                anyhow::bail!("expected the peer cap frame");
            };
            write_frame(
                &mut agent_end,
                &LinkFrame::Join {
                    cap: join_cap.unwrap_or(handed),
                    channel: Some(join_channel.to_string()),
                },
            )
            .await?;
            let reply = timeout(WAIT, read_frame(&mut agent_end)).await??;
            assert!(
                matches!(reply, Some(LinkFrame::Refused { .. })),
                "{join_channel}: got {reply:?}"
            );
            assert!(
                timeout(WAIT, relay).await??.is_err(),
                "{join_channel}: the relay must fail"
            );
        }
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
        let Some(LinkFrame::Cap { cap, .. }) = timeout(WAIT, read_frame(&mut agent_end)).await?? else {
            anyhow::bail!("the relay's first frame must be the cap");
        };
        write_frame(&mut agent_end, &LinkFrame::Join { cap, channel: None }).await?;
        let joined = timeout(WAIT, read_frame(&mut agent_end)).await??;
        anyhow::ensure!(
            joined == Some(LinkFrame::Joined { channel: None }),
            "expected Joined, got {joined:?}"
        );
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
                channel: None,
            },
        )
        .await?;
        let reply = timeout(WAIT, read_frame(&mut agent_end)).await??;
        assert!(matches!(reply, Some(LinkFrame::Refused { .. })), "got {reply:?}");
        assert!(
            timeout(WAIT, relay).await??.is_err(),
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
                channel: None,
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
                channel: None,
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
