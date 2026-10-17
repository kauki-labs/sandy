//! The sandbox agent (spec §3.2, issue #109): the per-sandbox gateway and
//! channel-membership unit. "Getting inside" a sandbox goes through the agent.
//!
//! [`SandboxAgent::bootstrap`] reads the orchestrator-channel cap exactly once
//! from a consumed-once handoff (never a staged file, which would leak into the
//! job's exported environment, see `docs/decisions/` and #177) and joins with
//! it. [`LinkAgent`] is the same agent as its own OS process (#216): the cap is
//! the first frame on its agent link
//! ([`AGENT_LINK_FD`](sandy_fabric::capauth::AGENT_LINK_FD)), and it joins
//! through the orchestrator-side relay ([`crate::link`]). [`SandboxAgent::serve_tty`] then bridges the
//! job's stdio to Tty traffic on that channel until the job exits.
//!
//! Cap-scope enforcement (observe vs interact) is never duplicated here: a
//! member without `post` rights is rejected by [`Channel::post`] before an
//! envelope is ever stored, so there is nothing for this bridge to forward in
//! the first place — the agent inherits the channel's own boundedness rather
//! than re-checking it.
//!
//! Two invariants this module relies on without re-checking, both load-bearing
//! for CWE-284 (authorization bypass):
//!
//! - **One channel per sandbox.** Spec §3.4: the orchestrator channel is "dedicated, per sandbox" — a 1:1 relationship.
//!   `SandboxAgent` does not, and cannot, verify that the `Channel` it was handed is really ITS OWN dedicated channel
//!   rather than one shared with another sandbox: nothing in an [`Envelope`](sandy_fabric::channel_backend::Envelope)
//!   carries a sandbox target to check against. Minting one channel id per sandbox is the composition root's job
//!   (#115/sandyd), not this module's; a composition root that reuses one channel across sandboxes lets every agent on
//!   it receive every other's `TTY_STDIN` traffic.
//! - **One job per bootstrap.** [`SandboxAgent::serve_tty`] is call-once, enforced structurally (a second call is a
//!   hard [`AgentError::AlreadyServed`], not a silent stale delivery): the per-membership delivery cursor
//!   ([`Channel::subscribe`]'s reconnect value) lives WITHIN one `serve_tty` session, not across sessions, so a second
//!   call on the same membership could otherwise deliver a stdin frame that arrived for the first job's session into a
//!   second job's stdin.
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
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::Mutex as AsyncMutex,
};

use crate::{
    channel::{Channel, ChannelError, MembershipId},
    link::{LinkError, LinkFrame, read_frame, unhex, write_frame},
};

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
    /// [`SandboxAgent::serve_tty`] was called more than once on this agent.
    /// Structural, not a doc-comment convention: a second call could otherwise
    /// deliver a stdin frame queued for the first job's session into a second
    /// job's stdin (CWE-284), since the per-membership delivery cursor persists
    /// across calls.
    #[error("serve_tty already called on this agent; one job per bootstrap")]
    AlreadyServed,
    /// The relay refused this agent's join over the link (#216): a forged,
    /// expired, or wrong-channel cap. The job must not be started.
    #[error("the relay refused the join: {0}")]
    Refused(String),
    /// A peer-channel operation named a channel this agent did not join.
    #[error("not a member of peer channel {0}")]
    NotAPeer(String),
    /// The agent link faulted or broke protocol.
    #[error("agent link: {0}")]
    Link(#[from] LinkError),
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
    /// Set by [`serve_tty`](Self::serve_tty) on its one allowed call. See the
    /// module doc's "one job per bootstrap" invariant.
    served: std::sync::atomic::AtomicBool,
}

impl<B: ChannelBackend + 'static, A: CapAuthority + 'static> SandboxAgent<B, A> {
    /// Read the bootstrap cap from `cap_handoff` to EOF, decode it, and join
    /// `channel` with it. `cap_handoff` is read exactly once and dropped before
    /// this returns — the consumed-once convention: never re-read, never staged
    /// to disk.
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
        Ok(Self {
            channel,
            membership,
            served: std::sync::atomic::AtomicBool::new(false),
        })
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
    /// [`AgentError::AlreadyServed`] if this is not the first call (see the
    /// module doc's "one job per bootstrap" invariant); [`AgentError::Channel`]
    /// if this membership can no longer subscribe (e.g. revoked since
    /// `bootstrap`); [`AgentError::Stdio`] if reading `job_stdout` faults;
    /// whatever [`Channel::post`] returns if a stdout post itself fails.
    pub async fn serve_tty(
        &self,
        job_stdout: impl AsyncRead + Unpin + Send + 'static,
        job_stderr: impl AsyncRead + Unpin + Send + 'static,
        job_stdin: impl AsyncWrite + Unpin + Send + 'static,
    ) -> Result<(), AgentError> {
        claim_once(&self.served)?;
        let inbound = self.channel.subscribe(&self.membership)?;
        let stdin_frames = inbound
            .take_while(|item| {
                if let Err(e) = item {
                    tracing::warn!(error = %e, "TTY inbound stream faulted; stdin bridge stopped");
                }
                std::future::ready(item.is_ok())
            })
            .filter_map(|item| {
                std::future::ready(item.ok().and_then(|env| {
                    (matches!(env.message_type, Some(MessageType::Tty(_))) && env.content_type == TTY_STDIN)
                        .then_some(env.payload)
                }))
            });
        let port = Arc::new(ChannelPort {
            channel: Arc::clone(&self.channel),
            membership: self.membership.clone(),
        });
        bridge_tty(port, stdin_frames, job_stdout, job_stderr, job_stdin).await
    }
}

/// Where a bridged job's output goes: the in-process channel membership, or the
/// agent link to the relay (#216). One bridge serves both, so the two agents
/// cannot drift apart in how they treat the job's stdio.
trait TtyPort: Send + Sync + 'static {
    /// Post one chunk of job output tagged `content_type`.
    fn post(
        &self,
        content_type: &'static str,
        payload: Vec<u8>,
    ) -> impl std::future::Future<Output = Result<(), AgentError>> + Send;
}

/// A [`TtyPort`] onto an in-process [`Channel`] membership.
struct ChannelPort<B, A> {
    channel: Arc<Channel<B, A>>,
    membership: MembershipId,
}

impl<B: ChannelBackend + 'static, A: CapAuthority + 'static> TtyPort for ChannelPort<B, A> {
    async fn post(&self, content_type: &'static str, payload: Vec<u8>) -> Result<(), AgentError> {
        self.channel
            .post(&self.membership, Some(MessageType::Tty(Tty {})), content_type, payload)
            .await
            .map(drop)
            .map_err(AgentError::from)
    }
}

/// Mark a one-job-per-bootstrap agent as served, refusing a second call.
fn claim_once(served: &std::sync::atomic::AtomicBool) -> Result<(), AgentError> {
    served
        .compare_exchange(
            false,
            true,
            std::sync::atomic::Ordering::SeqCst,
            std::sync::atomic::Ordering::SeqCst,
        )
        .map(drop)
        .map_err(|_| AgentError::AlreadyServed)
}

/// Bridge the job's stdio to `port` until `job_stdout` hits EOF: stdout and
/// stderr become [`TTY_STDOUT`]/[`TTY_STDERR`] posts, and each chunk of
/// `stdin_frames` is written to `job_stdin`. See [`SandboxAgent::serve_tty`]
/// for the exit and drain semantics.
async fn bridge_tty<P: TtyPort>(
    port: Arc<P>,
    stdin_frames: impl futures_core::Stream<Item = Vec<u8>> + Send + 'static,
    mut job_stdout: impl AsyncRead + Unpin + Send + 'static,
    job_stderr: impl AsyncRead + Unpin + Send + 'static,
    mut job_stdin: impl AsyncWrite + Unpin + Send + 'static,
) -> Result<(), AgentError> {
    let inbound = tokio::spawn(async move {
        let mut stdin_frames = std::pin::pin!(stdin_frames);
        while let Some(bytes) = stdin_frames.next().await {
            if let Err(e) = job_stdin.write_all(&bytes).await {
                tracing::warn!(error = %e, "writing to job stdin failed; stdin bridge stopped");
                break;
            }
        }
    });

    let stderr = tokio::spawn(forward_tty(Arc::clone(&port), job_stderr, TTY_STDERR));

    let mut buf = [0_u8; TTY_CHUNK];
    let result = loop {
        match job_stdout.read(&mut buf).await {
            Ok(0) => break Ok(()),
            Ok(n) => {
                if let Err(e) = port.post(TTY_STDOUT, buf[..n].to_vec()).await {
                    break Err(e);
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

/// A message for the agent on one of its peer channels (#238 slice 4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerDelivery {
    /// The peer channel it arrived on.
    pub channel: String,
    /// Its content type.
    pub content_type: String,
    /// Its bytes.
    pub payload: Vec<u8>,
}

/// The sandbox agent as its own OS process (#216): bootstraps over the agent
/// link from the orchestrator-side relay ([`crate::link::serve_agent_link`])
/// instead of holding the channel, then bridges the job's stdio the same way
/// [`SandboxAgent`] does.
pub struct LinkAgent {
    port: Arc<LinkPort>,
    reader: std::sync::Mutex<Option<Box<dyn AsyncRead + Send + Unpin>>>,
    served: std::sync::atomic::AtomicBool,
    /// The peer channels joined at setup (#238 slice 4).
    peers: Vec<String>,
    /// Where the link reader routes peer deliveries.
    peer_tx: tokio::sync::mpsc::Sender<PeerDelivery>,
    /// The receiving end, handed out once by [`LinkAgent::take_peer_inbox`].
    peer_inbox: std::sync::Mutex<Option<tokio::sync::mpsc::Receiver<PeerDelivery>>>,
    /// Peer deliveries dropped because the inbox was full.
    peer_dropped: Arc<std::sync::atomic::AtomicU64>,
}

/// How many peer deliveries wait in the inbox before newer ones are dropped
/// (with a warning), so a slow consumer never stalls the job's stdin.
pub(crate) const PEER_INBOX: usize = 1024;

impl LinkAgent {
    /// Read the cap frame from `link` exactly once, present it in `Join`, and
    /// wait for the relay's verdict. The cap is not kept past the `Join`.
    ///
    /// # Errors
    /// [`AgentError::Refused`] if the relay refuses the join,
    /// [`AgentError::BootstrapDecode`] if the cap frame is not a cap,
    /// [`AgentError::Link`] if the link faults or the relay breaks protocol.
    pub async fn bootstrap<L>(link: L) -> Result<Self, AgentError>
    where
        L: AsyncRead + AsyncWrite + Send + 'static,
    {
        let (mut rd, mut wr) = tokio::io::split(link);
        let (cap, peer_count) = match read_frame(&mut rd).await? {
            Some(LinkFrame::Cap {
                cap,
                channel: None,
                peers,
            }) => (cap, peers),
            Some(other) => {
                return Err(LinkError::Protocol(format!("expected the cap frame first, got {}", other.kind())).into());
            }
            None => return Err(LinkError::Protocol("the link closed before the cap frame".to_string()).into()),
        };
        // Refuse garbage here rather than presenting it; the relay re-verifies.
        decode_cap(&unhex(&cap, "the cap frame")?)?;
        write_frame(&mut wr, &LinkFrame::Join { cap, channel: None }).await?;
        match read_frame(&mut rd).await? {
            Some(LinkFrame::Joined { channel: None }) => {}
            Some(LinkFrame::Refused { reason }) => return Err(AgentError::Refused(reason)),
            Some(other) => {
                return Err(LinkError::Protocol(format!("expected the join verdict, got {}", other.kind())).into());
            }
            None => return Err(LinkError::Protocol("the link closed before the join verdict".to_string()).into()),
        }
        // Each peer membership in lockstep: its cap, our join for exactly that
        // channel with exactly that cap, the relay's verdict.
        let mut peers = Vec::new();
        for _ in 0..peer_count {
            let (cap, channel) = match read_frame(&mut rd).await? {
                Some(LinkFrame::Cap {
                    cap,
                    channel: Some(channel),
                    ..
                }) => (cap, channel),
                Some(other) => {
                    return Err(LinkError::Protocol(format!("expected a peer cap frame, got {}", other.kind())).into());
                }
                None => return Err(LinkError::Protocol("the link closed during the peer setup".to_string()).into()),
            };
            decode_cap(&unhex(&cap, "a peer cap frame")?)?;
            write_frame(
                &mut wr,
                &LinkFrame::Join {
                    cap,
                    channel: Some(channel.clone()),
                },
            )
            .await?;
            match read_frame(&mut rd).await? {
                Some(LinkFrame::Joined { channel: Some(joined) }) if joined == channel => peers.push(channel),
                Some(LinkFrame::Refused { reason }) => return Err(AgentError::Refused(reason)),
                Some(other) => {
                    return Err(LinkError::Protocol(format!(
                        "expected the verdict for peer channel {channel}, got {}",
                        other.kind()
                    ))
                    .into());
                }
                None => return Err(LinkError::Protocol("the link closed during the peer setup".to_string()).into()),
            }
        }
        let (peer_tx, peer_inbox) = tokio::sync::mpsc::channel(PEER_INBOX);
        Ok(Self {
            port: Arc::new(LinkPort {
                writer: AsyncMutex::new(Box::new(wr)),
            }),
            reader: std::sync::Mutex::new(Some(Box::new(rd))),
            served: std::sync::atomic::AtomicBool::new(false),
            peers,
            peer_tx,
            peer_inbox: std::sync::Mutex::new(Some(peer_inbox)),
            peer_dropped: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        })
    }

    /// Bridge the job's stdio over the link until `job_stdout` hits EOF, with
    /// the same semantics as [`SandboxAgent::serve_tty`].
    ///
    /// # Errors
    /// As [`SandboxAgent::serve_tty`], with link faults as [`AgentError::Link`].
    pub async fn serve_tty(
        &self,
        job_stdout: impl AsyncRead + Unpin + Send + 'static,
        job_stderr: impl AsyncRead + Unpin + Send + 'static,
        job_stdin: impl AsyncWrite + Unpin + Send + 'static,
    ) -> Result<(), AgentError> {
        claim_once(&self.served)?;
        let reader = self
            .reader
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
            .ok_or(AgentError::AlreadyServed)?;
        // A dedicated reader that never blocks: TTY stdin goes into an unbounded
        // queue (its only source is the trusted orchestrator, and keystrokes must
        // not be dropped) and peer deliveries go through the counted, drop-newest
        // inbox. A job that stops reading its stdin therefore cannot stall the
        // link, and peer messages keep being routed or counted.
        let (stdin_tx, stdin_rx) = tokio::sync::mpsc::unbounded_channel();
        let reader = tokio::spawn(route_link(
            reader,
            stdin_tx,
            self.peer_tx.clone(),
            Arc::clone(&self.peer_dropped),
        ));
        let stdin_frames =
            futures_util::stream::unfold(
                stdin_rx,
                |mut rx| async move { rx.recv().await.map(|bytes| (bytes, rx)) },
            );
        let bridged = bridge_tty(Arc::clone(&self.port), stdin_frames, job_stdout, job_stderr, job_stdin).await;
        reader.abort();
        bridged
    }
}

/// Read the agent link until it closes, routing TTY stdin to `stdin_tx` and
/// peer deliveries to `peer_tx`; never waits on either consumer.
async fn route_link(
    mut reader: Box<dyn AsyncRead + Send + Unpin>,
    stdin_tx: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    peer_tx: tokio::sync::mpsc::Sender<PeerDelivery>,
    peer_dropped: Arc<std::sync::atomic::AtomicU64>,
) {
    loop {
        match read_frame(&mut reader).await {
            Ok(Some(LinkFrame::Deliver {
                content_type,
                payload,
                channel: Some(channel),
            })) => match unhex(&payload, "a peer deliver payload") {
                Ok(payload) => {
                    let delivery = PeerDelivery {
                        channel,
                        content_type,
                        payload,
                    };
                    if let Err(tokio::sync::mpsc::error::TrySendError::Full(_)) = peer_tx.try_send(delivery) {
                        // Drop-newest, counted: never a silent loss.
                        let total = peer_dropped.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                        tracing::warn!(dropped = total, "peer inbox full; dropping the newest peer message");
                    }
                }
                Err(e) => tracing::warn!(error = %e, "dropping a malformed peer frame"),
            },
            Ok(Some(LinkFrame::Deliver {
                content_type,
                payload,
                channel: None,
            })) if content_type == TTY_STDIN => match unhex(&payload, "a deliver payload") {
                Ok(bytes) => {
                    // The stdin bridge is gone once the job's stdout closed.
                    let _ = stdin_tx.send(bytes);
                }
                Err(e) => tracing::warn!(error = %e, "dropping a malformed stdin frame"),
            },
            Ok(Some(other)) => tracing::warn!(kind = other.kind(), "ignoring an unexpected link frame"),
            Ok(None) => return,
            Err(e) => {
                tracing::warn!(error = %e, "agent link faulted; link reader stopped");
                return;
            }
        }
    }
}

impl LinkAgent {
    /// The peer channels this agent joined at setup.
    #[must_use]
    pub fn peers(&self) -> &[String] {
        &self.peers
    }

    /// Post on peer channel `channel`, which this agent must have joined.
    ///
    /// # Errors
    /// [`AgentError::NotAPeer`] for a channel this agent did not join, or
    /// [`AgentError::Link`] if the frame cannot be written.
    pub async fn post_peer(&self, channel: &str, content_type: &str, payload: Vec<u8>) -> Result<(), AgentError> {
        if !self.peers.iter().any(|joined| joined == channel) {
            return Err(AgentError::NotAPeer(channel.to_string()));
        }
        let frame = LinkFrame::Post {
            content_type: content_type.to_string(),
            payload: hex::encode(payload),
            channel: Some(channel.to_string()),
        };
        Ok(write_frame(&mut *self.port.writer.lock().await, &frame).await?)
    }

    /// How many peer deliveries were dropped because the inbox was full. The
    /// overflow policy is drop-newest: what the job reads is a gap-free, in-order
    /// prefix, and this count says how much was lost after it.
    #[must_use]
    pub fn peer_dropped(&self) -> u64 {
        self.peer_dropped.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// The receiver for messages on this agent's peer channels; `Some` once.
    /// They arrive while [`serve_tty`](Self::serve_tty) reads the link.
    pub fn take_peer_inbox(&self) -> Option<tokio::sync::mpsc::Receiver<PeerDelivery>> {
        self.peer_inbox
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
    }

    /// Report the job's exit to the relay as the link's last frame. A run whose
    /// agent never reports is an infra fault, not a job result (INV-11).
    ///
    /// # Errors
    /// [`AgentError::Link`] if the frame cannot be written.
    pub async fn report_exit(&self, code: i32) -> Result<(), AgentError> {
        Ok(write_frame(&mut *self.port.writer.lock().await, &LinkFrame::Exit { code }).await?)
    }
}

/// A [`TtyPort`] onto the agent link's write half.
struct LinkPort {
    writer: AsyncMutex<Box<dyn AsyncWrite + Send + Unpin>>,
}

impl TtyPort for LinkPort {
    async fn post(&self, content_type: &'static str, payload: Vec<u8>) -> Result<(), AgentError> {
        let frame = LinkFrame::Post {
            content_type: content_type.to_string(),
            payload: hex::encode(payload),
            channel: None,
        };
        Ok(write_frame(&mut *self.writer.lock().await, &frame).await?)
    }
}

/// Upper bound on draining the stderr bridge after `job_stdout` reaches EOF.
const STDERR_DRAIN: std::time::Duration = std::time::Duration::from_millis(500);

/// Forward `reader` to `port` as `content_type`-tagged posts until EOF or a
/// post fails. Used for the stderr side, which (unlike stdout) is not the
/// signal the bridge waits on to decide the job has exited.
async fn forward_tty<P: TtyPort>(port: Arc<P>, mut reader: impl AsyncRead + Unpin + Send, content_type: &'static str) {
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
        if let Err(e) = port.post(content_type, buf[..n].to_vec()).await {
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

    /// Adversarial (#109, CWE-284): a second `serve_tty` call on the same
    /// agent is a hard error, not a silent stale-stdin delivery into a new
    /// job. The delivery cursor's reconnect value lives within one session;
    /// without this guard a frame queued for the first job could land in a
    /// second job's stdin.
    #[tokio::test]
    async fn serve_tty_is_call_once() -> anyhow::Result<()> {
        let (channel, agent_cap, _) = new_channel_and_caps().await?;
        let agent = SandboxAgent::bootstrap(Arc::clone(&channel), Cursor::new(encode_cap(&agent_cap)?))?;

        let (stdout_agent, stdout_test) = tokio::io::duplex(1024);
        let (stderr_agent, stderr_test) = tokio::io::duplex(1024);
        let (stdin_agent, _stdin_test) = tokio::io::duplex(1024);
        drop(stdout_test); // EOFs stdout_agent immediately: the first call returns fast
        drop(stderr_test);
        agent.serve_tty(stdout_agent, stderr_agent, stdin_agent).await?;

        let (stdout_agent, _) = tokio::io::duplex(1024);
        let (stderr_agent, _) = tokio::io::duplex(1024);
        let (stdin_agent, _) = tokio::io::duplex(1024);
        let err = agent
            .serve_tty(stdout_agent, stderr_agent, stdin_agent)
            .await
            .expect_err("a second serve_tty call must be refused");
        assert!(matches!(err, AgentError::AlreadyServed), "got {err:?}");
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
