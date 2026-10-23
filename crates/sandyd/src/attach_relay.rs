//! The interactive attach data plane (#327): a UDS listener separate from
//! the control socket (`docs/decisions/sandyd.md` §1 keeps that one pure
//! request/response; streaming job output over it was explicitly set aside
//! there), where a client holding the cap `Attach`'s control-RPC response
//! handed back redeems it for a live, bidirectional TTY bridge.
//!
//! Wire protocol: `sandy_fabric_local::link`'s [`LinkFrame`] — the same
//! length-prefixed hex-JSON framing the real sandbox agent's own link
//! already uses, just from the other seat. The client's FIRST frame presents
//! its cap (`Join { cap, channel: None }`); nothing is written back before
//! that cap is verified, mirroring [`crate::mesh_accept`]'s own "zero bytes
//! before auth" discipline. The job this cap belongs to is read from the
//! cap's own (still-unverified) `scope().channel` — a routing hint only:
//! `Channel::join`'s call into the capability authority is the actual
//! verification, so a forged or mismatched scope is still refused there,
//! never trusted just because it named a real job id.
//!
//! Once joined: client `Post`s become `TTY_STDIN` channel posts (refused
//! with a `Refused` frame, not silently dropped, if the cap lacks `post` —
//! #327's one new behavioral fork, "read succeeds, post is refused"); every
//! `TTY_STDOUT`/`TTY_STDERR` envelope the channel yields is delivered back as
//! `Deliver`. A clean close (either side) ends the session — the membership
//! leaves, the job itself is untouched; a later re-attach is a fresh
//! connection presenting a fresh cap (from a fresh control-RPC `Attach`
//! call), never required to reuse this one.

use std::sync::Arc;

use futures_util::StreamExt;
use sandy_fabric::{
    capauth::{CapAuthority, decode_cap},
    channel_backend::ChannelBackend,
};
use sandy_fabric_local::{
    agent::{ARCHIVE_TRANSCRIPT, RESIZE_CONTROL, TTY_STDERR, TTY_STDIN, TTY_STDOUT, encode_resize},
    channel::{Channel, ChannelError, MembershipId},
    link::{LinkFrame, read_frame, write_frame},
};
use sandy_proto::{Control, MessageType, Tty};
use tokio::{net::UnixListener, sync::Mutex as AsyncMutex};

use crate::{
    dispatch::{self, JobRegistry},
    host_registry::HostRegistry,
};

/// How long a freshly accepted attach connection has to present its `Join`
/// cap before it's closed — mirrors `mesh_accept`'s `PREFIX_TIMEOUT` for the
/// identical pre-auth-DoS reason: an uncapped accept loop lets any local
/// peer on this socket EMFILE the daemon by opening connections and sending
/// nothing.
const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Accept connections from `listener` until it errors, handing each to
/// [`serve_one_attach`]. A single connection's own failure never stops the
/// loop — only ends that one connection.
pub async fn serve_attach_accept_loop(
    listener: &UnixListener,
    registry: &Arc<JobRegistry>,
    host_registry: &Arc<HostRegistry>,
) {
    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                let registry = Arc::clone(registry);
                let host_registry = Arc::clone(host_registry);
                tokio::spawn(async move {
                    serve_one_attach(stream, registry, host_registry).await;
                });
            }
            Err(e) => {
                tracing::warn!(error = %e, "attach accept loop: accept faulted; backing off");
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
    }
}

/// Join `cap` onto `job`'s channel, returning the resulting membership plus
/// — as ONE critical section, serialized against every other
/// `join_for_attach`/`leave_for_attach` call on this SAME job via
/// `job.attach_tracking` — the post-join DEDICATED attach count (never
/// `Channel::member_count()`, see [`dispatch::JobChannel::attach_tracking`]'s
/// own doc for the real bug that was) and the next monotonic attach-sequence
/// number (#340). Serializing the whole "mutate the channel, update the
/// attach count, assign the next sequence" step behind one lock fixes the
/// ORDERING; the sequence number is what then lets the asynchronous
/// send/delivery that follows happen in any order without losing that
/// ordering information — see [`notify_attach_state`]'s own doc for the
/// delivery side.
///
/// # Errors
/// Whatever [`Channel::join`] returns.
fn join_for_attach(
    job: &dispatch::JobChannel,
    cap: &sandy_fabric::capauth::Cap,
) -> Result<(MembershipId, usize, u64), ChannelError> {
    let mut tracking = job
        .attach_tracking
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let membership = job.channel.join(cap)?;
    tracking.count += 1;
    let count = tracking.count;
    let seq = tracking.next_seq;
    tracking.next_seq += 1;
    Ok((membership, count, seq))
}

/// Like [`join_for_attach`], for the leave side: no `Result` (`Channel::leave`
/// cannot fail), same atomicity guarantee. Saturating decrement: a leave
/// this function is never called for twice in practice (each connection
/// calls it at most once, on its own single exit path), but a saturating
/// subtract is a one-line defense against the count ever going negative
/// rather than panicking or wrapping if that invariant is ever violated.
fn leave_for_attach(job: &dispatch::JobChannel, membership: &MembershipId) -> (usize, u64) {
    let mut tracking = job
        .attach_tracking
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    job.channel.leave(membership);
    tracking.count = tracking.count.saturating_sub(1);
    let count = tracking.count;
    let seq = tracking.next_seq;
    tracking.next_seq += 1;
    (count, seq)
}

/// Best-effort: notify `job`'s placed host-executor (#340) that its attach-
/// membership count transitioned to `attached` at sequence `seq` (assigned
/// by [`join_for_attach`]/[`leave_for_attach`], atomically with the
/// transition itself — never derived from send order here). A no-op if the
/// job was never placed remotely (`host_id` is `None`, e.g. a local-only
/// run) or the send fails (the host disconnected, or never registered this
/// job at all) — logged, never propagated, since losing this notification
/// only costs the "unlimited while attached" policy for this job, never the
/// attach session itself (the same "best-effort, not a gate" discipline
/// `persist_attach_token` already follows elsewhere in this feature).
///
/// Delivery order is NOT guaranteed to match `seq` order (independent sends,
/// possibly over independent connections if a job were ever re-placed —
/// not something stage 1 does, but the design doesn't assume otherwise) —
/// the host-executor side is expected to keep only the highest `seq` it has
/// seen per `job_id` and discard anything at or below it, which is why a
/// correct `seq` at the SOURCE (this function's caller) is what actually
/// matters, not the order these async sends happen to complete in.
async fn notify_attach_state(
    job: &dispatch::JobChannel,
    host_registry: &HostRegistry,
    job_id: &str,
    attached: bool,
    seq: u64,
) {
    let Some(host_id) = &job.host_id else {
        return; // never placed remotely: no host-executor to notify
    };
    if let Err(e) = host_registry
        .send_attach_state_changed(
            host_id,
            sandy_executor_proto::AttachStateChanged {
                job_id: job_id.to_owned(),
                attached,
                sequence: seq,
            },
        )
        .await
    {
        tracing::debug!(host_id, job_id, attached, seq, error = %e, "could not notify the host-executor of an attach-state change");
    }
}

/// Like [`notify_attach_state`], but detached onto its own task (#340,
/// CodeRabbit finding on this PR): the real send can await the per-host
/// `attach_state_tx` channel (bounded, capacity 4) filling up, or the
/// connection's own write — neither should ever delay the attach
/// handshake's `Joined` response or `serve_one_attach`'s own teardown,
/// which is exactly what happened when this was called inline before
/// either of those. Fire-and-forget: nothing here observes whether the
/// spawned task ever completes, matching this notification's own
/// documented best-effort contract.
fn spawn_notify_attach_state(
    job: Arc<dispatch::JobChannel>,
    host_registry: Arc<HostRegistry>,
    job_id: String,
    attached: bool,
    seq: u64,
) {
    tokio::spawn(async move {
        notify_attach_state(&job, &host_registry, &job_id, attached, seq).await;
    });
}

/// Handshake, then relay, one accepted attach connection end to end. Logs
/// and returns on any failure — never panics, never brings down the accept
/// loop.
async fn serve_one_attach(
    stream: tokio::net::UnixStream,
    registry: Arc<JobRegistry>,
    host_registry: Arc<HostRegistry>,
) {
    let (mut read_half, write_half) = tokio::io::split(stream);
    let write_half = Arc::new(AsyncMutex::new(write_half));

    let (presented, initial_size) = match tokio::time::timeout(HANDSHAKE_TIMEOUT, read_frame(&mut read_half)).await {
        Ok(Ok(Some(LinkFrame::Join {
            cap,
            channel: None,
            cols,
            rows,
        }))) => (cap, cols.zip(rows)),
        Ok(Ok(Some(other))) => {
            tracing::warn!(
                frame = other.kind(),
                "attach accept: expected a Join, refusing the connection"
            );
            return;
        }
        Ok(Ok(None)) => return, // clean close before presenting anything
        Ok(Err(e)) => {
            tracing::warn!(error = %e, "attach accept: malformed handshake frame; refusing the connection");
            return;
        }
        Err(_elapsed) => {
            tracing::warn!("attach accept: peer did not present a cap within the timeout; closing");
            return;
        }
    };

    let refuse = {
        let write_half = Arc::clone(&write_half);
        move |reason: String| {
            let write_half = Arc::clone(&write_half);
            async move {
                let _ = write_frame(
                    &mut *write_half.lock().await,
                    &LinkFrame::Refused { reason: reason.clone() },
                )
                .await;
                tracing::info!(reason, "attach accept: refused");
            }
        }
    };

    let cap_bytes = match hex::decode(&presented) {
        Ok(bytes) => bytes,
        Err(e) => {
            refuse(format!("the presented cap is not valid hex: {e}")).await;
            return;
        }
    };
    let cap = match decode_cap(&cap_bytes) {
        Ok(cap) => cap,
        Err(e) => {
            refuse(format!("the presented cap did not decode: {e}")).await;
            return;
        }
    };
    // Routing only — see this module's own doc for why reading the claimed
    // (not-yet-verified) scope here is safe: `Channel::join` below is the
    // actual verification.
    let job_id = cap.scope().channel.0.clone();
    let Some(job) = registry.get(&job_id) else {
        refuse(format!("no such job: {job_id}")).await;
        return;
    };

    let (membership, count, seq) = match join_for_attach(&job, &cap) {
        Ok(joined) => joined,
        Err(e) => {
            refuse(e.to_string()).await;
            return;
        }
    };
    // #340, CodeRabbit finding on this PR: `Joined` goes out FIRST, before
    // anything that touches the host-executor notification — the earlier
    // version of this code notified first and only then wrote `Joined`,
    // which let a slow/blocked notification send (the per-host channel
    // filling up, or its own connection write) delay the handshake response
    // itself. The notification below is spawned, never awaited inline,
    // for the same reason: nothing about telling a REMOTE host-executor
    // about this attach should ever gate this LOCAL handshake.
    if write_frame(&mut *write_half.lock().await, &LinkFrame::Joined { channel: None })
        .await
        .is_err()
    {
        let (count, seq) = leave_for_attach(&job, &membership);
        if count == 0 {
            spawn_notify_attach_state(Arc::clone(&job), Arc::clone(&host_registry), job_id.clone(), false, seq);
        }
        return;
    }
    // The connection's initial size (epic #340 phase 2), posted as an
    // ordinary resize so the agent sizes its PTY for this attach before
    // anything else arrives — best-effort: a failure here is no worse than
    // starting at the agent's own default size, never a reason to refuse the
    // whole attach.
    if let Some((cols, rows)) = initial_size {
        let _ = job
            .channel
            .post(
                &membership,
                Some(MessageType::Control(Control {})),
                RESIZE_CONTROL,
                encode_resize(cols, rows),
            )
            .await;
    }
    // This join may be the one that brought the count from 0 to 1 —
    // `count`/`seq` were assigned atomically with the join itself
    // (`join_for_attach`), so unlike a separate later check, this is never
    // racing a concurrent transition on the same job.
    if count == 1 {
        spawn_notify_attach_state(Arc::clone(&job), Arc::clone(&host_registry), job_id.clone(), true, seq);
    }

    // `relay` always leaves `membership` itself (via its internal
    // `LeaveGuard`, on every exit path including a panic) — `leave_tx` is
    // how that guard hands back the atomically-assigned `(count, seq)` for
    // THIS leave once it's happened, so the notify below reports the real
    // transition rather than a separately (and racily) re-checked one. See
    // `LeaveGuard`'s own doc for why the leave and the count/seq assignment
    // have to be one critical section rather than two steps.
    let (leave_tx, leave_rx) = tokio::sync::oneshot::channel();
    if let Err(e) = relay(
        Arc::clone(&job.channel),
        membership,
        &mut read_half,
        write_half,
        Some((&job.attach_tracking, leave_tx)),
    )
    .await
    {
        tracing::warn!(error = %e, job_id, "attach relay faulted");
    }
    if let Ok((count, seq)) = leave_rx.await
        && count == 0
    {
        spawn_notify_attach_state(Arc::clone(&job), Arc::clone(&host_registry), job_id.clone(), false, seq);
    }
}

/// A relay failure: the connection faulted reading or writing a frame, or
/// the channel's backend faulted delivering output.
#[derive(Debug, thiserror::Error)]
pub enum AttachRelayError {
    /// The connection faulted reading or writing a [`LinkFrame`].
    #[error("attach relay link I/O: {0}")]
    Link(#[from] sandy_fabric_local::link::LinkError),
    /// The membership's subscribe stream faulted.
    #[error("attach relay channel: {0}")]
    Channel(#[from] ChannelError),
}

/// Aborts the wrapped task when dropped.
struct AbortOnDrop(tokio::task::AbortHandle);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Leaves `id` on `channel` when dropped, on every exit path out of
/// [`relay`] — including a panic unwind, which is exactly why the leave
/// itself must happen here (synchronously, in `Drop`) rather than in some
/// code after `relay`'s own `.await` resolves: that code would never run on
/// a panic.
///
/// `leave_seq`, when present (#340), is what makes the leave's resulting
/// member count and its attach-sequence-number assignment ATOMIC with the
/// leave itself — not a separate step after `relay` returns, which would
/// reopen exactly the race `join_for_attach`/`leave_for_attach` close for
/// every OTHER join/leave on this job: a concurrent transition could
/// otherwise interleave between this leave and a later, separate count
/// read. `Drop` can't `.await`, so the actual async notify send can't happen
/// here either — the computed `(count, seq)` is handed out over a
/// `oneshot` (whose `send` is a plain, synchronous, non-blocking call) for
/// the caller to pick up and act on asynchronously once `relay` returns.
/// The atomic-sequence-assignment handoff [`LeaveGuard`]'s `Drop` and
/// [`relay`] share (#340): the job's attach-tracking lock to update under,
/// and the one-shot channel the resulting `(attach_count, sequence)` pair
/// is handed back on. See [`LeaveGuard`]'s own doc for why this exists.
type LeaveSeqHandoff<'a> = (
    &'a std::sync::Mutex<dispatch::AttachTracking>,
    tokio::sync::oneshot::Sender<(usize, u64)>,
);

struct LeaveGuard<'a, B: ChannelBackend, A: CapAuthority> {
    channel: Arc<Channel<B, A>>,
    id: MembershipId,
    leave_seq: Option<LeaveSeqHandoff<'a>>,
}

impl<B: ChannelBackend, A: CapAuthority> Drop for LeaveGuard<'_, B, A> {
    fn drop(&mut self) {
        self.channel.leave(&self.id);
        if let Some((attach_tracking, tx)) = self.leave_seq.take() {
            let mut tracking = attach_tracking
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            tracking.count = tracking.count.saturating_sub(1);
            let count = tracking.count;
            let seq = tracking.next_seq;
            tracking.next_seq += 1;
            drop(tracking);
            // The receiver may already be gone (the caller stopped waiting,
            // e.g. it panicked too) — never a reason to panic again here.
            let _ = tx.send((count, seq));
        }
    }
}

/// The joined phase: deliver `channel`'s `TTY_STDOUT`/`TTY_STDERR` traffic to
/// the client as `Deliver` frames, and post the client's `Post` frames as
/// `TTY_STDIN`, until a clean close. Leaves `membership` on every exit path.
///
/// `leave_seq`, when `Some` (#340), is handed to the internal [`LeaveGuard`]
/// so the leave this function always performs also gets an atomically
/// assigned `(count, sequence)` pair, delivered to the caller over the
/// paired `oneshot` the moment this function returns (by which point
/// `LeaveGuard` has already dropped and sent it) — see [`LeaveGuard`]'s own
/// doc for why this can't just be a separate step after the `.await`
/// resolves. `None` for callers (this module's own unit tests of `relay` in
/// isolation) that don't care about attach-state notification at all.
///
/// # Errors
/// [`AttachRelayError::Link`] if the connection faults reading or writing a
/// frame. [`AttachRelayError::Channel`] if the channel's own subscribe
/// stream faults (not a plain rights refusal on a post — that's reported to
/// the client as `Refused` and does not end the relay).
async fn relay<B, A, R, W>(
    channel: Arc<Channel<B, A>>,
    membership: MembershipId,
    read_half: &mut R,
    write_half: Arc<AsyncMutex<W>>,
    leave_seq: Option<LeaveSeqHandoff<'_>>,
) -> Result<(), AttachRelayError>
where
    B: ChannelBackend + 'static,
    A: CapAuthority + 'static,
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let _leave = LeaveGuard {
        channel: Arc::clone(&channel),
        id: membership.clone(),
        leave_seq,
    };

    let inbound = channel.subscribe(&membership)?;
    let deliver = tokio::spawn({
        let write_half = Arc::clone(&write_half);
        async move {
            let mut inbound = std::pin::pin!(inbound);
            while let Some(item) = inbound.next().await {
                let Ok(env) = item else {
                    // A backend fault ends delivery only — the foreground
                    // loop keeps posting input until the client disconnects;
                    // losing output is not a reason to also sever input.
                    return;
                };
                let is_tty = matches!(env.message_type, Some(MessageType::Tty(_)))
                    && (env.content_type == TTY_STDOUT || env.content_type == TTY_STDERR);
                let is_archive =
                    matches!(env.message_type, Some(MessageType::Output(_))) && env.content_type == ARCHIVE_TRANSCRIPT;
                let frame = if is_tty {
                    LinkFrame::Deliver {
                        content_type: env.content_type,
                        payload: hex::encode(&env.payload),
                        channel: None,
                    }
                } else if is_archive {
                    LinkFrame::Archive {
                        content_type: env.content_type,
                        payload: hex::encode(&env.payload),
                    }
                } else {
                    continue;
                };
                if write_frame(&mut *write_half.lock().await, &frame).await.is_err() {
                    return;
                }
            }
        }
    });
    let _abort = AbortOnDrop(deliver.abort_handle());

    loop {
        match read_frame(read_half).await? {
            Some(LinkFrame::Post {
                content_type,
                payload,
                channel: None,
            }) => {
                if content_type != TTY_STDIN {
                    return Err(sandy_fabric_local::link::LinkError::Protocol(format!(
                        "an attach client may only post {TTY_STDIN}, not {content_type}"
                    ))
                    .into());
                }
                let bytes = hex::decode(&payload).map_err(|e| {
                    sandy_fabric_local::link::LinkError::Protocol(format!("a post payload is not hex: {e}"))
                })?;
                match channel
                    .post(&membership, Some(MessageType::Tty(Tty {})), TTY_STDIN, bytes)
                    .await
                {
                    Ok(_) => {}
                    Err(e @ ChannelError::InsufficientRights(_)) => {
                        // #327's one new behavioral fork, reported on the
                        // wire, not just logged: an observer-only cap's
                        // typed input is refused, never silently dropped or
                        // mistaken for a dead relay.
                        let _ = write_frame(
                            &mut *write_half.lock().await,
                            &LinkFrame::Refused { reason: e.to_string() },
                        )
                        .await;
                    }
                    Err(e) => return Err(e.into()),
                }
            }
            Some(LinkFrame::Resize { cols, rows }) => {
                match channel
                    .post(
                        &membership,
                        Some(MessageType::Control(Control {})),
                        RESIZE_CONTROL,
                        encode_resize(cols, rows),
                    )
                    .await
                {
                    Ok(_) => {}
                    Err(e @ ChannelError::InsufficientRights(_)) => {
                        let _ = write_frame(
                            &mut *write_half.lock().await,
                            &LinkFrame::Refused { reason: e.to_string() },
                        )
                        .await;
                    }
                    Err(e) => return Err(e.into()),
                }
            }
            Some(other) => {
                return Err(sandy_fabric_local::link::LinkError::Protocol(format!(
                    "unexpected {} frame from an attach client",
                    other.kind()
                ))
                .into());
            }
            None => return Ok(()), // clean close
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use anyhow::Context;
    use sandy_fabric::{
        capauth::{Cap, CapRights, CapScope, encode_cap},
        types::{ChannelId, PeerId},
    };
    use sandy_fabric_local::{LocalCapAuthority, SharedCapAuthority, inmem::InMem};
    use tokio::io::split;

    use super::*;
    use crate::dispatch;

    const WAIT: Duration = Duration::from_secs(5);

    type TestChannel = Arc<Channel<InMem, SharedCapAuthority>>;

    async fn test_channel(job_id: &str) -> anyhow::Result<(TestChannel, SharedCapAuthority)> {
        let authority = SharedCapAuthority::new(LocalCapAuthority::new(Duration::from_secs(3600))?);
        let channel = Channel::new(ChannelId::from(job_id), InMem::default(), authority.clone()).await?;
        Ok((Arc::new(channel), authority))
    }

    fn mint(authority: &SharedCapAuthority, job_id: &str, peer: &str, rights: CapRights) -> anyhow::Result<Cap> {
        Ok(authority.mint(CapScope {
            peer: PeerId::from(peer),
            channel: ChannelId::from(job_id),
            rights,
            expires_at: None,
        })?)
    }

    fn post_capable() -> CapRights {
        CapRights {
            post: true,
            read: true,
            invite: false,
        }
    }

    fn observer_only() -> CapRights {
        CapRights {
            post: false,
            read: true,
            invite: false,
        }
    }

    // ---- `relay` (the joined phase, membership already established) ----

    /// Positive, the core round trip (#327): a post-capable membership posts
    /// input that reaches the channel as `TTY_STDIN`, and `TTY_STDOUT` posted
    /// by ANOTHER membership (standing in for the real job's own agent) is
    /// delivered back over the attach connection.
    #[tokio::test]
    async fn a_post_capable_relay_round_trips_input_and_output() -> anyhow::Result<()> {
        let (channel, authority) = test_channel("job-1").await?;
        let agent_cap = mint(&authority, "job-1", "agent", post_capable())?;
        let agent = channel.join(&agent_cap)?;

        let attach_cap = mint(&authority, "job-1", "operator", post_capable())?;
        let attach_membership = channel.join(&attach_cap)?;

        let (client, server) = tokio::io::duplex(4096);
        let (mut client_rd, mut client_wr) = split(client);
        let (mut server_rd, server_wr) = split(server);
        let server_wr = Arc::new(AsyncMutex::new(server_wr));

        let channel_for_relay = Arc::clone(&channel);
        let relaying =
            tokio::spawn(
                async move { relay(channel_for_relay, attach_membership, &mut server_rd, server_wr, None).await },
            );

        write_frame(
            &mut client_wr,
            &LinkFrame::Post {
                content_type: TTY_STDIN.to_string(),
                payload: hex::encode(b"ls\n"),
                channel: None,
            },
        )
        .await?;

        let mut inbound = std::pin::pin!(channel.subscribe(&agent)?);
        let env = tokio::time::timeout(WAIT, inbound.next())
            .await
            .context("timed out waiting for the posted input")?
            .context("the channel stream ended")?
            .context("the channel stream faulted")?;
        assert_eq!(env.content_type, TTY_STDIN);
        assert_eq!(env.payload, b"ls\n");

        channel
            .post(
                &agent,
                Some(MessageType::Tty(Tty {})),
                TTY_STDOUT,
                b"total 0\n".to_vec(),
            )
            .await
            .context("post agent output")?;

        let delivered = tokio::time::timeout(WAIT, read_frame(&mut client_rd))
            .await
            .context("timed out waiting for delivered output")?
            .context("reading the delivered frame faulted")?
            .context("the connection closed before delivering output")?;
        match delivered {
            LinkFrame::Deliver {
                content_type, payload, ..
            } => {
                assert_eq!(content_type, TTY_STDOUT);
                assert_eq!(hex::decode(payload)?, b"total 0\n");
            }
            other => anyhow::bail!("expected a Deliver frame, got {other:?}"),
        }

        drop(client_wr);
        drop(client_rd);
        tokio::time::timeout(WAIT, relaying)
            .await
            .context("timed out waiting for the relay to end")??
            .context("the relay must end cleanly on a clean close")?;
        Ok(())
    }

    /// Epic #340 phase 2: a `Resize` frame from the attach client reaches
    /// the shared channel as a `Control`/`RESIZE_CONTROL` envelope the agent
    /// side can decode — a different wire shape from `TTY_STDIN`, proving
    /// the client-read loop's new arm posts it correctly rather than
    /// refusing it as an unexpected frame.
    #[tokio::test]
    async fn a_resize_frame_reaches_the_channel_as_a_control_envelope() -> anyhow::Result<()> {
        let (channel, authority) = test_channel("job-resize").await?;
        let agent_cap = mint(&authority, "job-resize", "agent", post_capable())?;
        let agent = channel.join(&agent_cap)?;
        let attach_cap = mint(&authority, "job-resize", "operator", post_capable())?;
        let attach_membership = channel.join(&attach_cap)?;

        let (client, server) = tokio::io::duplex(4096);
        let (client_rd, mut client_wr) = split(client);
        let (mut server_rd, server_wr) = split(server);
        let server_wr = Arc::new(AsyncMutex::new(server_wr));
        let channel_for_relay = Arc::clone(&channel);
        let relaying =
            tokio::spawn(
                async move { relay(channel_for_relay, attach_membership, &mut server_rd, server_wr, None).await },
            );

        write_frame(&mut client_wr, &LinkFrame::Resize { cols: 120, rows: 40 }).await?;

        let mut inbound = std::pin::pin!(channel.subscribe(&agent)?);
        let env = tokio::time::timeout(WAIT, inbound.next())
            .await
            .context("timed out waiting for the resize to reach the channel")?
            .context("the channel stream ended")?
            .context("the channel stream faulted")?;
        assert!(matches!(env.message_type, Some(MessageType::Control(_))), "got {env:?}");
        assert_eq!(env.content_type, RESIZE_CONTROL);
        assert_eq!(sandy_fabric_local::agent::decode_resize(&env.payload), Some((120, 40)));

        drop(client_wr);
        drop(client_rd);
        tokio::time::timeout(WAIT, relaying)
            .await
            .context("timed out waiting for the relay to end")??
            .context("the relay must end cleanly on a clean close")?;
        Ok(())
    }

    /// Epic #340 phase 2: an `Output`/`ARCHIVE_TRANSCRIPT` envelope posted
    /// onto the channel (standing in for the real agent's end-of-job
    /// archive post) is delivered to the attach client as a dedicated
    /// `Archive` frame, not folded into `Deliver` or silently dropped like
    /// any other non-TTY content would be.
    #[tokio::test]
    async fn an_archive_envelope_is_delivered_as_an_archive_frame() -> anyhow::Result<()> {
        let (channel, authority) = test_channel("job-archive").await?;
        let agent_cap = mint(&authority, "job-archive", "agent", post_capable())?;
        let agent = channel.join(&agent_cap)?;
        let attach_cap = mint(&authority, "job-archive", "operator", post_capable())?;
        let attach_membership = channel.join(&attach_cap)?;

        let (client, server) = tokio::io::duplex(4096);
        let (mut client_rd, client_wr) = split(client);
        let (mut server_rd, server_wr) = split(server);
        let server_wr = Arc::new(AsyncMutex::new(server_wr));
        let channel_for_relay = Arc::clone(&channel);
        let relaying =
            tokio::spawn(
                async move { relay(channel_for_relay, attach_membership, &mut server_rd, server_wr, None).await },
            );

        channel
            .post(
                &agent,
                Some(MessageType::Output(sandy_proto::Output {})),
                ARCHIVE_TRANSCRIPT,
                b"the whole transcript".to_vec(),
            )
            .await
            .context("post the archive envelope")?;

        let delivered = tokio::time::timeout(WAIT, read_frame(&mut client_rd))
            .await
            .context("timed out waiting for the archive delivery")?
            .context("reading the delivered frame faulted")?
            .context("the connection closed before delivering the archive")?;
        match delivered {
            LinkFrame::Archive { content_type, payload } => {
                assert_eq!(content_type, ARCHIVE_TRANSCRIPT);
                assert_eq!(hex::decode(payload)?, b"the whole transcript");
            }
            other => anyhow::bail!("expected an Archive frame, got {other:?}"),
        }

        drop(client_wr);
        drop(client_rd);
        tokio::time::timeout(WAIT, relaying)
            .await
            .context("timed out waiting for the relay to end")??
            .context("the relay must end cleanly on a clean close")?;
        Ok(())
    }

    /// Adversarial (#327's one new behavioral fork): an observer-only
    /// membership's posted input is refused at the channel layer, reported
    /// back as a `Refused` frame (not silently dropped), and never ends the
    /// relay or reaches another member.
    #[tokio::test]
    async fn an_observer_only_relay_reports_a_refused_post() -> anyhow::Result<()> {
        let (channel, authority) = test_channel("job-1").await?;
        let agent_cap = mint(&authority, "job-1", "agent", post_capable())?;
        let agent = channel.join(&agent_cap)?;

        let attach_cap = mint(&authority, "job-1", "observer", observer_only())?;
        let attach_membership = channel.join(&attach_cap)?;

        let (client, server) = tokio::io::duplex(4096);
        let (mut client_rd, mut client_wr) = split(client);
        let (mut server_rd, server_wr) = split(server);
        let server_wr = Arc::new(AsyncMutex::new(server_wr));

        let channel_for_relay = Arc::clone(&channel);
        let relaying =
            tokio::spawn(
                async move { relay(channel_for_relay, attach_membership, &mut server_rd, server_wr, None).await },
            );

        write_frame(
            &mut client_wr,
            &LinkFrame::Post {
                content_type: TTY_STDIN.to_string(),
                payload: hex::encode(b"should be refused"),
                channel: None,
            },
        )
        .await?;

        let refused = tokio::time::timeout(WAIT, read_frame(&mut client_rd))
            .await
            .context("timed out waiting for the refusal")?
            .context("reading the refusal faulted")?
            .context("the connection closed before refusing")?;
        assert!(matches!(refused, LinkFrame::Refused { .. }), "got {refused:?}");

        drop(client_wr);
        drop(client_rd);
        tokio::time::timeout(WAIT, relaying)
            .await
            .context("timed out waiting for the relay to end")??
            .context("a refused post must not end the relay in error")?;

        let mut inbound = std::pin::pin!(channel.subscribe(&agent)?);
        let nothing = tokio::time::timeout(Duration::from_millis(200), inbound.next()).await;
        assert!(nothing.is_err(), "a refused post must never reach the channel at all");
        Ok(())
    }

    /// Regression (#327, the Tty dedup fix): two IDENTICAL input chunks (the
    /// same keystroke or line typed twice) must BOTH reach the channel, not
    /// collapse to one stored entry.
    #[tokio::test]
    async fn two_identical_input_chunks_are_both_delivered() -> anyhow::Result<()> {
        let (channel, authority) = test_channel("job-1").await?;
        let agent_cap = mint(&authority, "job-1", "agent", post_capable())?;
        let agent = channel.join(&agent_cap)?;

        let attach_cap = mint(&authority, "job-1", "operator", post_capable())?;
        let attach_membership = channel.join(&attach_cap)?;

        let (client, server) = tokio::io::duplex(4096);
        let (client_rd, mut client_wr) = split(client);
        let (mut server_rd, server_wr) = split(server);
        let server_wr = Arc::new(AsyncMutex::new(server_wr));

        let channel_for_relay = Arc::clone(&channel);
        let relaying =
            tokio::spawn(
                async move { relay(channel_for_relay, attach_membership, &mut server_rd, server_wr, None).await },
            );

        for _ in 0..2 {
            write_frame(
                &mut client_wr,
                &LinkFrame::Post {
                    content_type: TTY_STDIN.to_string(),
                    payload: hex::encode(b"\n"),
                    channel: None,
                },
            )
            .await?;
        }

        let mut inbound = std::pin::pin!(channel.subscribe(&agent)?);
        let first = tokio::time::timeout(WAIT, inbound.next())
            .await
            .context("timed out on the first chunk")?
            .context("stream ended")?
            .context("stream faulted")?;
        let second = tokio::time::timeout(WAIT, inbound.next())
            .await
            .context("timed out on the second, identical chunk")?
            .context("stream ended before the second chunk arrived")?
            .context("stream faulted")?;
        assert_eq!(first.payload, b"\n");
        assert_eq!(second.payload, b"\n");
        assert_ne!(
            first.sequence, second.sequence,
            "two identical TTY posts must still be two distinct entries"
        );

        drop(client_wr);
        drop(client_rd);
        tokio::time::timeout(WAIT, relaying)
            .await
            .context("timed out waiting for the relay to end")??
            .context("relay must end cleanly")?;
        Ok(())
    }

    /// Positive: a clean close ends the relay AND leaves the channel
    /// membership — a later re-attach (a fresh connection, a fresh `Join`)
    /// finds no stale membership state left behind, proven here by a rejoin
    /// with the SAME cap seeing a cursor reset to 0 rather than resuming
    /// wherever the first session left off.
    #[tokio::test]
    async fn a_clean_close_leaves_the_membership() -> anyhow::Result<()> {
        let (channel, authority) = test_channel("job-1").await?;
        let attach_cap = mint(&authority, "job-1", "operator", post_capable())?;
        let first_membership = channel.join(&attach_cap)?;

        let (client, server) = tokio::io::duplex(4096);
        let (client_rd, client_wr) = split(client);
        let (mut server_rd, server_wr) = split(server);
        let server_wr = Arc::new(AsyncMutex::new(server_wr));

        let channel_for_relay = Arc::clone(&channel);
        let relaying =
            tokio::spawn(
                async move { relay(channel_for_relay, first_membership, &mut server_rd, server_wr, None).await },
            );

        drop(client_wr);
        drop(client_rd);
        tokio::time::timeout(WAIT, relaying)
            .await
            .context("timed out waiting for the relay to end")??
            .context("relay must end cleanly on a clean close")?;

        // Post one entry, THEN rejoin with the identical cap (same proof, same
        // MembershipId) and subscribe fresh: if `leave()` never ran, this
        // would resume at the old session's cursor and skip it; it must
        // instead start over from sequence 0 and see it.
        let agent_cap = mint(&authority, "job-1", "agent", post_capable())?;
        let agent = channel.join(&agent_cap)?;
        channel
            .post(
                &agent,
                Some(MessageType::Tty(Tty {})),
                TTY_STDOUT,
                b"after-close".to_vec(),
            )
            .await?;

        let rejoined = channel.join(&attach_cap)?;
        let mut stream = std::pin::pin!(channel.subscribe(&rejoined)?);
        let env = tokio::time::timeout(WAIT, stream.next())
            .await
            .context("timed out waiting for the rejoin to see history")?
            .context("stream ended")?
            .context("stream faulted")?;
        assert_eq!(
            env.payload, b"after-close",
            "a rejoin after the membership was left must resume from sequence 0, proving `leave()` ran"
        );
        Ok(())
    }

    // ---- `serve_one_attach` (the real wire handshake) ----

    async fn registry_with_job(job_id: &str) -> anyhow::Result<(Arc<JobRegistry>, Cap, Cap)> {
        let registry = Arc::new(JobRegistry::new()?);
        let job = dispatch::mint_job_channel(job_id, registry.authority()).await?;
        let agent_cap = job.agent_cap.clone();
        registry.insert(job_id.to_owned(), job);
        let operator_cap = registry.authority().mint(CapScope {
            peer: PeerId::from("operator"),
            channel: ChannelId::from(job_id),
            rights: post_capable(),
            expires_at: None,
        })?;
        Ok((registry, agent_cap, operator_cap))
    }

    /// Like [`registry_with_job`], but the job is recorded as placed on
    /// `host_id` (#340) — the fact [`notify_attach_state`] reads to decide
    /// which host-executor to notify.
    async fn registry_with_job_on_host(job_id: &str, host_id: &str) -> anyhow::Result<(Arc<JobRegistry>, Cap)> {
        let registry = Arc::new(JobRegistry::new()?);
        let mut job = dispatch::mint_job_channel(job_id, registry.authority()).await?;
        job.host_id = Some(host_id.to_owned());
        registry.insert(job_id.to_owned(), job);
        let operator_cap = registry.authority().mint(CapScope {
            peer: PeerId::from("operator"),
            channel: ChannelId::from(job_id),
            rights: post_capable(),
            expires_at: None,
        })?;
        Ok((registry, operator_cap))
    }

    /// Positive, end to end (#340): a real wire attach causes exactly one
    /// `AttachStateChanged { attached: true }` to reach the job's placed
    /// host-executor's queue, and the clean close that follows causes
    /// exactly one `{ attached: false }` — proving the 0→1/1→0 transition
    /// detection in `serve_one_attach` actually fires through the real
    /// `HostRegistry`, not just the lower-level `relay`/`Channel` pieces
    /// other tests in this module already cover.
    #[tokio::test]
    async fn a_real_attach_then_detach_notifies_the_jobs_placed_host() -> anyhow::Result<()> {
        use crate::host_registry::{ExecutorAllowlist, HostRegistry, Registration};

        let (registry, operator_cap) = registry_with_job_on_host("job-1", "ws01").await?;

        let host_registry = Arc::new(HostRegistry::default());
        let allowlist = ExecutorAllowlist::new([executor_ip()]);
        let Registration {
            mut attach_state_rx, ..
        } = host_registry
            .register(&allowlist, executor_ip(), "ws01".to_owned(), host_capabilities())
            .expect("ws01 must register");

        let (client, server) = tokio::net::UnixStream::pair()?;
        let accepting = {
            let registry = Arc::clone(&registry);
            let host_registry = Arc::clone(&host_registry);
            tokio::spawn(async move {
                serve_one_attach(server, registry, host_registry).await;
            })
        };

        let (mut client_rd, mut client_wr) = client.into_split();
        write_frame(
            &mut client_wr,
            &LinkFrame::Join {
                cap: hex::encode(encode_cap(&operator_cap)?),
                channel: None,
                cols: None,
                rows: None,
            },
        )
        .await?;
        let response = tokio::time::timeout(WAIT, read_frame(&mut client_rd))
            .await
            .context("timed out waiting for Joined")?
            .context("reading Joined faulted")?
            .context("closed before Joined")?;
        assert!(matches!(response, LinkFrame::Joined { .. }), "got {response:?}");

        let attached_true = tokio::time::timeout(WAIT, attach_state_rx.recv())
            .await
            .context("timed out waiting for AttachStateChanged{true}")?
            .context("attach_state_rx ended before the join notification")?;
        assert_eq!(attached_true.job_id, "job-1");
        assert!(attached_true.attached);

        drop(client_wr);
        drop(client_rd);
        tokio::time::timeout(WAIT, accepting)
            .await
            .context("timed out waiting for the relay to end")??;

        let attached_false = tokio::time::timeout(WAIT, attach_state_rx.recv())
            .await
            .context("timed out waiting for AttachStateChanged{false}")?
            .context("attach_state_rx ended before the leave notification")?;
        assert_eq!(attached_false.job_id, "job-1");
        assert!(!attached_false.attached);
        Ok(())
    }

    /// Regression (#340, CodeRabbit finding): the SANDBOX AGENT joining this
    /// job's channel — a real, separate join, from a real, separate code
    /// path, that happens as part of ordinary job execution regardless of
    /// whether anyone ever attaches — must never be conflated with an
    /// attach-client join. Before this fix, the transition check read
    /// `Channel::member_count()` directly, so with the agent already
    /// joined (count already 1), a real attach client's own join brought
    /// the count to 2, not 1, and the `count == 1` check that was supposed
    /// to fire `attached: true` never fired at all. Joining the agent FIRST
    /// here, before the attach client ever connects, is exactly the
    /// ordering that broke the old check.
    #[tokio::test]
    async fn an_already_joined_agent_never_suppresses_the_attach_notification() -> anyhow::Result<()> {
        use crate::host_registry::{ExecutorAllowlist, HostRegistry, Registration};

        let (registry, operator_cap) = registry_with_job_on_host("job-1", "ws01").await?;
        let agent_cap = registry
            .get("job-1")
            .context("the job must be registered")?
            .agent_cap
            .clone();
        // The agent joins first, exactly like the real dispatch path does
        // once the sandbox agent connects over its own link — independent
        // of, and well before, any attach client.
        registry
            .get("job-1")
            .context("the job must be registered")?
            .channel
            .join(&agent_cap)
            .context("the agent's own join must succeed")?;

        let host_registry = Arc::new(HostRegistry::default());
        let allowlist = ExecutorAllowlist::new([executor_ip()]);
        let Registration {
            mut attach_state_rx, ..
        } = host_registry
            .register(&allowlist, executor_ip(), "ws01".to_owned(), host_capabilities())
            .expect("ws01 must register");

        let (client, server) = tokio::net::UnixStream::pair()?;
        let accepting = {
            let registry = Arc::clone(&registry);
            let host_registry = Arc::clone(&host_registry);
            tokio::spawn(async move {
                serve_one_attach(server, registry, host_registry).await;
            })
        };

        let (mut client_rd, mut client_wr) = client.into_split();
        write_frame(
            &mut client_wr,
            &LinkFrame::Join {
                cap: hex::encode(encode_cap(&operator_cap)?),
                channel: None,
                cols: None,
                rows: None,
            },
        )
        .await?;
        let response = tokio::time::timeout(WAIT, read_frame(&mut client_rd))
            .await
            .context("timed out waiting for Joined")?
            .context("reading Joined faulted")?
            .context("closed before Joined")?;
        assert!(matches!(response, LinkFrame::Joined { .. }), "got {response:?}");

        // With the bug, this would time out: the agent's prior join already
        // put `member_count()` at 1, so the attach client's own join took
        // it to 2, never matching the old `count == 1` check.
        let attached_true = tokio::time::timeout(WAIT, attach_state_rx.recv())
            .await
            .context(
                "timed out waiting for AttachStateChanged{true} — the dedicated attach counter must fire this even \
                 with the agent already joined",
            )?
            .context("attach_state_rx ended before the join notification")?;
        assert_eq!(attached_true.job_id, "job-1");
        assert!(attached_true.attached);

        drop(client_wr);
        drop(client_rd);
        tokio::time::timeout(WAIT, accepting)
            .await
            .context("timed out waiting for the relay to end")??;
        Ok(())
    }

    /// Adversarial: a job that was never placed remotely (`host_id: None`,
    /// the default `registry_with_job` fixture every other test in this
    /// module uses) must never attempt an attach-state notification at all
    /// — there is no host-executor to notify, and `notify_attach_state`
    /// must return immediately rather than, say, panicking on a `None`
    /// unwrap or logging a confusing "no such host" for every local attach.
    #[tokio::test]
    async fn a_locally_run_jobs_attach_never_attempts_a_host_notification() -> anyhow::Result<()> {
        use crate::host_registry::HostRegistry;

        let (registry, _agent_cap, operator_cap) = registry_with_job("job-1").await?;
        let host_registry = Arc::new(HostRegistry::default());

        let (client, server) = tokio::net::UnixStream::pair()?;
        let accepting = {
            let registry = Arc::clone(&registry);
            let host_registry = Arc::clone(&host_registry);
            tokio::spawn(async move {
                serve_one_attach(server, registry, host_registry).await;
            })
        };

        let (mut client_rd, mut client_wr) = client.into_split();
        write_frame(
            &mut client_wr,
            &LinkFrame::Join {
                cap: hex::encode(encode_cap(&operator_cap)?),
                channel: None,
                cols: None,
                rows: None,
            },
        )
        .await?;
        let response = tokio::time::timeout(WAIT, read_frame(&mut client_rd))
            .await
            .context("timed out waiting for Joined")?
            .context("reading Joined faulted")?
            .context("closed before Joined")?;
        assert!(matches!(response, LinkFrame::Joined { .. }), "got {response:?}");

        drop(client_wr);
        drop(client_rd);
        tokio::time::timeout(WAIT, accepting).await??;
        // No assertion beyond "this didn't panic and ran to completion" —
        // there is no host registered at all, so any attempted notification
        // would have nowhere to go; the point is that none was attempted.
        Ok(())
    }

    fn executor_ip() -> std::net::IpAddr {
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(100, 64, 0, 7))
    }

    fn host_capabilities() -> sandy_executor_proto::Capabilities {
        sandy_executor_proto::Capabilities {
            supported_sandbox_kinds: vec![sandy_executor_proto::SandboxKind::Process.into()],
            arch: sandy_executor_proto::Arch::X8664.into(),
            attestation: false,
            supported_isolation_classes: vec![sandy_executor_proto::IsolationClass::Trusted.into()],
        }
    }

    /// Positive: presenting a real, validly-scoped cap over the real UDS
    /// handshake is admitted (`Joined`), not refused.
    #[tokio::test]
    async fn a_valid_presented_cap_is_admitted() -> anyhow::Result<()> {
        let (registry, _agent_cap, operator_cap) = registry_with_job("job-1").await?;
        let (client, server) = tokio::net::UnixStream::pair()?;

        let host_registry = Arc::new(HostRegistry::default());
        let accepting = tokio::spawn(async move {
            serve_one_attach(server, registry, host_registry).await;
        });

        let (mut client_rd, mut client_wr) = client.into_split();
        write_frame(
            &mut client_wr,
            &LinkFrame::Join {
                cap: hex::encode(encode_cap(&operator_cap)?),
                channel: None,
                cols: None,
                rows: None,
            },
        )
        .await?;

        let response = tokio::time::timeout(WAIT, read_frame(&mut client_rd))
            .await
            .context("timed out waiting for the handshake response")?
            .context("reading the handshake response faulted")?
            .context("the connection closed before answering the handshake")?;
        assert!(matches!(response, LinkFrame::Joined { .. }), "got {response:?}");

        drop(client_wr);
        drop(client_rd);
        tokio::time::timeout(WAIT, accepting).await??;
        Ok(())
    }

    /// Adversarial: a cap scoped to a job id that was never submitted is
    /// refused by name, zero bytes written before the refusal — mirrors
    /// `mesh_accept`'s own "unknown id" discipline.
    #[tokio::test]
    async fn a_cap_for_an_unknown_job_is_refused() -> anyhow::Result<()> {
        let registry = Arc::new(JobRegistry::new()?);
        let ghost_cap = registry.authority().mint(CapScope {
            peer: PeerId::from("operator"),
            channel: ChannelId::from("never-submitted"),
            rights: post_capable(),
            expires_at: None,
        })?;
        let (client, server) = tokio::net::UnixStream::pair()?;

        let host_registry = Arc::new(HostRegistry::default());
        let accepting = tokio::spawn(async move {
            serve_one_attach(server, registry, host_registry).await;
        });

        let (mut client_rd, mut client_wr) = client.into_split();
        write_frame(
            &mut client_wr,
            &LinkFrame::Join {
                cap: hex::encode(encode_cap(&ghost_cap)?),
                channel: None,
                cols: None,
                rows: None,
            },
        )
        .await?;

        let response = tokio::time::timeout(WAIT, read_frame(&mut client_rd))
            .await
            .context("timed out waiting for the refusal")?
            .context("reading the refusal faulted")?
            .context("the connection closed before refusing")?;
        assert!(matches!(response, LinkFrame::Refused { .. }), "got {response:?}");

        drop(client_wr);
        drop(client_rd);
        tokio::time::timeout(WAIT, accepting).await??;
        Ok(())
    }

    /// Adversarial: an expired cap routes correctly to its real job (the
    /// pre-verification `scope().channel` lookup finds it) but is still
    /// refused — by `Channel::join`'s own authority re-verification, not the
    /// routing step, which is never trusted as the actual authorization.
    #[tokio::test]
    async fn an_expired_cap_routes_correctly_but_is_refused_by_join_verification() -> anyhow::Result<()> {
        let (registry, _agent_cap, _operator_cap) = registry_with_job("job-1").await?;
        let wrong_job_cap = registry.authority().mint(CapScope {
            peer: PeerId::from("operator"),
            channel: ChannelId::from("job-1"),
            rights: post_capable(),
            expires_at: Some(0), // already expired -> CapError::Expired at verify time
        })?;
        let (client, server) = tokio::net::UnixStream::pair()?;

        let host_registry = Arc::new(HostRegistry::default());
        let accepting = tokio::spawn(async move {
            serve_one_attach(server, registry, host_registry).await;
        });

        let (mut client_rd, mut client_wr) = client.into_split();
        write_frame(
            &mut client_wr,
            &LinkFrame::Join {
                cap: hex::encode(encode_cap(&wrong_job_cap)?),
                channel: None,
                cols: None,
                rows: None,
            },
        )
        .await?;

        let response = tokio::time::timeout(WAIT, read_frame(&mut client_rd))
            .await
            .context("timed out waiting for the refusal")?
            .context("reading the refusal faulted")?
            .context("the connection closed before refusing")?;
        assert!(matches!(response, LinkFrame::Refused { .. }), "got {response:?}");

        drop(client_wr);
        drop(client_rd);
        tokio::time::timeout(WAIT, accepting).await??;
        Ok(())
    }
}
