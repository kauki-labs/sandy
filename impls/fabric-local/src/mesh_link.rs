//! Forwarding one agent link across a mesh connection (#159): the
//! executor-host side of #216's agent-link relay when the agent is not on
//! the same machine as the orchestrator that holds its `Channel`.
//!
//! [`serve_agent_link`](crate::link::serve_agent_link) always runs on the
//! orchestrator, over whatever stream reaches it — it never knows whether
//! that stream is local or crossed a mesh. [`forward_agent_link`] is the
//! executor-host counterpart: it pipes `local` (the agent's own link end) to
//! and from `remote` (an already-authenticated connection to the
//! orchestrator, e.g. a `sandy-conn` TCP stream over the mesh), independently
//! parsing the agent→orchestrator direction to resolve its own
//! [`ForwardedVerdict`] from the agent's `Exit` frame. The executor learns
//! the job's outcome directly from the agent, without waiting on a round
//! trip back from the orchestrator's own relay (`VERDICT_GRACE` in
//! `sandy-impls-local` only has to absorb a busy local relay, not a mesh
//! hop).

use std::net::SocketAddr;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::link::{LinkError, LinkFrame, read_frame, write_frame};

/// What [`forward_agent_link`] concluded about the agent's run, from its own
/// frames on this host — never from watching `remote` close, which only
/// tells this side that the orchestrator is done, not what it decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForwardedVerdict {
    /// The agent reported the job's exit code.
    JobExited(i32),
    /// The agent failed: the remote refused the link before any frame
    /// arrived, the agent closed its own link without reporting, or either
    /// direction faulted. `why` is for diagnostics, never a forged success.
    AgentFailed(String),
}

/// Pipe one agent link over `remote`, writing `prefix` first.
///
/// `prefix` is opaque to this function: a dispatch-protocol detail (a run
/// id, an authorization token, both) the caller encodes. It is written once,
/// before any [`LinkFrame`] flows, and this function treats a failure to
/// write it as the only case worth propagating as an [`LinkError`] — nothing
/// meaningful has happened yet, so there is no verdict to return instead.
///
/// Every frame after that forwards in both directions unconditionally: the
/// orchestrator's `serve_agent_link` still runs every real cap/membership
/// check on its own copy of the frames arriving over `remote`. This
/// function's own [`ForwardedVerdict`] is a local, faster-available echo of
/// that same outcome — read from the agent's own `Exit` frame, or its
/// absence, on `local` alone. It is never substituted for the
/// orchestrator's authoritative channel state; it exists so the executor
/// host's own backend (`AgentReport`) does not have to wait on a mesh round
/// trip to learn a job it ran has finished.
///
/// A remote that refuses the link outright (closes with zero frames ever
/// sent, per #159's run-identity check running before any frame is written)
/// forwards nothing to `local`: the agent observes a bare close, the same as
/// it would from a crashed relay, and gives up on its own. That unfolds here
/// as `local`'s own read reaching EOF without an `Exit` ever having been
/// seen, resolving [`ForwardedVerdict::AgentFailed`] with no special case
/// needed for "refused" versus "the agent gave up for any other reason" —
/// both are, correctly, the same outcome from the executor's point of view.
///
/// Each direction half-closes (`shutdown`) once its source reaches EOF, so
/// the other side is never left waiting past its own natural end. The
/// orchestrator→agent direction runs for the link's own remaining lifetime
/// on a spawned task, independent of this function's return: the agent may
/// still have orchestrator traffic in flight (TTY stdin, a late `Refused`)
/// after its own verdict is already known locally, and this function must
/// never block its own return on that traffic ever arriving or ending —
/// that would defeat the entire point of resolving the verdict locally
/// instead of waiting on the orchestrator.
///
/// # Errors
/// [`LinkError::Io`] if writing `prefix` itself fails.
pub async fn forward_agent_link<L, R>(local: L, remote: R, prefix: &[u8]) -> Result<ForwardedVerdict, LinkError>
where
    L: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    R: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    forward_agent_link_bounded(local, remote, prefix, REVERSE_PIPE_GRACE).await
}

/// How long the orchestrator->agent reverse pipe may keep running after
/// [`forward_agent_link`]'s own verdict is already known, before it's
/// aborted (#289 item 4). `reverse.detach()` used to let it run for as long
/// as the orchestrator's connection stayed open, unconditionally — a hung,
/// or merely slow-to-close, orchestrator leaked the task, its mesh socket,
/// and the agent's own link end for the rest of the process's life.
/// Generous relative to ordinary trailing traffic (a late TTY resize, a few
/// more stdin bytes already in flight when the agent exits) but bounded,
/// the same scale as this crate's other connection timeouts (`DIAL_TIMEOUT`
/// above, `sandyd::host_conn::DISPATCH_WRITE_TIMEOUT`).
const REVERSE_PIPE_GRACE: std::time::Duration = std::time::Duration::from_secs(30);

/// [`forward_agent_link`]'s real body, with the reverse-pipe grace period
/// injectable so a test can prove the bound deterministically and quickly
/// rather than waiting out the real production value — AGENTS.md flags
/// pairing a virtual (`start_paused`) clock with genuine I/O as flaky, and
/// this function's reads/writes are real duplex/socket I/O, so a short REAL
/// duration here is what keeps the test both fast and reliable.
async fn forward_agent_link_bounded<L, R>(
    local: L,
    remote: R,
    prefix: &[u8],
    reverse_grace: std::time::Duration,
) -> Result<ForwardedVerdict, LinkError>
where
    L: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    R: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let (mut local_rd, local_wr) = tokio::io::split(local);
    let (remote_rd, mut remote_wr) = tokio::io::split(remote);

    remote_wr.write_all(prefix).await?;
    remote_wr.flush().await?;

    // Aborts the reverse-pipe task if this function's own future is dropped
    // before returning normally (a caller's timeout, the run being killed):
    // without this, a cancelled forward_agent_link would leak the spawned
    // task and leave the orchestrator never seeing EOF on this side. Reaching
    // the end of this function calls `detach()`, which disarms the abort —
    // the whole point of spawning it is for it to keep running past this
    // function's own return on the ordinary path.
    let reverse = AbortOnDrop(Some(tokio::spawn(forward_orchestrator_to_agent(remote_rd, local_wr))));

    // agent (local) -> orchestrator (remote): the only direction this
    // function inspects for its own verdict.
    let verdict = loop {
        match read_frame(&mut local_rd).await {
            Ok(Some(frame)) => {
                let exit_code = match &frame {
                    LinkFrame::Exit { code } => Some(*code),
                    _ => None,
                };
                if let Err(e) = write_frame(&mut remote_wr, &frame).await {
                    break ForwardedVerdict::AgentFailed(format!("forwarding to the orchestrator failed: {e}"));
                }
                if let Some(code) = exit_code {
                    break ForwardedVerdict::JobExited(code);
                }
            }
            Ok(None) => {
                break ForwardedVerdict::AgentFailed("the agent closed its link without reporting an exit".to_string());
            }
            Err(e) => break ForwardedVerdict::AgentFailed(format!("reading the agent's link failed: {e}")),
        }
    };
    let _ = remote_wr.shutdown().await;
    // #289 item 4: bound the reverse pipe from here rather than detaching it
    // unconditionally — a supervising task owns the wait, so THIS function's
    // own return stays exactly as unblocked by the reverse pipe's lifetime
    // as the module doc above promises; only the supervisor, not this
    // function's caller, ever waits out `reverse_grace`.
    if let Some(mut handle) = reverse.detach() {
        tokio::spawn(async move {
            if tokio::time::timeout(reverse_grace, &mut handle).await.is_err() {
                tracing::warn!(
                    "the orchestrator->agent reverse pipe exceeded its grace period after the agent's own exit; \
                     aborting it rather than leaking the task and its mesh socket forever"
                );
                handle.abort();
            }
        });
    }
    Ok(verdict)
}

/// Orchestrator (remote) -> agent (local): a dumb pipe, but still framed
/// rather than a raw byte copy, so a partial frame is never forwarded.
/// Spawned so it outlives [`forward_agent_link`]'s own return.
async fn forward_orchestrator_to_agent<R, W>(mut remote_rd: R, mut local_wr: W)
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    while let Ok(Some(frame)) = read_frame(&mut remote_rd).await {
        if write_frame(&mut local_wr, &frame).await.is_err() {
            break;
        }
    }
    let _ = local_wr.shutdown().await;
}

/// Aborts its wrapped task on drop unless [`detach`](Self::detach) already
/// took the handle. Ties the reverse-pipe task's lifetime to
/// [`forward_agent_link`]'s own future: if that future is dropped before
/// returning (a caller's timeout, the run being killed), this guard's own
/// drop fires and aborts the still-running task, instead of leaking it and
/// its open stream half forever.
struct AbortOnDrop(Option<tokio::task::JoinHandle<()>>);

impl AbortOnDrop {
    /// Let the wrapped task keep running past this guard's own drop — the
    /// ordinary path, once `forward_agent_link` has its verdict and the
    /// reverse pipe may still have orchestrator traffic to deliver. Returns
    /// the handle (rather than discarding it) so the caller can still bound
    /// the detached task's lifetime itself (#289 item 4) instead of either
    /// aborting it immediately or losing track of it forever.
    fn detach(mut self) -> Option<tokio::task::JoinHandle<()>> {
        self.0.take()
    }
}

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        if let Some(handle) = self.0.take() {
            handle.abort();
        }
    }
}

/// A [`dial_and_forward`] failure: dialing the orchestrator, or the link
/// itself once dialed.
#[derive(Debug, thiserror::Error)]
pub enum DialAndForwardError {
    /// Dialing the orchestrator's mesh address failed.
    #[error("dialing the orchestrator: {0}")]
    Dial(#[from] sandy_conn::ConnError),
    /// The link itself failed — see [`forward_agent_link`].
    #[error("agent link: {0}")]
    Link(#[from] LinkError),
}

/// The executor-host entry point for #159's cross-machine hop: dial the
/// orchestrator's mesh address, hand the connection and `prefix` to
/// [`forward_agent_link`] along with `local` (the agent's own link end).
///
/// `prefix` is opaque here too, same as in [`forward_agent_link`] — the
/// run-id+token encoding and its enforcement are the orchestrator's accept
/// loop's concern (decision 6), not this function's.
///
/// # Errors
/// [`DialAndForwardError::Dial`] if the mesh dial itself fails (the
/// orchestrator is unreachable, refuses the TCP connection, …);
/// [`DialAndForwardError::Link`] for any failure inside the link once
/// dialed — though in the ordinary run of things `forward_agent_link`
/// resolves a [`ForwardedVerdict`] rather than erroring, see its own docs.
pub async fn dial_and_forward<L>(
    orchestrator: SocketAddr,
    local: L,
    prefix: &[u8],
) -> Result<ForwardedVerdict, DialAndForwardError>
where
    L: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    // Bounded: an orchestrator that's unreachable (down, firewalled, a
    // routing black hole on the mesh) must not hang this dial forever — the
    // caller (relay_agent_link's spawned task) has a report to deliver, and
    // an indefinite hang here would silently withhold it.
    //
    // Keepalive-tuned (#289 item 4): once dialed, a vanished orchestrator
    // (power cut, partition) would otherwise leave this side holding a
    // half-open connection the kernel still reports as open — the same
    // `HALF_OPEN_DETECTION` profile decision 16 already applies to
    // `sandyd`'s own dial/accept of the management channel.
    let remote = tokio::time::timeout(
        DIAL_TIMEOUT,
        sandy_conn::connect_tcp_keepalive(orchestrator, sandy_conn::TcpKeepalive::HALF_OPEN_DETECTION),
    )
    .await
    .map_err(|_| {
        DialAndForwardError::Dial(sandy_conn::ConnError::Io(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!("dialing {orchestrator} timed out after {DIAL_TIMEOUT:?}"),
        )))
    })??;
    Ok(forward_agent_link(local, remote, prefix).await?)
}

/// How long [`dial_and_forward`] waits for the mesh dial to the orchestrator
/// before giving up. Generous relative to mesh RTT (this is a TCP connect on
/// an already-authenticated WireGuard mesh, not a public-internet dial), but
/// bounded — an indefinitely hanging dial would never resolve the
/// `AgentReport` it owes the backend.
const DIAL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Relay one [`AgentLaunch::on_link`](sandy_api::agent::AgentLaunch) call to the
/// orchestrator over the mesh: the executor-host side of #269's stage-1
/// cross-machine dispatch, and the one place [`dial_and_forward`] meets
/// `sandy-api`'s agent-launch contract.
///
/// `OnLink` itself is sync and runs on whatever thread the backend's `run`
/// call is on, with **no ambient async runtime** — its own doc says so
/// explicitly: "no async runtime guaranteed... must not block." So this
/// function never awaits anything itself; it spawns the whole relay onto
/// `rt` (a [`tokio::runtime::Handle`] the caller must capture in an async
/// context before entering the `on_link` closure) and returns immediately,
/// exactly the "start the relay elsewhere and return" `OnLink` asks for.
///
/// `report` moves into the spawned task and is consumed exactly once there,
/// on every path: [`AgentReport::job_exited`] on
/// [`ForwardedVerdict::JobExited`], [`AgentReport::agent_failed`] on
/// [`ForwardedVerdict::AgentFailed`] or on a dial/link-conversion failure.
/// `AgentReport` wraps a capacity-1 channel, so none of these sends can
/// block. A `report` that never gets called (this function panicking before
/// spawning) disconnects the backend's receiver and surfaces as an infra
/// fault with no reason attached — by the type's own design, not something
/// this function tries to paper over; reached only if `rt.spawn` itself
/// panics, which means the runtime is already gone.
///
/// Reusable rather than inlined in any one backend's receive path: #269's
/// own design note is that no production `on_link` wiring exists yet, even
/// for the local case (#115's e2e test drives the agent library directly,
/// bypassing `on_link` entirely) — a local backend wiring up `on_link`
/// later for its own reasons can reuse this exact relay, not a inherit a
/// one-off built only for the remote path.
///
/// `control` bounds the whole relay, not just the dial (`dial_and_forward`'s
/// own `DIAL_TIMEOUT` already bounds connecting): a connected-but-silent
/// orchestrator — one that accepts the TCP connection and then never reads or
/// writes again — would otherwise hang `forward_agent_link`'s writes
/// indefinitely, leaking this task, the mesh socket, and the agent's link end
/// forever (CodeRabbit finding on #284; architect ruling, infra-f3, #289.4:
/// bound it here, at the call site that actually enters a long-lived loop,
/// against the job's own wall-clock rather than inside `dial_and_forward`
/// itself).
///
/// Unlike the original flat timeout, `control` is a LIVE handle (#340's
/// "unlimited while attached" policy, CodeRabbit on #344): the relay ends the
/// moment [`RunControl::is_cancelled`] is true, or the moment
/// [`RunControl::timed_out`] is — which, while the same job is attached and
/// its deadline suspended, never happens, so an attached job's relay is
/// exactly as unbounded as the job itself. The relay re-checks `control` on a
/// short interval rather than awaiting a single fixed instant, since a
/// suspended-then-reinstated deadline has nothing to await on directly — the
/// same polling discipline `impls/local/src/process.rs`'s own poll loop uses
/// for the identical reason.
pub fn relay_agent_link(
    rt: &tokio::runtime::Handle,
    forward_back: SocketAddr,
    host_end: std::os::fd::OwnedFd,
    prefix: Vec<u8>,
    report: sandy_api::agent::AgentReport,
    control: sandy_api::backend::RunControl,
) {
    rt.spawn(async move {
        let link = match owned_fd_into_unix_stream(host_end) {
            Ok(link) => link,
            Err(e) => {
                report.agent_failed(format!("converting the agent link fd: {e}"));
                return;
            }
        };
        tokio::select! {
            result = dial_and_forward(forward_back, link, &prefix) => {
                match result {
                    Ok(ForwardedVerdict::JobExited(code)) => report.job_exited(code),
                    Ok(ForwardedVerdict::AgentFailed(reason)) => report.agent_failed(reason),
                    // DialAndForwardError's own Display already names what
                    // failed ("dialing the orchestrator: ..." or "agent
                    // link: ..."); wrapping it again here would duplicate
                    // that prefix.
                    Err(e) => report.agent_failed(e.to_string()),
                }
            }
            reason = control_ended(&control) => {
                report.agent_failed(match reason {
                    ControlEndedReason::Cancelled => {
                        "the run was cancelled while the mesh relay was still in flight".to_owned()
                    }
                    ControlEndedReason::DeadlinePassed => "the mesh relay exceeded the job's deadline".to_owned(),
                });
            }
        }
    });
}

/// How often [`control_ended`] re-checks a [`RunControl`] it has no way to
/// await directly — a suspended deadline may be reinstated, or cancellation
/// may fire, at any moment with no notification. Coarse relative to
/// `impls/local/src/process.rs`'s 10ms poll: that loop also has to notice a
/// process's own exit promptly, this one only has to notice a deadline or
/// cancellation measured in whole seconds at the finest.
const CONTROL_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(250);

/// Why [`control_ended`] resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ControlEndedReason {
    /// [`RunControl::cancel`] was called.
    Cancelled,
    /// [`RunControl::timed_out`] became true (an active, non-suspended
    /// deadline passed).
    DeadlinePassed,
}

/// Resolves once `control` is cancelled or its live deadline has passed.
/// Never resolves while `control` is both un-cancelled and suspended
/// (`deadline() == None`) — exactly the "unlimited while attached" state.
async fn control_ended(control: &sandy_api::backend::RunControl) -> ControlEndedReason {
    loop {
        if control.is_cancelled() {
            return ControlEndedReason::Cancelled;
        }
        if control.timed_out() {
            return ControlEndedReason::DeadlinePassed;
        }
        tokio::time::sleep(CONTROL_POLL_INTERVAL).await;
    }
}

/// The relay side of the same fd-to-async-stream conversion
/// `impls/agent/src/main.rs`'s `claim_link` does on the agent side: take
/// ownership of a raw Unix-socket fd, mark it non-blocking (required before
/// tokio can drive it), and hand it to tokio's reactor.
fn owned_fd_into_unix_stream(fd: std::os::fd::OwnedFd) -> std::io::Result<tokio::net::UnixStream> {
    let std_stream = std::os::unix::net::UnixStream::from(fd);
    std_stream.set_nonblocking(true)?;
    tokio::net::UnixStream::from_std(std_stream)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use anyhow::Context;
    use sandy_conn::ConnAddr;
    use tokio::io::AsyncReadExt;

    use super::*;

    const PREFIX: &[u8] = b"run-7:token-bytes";

    /// Reads exactly `prefix.len()` bytes and asserts they match — the first
    /// thing any peer of [`forward_agent_link`] must see on `remote`.
    async fn expect_prefix(remote_side: &mut (impl AsyncRead + Unpin), prefix: &[u8]) -> anyhow::Result<()> {
        let mut buf = vec![0u8; prefix.len()];
        remote_side.read_exact(&mut buf).await.context("read prefix")?;
        assert_eq!(buf, prefix, "the prefix must be written before any LinkFrame");
        Ok(())
    }

    #[tokio::test]
    async fn the_agents_exit_frame_resolves_job_exited_and_still_forwards() -> anyhow::Result<()> {
        let (local_conn, mut agent_side) = tokio::io::duplex(4096);
        let (remote_conn, mut orchestrator_side) = tokio::io::duplex(4096);

        let forwarder = tokio::spawn(forward_agent_link(local_conn, remote_conn, PREFIX));

        expect_prefix(&mut orchestrator_side, PREFIX).await?;

        // Orchestrator -> agent: a Cap frame must reach the agent unchanged.
        write_frame(
            &mut orchestrator_side,
            &LinkFrame::Cap {
                cap: "deadbeef".to_string(),
                channel: None,
                peers: 0,
            },
        )
        .await?;
        let forwarded_cap = read_frame(&mut agent_side)
            .await?
            .context("agent should see the Cap frame")?;
        assert_eq!(
            forwarded_cap,
            LinkFrame::Cap {
                cap: "deadbeef".to_string(),
                channel: None,
                peers: 0,
            }
        );

        // Agent -> orchestrator: Join, then Exit.
        write_frame(
            &mut agent_side,
            &LinkFrame::Join {
                cap: "deadbeef".to_string(),
                channel: None,
                cols: None,
                rows: None,
            },
        )
        .await?;
        let forwarded_join = read_frame(&mut orchestrator_side)
            .await?
            .context("orchestrator should see Join")?;
        assert_eq!(
            forwarded_join,
            LinkFrame::Join {
                cap: "deadbeef".to_string(),
                channel: None,
                cols: None,
                rows: None,
            }
        );

        write_frame(&mut agent_side, &LinkFrame::Exit { code: 7 }).await?;
        let forwarded_exit = read_frame(&mut orchestrator_side)
            .await?
            .context("orchestrator should see Exit")?;
        assert_eq!(forwarded_exit, LinkFrame::Exit { code: 7 });

        let verdict = tokio::time::timeout(Duration::from_secs(2), forwarder)
            .await
            .context("forward_agent_link did not resolve after Exit")?
            .context("forwarder task panicked")??;
        assert_eq!(verdict, ForwardedVerdict::JobExited(7));
        Ok(())
    }

    #[tokio::test]
    async fn the_agent_closing_without_an_exit_resolves_agent_failed() -> anyhow::Result<()> {
        let (local_conn, agent_side) = tokio::io::duplex(4096);
        let (remote_conn, mut orchestrator_side) = tokio::io::duplex(4096);

        let forwarder = tokio::spawn(forward_agent_link(local_conn, remote_conn, PREFIX));
        expect_prefix(&mut orchestrator_side, PREFIX).await?;

        // The agent vanishes (crash, kill) without ever sending Exit.
        drop(agent_side);

        let verdict = tokio::time::timeout(Duration::from_secs(2), forwarder)
            .await
            .context("forward_agent_link did not resolve after the agent vanished")?
            .context("forwarder task panicked")??;
        assert!(
            matches!(verdict, ForwardedVerdict::AgentFailed(_)),
            "an agent that never reports an exit must never resolve as success: got {verdict:?}"
        );
        Ok(())
    }

    /// The acceptance test infra-f3/sandy-73 required: a remote that refuses
    /// the link (closes with zero frames, per #159's identity check running
    /// before any frame is written) must forward NOTHING to the agent and
    /// still resolve `AgentFailed`, never a forged success.
    #[tokio::test]
    async fn a_remote_refusal_forwards_nothing_and_resolves_agent_failed() -> anyhow::Result<()> {
        let (local_conn, mut agent_side) = tokio::io::duplex(4096);
        let (remote_conn, mut orchestrator_side) = tokio::io::duplex(4096);

        let forwarder = tokio::spawn(forward_agent_link(local_conn, remote_conn, PREFIX));
        expect_prefix(&mut orchestrator_side, PREFIX).await?;

        // Refused: the orchestrator closes immediately, writing nothing at
        // all (not even a Refused frame — per the hard requirement, a wrong
        // peer/token never sees the cap written, and writes zero bytes back).
        drop(orchestrator_side);

        // The agent must never receive anything: not a byte, not a frame.
        let mut buf = [0u8; 1];
        let saw_bytes = tokio::time::timeout(Duration::from_millis(200), agent_side.read(&mut buf)).await;
        match saw_bytes {
            Ok(Ok(0)) => {} // EOF: correct, nothing was ever sent.
            Ok(Ok(n)) => panic!("the agent must see zero bytes on a refused link, got {n}"),
            Ok(Err(e)) => return Err(e).context("unexpected read error on the agent side"),
            Err(_) => panic!("the agent's read neither produced data nor EOF within the timeout"),
        }

        // A real agent process, seeing EOF before ever getting its Cap, gives
        // up and exits, closing its own end of the link — simulated here so
        // forward_agent_link's own read of `local` also reaches EOF.
        drop(agent_side);

        let verdict = tokio::time::timeout(Duration::from_secs(2), forwarder)
            .await
            .context("forward_agent_link did not resolve after the refusal")?
            .context("forwarder task panicked")??;
        assert!(
            matches!(verdict, ForwardedVerdict::AgentFailed(_)),
            "a refused link must never resolve as success: got {verdict:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn writing_the_prefix_propagates_a_hard_write_failure() -> anyhow::Result<()> {
        let (local_conn, _agent_side) = tokio::io::duplex(4096);
        let (remote_conn, orchestrator_side) = tokio::io::duplex(4096);
        // Dropped before anything is written: the very first write_all(prefix)
        // must fail, since nothing meaningful has happened yet to resolve a
        // verdict instead.
        drop(orchestrator_side);

        let result = forward_agent_link(local_conn, remote_conn, PREFIX).await;
        assert!(
            result.is_err(),
            "a dead remote before the prefix write must propagate an error, not a verdict"
        );
        Ok(())
    }

    /// CodeRabbit's finding on the first version of this function: the
    /// spawned reverse-pipe task wasn't tied to `forward_agent_link`'s own
    /// future, so cancelling it (a caller's timeout, the run being killed)
    /// leaked the task and left the orchestrator's connection dangling
    /// indefinitely instead of seeing it close.
    #[tokio::test]
    async fn dropping_the_forwarder_mid_link_lets_the_orchestrator_see_eof() -> anyhow::Result<()> {
        let (local_conn, _agent_side) = tokio::io::duplex(4096);
        let (remote_conn, mut orchestrator_side) = tokio::io::duplex(4096);

        let forwarder = tokio::spawn(forward_agent_link(local_conn, remote_conn, PREFIX));
        expect_prefix(&mut orchestrator_side, PREFIX).await?;

        // Cancel mid-link: no verdict has been reached, the agent is still
        // sitting there, nothing has closed on its own yet.
        forwarder.abort();

        let mut buf = [0u8; 1];
        let saw_eof = tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                match orchestrator_side.read(&mut buf).await {
                    Ok(0) => return true,
                    Ok(_) => continue,
                    Err(_) => return true,
                }
            }
        })
        .await
        .context("orchestrator never observed EOF after the forwarder was cancelled")?;
        assert!(
            saw_eof,
            "a cancelled forward_agent_link must close the orchestrator's connection, not leak it"
        );
        Ok(())
    }

    /// Regression (#289 item 4): once the agent's own verdict is known, the
    /// orchestrator->agent reverse pipe must not run forever just because the
    /// orchestrator stays connected but silent (never sends EOF) — it must
    /// be aborted after its grace period, closing the agent's own link
    /// rather than leaking the task and the mesh socket for good. Drives the
    /// real abort-after-grace mechanism via `forward_agent_link_bounded`
    /// with a short real grace (not `start_paused`, per AGENTS.md: a virtual
    /// clock paired with genuine duplex I/O is flaky) and observes the
    /// agent's own side reaching EOF once it fires — not just that
    /// `forward_agent_link` itself resolved, which it already does well
    /// before the reverse pipe's fate is decided.
    #[tokio::test]
    async fn the_reverse_pipe_is_aborted_after_its_grace_period_against_a_silent_orchestrator() -> anyhow::Result<()> {
        const SHORT_GRACE: Duration = Duration::from_millis(100);

        let (local_conn, mut agent_side) = tokio::io::duplex(4096);
        let (remote_conn, mut orchestrator_side) = tokio::io::duplex(4096);

        let forwarder = tokio::spawn(forward_agent_link_bounded(local_conn, remote_conn, PREFIX, SHORT_GRACE));
        expect_prefix(&mut orchestrator_side, PREFIX).await?;

        write_frame(&mut agent_side, &LinkFrame::Exit { code: 0 }).await?;
        let forwarded_exit = read_frame(&mut orchestrator_side)
            .await?
            .context("orchestrator should see Exit")?;
        assert_eq!(forwarded_exit, LinkFrame::Exit { code: 0 });

        let verdict = tokio::time::timeout(Duration::from_secs(2), forwarder)
            .await
            .context("forward_agent_link_bounded did not resolve after Exit")?
            .context("forwarder task panicked")??;
        assert_eq!(verdict, ForwardedVerdict::JobExited(0));

        // The orchestrator never closes its side from here on — exactly the
        // hung/silent peer this bound exists for. Without it, the next read
        // would hang for the test's whole timeout rather than observing EOF.
        let mut buf = [0u8; 1];
        let n = tokio::time::timeout(Duration::from_secs(5), agent_side.read(&mut buf))
            .await
            .context(
                "the reverse pipe must be aborted (closing the agent's own link) once its grace period elapses, not \
                 hang forever against a silent orchestrator",
            )?
            .context("reading the agent's side after the reverse pipe's abort")?;
        assert_eq!(
            n, 0,
            "the agent's link must observe EOF once the unbounded reverse pipe is aborted"
        );

        drop(orchestrator_side);
        Ok(())
    }

    /// The real executor-side entry point, over an actual TCP dial (not an
    /// in-memory duplex pair, unlike the tests above) — the first test
    /// proving the TCP tier and `forward_agent_link` compose end to end, the
    /// way the real macOS↔WS01 hop will.
    #[tokio::test]
    async fn dial_and_forward_resolves_job_exited_over_a_real_tcp_dial() -> anyhow::Result<()> {
        let listener = sandy_conn::listen(&ConnAddr::Tcp("127.0.0.1:0".parse()?))
            .await
            .context("listen")?;
        let orchestrator_addr = listener.local_addr().context("local_addr")?;

        let orchestrator = tokio::spawn(async move {
            let (mut orchestrator_side, _peer) = listener.accept().await?;
            expect_prefix(&mut orchestrator_side, PREFIX).await?;
            write_frame(
                &mut orchestrator_side,
                &LinkFrame::Cap {
                    cap: "deadbeef".to_string(),
                    channel: None,
                    peers: 0,
                },
            )
            .await?;
            read_frame(&mut orchestrator_side).await?.context("expected Join")?;
            read_frame(&mut orchestrator_side).await?.context("expected Exit")?;
            Ok::<_, anyhow::Error>(())
        });

        let (agent_conn, mut agent_side) = tokio::io::duplex(4096);
        let forwarder = tokio::spawn(dial_and_forward(orchestrator_addr, agent_conn, PREFIX));

        let cap_frame = read_frame(&mut agent_side)
            .await?
            .context("agent should see the Cap frame")?;
        assert_eq!(
            cap_frame,
            LinkFrame::Cap {
                cap: "deadbeef".to_string(),
                channel: None,
                peers: 0,
            }
        );
        write_frame(
            &mut agent_side,
            &LinkFrame::Join {
                cap: "deadbeef".to_string(),
                channel: None,
                cols: None,
                rows: None,
            },
        )
        .await?;
        write_frame(&mut agent_side, &LinkFrame::Exit { code: 3 }).await?;

        let verdict = tokio::time::timeout(Duration::from_secs(2), forwarder)
            .await
            .context("dial_and_forward did not resolve")?
            .context("forwarder task panicked")??;
        assert_eq!(verdict, ForwardedVerdict::JobExited(3));

        tokio::time::timeout(Duration::from_secs(2), orchestrator)
            .await
            .context("the fake orchestrator did not finish")?
            .context("orchestrator task panicked")??;
        Ok(())
    }

    /// `relay_agent_link` is the function an `OnLink` closure actually calls:
    /// sync, no `.await`, on a thread with no ambient runtime — so this test
    /// drives it exactly that way, spawning the call on `spawn_blocking`
    /// rather than awaiting it directly, the same shape `ProcessBackend`'s
    /// own launch thread has.
    #[tokio::test]
    async fn relay_agent_link_resolves_job_exited_from_a_real_socketpair() -> anyhow::Result<()> {
        use sandy_api::{
            agent::{AgentReport, AgentVerdict},
            backend::RunControl,
        };

        let listener = sandy_conn::listen(&ConnAddr::Tcp("127.0.0.1:0".parse()?))
            .await
            .context("listen")?;
        let orchestrator_addr = listener.local_addr().context("local_addr")?;

        let orchestrator = tokio::spawn(async move {
            let (mut orchestrator_side, _peer) = listener.accept().await?;
            expect_prefix(&mut orchestrator_side, PREFIX).await?;
            write_frame(
                &mut orchestrator_side,
                &LinkFrame::Cap {
                    cap: "deadbeef".to_string(),
                    channel: None,
                    peers: 0,
                },
            )
            .await?;
            read_frame(&mut orchestrator_side).await?.context("expected Join")?;
            read_frame(&mut orchestrator_side).await?.context("expected Exit")?;
            Ok::<_, anyhow::Error>(())
        });

        // The real OwnedFd an OnLink closure receives: one end of a raw Unix
        // socketpair, exactly what ProcessBackend hands it (#216).
        let (relay_end, agent_end) = std::os::unix::net::UnixStream::pair().context("socketpair")?;
        agent_end.set_nonblocking(true).context("set_nonblocking")?;
        let mut agent_side = tokio::net::UnixStream::from_std(agent_end).context("from_std")?;

        let (report, verdict_rx) = AgentReport::channel();
        let rt = tokio::runtime::Handle::current();
        // Called from spawn_blocking: a stand-in for OnLink's own "no ambient
        // runtime" thread — relay_agent_link must not rely on one being
        // current on ITS thread, only on the Handle it's given.
        tokio::task::spawn_blocking(move || {
            relay_agent_link(
                &rt,
                orchestrator_addr,
                relay_end.into(),
                PREFIX.to_vec(),
                report,
                RunControl::with_timeout_secs(300),
            );
        })
        .await
        .context("spawn_blocking panicked")?;

        let cap_frame = read_frame(&mut agent_side)
            .await?
            .context("agent should see the Cap frame")?;
        assert_eq!(
            cap_frame,
            LinkFrame::Cap {
                cap: "deadbeef".to_string(),
                channel: None,
                peers: 0,
            }
        );
        write_frame(
            &mut agent_side,
            &LinkFrame::Join {
                cap: "deadbeef".to_string(),
                channel: None,
                cols: None,
                rows: None,
            },
        )
        .await?;
        write_frame(&mut agent_side, &LinkFrame::Exit { code: 9 }).await?;

        let verdict = tokio::task::spawn_blocking(move || verdict_rx.recv_timeout(Duration::from_secs(2)))
            .await
            .context("verdict recv task panicked")?
            .context("the report channel did not deliver a verdict within the timeout")?;
        assert_eq!(verdict, AgentVerdict::JobExited(9));

        tokio::time::timeout(Duration::from_secs(2), orchestrator)
            .await
            .context("the fake orchestrator did not finish")?
            .context("orchestrator task panicked")??;
        Ok(())
    }

    /// Regression (CodeRabbit on #284; architect ruling, #289.4): a connected
    /// orchestrator that never reads or writes again must not hang the relay
    /// forever — `relay_agent_link`'s `control` forces it to give up and
    /// report `agent_failed` once its deadline passes, so the task, the mesh
    /// socket, and the agent's link end all get torn down instead of leaking
    /// for the process's whole lifetime. Asserts the bad-path behavior
    /// explicitly, not just that the happy path still works.
    ///
    /// Uses real (short) time, not a paused virtual clock: this path dials a
    /// real TCP socket through `dial_and_forward`, including its own
    /// `DIAL_TIMEOUT`-bounded connect — paused time combined with real I/O is
    /// a known tokio pitfall (the virtual clock can auto-advance past a
    /// timeout while the real connect is still in flight), which is exactly
    /// what made this test flaky under `start_paused = true` during
    /// development.
    #[tokio::test]
    async fn relay_agent_link_times_out_against_a_connected_but_silent_orchestrator() -> anyhow::Result<()> {
        use sandy_api::{agent::AgentReport, backend::RunControl};

        let listener = sandy_conn::listen(&ConnAddr::Tcp("127.0.0.1:0".parse()?))
            .await
            .context("listen")?;
        let orchestrator_addr = listener.local_addr().context("local_addr")?;

        // Accepts the connection (so the dial itself succeeds) and then does
        // nothing else, ever — the exact "hung/never-EOF orchestrator"
        // scenario the bound exists for.
        let orchestrator = tokio::spawn(async move {
            let (_orchestrator_side, _peer) = listener.accept().await?;
            std::future::pending::<()>().await;
            Ok::<_, anyhow::Error>(())
        });

        let (relay_end, agent_end) = std::os::unix::net::UnixStream::pair().context("socketpair")?;
        agent_end.set_nonblocking(true).context("set_nonblocking")?;
        let mut agent_side = tokio::net::UnixStream::from_std(agent_end).context("from_std")?;
        let (report, verdict_rx) = AgentReport::channel();
        let rt = tokio::runtime::Handle::current();
        // Comfortably shorter than dial_and_forward's own 10s DIAL_TIMEOUT,
        // so a real-time test run resolves in well under a second without
        // the dial's own bound ever becoming a factor.
        const RELAY_TIMEOUT: Duration = Duration::from_millis(100);
        let control = RunControl::new(std::time::Instant::now() + RELAY_TIMEOUT);

        tokio::task::spawn_blocking(move || {
            relay_agent_link(
                &rt,
                orchestrator_addr,
                relay_end.into(),
                PREFIX.to_vec(),
                report,
                control,
            );
        })
        .await
        .context("spawn_blocking panicked")?;

        let verdict = tokio::task::spawn_blocking(move || verdict_rx.recv_timeout(Duration::from_secs(5)))
            .await
            .context("verdict recv task panicked")?
            .context("the report channel did not deliver a verdict after the deadline elapsed")?;
        assert!(
            matches!(&verdict, sandy_api::agent::AgentVerdict::AgentFailed(reason) if reason.contains("deadline")),
            "expected an AgentFailed verdict naming the deadline, got {verdict:?}"
        );

        // Proves actual teardown, not just the verdict: the timed-out
        // dial_and_forward future gets dropped, which drops its half of the
        // socketpair, so the agent's own side observes a clean EOF rather
        // than the fd leaking for the process's whole lifetime.
        let mut buf = [0u8; 1];
        let n = tokio::time::timeout(Duration::from_secs(2), AsyncReadExt::read(&mut agent_side, &mut buf))
            .await
            .context("agent side did not see EOF after the relay timed out")??;
        assert_eq!(n, 0, "expected EOF on the agent's side once the relay tears down");

        orchestrator.abort(); // still pending by design; nothing left to assert from it
        Ok(())
    }

    /// Regression (CodeRabbit on #344): `relay_agent_link`'s own bound is a
    /// live [`RunControl`], not a flat duration — a suspended deadline (the
    /// "attached" state) must not end the relay even long after the deadline
    /// it was suspended ahead of would otherwise have passed. Mirrors
    /// `impls/local/src/process.rs`'s own
    /// `suspending_the_control_survives_past_the_jobs_original_timeout` test
    /// at the relay's own layer.
    #[tokio::test]
    async fn relay_agent_link_survives_past_its_original_deadline_once_suspended() -> anyhow::Result<()> {
        use sandy_api::{agent::AgentReport, backend::RunControl};

        let listener = sandy_conn::listen(&ConnAddr::Tcp("127.0.0.1:0".parse()?))
            .await
            .context("listen")?;
        let orchestrator_addr = listener.local_addr().context("local_addr")?;

        // Silent once connected, same as the test above — the point here is
        // that nothing tears the relay down while suspended, not that the
        // orchestrator ever does anything.
        let orchestrator = tokio::spawn(async move {
            let (_orchestrator_side, _peer) = listener.accept().await?;
            std::future::pending::<()>().await;
            Ok::<_, anyhow::Error>(())
        });

        let (relay_end, agent_end) = std::os::unix::net::UnixStream::pair().context("socketpair")?;
        agent_end.set_nonblocking(true).context("set_nonblocking")?;
        let _agent_side = tokio::net::UnixStream::from_std(agent_end).context("from_std")?;
        let (report, verdict_rx) = AgentReport::channel();
        let rt = tokio::runtime::Handle::current();

        // A deadline that would already have passed by the time the relay
        // even starts, were it ever consulted — suspended up front, so it
        // must not be.
        let control = RunControl::new(std::time::Instant::now() + Duration::from_millis(50));
        control.suspend_deadline();
        let control_for_relay = control.clone();

        tokio::task::spawn_blocking(move || {
            relay_agent_link(
                &rt,
                orchestrator_addr,
                relay_end.into(),
                PREFIX.to_vec(),
                report,
                control_for_relay,
            );
        })
        .await
        .context("spawn_blocking panicked")?;

        // Wait well past the original (now-suspended) deadline: no verdict
        // should have arrived yet — the relay is still alive.
        let (too_soon, verdict_rx) = tokio::task::spawn_blocking(move || {
            let result = verdict_rx.recv_timeout(Duration::from_millis(500));
            (result, verdict_rx)
        })
        .await
        .context("recv task panicked")?;
        assert!(
            too_soon.is_err(),
            "a suspended deadline must not end the relay: got {too_soon:?}"
        );

        // Cancel it, proving the relay really is still alive and watching
        // `control` live rather than merely hung for an unrelated reason.
        control.cancel();
        let verdict = tokio::task::spawn_blocking(move || verdict_rx.recv_timeout(Duration::from_secs(2)))
            .await
            .context("verdict recv task panicked")?
            .context("the report channel did not deliver a verdict after cancellation")?;
        assert!(
            matches!(&verdict, sandy_api::agent::AgentVerdict::AgentFailed(reason) if reason.contains("cancelled")),
            "expected an AgentFailed verdict naming the cancellation, got {verdict:?}"
        );

        orchestrator.abort(); // still pending by design; nothing left to assert from it
        Ok(())
    }
}
