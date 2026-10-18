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

use sandy_conn::ConnAddr;
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
    reverse.detach();
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
    /// reverse pipe may still have orchestrator traffic to deliver.
    fn detach(mut self) {
        self.0 = None;
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
    let remote = tokio::time::timeout(DIAL_TIMEOUT, sandy_conn::connect(&ConnAddr::Tcp(orchestrator)))
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
/// `timeout` bounds the whole relay, not just the dial (`dial_and_forward`'s
/// own `DIAL_TIMEOUT` already bounds connecting): a connected-but-silent
/// orchestrator — one that accepts the TCP connection and then never reads or
/// writes again — would otherwise hang `forward_agent_link`'s writes
/// indefinitely, leaking this task, the mesh socket, and the agent's link end
/// forever (CodeRabbit finding on #284; architect ruling, infra-f3, #289.4:
/// bound it here, at the call site that actually enters a long-lived loop,
/// against the job's own wall-clock rather than inside `dial_and_forward`
/// itself). The caller passes the same bound the job's own `RunSpec.
/// timeout_secs` uses, so a stuck relay and a stuck job time out together.
pub fn relay_agent_link(
    rt: &tokio::runtime::Handle,
    forward_back: SocketAddr,
    host_end: std::os::fd::OwnedFd,
    prefix: Vec<u8>,
    report: sandy_api::agent::AgentReport,
    timeout: std::time::Duration,
) {
    rt.spawn(async move {
        let link = match owned_fd_into_unix_stream(host_end) {
            Ok(link) => link,
            Err(e) => {
                report.agent_failed(format!("converting the agent link fd: {e}"));
                return;
            }
        };
        match tokio::time::timeout(timeout, dial_and_forward(forward_back, link, &prefix)).await {
            Ok(Ok(ForwardedVerdict::JobExited(code))) => report.job_exited(code),
            Ok(Ok(ForwardedVerdict::AgentFailed(reason))) => report.agent_failed(reason),
            // DialAndForwardError's own Display already names what failed
            // ("dialing the orchestrator: ..." or "agent link: ...");
            // wrapping it again here would duplicate that prefix.
            Ok(Err(e)) => report.agent_failed(e.to_string()),
            Err(_elapsed) => report.agent_failed(format!("the mesh relay did not complete within {timeout:?}")),
        }
    });
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
        use sandy_api::agent::{AgentReport, AgentVerdict};

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
                Duration::from_secs(300),
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
    /// forever — `relay_agent_link`'s `timeout` forces it to give up and
    /// report `agent_failed`, so the task, the mesh socket, and the agent's
    /// link end all get torn down instead of leaking for the process's whole
    /// lifetime. Asserts the bad-path behavior explicitly, not just that the
    /// happy path still works.
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
        use sandy_api::agent::AgentReport;

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

        let (relay_end, _agent_end) = std::os::unix::net::UnixStream::pair().context("socketpair")?;
        let (report, verdict_rx) = AgentReport::channel();
        let rt = tokio::runtime::Handle::current();
        // Comfortably shorter than dial_and_forward's own 10s DIAL_TIMEOUT,
        // so a real-time test run resolves in well under a second without
        // the dial's own bound ever becoming a factor.
        const RELAY_TIMEOUT: Duration = Duration::from_millis(100);

        tokio::task::spawn_blocking(move || {
            relay_agent_link(
                &rt,
                orchestrator_addr,
                relay_end.into(),
                PREFIX.to_vec(),
                report,
                RELAY_TIMEOUT,
            );
        })
        .await
        .context("spawn_blocking panicked")?;

        let verdict = tokio::task::spawn_blocking(move || verdict_rx.recv_timeout(Duration::from_secs(5)))
            .await
            .context("verdict recv task panicked")?
            .context("the report channel did not deliver a verdict after the timeout elapsed")?;
        assert!(
            matches!(&verdict, sandy_api::agent::AgentVerdict::AgentFailed(reason) if reason.contains("did not complete")),
            "expected an AgentFailed verdict naming the timeout, got {verdict:?}"
        );

        orchestrator.abort(); // still pending by design; nothing left to assert from it
        Ok(())
    }
}
