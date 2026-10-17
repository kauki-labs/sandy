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

    tokio::spawn(forward_orchestrator_to_agent(remote_rd, local_wr));

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
            },
        )
        .await?;
        let forwarded_cap = read_frame(&mut agent_side)
            .await?
            .context("agent should see the Cap frame")?;
        assert_eq!(
            forwarded_cap,
            LinkFrame::Cap {
                cap: "deadbeef".to_string()
            }
        );

        // Agent -> orchestrator: Join, then Exit.
        write_frame(
            &mut agent_side,
            &LinkFrame::Join {
                cap: "deadbeef".to_string(),
            },
        )
        .await?;
        let forwarded_join = read_frame(&mut orchestrator_side)
            .await?
            .context("orchestrator should see Join")?;
        assert_eq!(
            forwarded_join,
            LinkFrame::Join {
                cap: "deadbeef".to_string()
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
}
