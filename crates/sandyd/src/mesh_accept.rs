//! The mesh accept loop for remote agent-link streams (#212 decision 6,
//! #279): the network half decision 6's `link_auth` module explicitly does
//! not provide. Binds nothing itself — takes an already-bound
//! [`sandy_conn::Listener`] — and for each accepted connection: decodes the
//! run-id+token prefix ([`decode_remote_link_prefix`], the one shared codec
//! both this loop and the executor's `forward_agent_link` import, #284),
//! authenticates it against [`JobRegistry`], and on success hands the stream
//! to [`serve_agent_link`]. Every refusal path (malformed prefix, wrong peer,
//! wrong token, unknown run, already-claimed/invalidated link) closes the
//! connection having written zero bytes — no cap leaks before
//! authentication.
//!
//! What this does NOT do: decide where to bind, or get wired into `main.rs`
//! — that needs a decision this module doesn't own (how `sandyd` learns its
//! own mesh bind address), tracked by decision 12's "set aside" note.

use std::sync::Arc;

use sandy_conn::{Conn, Listener, PeerAddr};
use sandy_executor_proto::decode_remote_link_prefix;
use sandy_fabric_local::link::serve_agent_link;

use crate::dispatch::JobRegistry;

/// How long a freshly accepted connection has to deliver its full run-id +
/// token prefix before it's closed. Without a deadline here, a peer that
/// opens a connection and sends nothing (or a partial prefix) would hold the
/// spawned task and its fd open indefinitely — an uncapped accept loop means
/// any mesh peer can EMFILE the whole daemon this way, including the
/// control socket and the host-client path. Mirrors `host_conn`'s
/// `REGISTER_TIMEOUT`, the same shape for the same pre-auth DoS.
const PREFIX_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Accept connections from `listener` until it errors, authenticating each
/// against `registry` before relaying it to its job's agent link. A single
/// connection's own failure (malformed prefix, auth refusal, a faulted link)
/// never stops the loop — only ends that one connection.
pub async fn serve_mesh_accept_loop(listener: &Listener, registry: &Arc<JobRegistry>) {
    loop {
        match listener.accept().await {
            Ok((conn, peer)) => {
                let registry = Arc::clone(registry);
                tokio::spawn(async move {
                    serve_one_remote_link(conn, peer, &registry).await;
                });
            }
            Err(e) => {
                tracing::warn!(error = %e, "mesh accept loop: accept faulted; backing off");
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
    }
}

/// Authenticate and serve one accepted connection end to end. `conn` is
/// never written to before [`JobRegistry::authenticate_remote_link`]
/// succeeds — every refusal path below returns having read only, so the
/// stream closes with zero bytes written.
async fn serve_one_remote_link(mut conn: Box<dyn Conn>, peer: PeerAddr, registry: &JobRegistry) {
    let peer_ip = match peer {
        PeerAddr::Tcp(addr) => addr.ip(),
        PeerAddr::Uds => {
            tracing::error!("mesh accept loop: got a UDS peer; this listener must be bound to the mesh TCP tier");
            return;
        }
    };

    let (job_id, token) = match tokio::time::timeout(PREFIX_TIMEOUT, decode_remote_link_prefix(&mut conn)).await {
        Ok(Ok(parsed)) => parsed,
        Ok(Err(e)) => {
            tracing::warn!(error = %e, peer = %peer_ip, "mesh accept loop: refusing a stream with a malformed prefix");
            return;
        }
        Err(_elapsed) => {
            tracing::warn!(peer = %peer_ip, "mesh accept loop: peer did not send a full prefix within the timeout; closing");
            return;
        }
    };

    let job = match registry.authenticate_remote_link(&job_id, peer_ip, &token) {
        Ok(job) => job,
        Err(e) => {
            tracing::warn!(error = %e, job_id, peer = %peer_ip, "mesh accept loop: refusing an unauthenticated agent-link stream");
            return;
        }
    };

    if let Err(e) = serve_agent_link(Arc::clone(&job.channel), &job.agent_cap, conn).await {
        tracing::warn!(error = %e, job_id, "mesh accept loop: the agent link faulted");
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use anyhow::Context;
    use sandy_conn::{ConnAddr, connect, listen};
    use sandy_executor_proto::encode_remote_link_prefix;

    use super::*;
    use crate::link_auth::RemoteLink;

    fn loopback(port: u16) -> ConnAddr {
        ConnAddr::Tcp(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port))
    }

    async fn new_registry_with_remote_job(
        executor_ip: IpAddr,
    ) -> anyhow::Result<(
        Arc<JobRegistry>,
        String,
        [u8; sandy_executor_proto::REMOTE_LINK_TOKEN_LEN],
    )> {
        let registry = Arc::new(JobRegistry::new().context("registry")?);
        let mut job = crate::dispatch::mint_job_channel("job-1", registry.authority())
            .await
            .context("mint job channel")?;
        let link = RemoteLink::new(executor_ip).context("remote link")?;
        let token = *link.token().as_bytes();
        job.remote_link = Some(link);
        registry.insert("job-1".to_owned(), job);
        Ok((registry, "job-1".to_owned(), token))
    }

    /// Positive: a stream presenting the real job id and token over the real
    /// peer address is authenticated and handed to the agent link, which
    /// immediately sees its `Join` cap frame (proof `serve_agent_link`
    /// actually ran, not just that authentication succeeded).
    #[tokio::test]
    async fn an_authenticated_stream_reaches_the_agent_link() -> anyhow::Result<()> {
        let listener = listen(&loopback(0)).await.context("listen")?;
        let addr = listener.local_addr().context("local_addr")?;
        let (registry, job_id, token) = new_registry_with_remote_job(addr.ip()).await?;

        let accept_registry = Arc::clone(&registry);
        let accepting = tokio::spawn(async move {
            let (conn, peer) = listener.accept().await.expect("accept");
            serve_one_remote_link(conn, peer, &accept_registry).await;
        });

        let mut client = connect(&loopback(addr.port())).await.context("connect")?;
        let prefix = encode_remote_link_prefix(&job_id, &token).expect("encode prefix");
        tokio::io::AsyncWriteExt::write_all(&mut client, &prefix)
            .await
            .context("write prefix")?;

        // The agent cap frame the relay writes first proves serve_agent_link
        // actually took over the stream.
        let mut buf = [0u8; 1];
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            tokio::io::AsyncReadExt::read(&mut client, &mut buf),
        )
        .await
        .context("timed out waiting for the agent link's first byte")?
        .context("read the agent link's first frame")?;

        drop(client);
        tokio::time::timeout(std::time::Duration::from_secs(5), accepting).await??;
        Ok(())
    }

    /// Adversarial: a stream presenting a well-formed prefix for an unknown
    /// job id is refused and the connection closes with zero bytes written —
    /// never handed to `serve_agent_link`.
    #[tokio::test]
    async fn an_unknown_job_id_is_refused_with_zero_bytes() -> anyhow::Result<()> {
        let listener = listen(&loopback(0)).await.context("listen")?;
        let addr = listener.local_addr().context("local_addr")?;
        let registry = Arc::new(JobRegistry::new().context("registry")?);

        let accept_registry = Arc::clone(&registry);
        let accepting = tokio::spawn(async move {
            let (conn, peer) = listener.accept().await.expect("accept");
            serve_one_remote_link(conn, peer, &accept_registry).await;
        });

        let mut client = connect(&loopback(addr.port())).await.context("connect")?;
        let prefix = encode_remote_link_prefix("ghost", &[0u8; 32]).expect("encode prefix");
        tokio::io::AsyncWriteExt::write_all(&mut client, &prefix)
            .await
            .context("write prefix")?;

        let mut buf = [0u8; 1];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            tokio::io::AsyncReadExt::read(&mut client, &mut buf),
        )
        .await
        .context("timed out waiting for the refusal close")?
        .context("read after refusal")?;
        assert_eq!(
            n, 0,
            "an unknown job id must close the stream having written zero bytes"
        );

        tokio::time::timeout(std::time::Duration::from_secs(5), accepting).await??;
        Ok(())
    }

    /// Adversarial: a stream presenting the right job id but the wrong token
    /// is refused with zero bytes — the token, not just the job id, gates
    /// access to the cap.
    #[tokio::test]
    async fn a_wrong_token_is_refused_with_zero_bytes() -> anyhow::Result<()> {
        let listener = listen(&loopback(0)).await.context("listen")?;
        let addr = listener.local_addr().context("local_addr")?;
        let (registry, job_id, _token) = new_registry_with_remote_job(addr.ip()).await?;

        let accept_registry = Arc::clone(&registry);
        let accepting = tokio::spawn(async move {
            let (conn, peer) = listener.accept().await.expect("accept");
            serve_one_remote_link(conn, peer, &accept_registry).await;
        });

        let mut client = connect(&loopback(addr.port())).await.context("connect")?;
        let prefix = encode_remote_link_prefix(&job_id, &[0xAA; 32]).expect("encode prefix");
        tokio::io::AsyncWriteExt::write_all(&mut client, &prefix)
            .await
            .context("write prefix")?;

        let mut buf = [0u8; 1];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            tokio::io::AsyncReadExt::read(&mut client, &mut buf),
        )
        .await
        .context("timed out waiting for the refusal close")?
        .context("read after refusal")?;
        assert_eq!(n, 0, "a wrong token must close the stream having written zero bytes");

        tokio::time::timeout(std::time::Duration::from_secs(5), accepting).await??;
        Ok(())
    }

    /// Adversarial: a job's link, once claimed by a first authenticated
    /// stream, refuses a second stream presenting the same valid token — the
    /// one-link-per-run invariant holds through the real network path, not
    /// just in `link_auth`'s own unit tests.
    #[tokio::test]
    async fn a_second_stream_for_an_already_claimed_link_is_refused_with_zero_bytes() -> anyhow::Result<()> {
        let listener = listen(&loopback(0)).await.context("listen")?;
        let addr = listener.local_addr().context("local_addr")?;
        let (registry, job_id, token) = new_registry_with_remote_job(addr.ip()).await?;

        // First stream claims the link.
        let accept_registry = Arc::clone(&registry);
        let listener = Arc::new(listener);
        let first_listener = Arc::clone(&listener);
        let first_accept = tokio::spawn(async move {
            let (conn, peer) = first_listener.accept().await.expect("accept");
            serve_one_remote_link(conn, peer, &accept_registry).await;
        });
        let mut first_client = connect(&loopback(addr.port())).await.context("connect")?;
        let prefix = encode_remote_link_prefix(&job_id, &token).expect("encode prefix");
        tokio::io::AsyncWriteExt::write_all(&mut first_client, &prefix)
            .await
            .context("write first prefix")?;
        let mut buf = [0u8; 1];
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            tokio::io::AsyncReadExt::read(&mut first_client, &mut buf),
        )
        .await
        .context("timed out waiting for the first stream's agent link byte")?
        .context("read the first stream's agent link byte")?;

        // Second stream, same valid token, must be refused.
        let accept_registry = Arc::clone(&registry);
        let second_accept = tokio::spawn(async move {
            let (conn, peer) = listener.accept().await.expect("accept");
            serve_one_remote_link(conn, peer, &accept_registry).await;
        });
        let mut second_client = connect(&loopback(addr.port())).await.context("connect")?;
        tokio::io::AsyncWriteExt::write_all(&mut second_client, &prefix)
            .await
            .context("write second prefix")?;
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            tokio::io::AsyncReadExt::read(&mut second_client, &mut buf),
        )
        .await
        .context("timed out waiting for the second stream's refusal close")?
        .context("read after the second stream's refusal")?;
        assert_eq!(n, 0, "a second stream for an already-claimed link must get zero bytes");

        drop(first_client);
        tokio::time::timeout(std::time::Duration::from_secs(5), first_accept).await??;
        tokio::time::timeout(std::time::Duration::from_secs(5), second_accept).await??;
        Ok(())
    }

    fn tcp_peer(ip: &str) -> PeerAddr {
        PeerAddr::Tcp(SocketAddr::new(ip.parse().expect("ip literal"), 0))
    }

    /// Regression (sandy-73, pre-auth DoS): a peer that opens a connection
    /// and never sends a full prefix must not hold the spawned task and its
    /// fd open forever — an uncapped accept loop lets any mesh peer EMFILE
    /// the whole daemon this way. Closed once `PREFIX_TIMEOUT` elapses.
    #[tokio::test(start_paused = true)]
    async fn a_peer_that_never_sends_a_full_prefix_is_disconnected_after_the_timeout() -> anyhow::Result<()> {
        let registry = Arc::new(JobRegistry::new().context("registry")?);
        let (client, server) = tokio::io::duplex(4096);

        let serving = tokio::spawn(async move {
            serve_one_remote_link(Box::new(server), tcp_peer("100.64.0.7"), &registry).await;
        });

        tokio::time::advance(PREFIX_TIMEOUT + std::time::Duration::from_millis(1)).await;
        serving.await?; // bounded by the virtual-clock advance above, not real time
        drop(client);
        Ok(())
    }
}
