//! `sandyd`: the per-machine control-plane daemon (epic #205). This block
//! (#212 B1 + its B2 dispatch slice) serves #211's control RPC against a
//! sqlite-backed job store: a `Submit` mints a real per-job channel and caps
//! (see [`dispatch`]), but nothing yet joins that channel and runs the job —
//! there is no `sandy-agent` binary or `ProcessBackend::with_agent` (#216)
//! for the executor to spawn. `Attach` returning a real channel/cap for a job
//! that stays `Pending` is the honest state of that gap, not a fake success.
//!
//! The control RPC itself stays pure request/response (`docs/decisions/
//! sandyd.md` §1: never a retrofit into a streaming call). `Attach`'s cap is
//! redeemed on a SEPARATE connection, [`attach_relay`]'s own data-plane
//! listener (#327) — the path §1 anticipated ("the caller subscribes on the
//! data plane itself") but that didn't exist until this module.

pub mod attach_relay;
pub mod dispatch;
pub mod handler;
pub mod host_conn;
pub mod host_registry;
pub mod link_auth;
pub mod mesh_accept;
pub mod mesh_config;
pub mod store;
#[cfg(test)]
mod test_support;

use std::{net::SocketAddr, sync::Arc};

use dispatch::JobRegistry;
use host_registry::HostRegistry;
use sandy_control_proto::{ControlRequest, read_frame, write_frame};
use store::JobStore;
use tokio::net::UnixStream;

/// Serve one client connection: read [`ControlRequest`] frames, dispatch each
/// against `store`, and write the matching
/// [`ControlResponse`](sandy_control_proto::ControlResponse), until the peer
/// closes the connection.
///
/// Stops on a clean close (the ordinary end of a connection) or the first
/// faulting frame — a single connection's own fault never brings down the
/// listener or any other connection, which is why this takes an owned stream
/// and is meant to run as its own task.
pub async fn serve_connection(
    mut stream: UnixStream,
    store: Arc<JobStore>,
    registry: Arc<JobRegistry>,
    host_registry: Arc<HostRegistry>,
    forward_back_addr: Option<SocketAddr>,
) {
    // CF-H-1: one session id per connection, not per request — minted once
    // here and compared, never trusted as access control, against the
    // session a Cancel/Attach's target job recorded at Submit. See
    // `handler::handle`'s own doc on `session`.
    let session = uuid::Uuid::new_v4();
    tracing::info!(%session, "control connection opened");

    loop {
        let request: ControlRequest = match read_frame(&mut stream).await {
            Ok(Some(request)) => request,
            Ok(None) => return, // clean close: the ordinary end of a connection
            Err(e) => {
                tracing::warn!(error = %e, "control connection faulted reading a frame; closing it");
                return;
            }
        };

        let request_id = request.request_id;
        let response =
            match handler::handle(&store, &registry, &host_registry, forward_back_addr, session, request).await {
                Ok(response) => response,
                Err(e) => {
                    tracing::error!(error = %e, request_id, "job store faulted handling a request");
                    return;
                }
            };

        if let Err(e) = write_frame(&mut stream, &response).await {
            tracing::warn!(error = %e, request_id, "control connection faulted writing a response; closing it");
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Context;
    use sandy_control_proto::{ControlResponse, SubmitRequest, control_request, control_response};

    use super::*;

    #[tokio::test]
    async fn a_client_can_submit_and_then_read_back_status() -> anyhow::Result<()> {
        let store = Arc::new(JobStore::open_in_memory()?);
        let (client, server) = UnixStream::pair()?;
        let registry = Arc::new(JobRegistry::new()?);
        let host_registry = Arc::new(HostRegistry::default());
        let serving = tokio::spawn(serve_connection(server, store, registry, host_registry, None));

        let mut client = client;
        write_frame(
            &mut client,
            &ControlRequest {
                request_id: 1,
                op: Some(control_request::Op::Submit(SubmitRequest {
                    manifest: b"m".to_vec(),
                    manifest_encoding: "test/v1".to_owned(),
                    submitter_caps: Vec::new(),
                })),
            },
        )
        .await?;
        let response: ControlResponse = read_frame(&mut client).await?.context("expected a Submit response")?;
        let job_id = match response.result {
            Some(control_response::Result::Submit(sandy_control_proto::SubmitResponse { job_id, .. })) => job_id,
            other => anyhow::bail!("expected Submit, got {other:?}"),
        };

        write_frame(
            &mut client,
            &ControlRequest {
                request_id: 2,
                op: Some(control_request::Op::Status(sandy_control_proto::StatusRequest {
                    job_id: job_id.clone(),
                })),
            },
        )
        .await?;
        let response: ControlResponse = read_frame(&mut client).await?.context("expected a Status response")?;
        match response.result {
            Some(control_response::Result::Status(sandy_control_proto::StatusResponse {
                job_id: id, status, ..
            })) => {
                assert_eq!(id, job_id);
                assert_eq!(status, i32::from(sandy_control_proto::JobStatus::Pending));
            }
            other => anyhow::bail!("expected Status, got {other:?}"),
        }

        drop(client); // clean close: serve_connection must return, not hang
        tokio::time::timeout(std::time::Duration::from_secs(5), serving).await??;
        Ok(())
    }

    /// CF-M-2: a Submit refused for being at the job store's row cap gets an
    /// `Error` response, but the connection itself stays alive — unlike a
    /// genuine `StoreError`, which tears down the whole connection (this
    /// function's own `Err(e)` match arm above). A routine capacity refusal
    /// must not look like that store-faulted case to the rest of this
    /// connection's traffic.
    #[tokio::test]
    async fn a_submit_past_the_row_cap_refuses_but_keeps_the_connection_alive() -> anyhow::Result<()> {
        let store = Arc::new(JobStore::open_in_memory()?.with_max_rows(Some(0)));
        let (client, server) = UnixStream::pair()?;
        let registry = Arc::new(JobRegistry::new()?);
        let host_registry = Arc::new(HostRegistry::default());
        let serving = tokio::spawn(serve_connection(server, store, registry, host_registry, None));

        let mut client = client;
        write_frame(
            &mut client,
            &ControlRequest {
                request_id: 1,
                op: Some(control_request::Op::Submit(SubmitRequest {
                    manifest: b"m".to_vec(),
                    manifest_encoding: "test/v1".to_owned(),
                    submitter_caps: Vec::new(),
                })),
            },
        )
        .await?;
        let response: ControlResponse = read_frame(&mut client).await?.context("expected an Error response")?;
        assert!(
            matches!(response.result, Some(control_response::Result::Error(_))),
            "got {:?}",
            response.result
        );

        // The connection must still answer a later request, not have been
        // torn down by the refusal above.
        write_frame(
            &mut client,
            &ControlRequest {
                request_id: 2,
                op: Some(control_request::Op::List(sandy_control_proto::ListRequest {})),
            },
        )
        .await?;
        let response: ControlResponse = read_frame(&mut client)
            .await?
            .context("the connection must stay alive after a capacity refusal")?;
        assert!(
            matches!(response.result, Some(control_response::Result::List(_))),
            "got {:?}",
            response.result
        );

        drop(client);
        tokio::time::timeout(std::time::Duration::from_secs(5), serving).await??;
        Ok(())
    }

    /// Adversarial: a client that disconnects mid-frame must not wedge the
    /// connection task — it simply ends, leaving other connections (not
    /// simulated here, but implied by `serve_connection` taking no shared
    /// lock across connections beyond the store's own internal one)
    /// unaffected.
    #[tokio::test]
    async fn a_mid_frame_disconnect_ends_the_connection_task_cleanly() -> anyhow::Result<()> {
        let store = Arc::new(JobStore::open_in_memory()?);
        let (client, server) = UnixStream::pair()?;
        let registry = Arc::new(JobRegistry::new()?);
        let host_registry = Arc::new(HostRegistry::default());
        let serving = tokio::spawn(serve_connection(server, store, registry, host_registry, None));

        use tokio::io::AsyncWriteExt;
        let mut client = client;
        client.write_all(&[0, 0, 0, 100]).await?; // announces 100 bytes
        client.write_all(b"short").await?; // far fewer
        drop(client);

        tokio::time::timeout(std::time::Duration::from_secs(5), serving).await??;
        Ok(())
    }
}
