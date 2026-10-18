//! `sandyd`: the per-machine control-plane daemon (epic #205). This block
//! (#212 B1 + its B2 dispatch slice) serves #211's control RPC against a
//! sqlite-backed job store: a `Submit` mints a real per-job channel and caps
//! (see [`dispatch`]), but nothing yet joins that channel and runs the job —
//! there is no `sandy-agent` binary or `ProcessBackend::with_agent` (#216)
//! for the executor to spawn. `Attach` returning a real channel/cap for a job
//! that stays `Pending` is the honest state of that gap, not a fake success.

pub mod dispatch;
pub mod handler;
pub mod host_conn;
pub mod host_registry;
pub mod link_auth;
pub mod store;

use std::sync::Arc;

use dispatch::JobRegistry;
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
pub async fn serve_connection(mut stream: UnixStream, store: Arc<JobStore>, registry: Arc<JobRegistry>) {
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
        let response = match handler::handle(&store, &registry, request).await {
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
        let serving = tokio::spawn(serve_connection(server, store, registry));

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
            Some(control_response::Result::Submit(sandy_control_proto::SubmitResponse { job_id })) => job_id,
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
            Some(control_response::Result::Status(sandy_control_proto::StatusResponse { job_id: id, status })) => {
                assert_eq!(id, job_id);
                assert_eq!(status, i32::from(sandy_control_proto::JobStatus::Pending));
            }
            other => anyhow::bail!("expected Status, got {other:?}"),
        }

        drop(client); // clean close: serve_connection must return, not hang
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
        let serving = tokio::spawn(serve_connection(server, store, registry));

        use tokio::io::AsyncWriteExt;
        let mut client = client;
        client.write_all(&[0, 0, 0, 100]).await?; // announces 100 bytes
        client.write_all(b"short").await?; // far fewer
        drop(client);

        tokio::time::timeout(std::time::Duration::from_secs(5), serving).await??;
        Ok(())
    }
}
