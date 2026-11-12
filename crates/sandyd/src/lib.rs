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
pub mod audit;
pub mod build_rev;
pub mod credential;
pub mod data_link_recv;
pub mod data_link_send;
pub mod dispatch;
pub mod environment;
pub mod environment_backend;
pub mod environment_credential;
pub mod environment_driver;
pub mod environment_store;
pub mod environment_vm;
pub mod handler;
pub mod host_conn;
pub mod host_registry;
pub mod link_auth;
pub mod mesh_accept;
pub mod mesh_config;
pub mod operator;
pub mod operator_values;
pub mod output_slot;
pub mod peer_cred;
pub mod profiles;
pub mod store;
pub mod stub_trust_root;
#[cfg(test)]
mod test_support;

use std::{future::Future, net::SocketAddr, sync::Arc};

use dispatch::JobRegistry;
use environment_store::EnvironmentStore;
use host_registry::HostRegistry;
use sandy_control_proto::{ControlRequest, read_frame, write_frame};
use store::JobStore;
use tokio::net::UnixStream;

/// Acquire one permit from `semaphore`, THEN await `accept` (CF-L-1, #289
/// item 3) — in that order, and combined into one future, so a full
/// semaphore blocks only this one `select!` branch, not the whole accept
/// loop: the surrounding `select!` keeps polling its sibling branches
/// (reaping finished connections, the shutdown signal) every iteration
/// regardless of whether this branch's permit acquisition has resolved yet.
/// Acquiring the permit as a plain `.await` inside a branch's handler (after
/// `select!` has already picked that branch) would instead block the loop's
/// next iteration on it — shutdown would never be observed while every
/// permit is held.
///
/// Shared by every accept loop in this crate (the UDS control socket, the
/// mesh management-channel listener, and the mesh agent-link listener) so
/// each gets the same pre-auth concurrency cap under the same discipline,
/// rather than one loop remembering it and the others not.
///
/// `Err` only if `semaphore` was explicitly closed, which no caller in this
/// crate ever does; the caller still matches on it rather than unwrapping,
/// per house style (no panics in a connection-accepting loop).
pub async fn gate_spawn<T>(
    semaphore: &Arc<tokio::sync::Semaphore>,
    accept: impl Future<Output = T>,
) -> (Result<tokio::sync::OwnedSemaphorePermit, tokio::sync::AcquireError>, T) {
    let permit = Arc::clone(semaphore).acquire_owned().await;
    let value = accept.await;
    (permit, value)
}

/// `(permit, accept result)`, as [`spawn_gated_accept`] hands back once its
/// spawned task resolves. The accept result is a raw [`sandy_conn::AcceptedStream`],
/// not yet handshaken on the TLS tier — see `spawn_gated_accept`'s own doc.
pub type GatedAcceptResult = (
    Result<tokio::sync::OwnedSemaphorePermit, tokio::sync::AcquireError>,
    Result<sandy_conn::AcceptedStream, sandy_conn::ConnError>,
);

/// Spawn one gated [`sandy_conn::Listener::accept_raw`] call into its own
/// task, decoupling its execution from whatever `select!` loop awaits the
/// returned [`tokio::task::JoinHandle`].
///
/// This spawns the RAW accept only, not the TLS handshake (the decision-20
/// accept+handshake hazard `listen_tls`'s own doc comment flags): a caller
/// holding one pending accept task at a time and re-arming it only once it
/// resolves — every accept loop in this crate — would otherwise have one
/// peer's handshake (up to the handshake timeout) delay the next accept from
/// even starting, serializing TLS handshakes across the whole listener. The
/// caller is responsible for calling [`sandy_conn::AcceptedStream::handshake`]
/// itself, inside the per-connection task it spawns once this resolves, so a
/// slow or silent peer's handshake only occupies its own task and connection
/// permit, never the shared accept slot.
///
/// `listener` is `Arc`-wrapped so the spawned task can hold its own
/// reference independent of the caller's loop — the point of spawning is
/// that the task must keep running even if the loop that spawned it moves on
/// to its next iteration before this task resolves.
pub fn spawn_gated_accept(
    semaphore: Arc<tokio::sync::Semaphore>,
    listener: Arc<sandy_conn::Listener>,
) -> tokio::task::JoinHandle<GatedAcceptResult> {
    tokio::spawn(async move { gate_spawn(&semaphore, async move { listener.accept_raw().await }).await })
}

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
    environments: Arc<EnvironmentStore>,
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
        // Environment operations have their own handler and store; every other
        // request goes to the job handler unchanged.
        let response = if environment::is_environment_op(&request.op) {
            match environment::handle(&environments, request).await {
                Ok(response) => response,
                Err(e) => {
                    tracing::error!(error = %e, request_id, "environment store faulted handling a request");
                    return;
                }
            }
        } else {
            match handler::handle(&store, &registry, &host_registry, forward_back_addr, session, request).await {
                Ok(response) => response,
                Err(e) => {
                    tracing::error!(error = %e, request_id, "job store faulted handling a request");
                    return;
                }
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

    /// An environment op is answered by the environment handler over the same
    /// connection that serves job ops, and neither disturbs the other.
    #[tokio::test]
    async fn environment_and_job_operations_share_one_connection() -> anyhow::Result<()> {
        use sandy_control_proto::v1::{
            CreateEnvironmentRequest, EnvironmentLifetime, EnvironmentLifetimeKind, EnvironmentSpec, EnvironmentState,
            GetEnvironmentRequest,
        };

        let environments = Arc::new(EnvironmentStore::open_in_memory()?.with_profiles(test_support::test_profiles()));
        let (client, server) = UnixStream::pair()?;
        let serving = tokio::spawn(serve_connection(
            server,
            Arc::new(JobStore::open_in_memory()?),
            Arc::clone(&environments),
            Arc::new(JobRegistry::new()?),
            Arc::new(HostRegistry::default()),
            None,
        ));
        let mut client = client;

        let create = ControlRequest {
            request_id: 1,
            op: Some(control_request::Op::CreateEnvironment(CreateEnvironmentRequest {
                idempotency_key: "k1".to_owned(),
                spec: Some(EnvironmentSpec {
                    profile: "harness".to_owned(),
                    size: String::new(),
                    lifetime: Some(EnvironmentLifetime {
                        kind: EnvironmentLifetimeKind::Ephemeral.into(),
                        ttl_secs: 600,
                    }),
                    task_ref: String::new(),
                }),
                ..Default::default()
            })),
        };
        write_frame(&mut client, &create).await?;
        let response: ControlResponse = read_frame(&mut client).await?.context("expected a create reply")?;
        assert_eq!(response.request_id, 1);
        let id = match response.result {
            Some(control_response::Result::Environment(env)) => {
                assert_eq!(env.state, i32::from(EnvironmentState::Provisioning));
                env.environment_id
            }
            other => anyhow::bail!("expected an environment, got {other:?}"),
        };
        assert_eq!(
            environments.list()?.len(),
            1,
            "the create must reach the environment store"
        );

        // A job op on the same connection still reaches the job handler.
        write_frame(
            &mut client,
            &ControlRequest {
                request_id: 2,
                op: Some(control_request::Op::List(sandy_control_proto::ListRequest {})),
            },
        )
        .await?;
        let response: ControlResponse = read_frame(&mut client).await?.context("expected a list reply")?;
        assert!(matches!(response.result, Some(control_response::Result::List(_))));

        write_frame(
            &mut client,
            &ControlRequest {
                request_id: 3,
                op: Some(control_request::Op::GetEnvironment(GetEnvironmentRequest {
                    environment_id: id.clone(),
                })),
            },
        )
        .await?;
        let response: ControlResponse = read_frame(&mut client).await?.context("expected a get reply")?;
        assert!(matches!(
            response.result,
            Some(control_response::Result::Environment(ref e)) if e.environment_id == id
        ));

        drop(client);
        tokio::time::timeout(std::time::Duration::from_secs(5), serving).await??;
        Ok(())
    }

    #[tokio::test]
    async fn a_client_can_submit_and_then_read_back_status() -> anyhow::Result<()> {
        let store = Arc::new(JobStore::open_in_memory()?);
        let (client, server) = UnixStream::pair()?;
        let registry = Arc::new(JobRegistry::new()?);
        let host_registry = Arc::new(HostRegistry::default());
        let serving = tokio::spawn(serve_connection(
            server,
            store,
            Arc::new(EnvironmentStore::open_in_memory()?),
            registry,
            host_registry,
            None,
        ));

        let mut client = client;
        write_frame(
            &mut client,
            &ControlRequest {
                request_id: 1,
                op: Some(control_request::Op::Submit(SubmitRequest {
                    manifest: b"m".to_vec(),
                    manifest_encoding: "test/v1".to_owned(),
                    submitter_caps: Vec::new(),
                    required_isolation_class: sandy_control_proto::IsolationClass::Trusted.into(),
                    inputs: Vec::new(),
                    outputs: Vec::new(),
                    secrets: Vec::new(),
                    credential: None,
                    cred_capabilities: Vec::new(),
                    egress: None,
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
        let serving = tokio::spawn(serve_connection(
            server,
            store,
            Arc::new(EnvironmentStore::open_in_memory()?),
            registry,
            host_registry,
            None,
        ));

        let mut client = client;
        write_frame(
            &mut client,
            &ControlRequest {
                request_id: 1,
                op: Some(control_request::Op::Submit(SubmitRequest {
                    manifest: b"m".to_vec(),
                    manifest_encoding: "test/v1".to_owned(),
                    submitter_caps: Vec::new(),
                    required_isolation_class: sandy_control_proto::IsolationClass::Trusted.into(),
                    inputs: Vec::new(),
                    outputs: Vec::new(),
                    secrets: Vec::new(),
                    credential: None,
                    cred_capabilities: Vec::new(),
                    egress: None,
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
        let serving = tokio::spawn(serve_connection(
            server,
            store,
            Arc::new(EnvironmentStore::open_in_memory()?),
            registry,
            host_registry,
            None,
        ));

        use tokio::io::AsyncWriteExt;
        let mut client = client;
        client.write_all(&[0, 0, 0, 100]).await?; // announces 100 bytes
        client.write_all(b"short").await?; // far fewer
        drop(client);

        tokio::time::timeout(std::time::Duration::from_secs(5), serving).await??;
        Ok(())
    }
}
