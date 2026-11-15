//! `sandyd`: the per-machine control-plane daemon (epic #205). It serves #211's control RPC against a
//! sqlite-backed job store: a `Submit` mints a per-job channel and caps (see [`dispatch`]), places the job on a
//! registered host-executor through the [`host_registry`], and the executor runs it behind `sandy-agent`. The job
//! moves `Pending`, `Running`, then terminal, and `Attach` returns its channel and a cap. A
//! job a previous daemon left open is failed at the next start (#830).
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
mod envelope;
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
use sandy_control_proto::{
    ControlRequest, ControlResponse, control_request, control_response, read_frame, write_frame,
};
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

/// Which socket accepted a control connection (#888). Only the broker socket may carry a client id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Caller {
    /// The main control socket (`SANDY_SOCK`): the CLI, `sandy-mcp` and every other local tool.
    Main,
    /// The broker socket (`SANDYD_BROKER_SOCK`): the broker, which names the API client of a Submit.
    Broker,
}

/// The refusal for a Submit that carries a `client_id` on the main socket (#888), or `None` for anything else.
fn main_socket_client_id_refusal(caller: Caller, request: &ControlRequest) -> Option<ControlResponse> {
    let Some(control_request::Op::Submit(submit)) = &request.op else {
        return None;
    };
    if caller != Caller::Main || submit.client_id.is_none() {
        return None;
    }
    Some(ControlResponse {
        request_id: request.request_id,
        result: Some(control_response::Result::Error(sandy_control_proto::ControlError {
            message: "client_id is only accepted on the broker socket (SANDYD_BROKER_SOCK); this is the main control \
                      socket"
                .to_owned(),
        })),
    })
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
    caller: Caller,
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
        // #888: a client id is honoured only on the broker socket. On the main socket it is refused, never ignored, so
        // the CLI, `sandy-mcp` and every other local tool cannot write one into a receipt.
        let response = if let Some(refused) = main_socket_client_id_refusal(caller, &request) {
            refused
        // Environment operations have their own handler and store; every other
        // request goes to the job handler unchanged.
        } else if environment::is_environment_op(&request.op) {
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
            Caller::Main,
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

    /// One Submit over a connection accepted as `caller`, with a trusted process host registered so a valid Submit is
    /// placed. Returns the response and the store.
    async fn submit_as(caller: Caller, client_id: Option<&str>) -> anyhow::Result<(ControlResponse, Arc<JobStore>)> {
        submit_on(Arc::new(JobStore::open_in_memory()?), caller, client_id).await
    }

    /// [`submit_as`] on a store the test prepared.
    async fn submit_on(
        store: Arc<JobStore>,
        caller: Caller,
        client_id: Option<&str>,
    ) -> anyhow::Result<(ControlResponse, Arc<JobStore>)> {
        let (mut client, server) = UnixStream::pair()?;
        let registry = Arc::new(JobRegistry::new()?);
        let host_registry = Arc::new(HostRegistry::default());
        let peer_ip: std::net::IpAddr = "100.64.0.7".parse().context("peer ip literal")?;
        let fingerprint = sandy_conn::Fingerprint::from_hex(&"aa".repeat(32)).context("fingerprint literal")?;
        let _registration = host_registry
            .register(
                &host_registry::ExecutorAllowlist::new([(peer_ip, fingerprint)]),
                peer_ip,
                fingerprint,
                "test-host".to_owned(),
                sandy_executor_proto::Capabilities {
                    supported_sandbox_kinds: vec![sandy_executor_proto::SandboxKind::Process.into()],
                    arch: sandy_executor_proto::Arch::X8664.into(),
                    supported_isolation_classes: vec![sandy_executor_proto::IsolationClass::Trusted.into()],
                    ..sandy_executor_proto::Capabilities::default()
                },
            )
            .context("register a test host")?;
        let serving = tokio::spawn(serve_connection(
            server,
            Arc::clone(&store),
            Arc::new(EnvironmentStore::open_in_memory()?),
            registry,
            host_registry,
            Some("100.64.0.1:9000".parse().context("forward_back literal")?),
            caller,
        ));
        write_frame(
            &mut client,
            &ControlRequest {
                request_id: 1,
                op: Some(control_request::Op::Submit(SubmitRequest {
                    client_id: client_id.map(str::to_owned),
                    digests: false,
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
        drop(client);
        tokio::time::timeout(std::time::Duration::from_secs(5), serving).await??;
        Ok((response, store))
    }

    fn submitted_job(response: ControlResponse) -> anyhow::Result<String> {
        match response.result {
            Some(control_response::Result::Submit(sandy_control_proto::SubmitResponse { job_id, .. })) => Ok(job_id),
            other => anyhow::bail!("expected a Submit response, got {other:?}"),
        }
    }

    fn refusal(response: &ControlResponse) -> anyhow::Result<&str> {
        match &response.result {
            Some(control_response::Result::Error(e)) => Ok(&e.message),
            other => anyhow::bail!("expected a refusal, got {other:?}"),
        }
    }

    /// #888: a Submit that carries a client id on the main socket (the CLI, `sandy-mcp`, any local tool) is refused
    /// naming the field, never ignored, and no job is created.
    #[tokio::test]
    async fn a_client_id_is_refused_on_the_main_socket() -> anyhow::Result<()> {
        let (response, store) = submit_as(Caller::Main, Some("alice")).await?;

        let message = refusal(&response)?;
        assert!(message.contains("client_id"), "must name the field: {message}");
        assert!(store.list()?.is_empty(), "no job may be created");
        Ok(())
    }

    /// #888: on the broker socket the client id is accepted and stored on the job row.
    #[tokio::test]
    async fn a_client_id_is_stored_on_the_broker_socket() -> anyhow::Result<()> {
        let (response, store) = submit_as(Caller::Broker, Some("alice")).await?;

        let job = submitted_job(response)?;
        assert_eq!(store.client_id(&job)?.as_deref(), Some("alice"));
        Ok(())
    }

    /// #888: a client id that is empty, longer than 128 bytes, or holds a control character is refused naming the
    /// field, before placement, with no job created. 128 bytes is the longest valid id.
    #[tokio::test]
    async fn an_invalid_client_id_is_refused_on_the_broker_socket() -> anyhow::Result<()> {
        for bad in [
            String::new(),
            "x".repeat(129),
            "a\nb".to_owned(),
            "a\0b".to_owned(),
            "tab\there".to_owned(),
        ] {
            let (response, store) = submit_as(Caller::Broker, Some(&bad)).await?;
            let message = refusal(&response).with_context(|| format!("{bad:?}"))?;
            assert!(message.contains("client_id"), "{bad:?}: must name the field: {message}");
            assert!(store.list()?.is_empty(), "{bad:?}: no job may be created");
        }
        let (response, store) = submit_as(Caller::Broker, Some(&"x".repeat(128))).await?;
        let job = submitted_job(response)?;
        assert_eq!(
            store.client_id(&job)?.map(|id| id.len()),
            Some(128),
            "the bound is inclusive"
        );
        Ok(())
    }

    /// #888: the client id is written by the INSERT of the job row, not by a later UPDATE, so a crash or a fault between two
    /// statements cannot leave a job that names the uid. This store faults on any UPDATE of `client_id` (the stand-in
    /// for that window): the Submit must still succeed with the id on the row.
    #[tokio::test]
    async fn a_fault_after_the_insert_cannot_lose_the_client_id() -> anyhow::Result<()> {
        let conn = rusqlite::Connection::open_in_memory()?;
        conn.execute_batch(
            "CREATE TABLE jobs (
                job_id TEXT PRIMARY KEY, status TEXT NOT NULL, manifest BLOB NOT NULL,
                manifest_encoding TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
                client_id TEXT
            );
            CREATE TRIGGER no_client_id_update BEFORE UPDATE OF client_id ON jobs
            BEGIN SELECT RAISE(ABORT, 'a fault between the insert and the update'); END;",
        )?;

        let (response, store) = submit_on(
            Arc::new(JobStore::from_connection(conn)?),
            Caller::Broker,
            Some("alice"),
        )
        .await?;

        let job = submitted_job(response)?;
        assert_eq!(store.client_id(&job)?.as_deref(), Some("alice"));
        Ok(())
    }

    /// #888: with no client id nothing changes, on either socket: the Submit is placed and the job has no client id.
    #[tokio::test]
    async fn a_submit_without_a_client_id_is_unchanged_on_both_sockets() -> anyhow::Result<()> {
        for caller in [Caller::Main, Caller::Broker] {
            let (response, store) = submit_as(caller, None).await?;
            let job = submitted_job(response).with_context(|| format!("{caller:?}"))?;
            assert_eq!(store.client_id(&job)?, None, "{caller:?}");
        }
        Ok(())
    }

    #[tokio::test]
    async fn a_client_can_submit_and_then_read_back_status() -> anyhow::Result<()> {
        let store = Arc::new(JobStore::open_in_memory()?);
        let (client, server) = UnixStream::pair()?;
        let registry = Arc::new(JobRegistry::new()?);
        let host_registry = Arc::new(HostRegistry::default());
        // A Submit with no capable host is refused (#868), so register a trusted process host first.
        let peer_ip: std::net::IpAddr = "100.64.0.7".parse().context("peer ip literal")?;
        let fingerprint = sandy_conn::Fingerprint::from_hex(&"aa".repeat(32)).context("fingerprint literal")?;
        let _registration = host_registry
            .register(
                &host_registry::ExecutorAllowlist::new([(peer_ip, fingerprint)]),
                peer_ip,
                fingerprint,
                "test-host".to_owned(),
                sandy_executor_proto::Capabilities {
                    supported_sandbox_kinds: vec![sandy_executor_proto::SandboxKind::Process.into()],
                    arch: sandy_executor_proto::Arch::X8664.into(),
                    supported_isolation_classes: vec![sandy_executor_proto::IsolationClass::Trusted.into()],
                    ..sandy_executor_proto::Capabilities::default()
                },
            )
            .context("register a test host")?;
        let serving = tokio::spawn(serve_connection(
            server,
            store,
            Arc::new(EnvironmentStore::open_in_memory()?),
            registry,
            host_registry,
            Some("100.64.0.1:9000".parse().context("forward_back literal")?),
            Caller::Main,
        ));

        let mut client = client;
        write_frame(
            &mut client,
            &ControlRequest {
                request_id: 1,
                op: Some(control_request::Op::Submit(SubmitRequest {
                    client_id: None,
                    digests: false,
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
            Caller::Main,
        ));

        let mut client = client;
        write_frame(
            &mut client,
            &ControlRequest {
                request_id: 1,
                op: Some(control_request::Op::Submit(SubmitRequest {
                    client_id: None,
                    digests: false,
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
            Caller::Main,
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
