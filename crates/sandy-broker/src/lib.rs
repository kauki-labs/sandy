//! The broker HTTP API tier over sandyd (#591, `docs/decisions/broker-api.md`).
//!
//! Serves the job and environment endpoints of `docs/api/broker.openapi.yaml` to bearer-token
//! clients and speaks the control RPC to one sandyd over a UDS.

mod attach;
mod auth;
mod body;
mod environments;
mod owners;
mod paths;
mod server;

use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
pub use owners::OwnersError;
use tokio::net::TcpListener;

/// The isolation class a client may request, lowest first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IsolationClass {
    /// May run only untrusted jobs.
    Untrusted,
    /// May also run trusted jobs.
    Trusted,
}

/// One API client, as read from the clients file.
#[derive(Clone, Debug, serde::Deserialize)]
pub struct Client {
    /// Stable client id, the owner key of its jobs.
    pub id: String,
    /// Lowercase hex SHA-256 of the client's bearer token.
    pub token_sha256: String,
    /// The highest isolation class the client may request.
    pub max_isolation_class: IsolationClass,
    /// Most non-terminal environments the client may hold at once.
    #[serde(default = "default_max_environments")]
    pub max_environments: usize,
    /// Most environments the client may ever create, deleted ones included. sandyd keeps
    /// a deleted row for replay, so this bounds the client's share of its table.
    #[serde(default = "default_max_environment_records")]
    pub max_environment_records: usize,
    /// Profile names the client may put in a spawn. Empty allows none.
    #[serde(default)]
    pub profiles: Vec<String>,
    /// Directories the client may name in inputs, outputs and secrets.
    #[serde(default)]
    pub roots: Vec<PathBuf>,
}

const fn default_max_environments() -> usize {
    4
}

const fn default_max_environment_records() -> usize {
    64
}

/// Broker settings.
#[derive(Clone, Debug)]
pub struct BrokerConfig {
    /// sandyd's control socket.
    pub control_socket: PathBuf,
    /// How long one control RPC may take, connect included.
    pub rpc_deadline: std::time::Duration,
    /// Directory holding the 0600 owner table.
    pub state_dir: PathBuf,
    /// Listen address. Must be loopback.
    pub bind: SocketAddr,
    /// Known clients.
    pub clients: Vec<Client>,
}

/// A running broker. Dropping it stops the listener.
#[derive(Debug)]
pub struct Running {
    /// The bound address.
    pub addr: SocketAddr,
    task: tokio::task::JoinHandle<()>,
}

impl Running {
    /// Waits for the listener task, which only ends if it is aborted.
    pub async fn wait(&mut self) {
        let _ = (&mut self.task).await;
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// The broker could not start.
#[derive(Debug, thiserror::Error)]
pub enum BrokerError {
    /// The requested address is not loopback, and this tier has no TLS yet.
    #[error("{addr} is not a loopback address; the broker serves plain HTTP on loopback only")]
    NonLoopback {
        /// The requested address.
        addr: SocketAddr,
    },
    /// Binding the listener failed.
    #[error("bind {addr}: {source}")]
    Bind {
        /// The requested address.
        addr: SocketAddr,
        /// The OS error.
        source: std::io::Error,
    },
    /// The owner table could not be opened.
    #[error(transparent)]
    Owners(#[from] OwnersError),
    /// The clients list is ambiguous or malformed.
    #[error("invalid clients: {0}")]
    InvalidClients(String),
}

/// Most connections served at once. A connection over the cap waits in the
/// accept queue instead of holding a task.
const MAX_CONNECTIONS: usize = 128;
/// Most requests in flight at once, detached ones included. One over the cap
/// gets `unavailable` at once.
const MAX_HANDLERS: usize = 64;
/// How long a client may take to send its request headers.
const HEADER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Refuses a clients list that could let one token act as another client:
/// duplicate ids or hashes, an empty id, or a hash that is not 64 lowercase hex.
fn validate_clients(clients: &[Client]) -> Result<(), BrokerError> {
    let bad = |m: String| Err(BrokerError::InvalidClients(m));
    let mut ids = std::collections::HashSet::new();
    let mut hashes = std::collections::HashSet::new();
    let mut prefixes = std::collections::HashSet::new();
    for c in clients {
        if c.id.is_empty() {
            return bad("a client has an empty id".to_owned());
        }
        let hex_ok = c.token_sha256.len() == 64
            && c.token_sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if !hex_ok {
            return bad(format!(
                "client {:?}: token_sha256 must be 64 lowercase hex digits",
                c.id
            ));
        }
        if !ids.insert(c.id.as_str()) {
            return bad(format!("duplicate client id {:?}", c.id));
        }
        if !prefixes.insert(environments::namespace_prefix(&c.id)) {
            return bad(format!(
                "client {:?} has the same idempotency namespace as another client",
                c.id
            ));
        }
        if !hashes.insert(c.token_sha256.as_str()) {
            return bad(format!("client {:?} shares a token hash with another client", c.id));
        }
    }
    Ok(())
}

/// Binds the listener and serves until the returned [`Running`] drops.
///
/// # Errors
/// [`BrokerError::NonLoopback`] for a non-loopback address, [`BrokerError::Bind`]
/// when the address cannot be bound, [`BrokerError::Owners`] when the state
/// directory is unsafe or its table is unreadable.
pub async fn serve(config: BrokerConfig) -> Result<Running, BrokerError> {
    serve_with_tuning(config, Tuning::default()).await
}

/// Attach-stream timing, for tests that need short ones.
#[doc(hidden)]
#[derive(Clone, Copy, Debug)]
pub struct Tuning {
    /// How long a stream ticket lives.
    pub ticket_ttl: std::time::Duration,
    /// How long one write to a client that stopped reading may block before the stream ends.
    pub send_timeout: std::time::Duration,
}

impl Default for Tuning {
    fn default() -> Self {
        Self {
            ticket_ttl: std::time::Duration::from_secs(30),
            send_timeout: std::time::Duration::from_secs(30),
        }
    }
}

/// [`serve`] with chosen attach-stream timing.
///
/// # Errors
/// As [`serve`].
#[doc(hidden)]
pub async fn serve_with_tuning(config: BrokerConfig, tuning: Tuning) -> Result<Running, BrokerError> {
    let ticket_ttl = tuning.ticket_ttl;
    if !config.bind.ip().is_loopback() {
        return Err(BrokerError::NonLoopback { addr: config.bind });
    }
    validate_clients(&config.clients)?;
    let env_create = config
        .clients
        .iter()
        .map(|c| (c.id.clone(), tokio::sync::Mutex::new(())))
        .collect();
    let state = Arc::new(server::State {
        owners: owners::Owners::open(&config.state_dir)?,
        tickets: attach::Tickets::new(ticket_ttl),
        control_socket: config.control_socket,
        rpc_deadline: config.rpc_deadline,
        clients: config.clients,
        env_create,
    });
    let bind_err = |source| BrokerError::Bind {
        addr: config.bind,
        source,
    };
    let listener = TcpListener::bind(config.bind).await.map_err(bind_err)?;
    let addr = listener.local_addr().map_err(bind_err)?;
    let slots = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
    let handlers = Arc::new(tokio::sync::Semaphore::new(MAX_HANDLERS));
    let task = tokio::spawn(async move {
        loop {
            let Ok(permit) = Arc::clone(&slots).acquire_owned().await else {
                return;
            };
            let stream = match listener.accept().await {
                Ok((stream, _)) => stream,
                Err(e) => {
                    // EMFILE and friends: back off instead of spinning.
                    tracing::warn!(error = %e, "accept failed");
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    continue;
                }
            };
            let state = Arc::clone(&state);
            let handlers = Arc::clone(&handlers);
            tokio::spawn(async move {
                let _permit = permit;
                let service = service_fn(move |req| {
                    let state = Arc::clone(&state);
                    let handlers = Arc::clone(&handlers);
                    async move {
                        // A handler slot is taken before spawning and moved into the
                        // task, so detached handlers stay bounded even after their
                        // connection is gone.
                        let Ok(slot) = handlers.try_acquire_owned() else {
                            return Ok(server::busy());
                        };
                        // Run the request on its own task: a client that hangs up
                        // mid-submit must not cancel the handler between sandyd
                        // accepting a job and the broker recording its owner.
                        let response = tokio::spawn(async move {
                            let _slot = slot;
                            server::handle(state, req).await
                        })
                        .await
                        .unwrap_or_else(|_| server::internal_error());
                        Ok::<_, std::convert::Infallible>(response)
                    }
                });
                if let Err(e) = hyper::server::conn::http1::Builder::new()
                    .timer(hyper_util::rt::TokioTimer::new())
                    .header_read_timeout(HEADER_TIMEOUT)
                    .serve_connection(TokioIo::new(stream), service)
                    .await
                {
                    tracing::debug!(error = %e, "connection ended with an error");
                }
            });
        }
    });
    Ok(Running { addr, task })
}
