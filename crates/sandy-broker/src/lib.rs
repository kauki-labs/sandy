//! The broker HTTP API tier over sandyd (#591, `docs/decisions/broker-api.md`).
//!
//! Serves the job endpoints of `docs/api/broker.openapi.yaml` to bearer-token
//! clients and speaks the control RPC to one sandyd over a UDS.

mod auth;
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
    /// Directories the client may name in inputs, outputs and secrets.
    #[serde(default)]
    pub roots: Vec<PathBuf>,
}

/// Broker settings.
#[derive(Clone, Debug)]
pub struct BrokerConfig {
    /// sandyd's control socket.
    pub control_socket: PathBuf,
    /// Directory holding the 0600 job-owner table.
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
}

/// Binds the listener and serves until the returned [`Running`] drops.
///
/// # Errors
/// [`BrokerError::NonLoopback`] for a non-loopback address, [`BrokerError::Bind`]
/// when the address cannot be bound, [`BrokerError::Owners`] when the state
/// directory is unsafe or its table is unreadable.
pub async fn serve(config: BrokerConfig) -> Result<Running, BrokerError> {
    if !config.bind.ip().is_loopback() {
        return Err(BrokerError::NonLoopback { addr: config.bind });
    }
    let state = Arc::new(server::State {
        owners: owners::Owners::open(&config.state_dir)?,
        control_socket: config.control_socket,
        clients: config.clients,
    });
    let bind_err = |source| BrokerError::Bind {
        addr: config.bind,
        source,
    };
    let listener = TcpListener::bind(config.bind).await.map_err(bind_err)?;
    let addr = listener.local_addr().map_err(bind_err)?;
    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            let state = Arc::clone(&state);
            tokio::spawn(async move {
                let service = service_fn(move |req| {
                    let state = Arc::clone(&state);
                    async move { Ok::<_, std::convert::Infallible>(server::handle(state, req).await) }
                });
                if let Err(e) = hyper::server::conn::http1::Builder::new()
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
