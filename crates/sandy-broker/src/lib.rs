//! The broker HTTP API tier over sandyd (#591, `docs/decisions/broker-api.md`).
//!
//! Serves the job endpoints of `docs/api/broker.openapi.yaml` to bearer-token
//! clients and speaks the control RPC to one sandyd over a UDS.

use std::{convert::Infallible, net::SocketAddr, path::PathBuf};

use http_body_util::Full;
use hyper::{
    Request, Response, StatusCode,
    body::{Bytes, Incoming},
    service::service_fn,
};
use hyper_util::rt::TokioIo;
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

/// A running broker.
#[derive(Debug)]
pub struct Running {
    /// The bound address.
    pub addr: SocketAddr,
    task: tokio::task::JoinHandle<()>,
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
}

/// Binds the listener and serves until the returned [`Running`] drops.
///
/// # Errors
/// Returns [`BrokerError::Bind`] when the address cannot be bound.
pub async fn serve(config: BrokerConfig) -> Result<Running, BrokerError> {
    let listener = TcpListener::bind(config.bind)
        .await
        .map_err(|source| BrokerError::Bind {
            addr: config.bind,
            source,
        })?;
    let addr = listener.local_addr().map_err(|source| BrokerError::Bind {
        addr: config.bind,
        source,
    })?;
    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            tokio::spawn(async move {
                let service = service_fn(|_req: Request<Incoming>| async {
                    Ok::<_, Infallible>(
                        Response::builder()
                            .status(StatusCode::NOT_IMPLEMENTED)
                            .body(Full::new(Bytes::new()))
                            .unwrap_or_default(),
                    )
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    Ok(Running { addr, task })
}
