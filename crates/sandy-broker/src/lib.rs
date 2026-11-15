//! The broker HTTP API tier over sandyd (#591, `docs/decisions/broker-api.md`).
//!
//! Serves the job and environment endpoints of `docs/api/broker.openapi.yaml` to bearer-token
//! clients and speaks the control RPC to one sandyd over a UDS.

mod attach;
mod auth;
mod body;
mod environments;
mod output;
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

/// A pinned client certificate (decision 10, #887).
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CertPin {
    /// The SHA-256 of the certificate's DER bytes: exactly 64 ASCII hex digits.
    pub sha256: String,
    /// Unix seconds after which the pin is refused. `None` never expires.
    #[serde(default)]
    pub not_after: Option<u64>,
}

/// One API client, as read from the clients file.
#[derive(Clone, Debug, serde::Deserialize)]
pub struct Client {
    /// Stable client id, the owner key of its jobs.
    pub id: String,
    /// Lowercase hex SHA-256 of the client's bearer token. Required in bearer mode, refused in mTLS mode.
    #[serde(default)]
    pub token_sha256: String,
    /// The certificates that authenticate this client in mTLS mode. Required there, refused in bearer mode.
    #[serde(default)]
    pub certs: Vec<CertPin>,
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
    /// Listen address. Loopback unless `tls` is set.
    pub bind: SocketAddr,
    /// Known clients.
    pub clients: Vec<Client>,
    /// `Some`: serve mutual TLS only, on any address, with no bearer path (decision 10). `None`: bearer over loopback.
    pub tls: Option<TlsConfig>,
}

/// mTLS settings (decision 10, #887).
#[derive(Clone, Debug)]
pub struct TlsConfig {
    /// The directory holding the broker's persisted TLS identity, created on first use. A caller pins its fingerprint.
    pub identity_dir: PathBuf,
}

/// A running broker. Dropping it stops the listener and the output collectors.
#[derive(Debug)]
pub struct Running {
    /// The bound address.
    pub addr: SocketAddr,
    /// The broker's TLS fingerprint (64 lowercase hex digits) in mTLS mode, which a caller pins. `None` in bearer
    /// mode.
    pub fingerprint: Option<String>,
    task: tokio::task::JoinHandle<()>,
    outputs: Arc<output::Outputs>,
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
        self.outputs.abort_collectors();
    }
}

/// The broker could not start.
#[derive(Debug, thiserror::Error)]
pub enum BrokerError {
    /// The requested address is not loopback, and no mutual TLS is configured: the bearer path is loopback only.
    #[error(
        "{addr} is not a loopback address; without --tls-identity-dir the broker serves plain HTTP on loopback only"
    )]
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
    /// Mutual TLS could not start: an unreadable or corrupt identity, or no usable pin.
    #[error("mutual TLS: {0}")]
    Tls(String),
}

/// Most connections served at once. A connection over the cap waits in the
/// accept queue instead of holding a task.
const MAX_CONNECTIONS: usize = 128;
/// Most requests in flight at once, detached ones included. One over the cap
/// gets `unavailable` at once.
const MAX_HANDLERS: usize = 64;
/// How long a client may take to send its request headers.
const HEADER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
/// How long an accepted TCP connection may take to finish its TLS handshake before it is dropped (decision 10).
const TLS_HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Refuses a clients list that could let one credential act as another client: duplicate ids or hashes, a client id
/// `sandyd` would refuse (#888), a hash that is not 64 lowercase hex, and, by mode (decision 10), a certificate pin
/// where only bearer tokens work or a bearer token where only certificates do. Returns the parsed pins, empty in
/// bearer mode.
fn validate_clients(clients: &[Client], tls: bool) -> Result<auth::Pins, BrokerError> {
    let bad = |m: String| Err(BrokerError::InvalidClients(m));
    let mut ids = std::collections::HashSet::new();
    let mut hashes = std::collections::HashSet::new();
    let mut prefixes = std::collections::HashSet::new();
    for c in clients {
        // The one check `sandyd` applies to a Submit's client id (#888), so a client whose id `sandyd` would refuse
        // never starts, instead of failing every submit later.
        if let Some(why) = sandy_control_proto::client_id_problem(&c.id) {
            return bad(format!(
                "client id {:?} {why}: a client id is 1 to {} bytes with no control character",
                c.id,
                sandy_control_proto::MAX_CLIENT_ID_BYTES
            ));
        }
        if tls {
            if !c.token_sha256.is_empty() {
                return bad(format!(
                    "client {:?}: a bearer token is refused in mTLS mode (there is no bearer path); remove \
                     token_sha256",
                    c.id
                ));
            }
            if c.certs.is_empty() {
                return bad(format!(
                    "client {:?}: mTLS mode needs at least one certificate pin in certs",
                    c.id
                ));
            }
        } else {
            if !c.certs.is_empty() {
                return bad(format!(
                    "client {:?}: certs is for mTLS mode, and this broker has no --tls-identity-dir",
                    c.id
                ));
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
            if !hashes.insert(c.token_sha256.as_str()) {
                return bad(format!("client {:?} shares a token hash with another client", c.id));
            }
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
    }
    auth::Pins::build(clients).map_err(BrokerError::InvalidClients)
}

/// Makes the identity directory safe before `sandy-conn` reads or writes the key in it (decision 10): created `0700`,
/// owned by this user and not writable by others, and a key already there is a regular `0600` file of this user's.
/// `sandy-conn` stays as it is, because the mesh uses the same loader. The directory is private, so nobody else can
/// swap the key between this check and the load.
///
/// Each refusal names the path and the fix, because an upgrade from a broker that made the directory under a loose
/// umask (0775, key 0644) meets them at startup.
fn prepare_identity_dir(dir: &std::path::Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let me = sandy_fsutil::current_uid();
    let shown = dir.display();
    // Read the directory first: the staging helper's own refusal names no fix.
    if let Ok(meta) = std::fs::symlink_metadata(dir) {
        if meta.file_type().is_symlink() {
            return Err(format!(
                "{shown} is a symlink: replace it with a real directory (`mkdir -m 700 {shown}`)"
            ));
        }
        if !meta.is_dir() {
            return Err(format!("{shown} is not a directory"));
        }
        if meta.uid() != me {
            return Err(format!(
                "{shown} is owned by another user: give it to the broker's user (`chown`) and run `chmod 700 {shown}`"
            ));
        }
        if meta.mode() & 0o022 != 0 {
            return Err(format!(
                "{shown} is mode {:o}: group or world can write it; run `chmod 700 {shown}`",
                meta.mode() & 0o777
            ));
        }
    }
    let owned = sandy_fsutil::OwnedDir::open_or_create(dir)
        .map_err(|e| format!("{e}; the directory must be mode 700 and owned by the broker's user"))?;
    let key = owned.path().join("identity.key.der");
    let meta = match std::fs::symlink_metadata(&key) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(format!("{}: {e}", key.display())),
    };
    let shown = key.display();
    if !meta.file_type().is_file() {
        return Err(format!(
            "{shown} is not a regular file (a symlink is refused): replace it with a regular file, or remove it to \
             mint a new identity (the fingerprint changes)"
        ));
    }
    if meta.uid() != me {
        return Err(format!(
            "{shown} is owned by another user: give it to the broker's user (`chown`), or remove it to mint a new \
             identity (the fingerprint changes)"
        ));
    }
    if meta.mode() & 0o077 != 0 {
        return Err(format!(
            "{shown} is mode {:o}: group or world can read it; run `chmod 600 {shown}`",
            meta.mode() & 0o777
        ));
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
    /// Bytes of one job's output the broker keeps. The oldest bytes drop first.
    pub output_job_cap: usize,
    /// Bytes of output the broker keeps across all jobs.
    pub output_total_cap: usize,
    /// How long a finished job's output stays readable.
    pub output_retention: std::time::Duration,
    /// Most output collectors one client may run at once. Later jobs wait for a slot.
    pub output_collectors_per_client: usize,
    /// Most output collectors the broker may run at once.
    pub output_collectors_total: usize,
    /// Wait between a collector's attach tries.
    pub output_join_backoff: std::time::Duration,
}

impl Default for Tuning {
    fn default() -> Self {
        Self {
            ticket_ttl: std::time::Duration::from_secs(30),
            send_timeout: std::time::Duration::from_secs(30),
            output_job_cap: 1024 * 1024,
            output_total_cap: 16 * 1024 * 1024,
            output_retention: std::time::Duration::from_secs(15 * 60),
            output_collectors_per_client: 16,
            output_collectors_total: 64,
            output_join_backoff: std::time::Duration::from_secs(10),
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
    // The bearer path is plaintext, so it is loopback only. Only mutual TLS may listen on another address (decision
    // 10).
    if !config.bind.ip().is_loopback() && config.tls.is_none() {
        return Err(BrokerError::NonLoopback { addr: config.bind });
    }
    let pins = validate_clients(&config.clients, config.tls.is_some())?;
    // Each root is resolved once, here: the canonical path is what the broker sends to sandyd as the root (#618), so a
    // client never controls it.
    let mut config = config;
    for client in &mut config.clients {
        client.roots = paths::canonical_roots(&client.roots)
            .map_err(|e| BrokerError::InvalidClients(format!("client {:?}: {e}", client.id)))?;
    }
    let bind = config.bind;
    let bind_err = |source| BrokerError::Bind { addr: bind, source };
    // Bound before any state is opened, so a broker that cannot listen leaves nothing behind.
    let (acceptor, addr, fingerprint) = if let Some(tls) = &config.tls {
        let now = auth::now_unix();
        let allowed = pins.live(now);
        if allowed.is_empty() {
            return Err(BrokerError::Tls(if now.is_none() {
                "the system clock cannot be read, so no certificate pin can be checked: fix the clock".to_owned()
            } else {
                "no usable certificate pin: every pin is past its not_after".to_owned()
            }));
        }
        let tls_err =
            |e: &dyn std::fmt::Display| BrokerError::Tls(format!("identity in {}: {e}", tls.identity_dir.display()));
        prepare_identity_dir(&tls.identity_dir).map_err(|e| tls_err(&e))?;
        let identity = sandy_conn::TlsIdentity::load_or_generate(&tls.identity_dir).map_err(|e| tls_err(&e))?;
        let fingerprint = identity.fingerprint().to_hex();
        let listener = sandy_conn::listen_tls(bind, identity, allowed, TLS_HANDSHAKE_TIMEOUT, None)
            .await
            .map_err(|e| match e {
                sandy_conn::ConnError::Io(source) => bind_err(source),
                other => BrokerError::Tls(other.to_string()),
            })?;
        let addr = listener
            .local_addr()
            .map_err(|e| BrokerError::Tls(format!("the bound address: {e}")))?;
        (Acceptor::Tls(listener), addr, Some(fingerprint))
    } else {
        let listener = TcpListener::bind(bind).await.map_err(bind_err)?;
        let addr = listener.local_addr().map_err(bind_err)?;
        (Acceptor::Plain(listener), addr, None)
    };
    let env_create = config
        .clients
        .iter()
        .map(|c| (c.id.clone(), tokio::sync::Mutex::new(())))
        .collect();
    let outputs = Arc::new(output::Outputs::new(
        tuning.output_job_cap,
        tuning.output_total_cap,
        config.clients.len(),
        tuning.output_retention,
        (tuning.output_collectors_per_client, tuning.output_collectors_total),
    ));
    let state = Arc::new(server::State {
        owners: owners::Owners::open(&config.state_dir)?,
        tickets: attach::Tickets::new(ticket_ttl),
        outputs: Arc::clone(&outputs),
        send_timeout: tuning.send_timeout,
        join_backoff: tuning.output_join_backoff,
        control_socket: config.control_socket,
        rpc_deadline: config.rpc_deadline,
        clients: config.clients,
        pins,
        env_create,
    });
    let slots = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
    let handlers = Arc::new(tokio::sync::Semaphore::new(MAX_HANDLERS));
    let task = tokio::spawn(async move {
        loop {
            let Ok(permit) = Arc::clone(&slots).acquire_owned().await else {
                return;
            };
            let (state, handlers) = (Arc::clone(&state), Arc::clone(&handlers));
            match &acceptor {
                Acceptor::Plain(listener) => {
                    let stream = match listener.accept().await {
                        Ok((stream, _)) => stream,
                        Err(e) => {
                            // EMFILE and friends: back off instead of spinning.
                            tracing::warn!(error = %e, "accept failed");
                            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                            continue;
                        }
                    };
                    tokio::spawn(async move {
                        let _permit = permit;
                        serve_stream(TokioIo::new(stream), server::Peer::Bearer, state, handlers).await;
                    });
                }
                Acceptor::Tls(listener) => {
                    let raw = match listener.accept_raw().await {
                        Ok(raw) => raw,
                        Err(e) => {
                            tracing::warn!(error = %e, "accept failed");
                            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                            continue;
                        }
                    };
                    // The handshake runs in the connection's own task, so one slow peer never delays the next accept.
                    // It holds the connection slot meanwhile (bounded by the handshake timeout).
                    tokio::spawn(async move {
                        let _permit = permit;
                        let peer_addr = match &raw {
                            sandy_conn::AcceptedStream::PendingTls(_, addr, ..) => Some(*addr),
                            sandy_conn::AcceptedStream::Ready(..) => None,
                        };
                        match raw.handshake().await {
                            Ok((conn, sandy_conn::PeerAddr::TcpTls(_, fingerprint))) => {
                                serve_stream(TokioIo::new(conn), server::Peer::Cert(fingerprint), state, handlers)
                                    .await;
                            }
                            Ok(_) => tracing::error!("a TLS listener produced a peer with no certificate; dropped"),
                            Err(e) => {
                                // The typed reason and the peer address, never certificate bytes.
                                let kind = match e {
                                    sandy_conn::ConnError::Tls(_) => "tls",
                                    sandy_conn::ConnError::HandshakeTimeout => "handshake_timeout",
                                    sandy_conn::ConnError::Io(_) => "io",
                                };
                                tracing::warn!(kind, peer = ?peer_addr, "handshake refused");
                            }
                        }
                    });
                }
            }
        }
    });
    Ok(Running {
        addr,
        fingerprint,
        task,
        outputs,
    })
}

/// What the broker accepts connections on: plaintext TCP (loopback, bearer) or mutual TLS.
enum Acceptor {
    Plain(TcpListener),
    Tls(sandy_conn::Listener),
}

/// Serve one accepted connection: HTTP/1.1 requests, each resolved to a client by `peer`.
async fn serve_stream<S>(io: S, peer: server::Peer, state: Arc<server::State>, handlers: Arc<tokio::sync::Semaphore>)
where
    S: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
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
                server::handle(state, req, peer).await
            })
            .await
            .unwrap_or_else(|_| server::internal_error());
            Ok::<_, std::convert::Infallible>(response)
        }
    });
    if let Err(e) = hyper::server::conn::http1::Builder::new()
        .timer(hyper_util::rt::TokioTimer::new())
        .header_read_timeout(HEADER_TIMEOUT)
        .serve_connection(io, service)
        .await
    {
        tracing::debug!(error = %e, "connection ended with an error");
    }
}
