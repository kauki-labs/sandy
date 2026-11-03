//! The one stream transport sandyd's control RPC (and, later, cross-machine
//! channel delivery) ride: UDS (local) → vsock (VM guest) → TCP/QUIC-over-mesh
//! (cross-machine), per epic #205's B6. Each tier produces the same thing — an
//! ordered, duplex byte stream ([`Conn`]) — so `sandy-control-proto`'s
//! length-prefixed framing rides any of them unchanged; swapping tiers is an
//! address choice, never a protocol change.
//!
//! Current state: UDS and the TCP/mesh tier (#159). vsock is parked (no
//! consumer yet; #216's agent-link relay covers the cross-machine dispatch
//! case this crate originally scoped vsock for). QUIC-over-mesh lands as
//! [`ConnAddr`] grows a variant and [`connect`]/[`listen`] grow a match arm,
//! not as a redesign.

use std::{
    net::SocketAddr,
    os::unix::fs::FileTypeExt,
    path::{Path, PathBuf},
    time::Duration,
};

pub mod bridge;
pub mod dial;

use tokio::net::{TcpListener, TcpStream, UnixListener, UnixStream};

/// An address to [`connect`] to or [`listen`] on, naming a tier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnAddr {
    /// A Unix domain socket path (step-1, local).
    Uds(PathBuf),
    /// A TCP socket address — the mesh tier (#159): the hosts are already on
    /// the Headscale/Netbird mesh, so a plain TCP dial to the peer's mesh IP
    /// is the whole "cross-machine" step, with WireGuard's own
    /// authentication and encryption as the trust boundary for whatever
    /// protocol rides this connection (no additional mTLS layer for step-1).
    Tcp(SocketAddr),
}

/// A connection failure: dialing, accepting, or binding.
#[derive(Debug, thiserror::Error)]
pub enum ConnError {
    /// The underlying I/O failed.
    #[error("connection I/O: {0}")]
    Io(#[from] std::io::Error),
    /// A TLS-tier failure: config construction, the handshake itself, or a
    /// pinned-key fingerprint mismatch (decision 20).
    #[error("TLS: {0}")]
    Tls(String),
    /// An accepted TCP connection did not complete its TLS handshake within
    /// the configured timeout (decision 20) — dropped rather than held
    /// forever.
    #[error("TLS handshake did not complete within the configured timeout")]
    HandshakeTimeout,
}

/// TCP keepalive tuning for a connection — the half-open-detection fix from
/// #289: without this, a vanished peer (power-off, partition) leaves a
/// TCP connection the kernel still reports as open, so the orchestrator's
/// "the connection is the liveness signal" model (#269) never notices and
/// keeps dispatching to a peer that's gone. The kernel tears the connection
/// down once `idle` has passed with no traffic and `retries` keepalive
/// probes spaced `interval` apart go unanswered — total detection time is
/// roughly `idle + interval * retries`.
///
/// UDS has no equivalent (local peers can't "vanish" the way a cross-machine
/// one can — a crashed local process gives an immediate connection-reset),
/// so this only applies to the TCP tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpKeepalive {
    /// How long the connection may sit idle before the first keepalive probe.
    pub idle: Duration,
    /// Spacing between successive unanswered probes.
    pub interval: Duration,
    /// How many unanswered probes before the kernel gives up on the peer.
    pub retries: u32,
}

impl TcpKeepalive {
    /// A profile tuned to detect a vanished peer within roughly one to two
    /// minutes (`idle + interval * retries` = 30s + 15s * 4 = 90s) — #289
    /// item 1's ruling for the orchestrator↔host-client management channel,
    /// used on both the dial (`sandy-host-executor`) and accept (`sandyd`'s
    /// `host_conn`) sides so either direction notices a half-open peer.
    pub const HALF_OPEN_DETECTION: TcpKeepalive = TcpKeepalive {
        idle: Duration::from_secs(30),
        interval: Duration::from_secs(15),
        retries: 4,
    };
}

fn apply_tcp_keepalive(stream: &TcpStream, keepalive: &TcpKeepalive) -> std::io::Result<()> {
    let params = socket2::TcpKeepalive::new()
        .with_time(keepalive.idle)
        .with_interval(keepalive.interval)
        .with_retries(keepalive.retries);
    socket2::SockRef::from(stream).set_tcp_keepalive(&params)
}

/// An ordered, duplex byte stream — what `sandy-control-proto`'s
/// length-prefixed framing (`write_frame`/`read_frame`) rides directly,
/// whichever tier produced it. A blanket impl: any type that is already
/// `AsyncRead + AsyncWrite + Send + Unpin` (every tokio stream type) gets this
/// for free.
pub trait Conn: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin> Conn for T {}

/// Dial `addr`, returning a duplex stream once connected.
///
/// # Errors
/// [`ConnError::Io`] if the dial fails (no listener, permission denied, …).
pub async fn connect(addr: &ConnAddr) -> Result<Box<dyn Conn>, ConnError> {
    match addr {
        ConnAddr::Uds(path) => Ok(Box::new(UnixStream::connect(path).await?)),
        ConnAddr::Tcp(socket_addr) => Ok(Box::new(TcpStream::connect(socket_addr).await?)),
    }
}

/// Dial a TCP peer with [`TcpKeepalive`] tuning applied before handing the
/// connection back, so a vanished peer is detected rather than left
/// half-open forever. See [`TcpKeepalive`] for what "vanished" covers and
/// why this is TCP-only.
///
/// # Errors
/// [`ConnError::Io`] if the dial or the keepalive sockopt call fails.
pub async fn connect_tcp_keepalive(addr: SocketAddr, keepalive: TcpKeepalive) -> Result<Box<dyn Conn>, ConnError> {
    let stream = TcpStream::connect(addr).await?;
    apply_tcp_keepalive(&stream, &keepalive)?;
    Ok(Box::new(stream))
}

/// An accepted connection's peer identity, tagged by the tier it arrived on.
///
/// Not `Option<SocketAddr>`: each tier's own peer-auth check needs its own
/// identity kind — a mesh IP for TCP, a CID for vsock (parked, no variant
/// yet), a peer uid for UDS (no consumer needs it yet, so [`PeerAddr::Uds`]
/// carries nothing rather than guessing a shape nobody's checked against). A
/// lossy `Option<SocketAddr>` would force every non-TCP tier's real identity
/// into `None`, which a caller could too easily mistake for "no peer to
/// check" instead of "this tier's identity isn't `SocketAddr`-shaped."
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerAddr {
    /// A UDS peer carries no identity here yet (no consumer checks it); add
    /// a credential (peer uid) when one does, rather than reusing this
    /// variant to mean something it doesn't check today.
    Uds,
    /// The dialing peer's socket address, as the kernel reports it to
    /// `accept(2)` — on a mesh connection, this is the peer's mesh IP,
    /// authenticated by WireGuard underneath (see [`ConnAddr::Tcp`]).
    Tcp(SocketAddr),
    /// A TCP peer authenticated over mutual TLS (decision 20): the dialer's
    /// socket address plus the pinned-key [`Fingerprint`] its certificate
    /// presented — already verified against the listener's allowlist by the
    /// time [`Listener::accept`] returns this.
    TcpTls(SocketAddr, Fingerprint),
}

/// Accepts incoming connections on whatever [`listen`] bound.
pub struct Listener(ListenerInner);

enum ListenerInner {
    Uds(UnixListener),
    Tcp(TcpListener, Option<TcpKeepalive>),
    TcpTls(TcpListener, Option<TcpKeepalive>, tokio_rustls::TlsAcceptor, Duration),
}

/// A raw-accepted connection, from [`Listener::accept_raw`]: the TCP accept
/// has completed but a TLS-tier connection has not yet run its handshake.
/// Splitting the two steps is what lets a caller re-arm the next accept
/// immediately rather than waiting on one peer's handshake (see
/// `accept_raw`'s own doc for the hazard this avoids).
pub enum AcceptedStream {
    /// Already a usable connection — the UDS and plaintext-TCP tiers have no
    /// handshake step, so there is nothing left to defer.
    Ready(Box<dyn Conn>, PeerAddr),
    /// A TCP-tier TLS connection whose handshake has not run yet. Call
    /// [`AcceptedStream::handshake`] to complete it.
    PendingTls(TcpStream, SocketAddr, tokio_rustls::TlsAcceptor, Duration),
}

impl AcceptedStream {
    /// Complete the connection: a no-op for [`AcceptedStream::Ready`], or run
    /// the deferred TLS handshake for [`AcceptedStream::PendingTls`].
    ///
    /// # Errors
    /// [`ConnError::HandshakeTimeout`] if the TLS handshake does not finish
    /// within the configured timeout, or [`ConnError::Tls`] for any other
    /// handshake failure (a wrong pinned key, no client certificate, …).
    pub async fn handshake(self) -> Result<(Box<dyn Conn>, PeerAddr), ConnError> {
        match self {
            AcceptedStream::Ready(conn, peer) => Ok((conn, peer)),
            AcceptedStream::PendingTls(stream, addr, acceptor, handshake_timeout) => {
                let tls_stream = tokio::time::timeout(handshake_timeout, acceptor.accept(stream))
                    .await
                    .map_err(|_elapsed| ConnError::HandshakeTimeout)?
                    .map_err(|err| ConnError::Tls(format!("TLS handshake: {err}")))?;
                let peer_cert = tls_stream
                    .get_ref()
                    .1
                    .peer_certificates()
                    .and_then(|certs| certs.first())
                    .ok_or_else(|| ConnError::Tls("no client certificate presented".to_owned()))?;
                let fingerprint = Fingerprint::of(peer_cert);
                Ok((Box::new(tls_stream), PeerAddr::TcpTls(addr, fingerprint)))
            }
        }
    }
}

impl Listener {
    /// Accept the next incoming connection without running a TLS-tier
    /// handshake yet: the raw `accept(2)` resolves as soon as the OS hands
    /// over a connection, so a caller holding one pending accept at a time
    /// (as `sandyd`'s mesh accept loops do) is never blocked by another
    /// peer's in-progress handshake — the hazard `accept`'s doc used to warn
    /// callers about. Call [`AcceptedStream::handshake`] to finish it.
    ///
    /// # Errors
    /// [`ConnError::Io`] if accepting fails.
    pub async fn accept_raw(&self) -> Result<AcceptedStream, ConnError> {
        match &self.0 {
            ListenerInner::Uds(listener) => {
                let (stream, _addr) = listener.accept().await?;
                Ok(AcceptedStream::Ready(Box::new(stream), PeerAddr::Uds))
            }
            ListenerInner::Tcp(listener, keepalive) => {
                let (stream, addr) = listener.accept().await?;
                if let Some(keepalive) = keepalive {
                    apply_tcp_keepalive(&stream, keepalive)?;
                }
                Ok(AcceptedStream::Ready(Box::new(stream), PeerAddr::Tcp(addr)))
            }
            ListenerInner::TcpTls(listener, keepalive, acceptor, handshake_timeout) => {
                let (stream, addr) = listener.accept().await?;
                if let Some(keepalive) = keepalive {
                    apply_tcp_keepalive(&stream, keepalive)?;
                }
                Ok(AcceptedStream::PendingTls(
                    stream,
                    addr,
                    acceptor.clone(),
                    *handshake_timeout,
                ))
            }
        }
    }

    /// Accept the next incoming connection, with the peer's identity on
    /// whatever tier this listener is — [`Listener::accept_raw`] followed
    /// immediately by [`AcceptedStream::handshake`]. Fine for a caller with no
    /// reason to split the two steps; `sandyd`'s mesh/host-conn accept loops
    /// use `accept_raw` and `handshake` separately instead, so one peer's
    /// handshake never delays the next accept.
    ///
    /// # Errors
    /// [`ConnError::Io`] if accepting fails, or whatever [`AcceptedStream::handshake`] returns.
    pub async fn accept(&self) -> Result<(Box<dyn Conn>, PeerAddr), ConnError> {
        self.accept_raw().await?.handshake().await
    }

    /// The address actually bound — the OS-assigned port when [`listen`] was
    /// given port 0, as every test here does to avoid a fixed, collidable
    /// port. UDS has no socket address of this kind.
    ///
    /// # Errors
    /// [`ConnError::Io`] on the UDS tier, or if the underlying query fails.
    pub fn local_addr(&self) -> Result<SocketAddr, ConnError> {
        match &self.0 {
            ListenerInner::Uds(_) => Err(ConnError::Io(std::io::Error::other(
                "a UDS listener has no SocketAddr; local_addr is TCP-only",
            ))),
            ListenerInner::Tcp(listener, _keepalive) => Ok(listener.local_addr()?),
            ListenerInner::TcpTls(listener, ..) => Ok(listener.local_addr()?),
        }
    }
}

/// Bind `addr`, returning a [`Listener`] ready to [`Listener::accept`].
///
/// For a UDS path left behind by a crashed prior listener (a real socket file
/// with nothing behind it — a well-known UDS footgun absent from TCP, which
/// has no filesystem footprint), this detects staleness by probing with a
/// connect and removes the orphan before (re)binding. A path where something
/// is genuinely still listening is never touched — [`ConnError::Io`]
/// propagates instead, so a second `sandyd` instance can't silently steal the
/// first's socket.
///
/// # Errors
/// [`ConnError::Io`] if binding fails: another listener genuinely holds the
/// path, or the path is otherwise inaccessible (permissions, missing parent
/// directory, …).
pub async fn listen(addr: &ConnAddr) -> Result<Listener, ConnError> {
    match addr {
        ConnAddr::Uds(path) => Ok(Listener(ListenerInner::Uds(bind_uds(path).await?))),
        ConnAddr::Tcp(socket_addr) => Ok(Listener(ListenerInner::Tcp(
            TcpListener::bind(socket_addr).await?,
            None,
        ))),
    }
}

/// Bind a TCP listener that applies [`TcpKeepalive`] to every accepted
/// connection, so a vanished peer on the accepting side is detected the same
/// way a dialing one is via [`connect_tcp_keepalive`].
///
/// # Errors
/// [`ConnError::Io`] if binding fails.
pub async fn listen_tcp_keepalive(addr: SocketAddr, keepalive: TcpKeepalive) -> Result<Listener, ConnError> {
    Ok(Listener(ListenerInner::Tcp(
        TcpListener::bind(addr).await?,
        Some(keepalive),
    )))
}

/// A pinned-key fingerprint: the SHA-256 digest of a [`TlsIdentity`]'s
/// end-entity certificate DER bytes. This is the identity a peer is checked
/// against (decision 20: pinned per-host keys, not a CA) — never a chain
/// validation, since every certificate here is self-signed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Fingerprint([u8; 32]);

impl Fingerprint {
    fn of(cert: &rustls::pki_types::CertificateDer<'_>) -> Self {
        use sha2::Digest;
        let digest = sha2::Sha256::digest(cert.as_ref());
        Fingerprint(digest.into())
    }

    /// Render as lowercase hex, for config files and CLI display.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex_encode(&self.0)
    }

    /// Parse a lowercase-or-uppercase hex fingerprint, as produced by
    /// [`Fingerprint::to_hex`].
    ///
    /// # Errors
    /// [`ConnError::Tls`] if `hex` is not exactly 64 hex characters.
    pub fn from_hex(hex: &str) -> Result<Self, ConnError> {
        let bytes = hex_decode(hex).ok_or_else(|| ConnError::Tls(format!("not a 64-char hex fingerprint: {hex}")))?;
        Ok(Fingerprint(bytes))
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

fn hex_decode(s: &str) -> Option<[u8; 32]> {
    // `is_ascii` first: a 64-*byte* string containing a multi-byte UTF-8
    // character (e.g. one "€" plus 61 ASCII bytes) would pass the length
    // check below and then panic on a `&s[i*2..i*2+2]` slice that lands
    // mid-character. ASCII guarantees every byte is its own char boundary.
    if !s.is_ascii() || s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, chunk) in out.iter_mut().enumerate() {
        *chunk = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// A self-signed TLS identity for the mesh tier: a fresh keypair and the
/// matching self-signed certificate, minted once per node (decision 20 —
/// pinned per-host keys, no CA). The certificate's only job is to carry the
/// public key through the TLS handshake; its subject/SAN content is never
/// checked by either [`connect_tls`] or [`listen_tls`], only its
/// [`Fingerprint`].
pub struct TlsIdentity {
    cert: rustls::pki_types::CertificateDer<'static>,
    key: rustls::pki_types::PrivateKeyDer<'static>,
}

impl TlsIdentity {
    /// Generate a fresh self-signed identity.
    ///
    /// # Errors
    /// [`ConnError::Tls`] if key generation or self-signing fails.
    pub fn generate() -> Result<Self, ConnError> {
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["sandy-mesh".to_owned()])
                .map_err(|err| ConnError::Tls(format!("generating a self-signed identity: {err}")))?;
        let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(signing_key.serialize_der().into());
        Ok(TlsIdentity {
            cert: cert.der().clone(),
            key: key_der,
        })
    }

    /// This identity's [`Fingerprint`] — what a peer pins against.
    #[must_use]
    pub fn fingerprint(&self) -> Fingerprint {
        Fingerprint::of(&self.cert)
    }

    /// Load a previously persisted identity from `dir`
    /// (`identity.cert.der`/`identity.key.der`), or generate a fresh one and
    /// persist it there if `dir` holds neither file yet.
    ///
    /// Persisting (not regenerating on every start) is the whole point: a
    /// [`Fingerprint`] is the SHA-256 digest of the CERTIFICATE, so minting a
    /// fresh self-signed cert over the same key — or just calling
    /// [`Self::generate`] again — would change the fingerprint on every
    /// restart and silently break whatever peer pinned the old one (decision
    /// 20's "pinned per-host keys, not TOFU" only holds if the pinned value
    /// is actually stable across restarts).
    ///
    /// Exactly one of the two files existing is treated as a corrupt or
    /// tampered directory, not an invitation to regenerate: silently minting
    /// a new identity there would rotate the fingerprint without telling the
    /// operator, the same silent-failure class this module refuses elsewhere
    /// (decision 20: fail closed, never a silent downgrade).
    ///
    /// # Errors
    /// [`ConnError::Io`] if `dir` cannot be created, or exactly one of the two
    /// identity files exists; [`ConnError::Tls`] if an existing key file is
    /// not valid PKCS#8 DER, or key generation fails for a fresh identity.
    pub fn load_or_generate(dir: &Path) -> Result<Self, ConnError> {
        let cert_path = dir.join("identity.cert.der");
        let key_path = dir.join("identity.key.der");
        match (cert_path.exists(), key_path.exists()) {
            (true, true) => {
                let cert_bytes = std::fs::read(&cert_path)?;
                let key_bytes = std::fs::read(&key_path)?;
                Ok(TlsIdentity {
                    cert: rustls::pki_types::CertificateDer::from(cert_bytes),
                    key: rustls::pki_types::PrivateKeyDer::try_from(key_bytes)
                        .map_err(|err| ConnError::Tls(format!("loading persisted TLS key: {err}")))?,
                })
            }
            (false, false) => {
                let identity = Self::generate()?;
                identity.persist(dir, &cert_path, &key_path)?;
                Ok(identity)
            }
            (true, false) | (false, true) => Err(ConnError::Io(std::io::Error::other(format!(
                "{} holds only one of identity.cert.der/identity.key.der; refusing to regenerate over a \
                 partial/corrupt identity (that would silently rotate the pinned fingerprint)",
                dir.display()
            )))),
        }
    }

    /// Write this identity's cert/key DER bytes to `dir`, creating it if
    /// needed. The key is written mode 0600 at creation (same umask-bracketed
    /// discipline [`bind_uds_0600`] uses for the UDS socket) — a key readable
    /// by another local user defeats the whole point of pinning it.
    fn persist(&self, dir: &Path, cert_path: &Path, key_path: &Path) -> Result<(), ConnError> {
        std::fs::create_dir_all(dir)?;
        std::fs::write(cert_path, self.cert.as_ref())?;
        use std::os::unix::fs::OpenOptionsExt;
        let mut key_file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(key_path)?;
        use std::io::Write;
        key_file.write_all(self.key.secret_der())?;
        Ok(())
    }
}

fn ensure_crypto_provider() {
    static INSTALLED: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    INSTALLED.get_or_init(|| {
        // Ignore the result: a concurrent caller (or an embedding binary)
        // may have already installed a different provider (e.g. aws-lc-rs,
        // also in this workspace's dependency graph via octocrab), which is
        // fine — we only need *a* provider installed, and the verifiers
        // below always read back whichever one actually won via
        // `active_verification_algorithms`, never assuming it was ring's.
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// The signature-verification algorithms of whichever [`rustls::CryptoProvider`]
/// actually won process-wide installation — never hardcoded to `ring`, since
/// [`ensure_crypto_provider`] only guarantees *some* provider is installed,
/// not which one (another dependency may install `aws-lc-rs` first). The
/// `ring` fallback only matters if this is somehow called before any
/// `connect_tls`/`listen_tls` call has run `ensure_crypto_provider`.
fn active_verification_algorithms() -> &'static rustls::crypto::WebPkiSupportedAlgorithms {
    if let Some(provider) = rustls::crypto::CryptoProvider::get_default() {
        return &provider.signature_verification_algorithms;
    }
    static FALLBACK: std::sync::OnceLock<rustls::crypto::CryptoProvider> = std::sync::OnceLock::new();
    &FALLBACK
        .get_or_init(rustls::crypto::ring::default_provider)
        .signature_verification_algorithms
}

#[derive(Debug)]
struct PinnedServerVerifier {
    allowed: std::collections::HashSet<Fingerprint>,
}

impl rustls::client::danger::ServerCertVerifier for PinnedServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        if self.allowed.contains(&Fingerprint::of(end_entity)) {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "server certificate fingerprint is not in the pinned allowlist".to_owned(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, active_verification_algorithms())
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, active_verification_algorithms())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        active_verification_algorithms().supported_schemes()
    }
}

#[derive(Debug)]
struct PinnedClientVerifier {
    allowed: std::collections::HashSet<Fingerprint>,
}

impl rustls::server::danger::ClientCertVerifier for PinnedClientVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        // Fail closed (decision 20): an anonymous peer is never accepted.
        true
    }

    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        if self.allowed.contains(&Fingerprint::of(end_entity)) {
            Ok(rustls::server::danger::ClientCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "client certificate fingerprint is not in the pinned allowlist".to_owned(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, active_verification_algorithms())
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, active_verification_algorithms())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        active_verification_algorithms().supported_schemes()
    }
}

fn client_tls_config(
    identity: &TlsIdentity,
    expected_peer: Fingerprint,
) -> Result<std::sync::Arc<rustls::ClientConfig>, ConnError> {
    ensure_crypto_provider();
    let verifier = PinnedServerVerifier {
        allowed: std::collections::HashSet::from([expected_peer]),
    };
    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(std::sync::Arc::new(verifier))
        .with_client_auth_cert(vec![identity.cert.clone()], identity.key.clone_key())
        .map_err(|err| ConnError::Tls(format!("building the TLS client config: {err}")))?;
    Ok(std::sync::Arc::new(config))
}

fn server_tls_config(
    identity: &TlsIdentity,
    allowed: std::collections::HashSet<Fingerprint>,
) -> Result<std::sync::Arc<rustls::ServerConfig>, ConnError> {
    ensure_crypto_provider();
    let verifier = PinnedClientVerifier { allowed };
    let config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(std::sync::Arc::new(verifier))
        .with_single_cert(vec![identity.cert.clone()], identity.key.clone_key())
        .map_err(|err| ConnError::Tls(format!("building the TLS server config: {err}")))?;
    Ok(std::sync::Arc::new(config))
}

/// Dial `addr` over mutual TLS, pinning the peer to `expected_peer`'s
/// [`Fingerprint`] (decision 20) rather than validating a certificate chain —
/// every identity here is self-signed, so chain validation would check
/// nothing. [`TcpKeepalive`], if given, is applied to the underlying TCP
/// socket before the handshake, so it governs the connection regardless of
/// the TLS layer above it.
///
/// # Errors
/// [`ConnError::Io`] if the TCP dial fails; [`ConnError::Tls`] if the
/// handshake fails or the peer's certificate fingerprint does not match
/// `expected_peer`.
pub async fn connect_tls(
    addr: SocketAddr,
    identity: &TlsIdentity,
    expected_peer: Fingerprint,
    keepalive: Option<TcpKeepalive>,
) -> Result<Box<dyn Conn>, ConnError> {
    let stream = TcpStream::connect(addr).await?;
    if let Some(keepalive) = &keepalive {
        apply_tcp_keepalive(&stream, keepalive)?;
    }
    let config = client_tls_config(identity, expected_peer)?;
    let connector = tokio_rustls::TlsConnector::from(config);
    let server_name = rustls::pki_types::ServerName::IpAddress(addr.ip().into());
    let tls_stream = connector
        .connect(server_name, stream)
        .await
        .map_err(|err| ConnError::Tls(format!("TLS handshake: {err}")))?;
    Ok(Box::new(tls_stream))
}

/// Bind `addr`, accepting only mutual-TLS connections from a peer whose
/// certificate fingerprint is in `allowed` (decision 20). Refuses to bind at
/// all if `allowed` is empty — a listener with no one who could ever connect
/// is a startup-time misconfiguration, not a running-but-useless listener
/// (mirrors decision 13's empty-allowlist refusal). An accepted TCP
/// connection that does not complete the TLS handshake within
/// `handshake_timeout` is dropped rather than held forever.
///
/// **Caller note:** [`Listener::accept`] bundles the raw TCP accept and the
/// full TLS handshake into one future. A caller that holds a single pending
/// accept at a time (as `sandyd`'s mesh accept loops do) should use
/// [`Listener::accept_raw`] and [`AcceptedStream::handshake`] separately
/// instead, so one peer's handshake never delays the next raw accept.
///
/// # Errors
/// [`ConnError::Io`] if binding fails, or `allowed` is empty.
pub async fn listen_tls(
    addr: SocketAddr,
    identity: TlsIdentity,
    allowed: std::collections::HashSet<Fingerprint>,
    handshake_timeout: Duration,
    keepalive: Option<TcpKeepalive>,
) -> Result<Listener, ConnError> {
    if allowed.is_empty() {
        return Err(ConnError::Io(std::io::Error::other(
            "listen_tls refuses an empty pinned-key allowlist: nobody could ever connect",
        )));
    }
    let config = server_tls_config(&identity, allowed)?;
    let listener = TcpListener::bind(addr).await?;
    Ok(Listener(ListenerInner::TcpTls(
        listener,
        keepalive,
        tokio_rustls::TlsAcceptor::from(config),
        handshake_timeout,
    )))
}

async fn bind_uds(path: &Path) -> Result<UnixListener, ConnError> {
    // The whole check-probe-maybe-remove-bind sequence must be atomic across
    // every caller — same process or a different one — or two callers racing
    // to recover the same orphaned path can both conclude "stale" and
    // interleave a remove_file against the socket the other just bound. An
    // flock on a sibling lockfile serializes it, same pattern as
    // sandy::journal's job locks: not the socket path itself, since recovery
    // unlinks and rebinds that path, which a lock ON it wouldn't survive.
    let lock_path = lock_file_path(path);
    let _lock = tokio::task::spawn_blocking(move || -> std::io::Result<std::fs::File> {
        use std::os::unix::fs::OpenOptionsExt;
        // mode(0o600): a world-readable lockfile lets another local user open
        // it and take LOCK_EX, blocking every future listen() here (CWE-59,
        // availability, not data exposure — the file holds no content).
        // NOFOLLOW: refuse a symlink planted at the lockfile path for the
        // same reason the socket path itself is checked above.
        let file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(&lock_path)?;
        fs2::FileExt::lock_exclusive(&file)?;
        Ok(file)
    })
    .await
    .map_err(std::io::Error::other)??;

    bind_uds_locked(path).await
    // _lock drops here, releasing the flock — held only for this function's
    // duration, not the listener's whole lifetime.
}

fn lock_file_path(socket_path: &Path) -> PathBuf {
    let mut lock_path = socket_path.as_os_str().to_owned();
    lock_path.push(".lock");
    PathBuf::from(lock_path)
}

async fn bind_uds_locked(path: &Path) -> Result<UnixListener, ConnError> {
    // Checked before the first bind attempt at all, not only inside AddrInUse
    // recovery below: AF_UNIX `bind()` follows a symlink at the target path,
    // so an attacker who pre-plants one at a predictable socket path (e.g.
    // $XDG_RUNTIME_DIR/sandyd.sock) could redirect the real socket wherever
    // the link points. Refuse outright rather than silently following it.
    if is_symlink(path) {
        return Err(ConnError::Io(std::io::Error::other(format!(
            "refusing to bind through a symlink at {}",
            path.display()
        ))));
    }
    match bind_uds_0600(path) {
        Ok(listener) => Ok(listener),
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
            // Only a real UDS at this path is even eligible for orphan
            // recovery: a plain file (or anything else) left at the
            // configured path also makes bind() fail with AddrInUse, and
            // deleting an unrelated file just because it occupies this path
            // would be a worse bug than the one being guarded against.
            if !is_socket(path) {
                return Err(ConnError::Io(e));
            }
            match UnixStream::connect(path).await {
                // Answered (even if it then closes immediately): a real
                // listener holds this path.
                Ok(_) => Err(ConnError::Io(e)),
                // Refused specifically is the proof an orphan needs: the
                // socket file exists but nothing is listening behind it. Any
                // OTHER probe failure (permission denied, …) is inconclusive,
                // not proof of staleness, and must not trigger a delete.
                Err(probe_err) if probe_err.kind() == std::io::ErrorKind::ConnectionRefused => {
                    // Re-verified immediately before acting, not just relying
                    // on the check above: narrows, but doesn't eliminate
                    // (a true atomic remove-iff-still-this-exact-inode needs a
                    // heavier primitive than remove_file), the window between
                    // concluding "orphan" and acting on that conclusion.
                    if !is_socket(path) {
                        return Err(ConnError::Io(e));
                    }
                    std::fs::remove_file(path)?;
                    Ok(bind_uds_0600(path)?)
                }
                Err(_) => Err(ConnError::Io(e)),
            }
        }
        Err(e) => Err(e.into()),
    }
}

/// `path`'s own file type is a symlink. `symlink_metadata`, unlike `metadata`,
/// does not follow the link, so this reports the link itself, not its target.
fn is_symlink(path: &Path) -> bool {
    std::fs::symlink_metadata(path)
        .map(|metadata| metadata.file_type().is_symlink())
        .unwrap_or(false)
}

/// `path` exists and its own file type is a Unix domain socket.
fn is_socket(path: &Path) -> bool {
    std::fs::symlink_metadata(path)
        .map(|metadata| metadata.file_type().is_socket())
        .unwrap_or(false)
}

/// Binds a Unix listener at `path` with mode 0600, set at creation rather
/// than via a `chmod` afterward, which would leave a window where the socket
/// exists under the ambient (often far more permissive) umask. `bind(2)` on
/// an AF_UNIX socket takes no mode parameter of its own; the kernel applies
/// the umask exactly as it would for a new file. This brackets the one
/// `bind` syscall with a tightened umask and restores the original
/// immediately after. The umask is process-wide, not scoped to this call, so
/// unrelated file creation elsewhere in the process during this one syscall
/// would transiently see the tightened mask too: a narrow, single-syscall
/// window, and the standard, accepted tradeoff for a mode-at-creation UDS
/// bind (there is no race-free alternative without a mode parameter on bind
/// itself).
fn bind_uds_0600(path: &Path) -> std::io::Result<UnixListener> {
    use rustix::{fs::Mode, process::umask};
    let previous = umask(Mode::from_raw_mode(0o177));
    let bound = std::os::unix::net::UnixListener::bind(path);
    umask(previous);
    let std_listener = bound?;
    std_listener.set_nonblocking(true)?;
    UnixListener::from_std(std_listener)
}

#[cfg(test)]
mod tests {
    use anyhow::Context;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    fn uds_path(dir: &tempfile::TempDir) -> ConnAddr {
        ConnAddr::Uds(dir.path().join("sandy-conn-test.sock"))
    }

    #[tokio::test]
    async fn tcp_connect_and_accept_round_trip_bytes() -> anyhow::Result<()> {
        let addr = ConnAddr::Tcp("127.0.0.1:0".parse()?);
        let listener = listen(&addr).await.context("listen")?;
        let bound = ConnAddr::Tcp(listener.local_addr().context("local_addr")?);

        let ((accepted, peer), mut dialed) = tokio::try_join!(listener.accept(), connect(&bound))?;
        match peer {
            PeerAddr::Tcp(addr) => assert_eq!(addr.ip(), "127.0.0.1".parse::<std::net::IpAddr>()?),
            other => panic!("expected PeerAddr::Tcp, got {other:?}"),
        }
        let mut accepted = accepted;

        dialed.write_all(b"hello").await.context("write")?;
        dialed.flush().await?;
        let mut buf = [0u8; 5];
        accepted.read_exact(&mut buf).await.context("read")?;
        assert_eq!(&buf, b"hello");
        Ok(())
    }

    /// Precise version of the assertion above: the accepted `PeerAddr` must be
    /// exactly the dialing side's own bound address (ip *and* port), not just
    /// the right IP. Dials with a raw `TcpStream` directly (not `connect()`,
    /// which returns `Box<dyn Conn>` with no `local_addr()`) so the dialer's
    /// own address is available to compare against.
    #[tokio::test]
    async fn tcp_accept_reports_exactly_the_dialers_bound_address() -> anyhow::Result<()> {
        let listener = listen(&ConnAddr::Tcp("127.0.0.1:0".parse()?)).await.context("listen")?;
        let bound = listener.local_addr().context("local_addr")?;

        let (accept_result, dial_result) = tokio::join!(listener.accept(), tokio::net::TcpStream::connect(bound));
        let (_accepted, peer) = accept_result?;
        let dialed = dial_result.context("dial")?;
        let dialer_addr = dialed.local_addr().context("dialed.local_addr")?;

        assert_eq!(
            peer,
            PeerAddr::Tcp(dialer_addr),
            "the accepted peer must match the dialer's own bound address exactly"
        );
        Ok(())
    }

    #[tokio::test]
    async fn tcp_connecting_with_nothing_listening_fails_cleanly() -> anyhow::Result<()> {
        // Port 0 never has a real listener behind it as a dial target; a
        // closed, unused high port stands in for "nothing there."
        let addr = ConnAddr::Tcp("127.0.0.1:1".parse()?);
        assert!(
            connect(&addr).await.is_err(),
            "dialing a port nothing listens on must error, not hang"
        );
        Ok(())
    }

    #[tokio::test]
    async fn tcp_binding_port_zero_picks_a_free_ephemeral_port() -> anyhow::Result<()> {
        let addr = ConnAddr::Tcp("127.0.0.1:0".parse()?);
        let listener = listen(&addr).await.context("listen")?;
        assert_ne!(
            listener.local_addr().context("local_addr")?.port(),
            0,
            "the OS must assign a real port, not echo back 0"
        );
        Ok(())
    }

    #[tokio::test]
    async fn connect_and_accept_round_trip_bytes() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let addr = uds_path(&dir);
        let listener = listen(&addr).await.context("listen")?;

        let ((accepted, peer), mut dialed) = tokio::try_join!(listener.accept(), connect(&addr))?;
        assert_eq!(peer, PeerAddr::Uds, "a UDS peer carries no address, step-1");
        let mut accepted = accepted;

        dialed.write_all(b"hello").await.context("write")?;
        dialed.flush().await?;
        let mut buf = [0u8; 5];
        accepted.read_exact(&mut buf).await.context("read")?;
        assert_eq!(&buf, b"hello");
        Ok(())
    }

    #[tokio::test]
    async fn connecting_with_nothing_listening_fails_cleanly() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        // Never listened on: no socket file exists at all.
        let addr = ConnAddr::Uds(dir.path().join("nobody-home.sock"));

        assert!(
            connect(&addr).await.is_err(),
            "dialing a non-existent socket must error, not hang"
        );
        Ok(())
    }

    #[tokio::test]
    async fn listening_on_a_path_still_in_use_fails_without_stealing_it() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let addr = uds_path(&dir);
        let first = listen(&addr).await.context("first listen")?;

        assert!(
            listen(&addr).await.is_err(),
            "a second listener on a path a live one still holds must not silently take over"
        );

        // The first listener is still the real one: a connect against it must
        // still work, proving it wasn't disturbed by the failed second attempt.
        let (_accepted, _dialed) = tokio::try_join!(first.accept(), connect(&addr))?;
        Ok(())
    }

    /// The actual design claim: `sandy-control-proto`'s length-prefixed
    /// framing (the control RPC's wire format) rides a `sandy-conn`
    /// connection unchanged, not just "some type that happens to implement
    /// AsyncRead/AsyncWrite in isolation."
    #[tokio::test]
    async fn control_proto_framing_rides_a_conn_end_to_end() -> anyhow::Result<()> {
        use sandy_control_proto::{ControlRequest, ListRequest, control_request, read_frame, write_frame};

        let dir = tempfile::tempdir()?;
        let addr = uds_path(&dir);
        let listener = listen(&addr).await.context("listen")?;

        let ((mut server, _peer), mut client) = tokio::try_join!(listener.accept(), connect(&addr))?;

        let request = ControlRequest {
            request_id: 42,
            op: Some(control_request::Op::List(ListRequest {})),
        };
        write_frame(&mut client, &request).await.context("write_frame")?;

        let received: ControlRequest = read_frame(&mut server)
            .await
            .context("read_frame")?
            .context("connection closed before a frame arrived")?;
        assert_eq!(received, request);
        Ok(())
    }

    #[tokio::test]
    async fn listening_on_a_path_orphaned_by_a_dead_process_recovers() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let addr = uds_path(&dir);

        // Simulate a crashed prior sandyd: a listener existed, bound the
        // path, and was dropped without ever removing the socket file (a
        // real `UnixListener` does NOT clean up its own path on Drop).
        let orphan = listen(&addr).await.context("orphaned listen")?;
        drop(orphan);
        assert!(
            dir.path().join("sandy-conn-test.sock").exists(),
            "dropping a UnixListener leaves its socket file behind — the premise this test needs"
        );

        // A fresh listen() on the same path must detect the orphan (nothing
        // answers a connect probe) and recover, not propagate AddrInUse.
        let recovered = listen(&addr)
            .await
            .context("recovered listen should succeed, not propagate AddrInUse")?;
        let (_accepted, _dialed) = tokio::try_join!(recovered.accept(), connect(&addr))?;
        Ok(())
    }

    #[tokio::test]
    async fn a_file_occupying_the_path_is_never_deleted() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("sandy-conn-test.sock");
        std::fs::write(&path, b"not a socket")?;

        assert!(
            listen(&ConnAddr::Uds(path.clone())).await.is_err(),
            "a plain file at the configured path must not be mistaken for an orphaned socket"
        );
        assert!(path.exists(), "the unrelated file must survive untouched");
        Ok(())
    }

    /// The fix for a real TOCTOU CodeRabbit found on #223: a bare re-probe
    /// before `remove_file` doesn't close the window between two callers
    /// recovering the same orphan concurrently. A test that just races two
    /// `tokio::spawn`ed `listen()` calls against each other and checks
    /// "exactly one wins" does NOT reliably prove this: tried first,
    /// confirmed by mutation that it passed 5/5 runs with the lock entirely
    /// removed, because without an explicit forced overlap the two tasks tend
    /// not to actually interleave inside the narrow vulnerable window —
    /// each one's recovery (self-correctingly) completes before the other
    /// starts, so "exactly one wins" holds either way. Same category of
    /// honesty issue as #106/#184's concurrency fixes (#213 tracks a general
    /// harness for this).
    ///
    /// This instead proves the mechanism directly and deterministically: an
    /// externally-held flock on the lockfile `bind_uds` uses must make
    /// `listen()` block until released, not race past it. That's the one
    /// fact the whole fix depends on — if flock itself correctly serializes
    /// (a well-established kernel guarantee, not in question), and `listen()`
    /// correctly waits on it (this test), then no two real callers — same
    /// process or different ones — can ever interleave the vulnerable
    /// section, regardless of timing.
    #[tokio::test]
    async fn bind_uds_waits_for_a_lockfile_held_by_someone_else() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let addr = uds_path(&dir);
        let ConnAddr::Uds(socket_path) = &addr else {
            unreachable!("uds_path always builds a ConnAddr::Uds")
        };
        let socket_path = socket_path.clone();

        // Hold the lock externally, simulating another caller mid-recovery.
        let lock_file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(lock_file_path(&socket_path))
            .context("open lockfile")?;
        fs2::FileExt::lock_exclusive(&lock_file).context("acquire the external lock")?;

        let listen_task = tokio::spawn(async move { listen(&addr).await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(
            !listen_task.is_finished(),
            "listen() must block while the lockfile is held elsewhere, not race past it"
        );

        fs2::FileExt::unlock(&lock_file).context("release the external lock")?;
        let result = tokio::time::timeout(std::time::Duration::from_secs(2), listen_task)
            .await
            .context("listen() did not proceed once the lock was released")?
            .context("listen task panicked")?;
        assert!(result.is_ok(), "a fresh path should bind cleanly once the lock clears");
        Ok(())
    }

    #[tokio::test]
    async fn a_bound_socket_is_mode_0600() -> anyhow::Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir()?;
        let addr = uds_path(&dir);
        // Not manipulated here: the process umask is global, and tests run
        // concurrently in the same process, so forcing it in one test would
        // race every other test's bind. bind_uds_0600 brackets its own umask
        // internally around the single bind syscall, which is what's under
        // test regardless of whatever the ambient umask happens to be.
        let _listener = listen(&addr).await.context("listen")?;

        let ConnAddr::Uds(path) = &addr else {
            unreachable!("uds_path always builds a ConnAddr::Uds")
        };
        let mode = std::fs::metadata(path)?.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "socket mode must be 0600, set at creation");
        Ok(())
    }

    #[tokio::test]
    async fn the_lockfile_is_mode_0600() -> anyhow::Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir()?;
        let addr = uds_path(&dir);
        let ConnAddr::Uds(socket_path) = &addr else {
            unreachable!("uds_path always builds a ConnAddr::Uds")
        };
        let socket_path = socket_path.clone();
        let _listener = listen(&addr).await.context("listen")?;

        let mode = std::fs::metadata(lock_file_path(&socket_path))?.permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "a world-readable lockfile lets another user block our flock (CWE-59)"
        );
        Ok(())
    }

    fn test_keepalive() -> TcpKeepalive {
        TcpKeepalive {
            idle: Duration::from_secs(30),
            interval: Duration::from_secs(15),
            retries: 4,
        }
    }

    /// Proves `apply_tcp_keepalive` actually sets the kernel sockopts, not
    /// just that the call returns `Ok`. Reads the values straight back via
    /// `SockRef`, the same crate the setter uses, so this would catch a
    /// no-op implementation (e.g. a builder constructed but never applied).
    #[tokio::test]
    async fn apply_tcp_keepalive_sets_the_kernel_sockopts() -> anyhow::Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0").await.context("bind")?;
        let addr = listener.local_addr().context("local_addr")?;
        let (stream, _accepted) = tokio::try_join!(TcpStream::connect(addr), async { listener.accept().await })?;

        let keepalive = test_keepalive();
        apply_tcp_keepalive(&stream, &keepalive).context("apply_tcp_keepalive")?;

        let sock_ref = socket2::SockRef::from(&stream);
        assert!(
            sock_ref.keepalive().context("keepalive")?,
            "SO_KEEPALIVE must be enabled"
        );
        assert_eq!(
            sock_ref.tcp_keepalive_time().context("tcp_keepalive_time")?,
            keepalive.idle
        );
        assert_eq!(
            sock_ref.tcp_keepalive_interval().context("tcp_keepalive_interval")?,
            keepalive.interval
        );
        assert_eq!(
            sock_ref.tcp_keepalive_retries().context("tcp_keepalive_retries")?,
            keepalive.retries
        );
        Ok(())
    }

    #[tokio::test]
    async fn connect_tcp_keepalive_round_trips_bytes_like_plain_connect() -> anyhow::Result<()> {
        let listener = listen_tcp_keepalive("127.0.0.1:0".parse()?, test_keepalive())
            .await
            .context("listen_tcp_keepalive")?;
        let bound = listener.local_addr().context("local_addr")?;

        let ((accepted, _peer), mut dialed) =
            tokio::try_join!(listener.accept(), connect_tcp_keepalive(bound, test_keepalive()))?;
        let mut accepted = accepted;

        dialed.write_all(b"hello").await.context("write")?;
        dialed.flush().await?;
        let mut buf = [0u8; 5];
        accepted.read_exact(&mut buf).await.context("read")?;
        assert_eq!(&buf, b"hello");
        Ok(())
    }

    #[tokio::test]
    async fn listening_through_a_symlink_is_refused() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let real_target = dir.path().join("elsewhere.sock");
        let link_path = dir.path().join("sandy-conn-test.sock");
        std::os::unix::fs::symlink(&real_target, &link_path).context("create symlink")?;

        assert!(
            listen(&ConnAddr::Uds(link_path.clone())).await.is_err(),
            "binding through a symlink must be refused, not silently followed"
        );
        assert!(
            !real_target.exists(),
            "a refused bind must never create anything at the symlink's target"
        );
        Ok(())
    }

    #[tokio::test]
    async fn tls_round_trips_bytes_when_both_fingerprints_are_pinned() -> anyhow::Result<()> {
        let server_identity = TlsIdentity::generate().context("server identity")?;
        let client_identity = TlsIdentity::generate().context("client identity")?;
        let server_fp = server_identity.fingerprint();
        let client_fp = client_identity.fingerprint();

        let listener = listen_tls(
            "127.0.0.1:0".parse()?,
            server_identity,
            std::collections::HashSet::from([client_fp]),
            Duration::from_secs(5),
            None,
        )
        .await
        .context("listen_tls")?;
        let bound = listener.local_addr().context("local_addr")?;

        let (accept_result, connect_result) =
            tokio::join!(listener.accept(), connect_tls(bound, &client_identity, server_fp, None));
        let (mut accepted, peer) = accept_result.context("accept")?;
        let mut dialed = connect_result.context("connect_tls")?;

        match peer {
            PeerAddr::TcpTls(addr, fp) => {
                assert_eq!(addr.ip(), "127.0.0.1".parse::<std::net::IpAddr>()?);
                assert_eq!(fp, client_fp, "accept must report the dialer's own pinned fingerprint");
            }
            other => panic!("expected PeerAddr::TcpTls, got {other:?}"),
        }

        dialed.write_all(b"hello").await.context("write")?;
        dialed.flush().await?;
        let mut buf = [0u8; 5];
        accepted.read_exact(&mut buf).await.context("read")?;
        assert_eq!(&buf, b"hello");
        Ok(())
    }

    #[tokio::test]
    async fn connect_tls_is_refused_when_the_servers_fingerprint_does_not_match() -> anyhow::Result<()> {
        let server_identity = TlsIdentity::generate().context("server identity")?;
        let client_identity = TlsIdentity::generate().context("client identity")?;
        let wrong_fp = TlsIdentity::generate().context("unrelated identity")?.fingerprint();

        let listener = listen_tls(
            "127.0.0.1:0".parse()?,
            server_identity,
            std::collections::HashSet::from([client_identity.fingerprint()]),
            Duration::from_secs(5),
            None,
        )
        .await
        .context("listen_tls")?;
        let bound = listener.local_addr().context("local_addr")?;

        let (accept_result, connect_result) =
            tokio::join!(listener.accept(), connect_tls(bound, &client_identity, wrong_fp, None));
        assert!(
            connect_result.is_err(),
            "pinning the wrong server fingerprint must be refused, not silently accepted"
        );
        // The server side also sees the handshake fail (the client aborted
        // mid-handshake once it rejected the server's certificate).
        assert!(
            accept_result.is_err(),
            "the server's accept must also fail, not hang or succeed"
        );
        Ok(())
    }

    #[tokio::test]
    async fn accept_refuses_a_client_whose_fingerprint_is_not_allowlisted() -> anyhow::Result<()> {
        let server_identity = TlsIdentity::generate().context("server identity")?;
        let client_identity = TlsIdentity::generate().context("client identity")?;
        let unlisted_identity = TlsIdentity::generate().context("unlisted identity")?;
        let server_fp = server_identity.fingerprint();

        let listener = listen_tls(
            "127.0.0.1:0".parse()?,
            server_identity,
            // The allowlist pins a different client than the one that dials.
            std::collections::HashSet::from([client_identity.fingerprint()]),
            Duration::from_secs(5),
            None,
        )
        .await
        .context("listen_tls")?;
        let bound = listener.local_addr().context("local_addr")?;

        let (accept_result, _connect_result) = tokio::join!(
            listener.accept(),
            connect_tls(bound, &unlisted_identity, server_fp, None)
        );
        assert!(
            accept_result.is_err(),
            "a client whose fingerprint isn't pinned must be refused, not accepted"
        );
        Ok(())
    }

    #[tokio::test]
    async fn listen_tls_refuses_to_bind_with_an_empty_allowlist() -> anyhow::Result<()> {
        let identity = TlsIdentity::generate().context("identity")?;
        let result = listen_tls(
            "127.0.0.1:0".parse()?,
            identity,
            std::collections::HashSet::new(),
            Duration::from_secs(5),
            None,
        )
        .await;
        assert!(
            result.is_err(),
            "an empty pinned-key allowlist must refuse to bind at all, not run and refuse every peer"
        );
        Ok(())
    }

    #[tokio::test]
    async fn an_accept_that_never_completes_the_tls_handshake_times_out() -> anyhow::Result<()> {
        let identity = TlsIdentity::generate().context("identity")?;
        let allowed =
            std::collections::HashSet::from([TlsIdentity::generate().context("peer identity")?.fingerprint()]);
        // A real, short duration — a paused virtual clock races the real TCP
        // connect below and is flaky for this kind of test (AGENTS.md).
        let listener = listen_tls(
            "127.0.0.1:0".parse()?,
            identity,
            allowed,
            Duration::from_millis(200),
            None,
        )
        .await
        .context("listen_tls")?;
        let bound = listener.local_addr().context("local_addr")?;

        // A raw TCP client that completes the three-way handshake but never
        // speaks TLS: the "accepted but never finishes" case the timeout
        // exists for.
        let _dangling = tokio::net::TcpStream::connect(bound).await.context("raw dial")?;
        let result = listener.accept().await;
        let is_timeout = matches!(result, Err(ConnError::HandshakeTimeout));
        assert!(
            is_timeout,
            "a connection that never completes its TLS handshake must time out, not hang forever; got {:?}",
            result.map(|_| "Ok").map_err(|err| err.to_string())
        );
        Ok(())
    }

    /// Regression: a stalled peer's TLS handshake must not delay accepting
    /// the NEXT connection. Before splitting `accept_raw`/`handshake`, a
    /// caller that held one pending `Listener::accept` at a time (as
    /// `sandyd`'s mesh accept loops do) would not even issue its next raw
    /// `accept(2)` until the current connection's handshake resolved —
    /// serializing every handshake across the whole listener. With the
    /// split, `accept_raw` on a second connection must resolve promptly even
    /// while a first connection's handshake has not completed and never will.
    #[tokio::test]
    async fn a_stalled_handshake_does_not_delay_the_next_raw_accept() -> anyhow::Result<()> {
        let identity = TlsIdentity::generate().context("identity")?;
        let client_identity = TlsIdentity::generate().context("client identity")?;
        let server_fp = identity.fingerprint();
        let allowed = std::collections::HashSet::from([client_identity.fingerprint()]);
        let listener = listen_tls(
            "127.0.0.1:0".parse()?,
            identity,
            allowed,
            Duration::from_secs(30), // long enough that this test's own bound catches a regression first
            None,
        )
        .await
        .context("listen_tls")?;
        let bound = listener.local_addr().context("local_addr")?;

        // First peer: completes the TCP three-way handshake but never speaks
        // TLS, so its handshake stalls for the full (long) timeout above.
        let _dangling = tokio::net::TcpStream::connect(bound).await.context("raw dial")?;
        let first = listener
            .accept_raw()
            .await
            .context("accept_raw (first, stalled peer)")?;
        assert!(
            matches!(first, AcceptedStream::PendingTls(..)),
            "the first accept must hand back a pending handshake, not run it inline"
        );

        // Second peer: a real, well-behaved client, dialed in the
        // background — its own TLS handshake can't complete until THIS
        // test calls `second.handshake()` below, so it must run
        // concurrently with the raw-accept check below, not be awaited
        // alongside it (joining the two would deadlock: the client's
        // handshake never finishes until the server runs its own, which
        // only happens after the raw accept resolves).
        let connect_task = tokio::spawn(async move { connect_tls(bound, &client_identity, server_fp, None).await });

        // The raw accept must resolve quickly — not wait on the first
        // connection's handshake, which is never going to complete.
        let second = tokio::time::timeout(Duration::from_secs(2), listener.accept_raw())
            .await
            .context(
                "accept_raw (second, well-behaved peer) must not be blocked by the first peer's stalled handshake",
            )?
            .context("accept_raw (second)")?;

        // The second connection's own handshake completes normally — the
        // first peer's stall affects only its own connection. This also
        // unblocks the spawned `connect_tls` task above.
        let (mut accepted, peer) = second.handshake().await.context("handshake (second)")?;
        assert!(matches!(peer, PeerAddr::TcpTls(..)));
        let mut dialed = connect_task
            .await
            .context("join connect_tls task")?
            .context("connect_tls")?;
        dialed.write_all(b"ok").await.context("write")?;
        dialed.flush().await?;
        let mut buf = [0u8; 2];
        accepted.read_exact(&mut buf).await.context("read")?;
        assert_eq!(&buf, b"ok");
        Ok(())
    }

    #[tokio::test]
    async fn fingerprint_hex_round_trips() -> anyhow::Result<()> {
        let fp = TlsIdentity::generate().context("identity")?.fingerprint();
        let hex = fp.to_hex();
        assert_eq!(hex.len(), 64);
        assert_eq!(Fingerprint::from_hex(&hex)?, fp);
        Ok(())
    }

    #[test]
    fn load_or_generate_persists_and_reloads_the_same_fingerprint() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let first = TlsIdentity::load_or_generate(dir.path()).context("first load_or_generate")?;
        let second = TlsIdentity::load_or_generate(dir.path()).context("second load_or_generate")?;
        assert_eq!(
            first.fingerprint(),
            second.fingerprint(),
            "reloading a persisted identity must report the same fingerprint, not mint a fresh one"
        );
        Ok(())
    }

    #[test]
    fn load_or_generate_persisted_key_file_is_mode_0600() -> anyhow::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir()?;
        TlsIdentity::load_or_generate(dir.path()).context("load_or_generate")?;
        let mode = std::fs::metadata(dir.path().join("identity.key.der"))?
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode, 0o600,
            "a world-readable key file defeats the whole point of pinning it"
        );
        Ok(())
    }

    #[test]
    fn load_or_generate_refuses_a_directory_with_only_the_cert() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        std::fs::write(dir.path().join("identity.cert.der"), b"not a real cert")?;
        assert!(
            TlsIdentity::load_or_generate(dir.path()).is_err(),
            "a partial identity directory must be refused, not silently regenerated over"
        );
        Ok(())
    }

    #[test]
    fn fingerprint_from_hex_rejects_malformed_input_instead_of_panicking() {
        // A 64-*byte* string containing a multi-byte UTF-8 character: the
        // length check alone would pass, and slicing by byte index would
        // panic on a non-char-boundary without the `is_ascii` guard.
        let non_ascii_but_64_bytes = format!("{}{}", "€", "a".repeat(61));
        assert_eq!(non_ascii_but_64_bytes.len(), 64);
        assert!(Fingerprint::from_hex(&non_ascii_but_64_bytes).is_err());

        assert!(Fingerprint::from_hex("too-short").is_err());
        assert!(Fingerprint::from_hex(&"zz".repeat(32)).is_err());
    }
}
