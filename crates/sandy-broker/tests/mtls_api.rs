//! Tier-2 acceptance for remote callers over mutual TLS (#887, `docs/decisions/broker-api.md` decision 10): the client
//! id comes from the pinned certificate, nothing else authenticates, and the per-client policies still apply.

mod common;

use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use anyhow::{Context, Result};
use common::{Opts, TOKEN_B, fixture_with_opts, http_over, submit_body};
use sandy_broker::{BrokerConfig, BrokerError, CertPin, Client, IsolationClass, TlsConfig, serve};
use sandy_conn::TlsIdentity;
use serde_json::json;
use sha2::{Digest, Sha256};

fn mtls() -> Opts {
    Opts {
        mtls: true,
        ..Opts::default()
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The id a job was submitted for, as `sandyd` recorded it from the client id the broker sent (#888).
fn owner_of(f: &common::Fixture, job: &str) -> Result<Option<String>> {
    Ok(f.store.client_id(job)?)
}

/// A non-loopback bind is accepted in mTLS mode (the fixture binds every address), and the caller is the client its
/// certificate is pinned to: a job submitted over A's certificate is A's, over C's certificate is C's.
#[tokio::test]
async fn the_client_id_derives_from_the_certificate() -> Result<()> {
    let f = fixture_with_opts(mtls()).await?;
    let m = f.mtls.as_ref().context("an mTLS fixture")?;

    let (status, a) = m.call("a", "POST", "/v1/jobs", Some(submit_body()), None).await?;
    assert_eq!(status, 202, "{a}");
    let (status, c) = m.call("c", "POST", "/v1/jobs", Some(submit_body()), None).await?;
    assert_eq!(status, 202, "{c}");

    assert_eq!(
        owner_of(&f, a["job_id"].as_str().context("job id")?)?.as_deref(),
        Some("a")
    );
    assert_eq!(
        owner_of(&f, c["job_id"].as_str().context("job id")?)?.as_deref(),
        Some("c")
    );
    Ok(())
}

/// A certificate for client A cannot act as client B: B's job is invisible to A, and A cannot cancel it.
#[tokio::test]
async fn a_certificate_for_one_client_cannot_act_as_another() -> Result<()> {
    let f = fixture_with_opts(mtls()).await?;
    let m = f.mtls.as_ref().context("an mTLS fixture")?;
    let (_, a) = m.call("a", "POST", "/v1/jobs", Some(submit_body()), None).await?;
    let job = a["job_id"].as_str().context("job id")?.to_owned();

    let (status, _) = m.call("b", "GET", &format!("/v1/jobs/{job}"), None, None).await?;
    assert_eq!(status, 404, "B must not see A's job");
    let (status, _) = m
        .call("b", "POST", &format!("/v1/jobs/{job}/cancel"), None, None)
        .await?;
    assert_eq!(status, 404, "B must not cancel A's job");
    let (status, listed) = m.call("b", "GET", "/v1/jobs", None, None).await?;
    assert_eq!(status, 200, "{listed}");
    assert!(
        listed["jobs"].as_array().is_some_and(Vec::is_empty),
        "B's list is its own: {listed}"
    );
    let (status, _) = m.call("a", "GET", &format!("/v1/jobs/{job}"), None, None).await?;
    assert_eq!(status, 200, "A still sees its own job");
    Ok(())
}

/// The `Authorization` header is not read over mTLS: B's valid token, or garbage, changes nothing about who the caller
/// is, and a missing one is not required.
#[tokio::test]
async fn the_authorization_header_is_not_read_over_mtls() -> Result<()> {
    let f = fixture_with_opts(mtls()).await?;
    let m = f.mtls.as_ref().context("an mTLS fixture")?;

    for bearer in [Some(TOKEN_B), Some("garbage"), None] {
        let (status, job) = m.call("a", "POST", "/v1/jobs", Some(submit_body()), bearer).await?;
        assert_eq!(status, 202, "{bearer:?}: {job}");
        assert_eq!(
            owner_of(&f, job["job_id"].as_str().context("job id")?)?.as_deref(),
            Some("a"),
            "{bearer:?}"
        );
    }
    Ok(())
}

/// A certificate that is not pinned is refused at the handshake: the request never reaches HTTP, and the refusal is
/// logged with its typed reason and no certificate bytes. The stranger has the same subject and SAN as every pinned
/// identity (the mesh generator is the same), so only the pinned fingerprint tells it apart.
#[tokio::test]
async fn an_unpinned_certificate_is_refused_at_the_handshake_and_logged_typed() -> Result<()> {
    let logs = capture_logs();
    let f = fixture_with_opts(mtls()).await?;
    let m = f.mtls.as_ref().context("an mTLS fixture")?;
    let stranger = TlsIdentity::generate()?;

    let attempt = async {
        let mut conn = m.connect(&stranger).await?;
        http_over(&mut conn, "GET", "/v1/jobs", None, None, true).await
    }
    .await;

    assert!(
        attempt.is_err(),
        "an unpinned certificate must get no HTTP response: {attempt:?}"
    );
    // The refusal is logged on the broker's side asynchronously: wait for it, bounded.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let text = loop {
        let text = String::from_utf8_lossy(&logs.lock().unwrap_or_else(PoisonError::into_inner)).into_owned();
        if text.contains("handshake refused") || std::time::Instant::now() > deadline {
            break text;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    };
    assert!(text.contains("handshake refused"), "the refusal must be logged: {text}");
    assert!(text.contains("kind=\"tls\""), "the typed reason must be logged: {text}");
    assert!(
        !text.contains(&stranger.fingerprint().to_hex()),
        "the log must not carry the certificate's fingerprint"
    );
    Ok(())
}

/// Plaintext HTTP to the TLS port gets no response.
#[tokio::test]
async fn a_plaintext_client_cannot_use_the_tls_port() -> Result<()> {
    let f = fixture_with_opts(mtls()).await?;
    let m = f.mtls.as_ref().context("an mTLS fixture")?;

    let plain = reqwest::Client::new()
        .get(format!("http://{}/v1/jobs", m.addr))
        .send()
        .await;

    assert!(plain.is_err(), "a plaintext request must not be answered: {plain:?}");
    Ok(())
}

/// The per-client policies apply as they do for a bearer client: a path outside the client's roots, and an isolation
/// class above its maximum, are `forbidden`.
#[tokio::test]
async fn the_per_client_policies_still_apply_over_mtls() -> Result<()> {
    let f = fixture_with_opts(mtls()).await?;
    let m = f.mtls.as_ref().context("an mTLS fixture")?;

    let mut outside = submit_body();
    outside["outputs"] = json!([{"dest": "/tmp/anywhere"}]);
    let (status, body) = m.call("a", "POST", "/v1/jobs", Some(outside), None).await?;
    assert_eq!(
        (status, &body["code"]),
        (403, &json!("forbidden")),
        "A has a root of its own only"
    );

    let (status, body) = m.call("b", "POST", "/v1/jobs", Some(submit_body()), None).await?;
    assert_eq!(
        (status, &body["code"]),
        (403, &json!("forbidden")),
        "B may not run trusted jobs"
    );

    let (status, body) = m
        .call(
            "c",
            "POST",
            "/v1/jobs",
            Some(json!({
                "manifest": "bQ==", "manifest_encoding": "test/v1", "required_isolation_class": "trusted",
                "inputs": [{"host": "/etc/passwd", "name": "n"}]
            })),
            None,
        )
        .await?;
    assert_eq!(
        (status, &body["code"]),
        (403, &json!("forbidden")),
        "C has no roots at all"
    );
    Ok(())
}

/// A pin past its `not_after` at start is left out of the handshake allowlist: its certificate is refused, and the
/// other clients are unaffected.
#[tokio::test]
async fn an_expired_pin_is_refused_at_the_handshake() -> Result<()> {
    let f = fixture_with_opts(Opts {
        mtls_not_after_c: Some(1),
        ..mtls()
    })
    .await?;
    let m = f.mtls.as_ref().context("an mTLS fixture")?;

    let c = async {
        let mut conn = m.connect(m.identity("c")).await?;
        http_over(&mut conn, "GET", "/v1/jobs", None, None, true).await
    }
    .await;
    let (status, _) = m.call("a", "GET", "/v1/jobs", None, None).await?;

    assert!(c.is_err(), "an expired pin must not get a response: {c:?}");
    assert_eq!(status, 200, "client A is unaffected");
    Ok(())
}

/// A pin that expires while a connection is open stops working on that connection: the next request is
/// `unauthenticated`, not served on the strength of the handshake alone.
#[tokio::test]
async fn a_pin_that_expires_during_a_connection_stops_working() -> Result<()> {
    let f = fixture_with_opts(Opts {
        mtls_not_after_c: Some(now() + 4),
        ..mtls()
    })
    .await?;
    let m = f.mtls.as_ref().context("an mTLS fixture")?;
    let mut conn = m.connect(m.identity("c")).await?;

    let (status, _) = http_over(&mut conn, "GET", "/v1/jobs", None, None, false).await?;
    assert_eq!(status, 200, "valid before the deadline");

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    let status = loop {
        let (status, _) = http_over(&mut conn, "GET", "/v1/jobs", None, None, false).await?;
        if status != 200 || std::time::Instant::now() > deadline {
            break status;
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    };
    assert_eq!(status, 401, "the same connection must stop working at the deadline");
    Ok(())
}

fn pin(identity: &TlsIdentity) -> CertPin {
    CertPin {
        sha256: identity.fingerprint().to_hex(),
        not_after: None,
    }
}

fn token_hash(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

fn client(id: &str, token: Option<&str>, certs: Vec<CertPin>) -> Client {
    Client {
        id: id.to_owned(),
        token_sha256: token.map(token_hash).unwrap_or_default(),
        certs,
        max_isolation_class: IsolationClass::Trusted,
        max_environments: 4,
        max_environment_records: 64,
        profiles: Vec::new(),
        roots: Vec::new(),
    }
}

fn config(dir: &std::path::Path, bind: &str, clients: Vec<Client>, tls: bool) -> Result<BrokerConfig> {
    Ok(BrokerConfig {
        control_socket: std::path::Path::new("/nonexistent").to_path_buf(),
        rpc_deadline: std::time::Duration::from_secs(30),
        state_dir: dir.join("state"),
        bind: bind.parse()?,
        clients,
        tls: tls.then(|| TlsConfig {
            identity_dir: dir.join("tls"),
        }),
    })
}

/// A broker whose clients file cannot work is refused at start, naming the client and the problem.
#[tokio::test]
async fn startup_refuses_inconsistent_pins_naming_the_client() -> Result<()> {
    let id = TlsIdentity::generate()?;
    let other = TlsIdentity::generate()?;
    let hex = id.fingerprint().to_hex();
    let bad_pin = |sha256: String| CertPin {
        sha256,
        not_after: None,
    };
    // (name, tls, clients, what the error must say)
    let cases: Vec<(&str, bool, Vec<Client>, &str)> = vec![
        (
            "a token in mTLS mode",
            true,
            vec![client("alice", Some("t"), vec![pin(&id)])],
            "bearer",
        ),
        (
            "no pin in mTLS mode",
            true,
            vec![client("alice", None, vec![])],
            "certificate",
        ),
        (
            "a pin in bearer mode",
            false,
            vec![client("alice", Some("t"), vec![pin(&id)])],
            "certs",
        ),
        (
            "63 hex digits",
            true,
            vec![client("alice", None, vec![bad_pin(hex[..63].to_owned())])],
            "fingerprint",
        ),
        (
            "not hex",
            true,
            vec![client("alice", None, vec![bad_pin("z".repeat(64))])],
            "fingerprint",
        ),
        (
            "a prefix",
            true,
            vec![client("alice", None, vec![bad_pin(format!("sha256:{hex}"))])],
            "fingerprint",
        ),
        (
            "non-ASCII",
            true,
            vec![client("alice", None, vec![bad_pin(format!("€{}", &hex[..61]))])],
            "fingerprint",
        ),
        (
            "one fingerprint for two clients",
            true,
            vec![
                client("alice", None, vec![pin(&id)]),
                client("bob", None, vec![pin(&id)]),
            ],
            "more than one",
        ),
        (
            "two clients, distinct pins, is fine as a control",
            true,
            vec![
                client("alice", None, vec![pin(&id)]),
                client("bob", None, vec![pin(&other)]),
            ],
            "",
        ),
    ];
    for (name, tls, clients, needle) in cases {
        let dir = tempfile::tempdir()?;
        let result = serve(config(dir.path(), "127.0.0.1:0", clients, tls)?).await;
        if needle.is_empty() {
            result.map(drop).with_context(|| format!("{name}: must start"))?;
            continue;
        }
        match result {
            Err(BrokerError::InvalidClients(message)) => {
                assert!(message.contains(needle), "{name}: must say `{needle}`: {message}");
                assert!(
                    message.contains("alice") || message.contains("bob"),
                    "{name}: must name a client: {message}"
                );
            }
            other => anyhow::bail!("{name}: expected InvalidClients, got {other:?}"),
        }
    }
    Ok(())
}

/// Every pin expired at start leaves nobody who could connect: the broker refuses to start, typed.
#[tokio::test]
async fn a_broker_with_no_usable_pin_refuses_to_start() -> Result<()> {
    let id = TlsIdentity::generate()?;
    let expired = CertPin {
        sha256: id.fingerprint().to_hex(),
        not_after: Some(1),
    };
    let dir = tempfile::tempdir()?;

    let result = serve(config(
        dir.path(),
        "127.0.0.1:0",
        vec![client("alice", None, vec![expired])],
        true,
    )?)
    .await;

    match result {
        Err(BrokerError::Tls(message)) => assert!(message.contains("no usable"), "{message}"),
        other => anyhow::bail!("expected Tls, got {other:?}"),
    }
    Ok(())
}

/// The broker's own identity is persisted: the same directory gives the same fingerprint after a restart, a caller's
/// pin holds, and a corrupt directory (one file of two) refuses to start, typed, rather than minting a new identity.
#[tokio::test]
async fn the_brokers_identity_is_stable_and_a_corrupt_one_is_refused() -> Result<()> {
    let id = TlsIdentity::generate()?;
    let dir = tempfile::tempdir()?;
    // Each start has its own state directory: dropping a `Running` aborts its task asynchronously, so the previous
    // owner table's lock may still be held. Only the TLS identity directory is shared, which is what this tests.
    let attempt = std::cell::Cell::new(0);
    let start = || {
        attempt.set(attempt.get() + 1);
        let mut cfg = config(
            dir.path(),
            "127.0.0.1:0",
            vec![client("alice", None, vec![pin(&id)])],
            true,
        );
        if let Ok(cfg) = cfg.as_mut() {
            cfg.state_dir = dir.path().join(format!("state-{}", attempt.get()));
        }
        async move { serve(cfg.map_err(|e| BrokerError::Tls(e.to_string()))?).await }
    };

    let first = start().await.context("the first start")?;
    let fingerprint = first.fingerprint.clone().context("an mTLS broker has a fingerprint")?;
    assert_eq!(fingerprint.len(), 64);
    drop(first);
    let second = start().await.context("the second start")?;
    assert_eq!(
        second.fingerprint.as_deref(),
        Some(fingerprint.as_str()),
        "the identity must survive a restart"
    );
    drop(second);

    std::fs::remove_file(dir.path().join("tls/identity.key.der"))?;
    match start().await {
        Err(BrokerError::Tls(message)) => assert!(!message.is_empty()),
        other => anyhow::bail!("expected Tls for a corrupt identity, got {other:?}"),
    }
    Ok(())
}

/// A non-loopback bind without mTLS is still refused (the bearer path is loopback only).
#[tokio::test]
async fn a_non_loopback_bind_without_mtls_is_refused() -> Result<()> {
    let dir = tempfile::tempdir()?;

    let result = serve(config(
        dir.path(),
        "0.0.0.0:0",
        vec![client("alice", Some("t"), vec![])],
        false,
    )?)
    .await;

    assert!(matches!(result, Err(BrokerError::NonLoopback { .. })), "{result:?}");
    Ok(())
}

struct LogWriter(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for LogWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Routes every tracing event of this process into a buffer.
fn capture_logs() -> Arc<Mutex<Vec<u8>>> {
    static LOGS: OnceLock<Arc<Mutex<Vec<u8>>>> = OnceLock::new();
    Arc::clone(LOGS.get_or_init(|| {
        let buf = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&buf);
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .with_writer(move || LogWriter(Arc::clone(&sink)))
            .try_init();
        buf
    }))
}
