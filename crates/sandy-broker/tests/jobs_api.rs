//! Tier-2 acceptance for the broker's job endpoints (#591): the broker runs over
//! an in-process sandyd on a real UDS, and a real HTTP client drives it.

mod common;

use std::{
    net::SocketAddr,
    path::Path,
    sync::{Arc, Mutex, OnceLock, PoisonError},
};

use anyhow::{Context, Result};
use base64::Engine;
use common::{Opts, TOKEN_A, TOKEN_B, client, fixture, fixture_with_opts, submit_body};
use reqwest::{Client as Http, StatusCode};
use sandy_broker::{BrokerConfig, BrokerError, Client, IsolationClass, serve};
use serde_json::{Value, json};
use tokio::net::UnixListener;

#[tokio::test]
async fn a_request_without_a_valid_token_is_unauthenticated() -> Result<()> {
    let f = fixture().await?;
    for token in [None, Some("wrong-token")] {
        let (status, body) = f.call("GET", "/v1/jobs", token, None).await?;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["code"], "unauthenticated");
    }
    Ok(())
}

#[tokio::test]
async fn a_submitted_job_can_be_read_back_and_listed() -> Result<()> {
    let f = fixture().await?;
    let id = f.submit(TOKEN_A).await?;
    let (status, body) = f.call("GET", &format!("/v1/jobs/{id}"), Some(TOKEN_A), None).await?;
    assert_eq!(
        (status, body["job_id"].as_str(), body["state"].as_str()),
        (StatusCode::OK, Some(id.as_str()), Some("pending"))
    );
    let (_, list) = f.call("GET", "/v1/jobs", Some(TOKEN_A), None).await?;
    assert_eq!(list["jobs"].as_array().map(Vec::len), Some(1));
    Ok(())
}

#[tokio::test]
async fn a_client_cannot_see_or_cancel_another_clients_job() -> Result<()> {
    let f = fixture().await?;
    let id = f.submit(TOKEN_A).await?;
    let (status, body) = f.call("GET", &format!("/v1/jobs/{id}"), Some(TOKEN_B), None).await?;
    assert_eq!((status, &body["code"]), (StatusCode::NOT_FOUND, &json!("not_found")));
    let (status, _) = f
        .call("POST", &format!("/v1/jobs/{id}/cancel"), Some(TOKEN_B), None)
        .await?;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (_, list) = f.call("GET", "/v1/jobs", Some(TOKEN_B), None).await?;
    assert_eq!(
        list["jobs"].as_array().map(Vec::len),
        Some(0),
        "list leaked another client's job"
    );
    let (_, own) = f.call("GET", &format!("/v1/jobs/{id}"), Some(TOKEN_A), None).await?;
    assert_eq!(
        own["state"], "pending",
        "the foreign cancel must not have cancelled the job"
    );
    Ok(())
}

#[tokio::test]
async fn the_owner_cancels_with_the_token_the_broker_holds() -> Result<()> {
    let f = fixture().await?;
    let id = f.submit(TOKEN_A).await?;
    let (status, body) = f
        .call("POST", &format!("/v1/jobs/{id}/cancel"), Some(TOKEN_A), None)
        .await?;
    assert_eq!(
        (status, body["state"].as_str()),
        (StatusCode::OK, Some("cancelled")),
        "{body}"
    );
    let (_, got) = f.call("GET", &format!("/v1/jobs/{id}"), Some(TOKEN_A), None).await?;
    assert_eq!(got["state"], "cancelled");
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

/// Every encoding `bytes` could leak in: hex (both cases), and standard and URL-safe base64,
/// padded and not.
fn encodings(bytes: &[u8]) -> Vec<String> {
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
    vec![
        hex::encode(bytes),
        hex::encode_upper(bytes),
        STANDARD.encode(bytes),
        STANDARD_NO_PAD.encode(bytes),
        URL_SAFE.encode(bytes),
        URL_SAFE_NO_PAD.encode(bytes),
    ]
}

#[tokio::test]
async fn no_response_carries_the_attach_token() -> Result<()> {
    let logs = capture_logs();
    let f = fixture().await?;
    let (_, submitted) = f.call("POST", "/v1/jobs", Some(TOKEN_A), Some(submit_body())).await?;
    let id = submitted["job_id"].as_str().context("job_id")?.to_owned();
    let token = f.store.attach_token(&id)?.context("sandyd stored no attach token")?;
    // The token is random bytes, so match the encodings it could leak in.
    let needles = [
        hex::encode(&token),
        base64::engine::general_purpose::STANDARD.encode(&token),
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&token),
    ];
    let mut bodies = vec![("submit".to_owned(), submitted)];
    for (method, path, bearer) in [
        ("GET", "/v1/jobs".to_owned(), TOKEN_A),
        ("GET", format!("/v1/jobs/{id}"), TOKEN_A),
        ("GET", format!("/v1/jobs/{id}"), TOKEN_B),
        ("POST", format!("/v1/jobs/{id}/cancel"), TOKEN_B),
        ("POST", format!("/v1/jobs/{id}/attach"), TOKEN_A),
        ("POST", format!("/v1/jobs/{id}/cancel"), TOKEN_A),
        ("POST", format!("/v1/jobs/{id}/cancel"), TOKEN_A),
    ] {
        let (_, body) = f.call(method, &path, Some(bearer), None).await?;
        bodies.push((path, body));
    }
    assert!(token.len() >= 16, "the token must be long enough to be a real needle");
    for (what, body) in bodies {
        let text = body.to_string();
        assert!(
            needles.iter().all(|n| !text.contains(n.as_str())),
            "{what} leaked the attach token"
        );
    }

    // The attach bridge: its responses, the stream URL, the stream's headers, lines and error
    // bodies, and the broker's logs carry neither the token nor the cap the broker presented on
    // sandyd's attach socket.
    // The job above was cancelled; attach needs a live one.
    let live = f.submit(TOKEN_A).await?;
    let agent = f.agent(&live)?;
    agent.stdout(b"hello").await?;
    let attach = f
        .http
        .post(format!("{}/v1/jobs/{live}/attach", f.base))
        .bearer_auth(TOKEN_A)
        .send()
        .await?;
    let mut seen = format!("{:?}", attach.headers());
    let attach_body: Value = attach.json().await?;
    seen.push_str(&attach_body.to_string());
    let stream_url = attach_body["stream_url"].as_str().context("stream_url")?.to_owned();
    let ticket = stream_url.rsplit('/').next().context("ticket")?.to_owned();
    let resp = f.open_stream(&stream_url, Some(TOKEN_A)).await?;
    seen.push_str(&format!("{:?}", resp.headers()));
    let mut lines = common::Lines::new(resp);
    lines.output_bytes(5).await?;
    f.finish(&live, sandy_control_proto::JobStatus::Succeeded)?;
    lines.last().await?;
    seen.push_str(&lines.transcript);
    // A spent ticket gives the stream route's 404 body.
    let spent = f.open_stream(&stream_url, Some(TOKEN_A)).await?;
    seen.push_str(&spent.text().await?);
    let caps = f.caps.lock().map_err(|_| anyhow::anyhow!("poisoned"))?.clone();
    assert!(
        !caps.is_empty(),
        "the broker never presented a cap, so there is no needle"
    );
    let mut cap_needles = Vec::new();
    for cap_hex in &caps {
        cap_needles.extend(encodings(&hex::decode(cap_hex)?));
    }
    let token_needles = encodings(&token);
    let all: Vec<&String> = token_needles.iter().chain(&cap_needles).collect();
    assert!(
        all.iter().all(|n| !seen.contains(n.as_str())),
        "the attach bridge leaked the token or the cap"
    );

    // The stream route's 503 body, from a broker whose sandyd has no attach socket.
    let g = fixture_with_opts(Opts {
        attach_socket: false,
        ..Opts::default()
    })
    .await?;
    let gid = g.submit(TOKEN_A).await?;
    let gtoken = g.store.attach_token(&gid)?.context("sandyd stored no attach token")?;
    let url = g.attach(&gid, TOKEN_A).await?;
    let unavailable = g.open_stream(&url, Some(TOKEN_A)).await?;
    assert_eq!(unavailable.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = unavailable.text().await?;
    assert!(
        encodings(&gtoken).iter().all(|n| !body.contains(n.as_str())),
        "the 503 body leaked the token"
    );

    // The broker's logs, for both brokers, hold no token, cap or ticket in any encoding.
    let logs = String::from_utf8_lossy(&logs.lock().map_err(|_| anyhow::anyhow!("poisoned"))?).into_owned();
    assert!(!logs.is_empty(), "no log line was captured, so the scan proves nothing");
    let log_needles: Vec<String> = all
        .into_iter()
        .cloned()
        .chain(encodings(&gtoken))
        .chain([ticket, url.rsplit('/').next().context("ticket")?.to_owned()])
        .collect();
    assert!(
        log_needles.iter().all(|n| !logs.contains(n.as_str())),
        "a log line carried a token, cap or ticket"
    );
    Ok(())
}

#[tokio::test]
async fn an_isolation_class_above_the_clients_maximum_is_forbidden() -> Result<()> {
    let f = fixture().await?;
    let (status, body) = f.call("POST", "/v1/jobs", Some(TOKEN_B), Some(submit_body())).await?;
    assert_eq!((status, &body["code"]), (StatusCode::FORBIDDEN, &json!("forbidden")));
    Ok(())
}

#[tokio::test]
async fn a_host_path_outside_the_clients_roots_is_forbidden() -> Result<()> {
    let f = fixture().await?;
    let inside = f.root_a.join("in.txt");
    std::fs::write(&inside, b"x")?;
    let escape = f.root_a.join("..").join("..").join("etc").join("passwd");
    let bodies = [
        json!({"inputs": [{"host": escape.to_string_lossy(), "name": "n"}]}),
        json!({"secrets": [{"name": "s", "host_path": "/etc/passwd"}]}),
        json!({"outputs": [{"dest": "/tmp/anywhere"}]}),
    ];
    for extra in bodies {
        let mut body = submit_body();
        body.as_object_mut()
            .context("object")?
            .extend(extra.as_object().context("object")?.clone());
        let (status, resp) = f.call("POST", "/v1/jobs", Some(TOKEN_A), Some(body)).await?;
        assert_eq!(
            (status, &resp["code"]),
            (StatusCode::FORBIDDEN, &json!("forbidden")),
            "{extra}"
        );
    }
    let mut ok = submit_body();
    ok["inputs"] = json!([{"host": inside.to_string_lossy(), "name": "n"}]);
    let (status, resp) = f.call("POST", "/v1/jobs", Some(TOKEN_A), Some(ok)).await?;
    // sandyd refuses path fields without a local-dispatch host (decision 21), so
    // 503 is expected here. The broker's own boundary is: it forwards, not 403.
    assert!(
        matches!(status, StatusCode::ACCEPTED | StatusCode::SERVICE_UNAVAILABLE),
        "a path inside the root must pass the broker: {status} {resp}"
    );
    Ok(())
}

/// #618: the broker sends the client's root with every host path, so sandyd opens each path beneath it without
/// following a link. A path under a nested root gets the nested root, and a client's root is never sent for a path
/// the client may not name.
#[tokio::test]
async fn the_broker_sends_the_clients_root_with_every_host_path() -> Result<()> {
    let mut f = fixture_with_opts(Opts {
        path_host: true,
        ..Opts::default()
    })
    .await?;
    // The broker sends the configured root in canonical form (#618), so `/tmp` on macOS is `/private/tmp`.
    let root = f.root_a.canonicalize()?;
    std::fs::write(root.join("in.txt"), b"x")?;
    let mut body = submit_body();
    body["inputs"] = json!([{"host": root.join("in.txt").to_string_lossy(), "name": "n"}]);
    body["outputs"] = json!([{"name": "o", "dest": root.join("out").to_string_lossy()}]);
    body["secrets"] = json!([{"name": "S", "host_path": root.join("secret").to_string_lossy()}]);

    let (status, resp) = f.call("POST", "/v1/jobs", Some(TOKEN_A), Some(body)).await?;
    assert_eq!(status, StatusCode::ACCEPTED, "{resp}");

    let dispatch = tokio::time::timeout(std::time::Duration::from_secs(5), f._host_dispatch.recv())
        .await
        .context("the job was never dispatched")?
        .context("the dispatch channel closed")?;
    let want = Some(root.to_string_lossy().into_owned());
    assert_eq!(dispatch.inputs[0].root, want);
    assert_eq!(dispatch.outputs[0].root, want);
    assert_eq!(dispatch.secrets[0].root, want);
    Ok(())
}

/// #618 (review of #889): the root sandyd opens is followed, so it must be the operator's configured root, never a
/// spelling the client chose. A client that names its path through a symlink it controls (`alias` here, in a directory
/// the client can write) must not make that alias the root: it could retarget the alias after the broker's check.
/// The Dispatch carries the canonical configured root, and what the sender reads after the retarget is still inside it.
#[tokio::test]
async fn a_client_controlled_alias_never_becomes_the_root_sandyd_opens() -> Result<()> {
    let mut f = fixture_with_opts(Opts {
        path_host: true,
        ..Opts::default()
    })
    .await?;
    let root = f.root_a.canonicalize()?;
    std::fs::write(root.join("in.txt"), b"inside the root")?;
    let outside = f._dir.path().join("outside");
    std::fs::create_dir(&outside)?;
    std::fs::write(outside.join("in.txt"), b"OUTSIDE THE ROOT")?;
    let alias = f._dir.path().join("alias");
    std::os::unix::fs::symlink(&root, &alias)?;
    let mut body = submit_body();
    body["inputs"] = json!([{"host": alias.join("in.txt").to_string_lossy(), "name": "n"}]);

    let (status, resp) = f.call("POST", "/v1/jobs", Some(TOKEN_A), Some(body)).await?;
    assert_eq!(status, StatusCode::ACCEPTED, "{resp}");
    let dispatch = tokio::time::timeout(std::time::Duration::from_secs(5), f._host_dispatch.recv())
        .await
        .context("the job was never dispatched")?
        .context("the dispatch channel closed")?;

    assert_eq!(
        dispatch.inputs[0].root.as_deref(),
        Some(root.to_string_lossy().as_ref()),
        "the root must be the configured one, not the alias the client spelled"
    );
    // The client retargets the alias after the broker's check; the sender then reads what the Dispatch names.
    std::fs::remove_file(&alias)?;
    std::os::unix::fs::symlink(&outside, &alias)?;
    let (mut tx, mut rx) = tokio::io::duplex(1 << 20);
    let _ =
        sandyd::data_link_send::send_inputs(&mut tx, &dispatch.inputs, sandyd::data_link_send::SendLimits::default())
            .await;
    drop(tx);
    let mut sent = Vec::new();
    while let Some(message) = sandy_control_proto::read_frame::<sandy_executor_proto::DataLinkMessage>(&mut rx).await? {
        if let Some(sandy_executor_proto::data_link_message::Op::InputChunk(chunk)) = message.op {
            sent.extend(chunk.bytes);
        }
    }
    assert!(
        !String::from_utf8_lossy(&sent).contains("OUTSIDE"),
        "the retargeted alias must not redirect the read outside the root"
    );
    Ok(())
}

#[tokio::test]
async fn a_planted_symlink_under_the_root_cannot_redirect_a_path() -> Result<()> {
    let f = fixture().await?;
    let outside = f._dir.path().join("outside");
    std::fs::create_dir(&outside)?;
    std::os::unix::fs::symlink(&outside, f.root_a.join("out"))?;
    std::os::unix::fs::symlink(f._dir.path().join("absent"), f.root_a.join("dangling"))?;
    for dest in [f.root_a.join("out").join("x"), f.root_a.join("dangling")] {
        let mut body = submit_body();
        body["outputs"] = json!([{"dest": dest.to_string_lossy()}]);
        let (status, resp) = f.call("POST", "/v1/jobs", Some(TOKEN_A), Some(body)).await?;
        assert_eq!(
            (status, &resp["code"]),
            (StatusCode::FORBIDDEN, &json!("forbidden")),
            "{dest:?}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn a_client_with_no_roots_may_name_no_host_path() -> Result<()> {
    let f = fixture().await?;
    let mut body = submit_body();
    body["required_isolation_class"] = json!("untrusted");
    body["inputs"] = json!([{"host": f.root_a.join("any").to_string_lossy(), "name": "n"}]);
    let (status, resp) = f.call("POST", "/v1/jobs", Some(TOKEN_B), Some(body)).await?;
    assert_eq!((status, &resp["code"]), (StatusCode::FORBIDDEN, &json!("forbidden")));
    Ok(())
}

#[tokio::test]
async fn an_unknown_job_id_is_not_found_for_get_and_cancel() -> Result<()> {
    let f = fixture().await?;
    for (method, path) in [("GET", "/v1/jobs/nope"), ("POST", "/v1/jobs/nope/cancel")] {
        let (status, body) = f.call(method, path, Some(TOKEN_A), None).await?;
        assert_eq!((status, &body["code"]), (StatusCode::NOT_FOUND, &json!("not_found")));
    }
    Ok(())
}

#[tokio::test]
async fn an_ambiguous_clients_list_is_refused_at_startup() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let mk = |clients| BrokerConfig {
        control_socket: Path::new("/nonexistent").to_path_buf(),
        rpc_deadline: std::time::Duration::from_secs(30),
        state_dir: dir.path().join("state"),
        bind: "127.0.0.1:0".parse().expect("literal"),
        clients,
    };
    let a = client("a", "same", IsolationClass::Trusted, vec![]);
    let dup_hash = serve(mk(vec![
        a.clone(),
        client("b", "same", IsolationClass::Trusted, vec![]),
    ]))
    .await;
    assert!(matches!(dup_hash, Err(BrokerError::InvalidClients(_))), "{dup_hash:?}");
    let dup_id = serve(mk(vec![
        a.clone(),
        client("a", "other", IsolationClass::Trusted, vec![]),
    ]))
    .await;
    assert!(matches!(dup_id, Err(BrokerError::InvalidClients(_))), "{dup_id:?}");
    let upper = Client {
        token_sha256: a.token_sha256.to_uppercase(),
        ..a
    };
    let r = serve(mk(vec![upper])).await;
    assert!(matches!(r, Err(BrokerError::InvalidClients(_))), "{r:?}");
    Ok(())
}

#[tokio::test]
async fn a_non_loopback_bind_is_refused_at_startup() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let bind: SocketAddr = "0.0.0.0:0".parse()?;
    let result = serve(BrokerConfig {
        control_socket: Path::new("/nonexistent").to_path_buf(),
        rpc_deadline: std::time::Duration::from_secs(30),
        state_dir: dir.path().join("state"),
        bind,
        clients: vec![],
    })
    .await;
    assert!(matches!(result, Err(BrokerError::NonLoopback { .. })), "got {result:?}");
    Ok(())
}

#[tokio::test]
async fn a_sandyd_that_never_answers_gives_unavailable_within_the_deadline() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let socket = dir.path().join("silent.sock");
    let listener = UnixListener::bind(&socket)?;
    // Reads the request and then holds the connection open without a reply.
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            held.push(stream);
        }
    });
    let broker = serve(BrokerConfig {
        control_socket: socket,
        rpc_deadline: std::time::Duration::from_millis(200),
        state_dir: dir.path().join("state"),
        bind: "127.0.0.1:0".parse()?,
        clients: vec![client("a", TOKEN_A, IsolationClass::Trusted, vec![])],
    })
    .await?;
    let started = std::time::Instant::now();
    let resp = Http::new()
        .get(format!("http://{}/v1/jobs", broker.addr))
        .bearer_auth(TOKEN_A)
        .send()
        .await?;
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(resp.json::<Value>().await?["code"], "unavailable");
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "the deadline did not fire"
    );
    Ok(())
}
