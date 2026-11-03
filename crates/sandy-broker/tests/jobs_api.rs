//! Tier-2 acceptance for the broker's job endpoints (#591): the broker runs over
//! an in-process sandyd on a real UDS, and a real HTTP client drives it.

mod common;

use std::{net::SocketAddr, path::Path};

use anyhow::{Context, Result};
use base64::Engine;
use common::{TOKEN_A, TOKEN_B, client, fixture, submit_body};
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

#[tokio::test]
async fn no_response_carries_the_attach_token() -> Result<()> {
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

    // The attach bridge: its response, the stream URL, the stream's headers and content carry
    // neither the token nor the cap the broker presented on sandyd's attach socket.
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
    let resp = f.open_stream(&stream_url, Some(TOKEN_A)).await?;
    seen.push_str(&format!("{:?}", resp.headers()));
    let mut lines = common::Lines::new(resp);
    lines.output_bytes(5).await?;
    f.finish(&live, sandy_control_proto::JobStatus::Succeeded)?;
    seen.push_str(&lines.last().await?.to_string());
    let caps = f.caps.lock().map_err(|_| anyhow::anyhow!("poisoned"))?.clone();
    assert!(
        !caps.is_empty(),
        "the broker never presented a cap, so there is no needle"
    );
    let mut needles = needles.to_vec();
    for cap_hex in caps {
        let raw = hex::decode(&cap_hex)?;
        needles.extend([
            cap_hex,
            base64::engine::general_purpose::STANDARD.encode(&raw),
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&raw),
        ]);
    }
    assert!(
        needles.iter().all(|n| !seen.contains(n.as_str())),
        "the attach bridge leaked the token or the cap"
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
