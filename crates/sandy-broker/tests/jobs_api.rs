//! Tier-2 acceptance for the broker's job endpoints (#591): the broker runs over
//! an in-process sandyd on a real UDS, and a real HTTP client drives it.

use std::{net::SocketAddr, path::Path, sync::Arc};

use anyhow::{Context, Result};
use reqwest::{Client as Http, StatusCode};
use sandy_broker::{BrokerConfig, BrokerError, Client, IsolationClass, Running, serve};
use sandyd::{dispatch::JobRegistry, host_registry::HostRegistry, store::JobStore};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::net::UnixListener;

const TOKEN_A: &str = "token-of-client-a";
const TOKEN_B: &str = "token-of-client-b";

struct Fixture {
    base: String,
    store: Arc<JobStore>,
    http: Http,
    _broker: Running,
    _dir: tempfile::TempDir,
    root_a: std::path::PathBuf,
}

fn client(id: &str, token: &str, max: IsolationClass, roots: Vec<std::path::PathBuf>) -> Client {
    Client {
        id: id.to_owned(),
        token_sha256: hex::encode(Sha256::digest(token.as_bytes())),
        max_isolation_class: max,
        roots,
    }
}

async fn fixture() -> Result<Fixture> {
    let dir = tempfile::tempdir()?;
    let socket = dir.path().join("sandyd.sock");
    let store = Arc::new(JobStore::open_in_memory()?);
    let registry = Arc::new(JobRegistry::new()?);
    let hosts = Arc::new(HostRegistry::default());
    let listener = UnixListener::bind(&socket)?;
    let (s, r, h) = (Arc::clone(&store), registry, hosts);
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(sandyd::serve_connection(
                stream,
                Arc::clone(&s),
                Arc::clone(&r),
                Arc::clone(&h),
                None,
            ));
        }
    });
    let root_a = dir.path().join("root-a");
    std::fs::create_dir(&root_a)?;
    let broker = serve(BrokerConfig {
        control_socket: socket,
        state_dir: dir.path().join("state"),
        bind: "127.0.0.1:0".parse()?,
        clients: vec![
            client("a", TOKEN_A, IsolationClass::Trusted, vec![root_a.clone()]),
            client("b", TOKEN_B, IsolationClass::Untrusted, vec![]),
        ],
    })
    .await?;
    Ok(Fixture {
        base: format!("http://{}", broker.addr),
        store,
        http: Http::new(),
        _broker: broker,
        _dir: dir,
        root_a,
    })
}

fn submit_body() -> Value {
    json!({"manifest": "bQ==", "manifest_encoding": "test/v1", "required_isolation_class": "trusted"})
}

impl Fixture {
    async fn call(
        &self,
        method: &str,
        path: &str,
        token: Option<&str>,
        body: Option<Value>,
    ) -> Result<(StatusCode, Value)> {
        let mut req = self.http.request(method.parse()?, format!("{}{path}", self.base));
        if let Some(t) = token {
            req = req.bearer_auth(t);
        }
        if let Some(b) = body {
            req = req.json(&b);
        }
        let resp = req.send().await?;
        let status = resp.status();
        let text = resp.text().await?;
        Ok((status, serde_json::from_str(&text).unwrap_or(Value::String(text))))
    }

    async fn submit(&self, token: &str) -> Result<String> {
        let (status, body) = self.call("POST", "/v1/jobs", Some(token), Some(submit_body())).await?;
        assert_eq!(status, StatusCode::ACCEPTED, "submit failed: {body}");
        Ok(body["job_id"].as_str().context("job_id")?.to_owned())
    }
}

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
    let id = f.submit(TOKEN_A).await?;
    let token = f.store.attach_token(&id)?.context("sandyd stored no attach token")?;
    let needles = [hex::encode(&token), String::from_utf8_lossy(&token).into_owned()];
    for (method, path) in [
        ("GET", "/v1/jobs".to_owned()),
        ("GET", format!("/v1/jobs/{id}")),
        ("POST", format!("/v1/jobs/{id}/cancel")),
    ] {
        let (_, body) = f.call(method, &path, Some(TOKEN_A), None).await?;
        let text = body.to_string();
        assert!(
            needles.iter().all(|n| n.is_empty() || !text.contains(n.as_str())),
            "{path} leaked the attach token"
        );
    }
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
    // 503 is expected here. The broker's own boundary is: not 403.
    assert_ne!(
        status,
        StatusCode::FORBIDDEN,
        "a path inside the root must pass the broker: {resp}"
    );
    Ok(())
}

#[tokio::test]
async fn attach_and_environments_are_typed_unsupported() -> Result<()> {
    let f = fixture().await?;
    let id = f.submit(TOKEN_A).await?;
    for (method, path) in [
        ("POST", format!("/v1/jobs/{id}/attach")),
        ("GET", "/v1/environments".to_owned()),
        ("POST", "/v1/environments".to_owned()),
    ] {
        let (status, body) = f.call(method, &path, Some(TOKEN_A), Some(json!({}))).await?;
        assert_eq!(
            (status, &body["code"]),
            (StatusCode::NOT_IMPLEMENTED, &json!("unsupported")),
            "{path}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn a_non_loopback_bind_is_refused_at_startup() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let bind: SocketAddr = "0.0.0.0:0".parse()?;
    let result = serve(BrokerConfig {
        control_socket: Path::new("/nonexistent").to_path_buf(),
        state_dir: dir.path().join("state"),
        bind,
        clients: vec![],
    })
    .await;
    assert!(matches!(result, Err(BrokerError::NonLoopback { .. })), "got {result:?}");
    Ok(())
}
