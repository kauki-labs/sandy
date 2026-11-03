//! Shared fixture for the broker's tier-2 acceptance tests: an in-process sandyd on
//! a real UDS, the broker in front of it, and a real HTTP client.
#![allow(dead_code, reason = "shared by several test binaries; each uses a subset")]

use std::sync::Arc;

use anyhow::{Context, Result};
use reqwest::{Client as Http, StatusCode};
use sandy_broker::{BrokerConfig, Client, IsolationClass, Running, serve};
use sandyd::{
    dispatch::JobRegistry, environment_store::EnvironmentStore, host_registry::HostRegistry, store::JobStore,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::net::UnixListener;

pub const TOKEN_A: &str = "token-of-client-a";
pub const TOKEN_B: &str = "token-of-client-b";

pub struct Fixture {
    pub base: String,
    pub store: Arc<JobStore>,
    pub http: Http,
    pub _broker: Running,
    pub _dir: tempfile::TempDir,
    pub root_a: std::path::PathBuf,
}

pub fn client(id: &str, token: &str, max: IsolationClass, roots: Vec<std::path::PathBuf>) -> Client {
    Client {
        id: id.to_owned(),
        token_sha256: hex::encode(Sha256::digest(token.as_bytes())),
        max_isolation_class: max,
        max_environments: 4,
        max_environment_records: 64,
        profiles: ["dev", "prod", "other"].map(String::from).to_vec(),
        roots,
    }
}

pub async fn fixture() -> Result<Fixture> {
    fixture_with_env_quota(4).await
}

/// A fixture whose client `a` may hold `max_environments` environments.
pub async fn fixture_with_env_quota(max_environments: usize) -> Result<Fixture> {
    fixture_with_limits(max_environments, 64).await
}

/// A fixture whose client `a` may hold `max_environments` live environments and ever
/// create `max_environment_records`.
pub async fn fixture_with_limits(max_environments: usize, max_environment_records: usize) -> Result<Fixture> {
    let dir = tempfile::tempdir()?;
    let socket = dir.path().join("sandyd.sock");
    let store = Arc::new(JobStore::open_in_memory()?);
    let environments = Arc::new(EnvironmentStore::open_in_memory()?);
    let registry = Arc::new(JobRegistry::new()?);
    let hosts = Arc::new(HostRegistry::default());
    let listener = UnixListener::bind(&socket)?;
    let (s, e, r, h) = (Arc::clone(&store), environments, registry, hosts);
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(sandyd::serve_connection(
                stream,
                Arc::clone(&s),
                Arc::clone(&e),
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
        rpc_deadline: std::time::Duration::from_secs(30),
        state_dir: dir.path().join("state"),
        bind: "127.0.0.1:0".parse()?,
        clients: vec![
            Client {
                max_environments,
                max_environment_records,
                ..client("a", TOKEN_A, IsolationClass::Trusted, vec![root_a.clone()])
            },
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

pub fn submit_body() -> Value {
    json!({"manifest": "bQ==", "manifest_encoding": "test/v1", "required_isolation_class": "trusted"})
}

impl Fixture {
    pub async fn call(
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

    pub async fn submit(&self, token: &str) -> Result<String> {
        let (status, body) = self.call("POST", "/v1/jobs", Some(token), Some(submit_body())).await?;
        assert_eq!(status, StatusCode::ACCEPTED, "submit failed: {body}");
        Ok(body["job_id"].as_str().context("job_id")?.to_owned())
    }
}
