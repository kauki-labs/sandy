//! Environment tools over a stateful fake broker: the contract the tools must
//! pass through unchanged (O1-O9; AT-1 to AT-4, AT-6, AT-9, AT-14, AT-16, AT-17).

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use anyhow::{Context, Result};
use sandy_mcp::{Api, Server};
use serde_json::{Value, json};

/// A minimal in-memory broker: idempotent spawn, a probe gate, typed errors.
#[derive(Default)]
struct Broker {
    by_request: HashMap<String, (Value, String)>,
    states: HashMap<String, String>,
    requests: Vec<(String, String)>,
}

fn broker() -> Result<(String, Arc<Mutex<Broker>>)> {
    let server = tiny_http::Server::http("127.0.0.1:0").map_err(|e| anyhow::anyhow!("{e}"))?;
    let url = format!("http://{}", server.server_addr());
    let state = Arc::new(Mutex::new(Broker::default()));
    let s = Arc::clone(&state);
    std::thread::spawn(move || {
        for mut req in server.incoming_requests() {
            let mut body = String::new();
            let _ = req.as_reader().read_to_string(&mut body);
            let method = req.method().to_string();
            let url = req.url().to_string();
            let (status, out) = route(&mut s.lock().unwrap(), &method, &url, &body);
            let resp = tiny_http::Response::from_string(out.to_string())
                .with_status_code(status)
                .with_header(tiny_http::Header::from_bytes("content-type", "application/json").unwrap());
            let _ = req.respond(resp);
        }
    });
    Ok((url, state))
}

fn err(status: u16, code: &str) -> (u16, Value) {
    (status, json!({"code": code, "message": code}))
}

fn route(b: &mut Broker, method: &str, url: &str, body: &str) -> (u16, Value) {
    b.requests.push((method.to_owned(), url.to_owned()));
    let (path, query) = url.split_once('?').unwrap_or((url, ""));
    let parts: Vec<_> = path.trim_matches('/').split('/').collect();
    match (method, parts.as_slice()) {
        ("POST", ["v1", "environments"]) => {
            let payload: Value = serde_json::from_str(body).unwrap_or_default();
            let rid = payload["request_id"].as_str().unwrap_or_default().to_owned();
            if let Some((first, id)) = b.by_request.get(&rid) {
                if *first != payload {
                    return err(409, "request_id_conflict");
                }
                return (202, json!({"environment_id": id, "state": b.states[id]}));
            }
            if b.states.values().filter(|s| *s != "deleted").count() >= 2 {
                return err(429, "quota_exceeded");
            }
            let id = format!("env{}", b.states.len() + 1);
            b.by_request.insert(rid, (payload, id.clone()));
            b.states.insert(id.clone(), "provisioning".into());
            (202, json!({"environment_id": id, "state": "provisioning"}))
        }
        ("GET", ["v1", "environments"]) => {
            let want = query.strip_prefix("state=");
            let envs: Vec<_> = b
                .states
                .iter()
                .filter(|(_, s)| want.is_none_or(|w| w == s.as_str()))
                .map(|(id, s)| json!({"environment_id": id, "state": s}))
                .collect();
            (200, json!({"environments": envs}))
        }
        ("GET", ["v1", "environments", id]) => match b.states.get(*id) {
            None => err(404, "not_found"),
            Some(s) if s == "ready" => (
                200,
                json!({"environment_id": id, "state": s, "steps": [],
                       "connection": {"url": "http://10.0.0.2:3773"}}),
            ),
            Some(s) if s == "failed" => (
                200,
                json!({"environment_id": id, "state": s, "steps": [],
                       "failure": {"step": "boot", "reason": "probe timed out"}}),
            ),
            Some(s) => (200, json!({"environment_id": id, "state": s, "steps": []})),
        },
        ("DELETE", ["v1", "environments", id]) | ("POST", ["v1", "environments", id, "cancel"]) => {
            if !b.states.contains_key(*id) {
                return err(404, "not_found");
            }
            b.states.insert((*id).to_owned(), "deleted".into());
            (200, json!({"environment_id": id, "state": "deleted"}))
        }
        ("POST", ["v1", "environments", _, "stop" | "resume"]) => err(409, "unsupported_for_lifetime"),
        ("POST", ["v1", "environments", _, "link"]) => (200, json!({"link_status": "unsupported"})),
        _ => err(404, "not_found"),
    }
}

async fn call(server: &Server, name: &str, args: Value) -> Result<(bool, Value)> {
    let resp = server
        .handle(json!({"jsonrpc":"2.0","id":1,"method":"tools/call",
                       "params":{"name":name,"arguments":args}}))
        .await
        .context("answer")?;
    let is_err = resp["result"]["isError"].as_bool().unwrap_or(false);
    let text = resp["result"]["content"][0]["text"].as_str().context("text")?;
    Ok((is_err, serde_json::from_str(text)?))
}

fn spawn_args(request_id: &str) -> Value {
    json!({"request_id": request_id, "profile": "harness",
           "lifetime": {"kind": "ephemeral", "ttl_secs": 600}, "task_ref": "t1"})
}

#[tokio::test]
async fn spawn_is_idempotent_by_request_id() -> Result<()> {
    let (url, state) = broker()?;
    let server = Server::new(Api::new(&url, "c"));
    let (_, a) = call(&server, "spawn_environment", spawn_args("r1")).await?;
    let (_, b) = call(&server, "spawn_environment", spawn_args("r1")).await?;
    assert_eq!(a["environment_id"], b["environment_id"]);
    assert_eq!(state.lock().unwrap().by_request.len(), 1);
    Ok(())
}

#[tokio::test]
async fn the_same_request_id_with_another_payload_is_a_typed_conflict() -> Result<()> {
    let (url, _) = broker()?;
    let server = Server::new(Api::new(&url, "c"));
    call(&server, "spawn_environment", spawn_args("r1")).await?;
    let mut other = spawn_args("r1");
    other["profile"] = json!("other");
    let (is_err, body) = call(&server, "spawn_environment", other).await?;
    assert!(is_err);
    assert_eq!(body["code"], "request_id_conflict");
    Ok(())
}

#[tokio::test]
async fn connection_appears_only_when_ready_and_failure_names_the_step() -> Result<()> {
    let (url, state) = broker()?;
    let server = Server::new(Api::new(&url, "c"));
    let (_, s) = call(&server, "spawn_environment", spawn_args("r1")).await?;
    let id = s["environment_id"].as_str().context("id")?.to_owned();
    let get = || call(&server, "get_environment", json!({"environment_id": id}));
    let (_, provisioning) = get().await?;
    assert_eq!(provisioning["state"], "provisioning");
    assert!(provisioning.get("connection").is_none());
    state.lock().unwrap().states.insert(id.clone(), "ready".into());
    let (_, ready) = get().await?;
    assert_eq!(ready["connection"]["url"], "http://10.0.0.2:3773");
    state.lock().unwrap().states.insert(id.clone(), "failed".into());
    let (_, failed) = get().await?;
    assert_eq!(failed["failure"]["step"], "boot");
    assert!(!failed["failure"]["reason"].as_str().unwrap_or_default().is_empty());
    Ok(())
}

#[tokio::test]
async fn cancel_and_delete_end_deleted_and_delete_is_idempotent() -> Result<()> {
    let (url, _) = broker()?;
    let server = Server::new(Api::new(&url, "c"));
    let (_, a) = call(&server, "spawn_environment", spawn_args("r1")).await?;
    let id = a["environment_id"].clone();
    let (e, cancelled) = call(&server, "cancel_environment", json!({"environment_id": id})).await?;
    assert!(!e);
    assert_eq!(cancelled["state"], "deleted");
    for _ in 0..2 {
        let (e, del) = call(&server, "delete_environment", json!({"environment_id": id})).await?;
        assert!(!e);
        assert_eq!(del["state"], "deleted");
    }
    Ok(())
}

#[tokio::test]
async fn stop_and_resume_on_an_ephemeral_environment_are_typed_unsupported() -> Result<()> {
    let (url, _) = broker()?;
    let server = Server::new(Api::new(&url, "c"));
    let (_, a) = call(&server, "spawn_environment", spawn_args("r1")).await?;
    for tool in ["stop_environment", "resume_environment"] {
        let (e, body) = call(&server, tool, json!({"environment_id": a["environment_id"]})).await?;
        assert!(e);
        assert_eq!(body["code"], "unsupported_for_lifetime");
    }
    Ok(())
}

#[tokio::test]
async fn the_quota_error_is_typed() -> Result<()> {
    let (url, _) = broker()?;
    let server = Server::new(Api::new(&url, "c"));
    for r in ["r1", "r2"] {
        call(&server, "spawn_environment", spawn_args(r)).await?;
    }
    let (e, body) = call(&server, "spawn_environment", spawn_args("r3")).await?;
    assert!(e);
    assert_eq!(body["code"], "quota_exceeded");
    Ok(())
}

#[tokio::test]
async fn list_filters_by_state_in_the_query() -> Result<()> {
    let (url, state) = broker()?;
    let server = Server::new(Api::new(&url, "c"));
    call(&server, "spawn_environment", spawn_args("r1")).await?;
    let (_, all) = call(&server, "list_environments", json!({})).await?;
    assert_eq!(all["environments"].as_array().context("arr")?.len(), 1);
    let (_, none) = call(&server, "list_environments", json!({"state": "ready"})).await?;
    assert!(none["environments"].as_array().context("arr")?.is_empty());
    assert!(
        state
            .lock()
            .unwrap()
            .requests
            .iter()
            .any(|(_, u)| u == "/v1/environments?state=ready")
    );
    Ok(())
}

/// AT-17 at the tool boundary: link takes no code and returns none.
#[tokio::test]
async fn link_has_no_code_argument_and_returns_only_a_status() -> Result<()> {
    let (url, _) = broker()?;
    let server = Server::new(Api::new(&url, "c"));
    let (_, a) = call(&server, "spawn_environment", spawn_args("r1")).await?;
    let id = a["environment_id"].clone();
    let (e, refused) = call(
        &server,
        "link_environment",
        json!({"environment_id": id, "primary": "p", "pairing_code": "123456"}),
    )
    .await?;
    assert!(e, "a pairing code argument must be refused: {refused}");
    let (e, ok) = call(
        &server,
        "link_environment",
        json!({"environment_id": id, "primary": "p"}),
    )
    .await?;
    assert!(!e);
    assert_eq!(ok["link_status"], "unsupported");
    Ok(())
}

#[tokio::test]
async fn an_environment_id_cannot_escape_its_path_segment() -> Result<()> {
    let (url, state) = broker()?;
    let server = Server::new(Api::new(&url, "c"));
    let (e, _) = call(&server, "get_environment", json!({"environment_id": "../jobs"})).await?;
    assert!(e);
    assert!(state.lock().unwrap().requests.is_empty());
    Ok(())
}
