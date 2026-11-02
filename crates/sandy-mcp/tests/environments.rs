//! Environment tools over a stateful fake broker: the contract the tools must
//! pass through unchanged. The fake broker holds the O1-O9 rules; these tests prove the
//! tools forward arguments and typed results faithfully, not that a real broker obeys them.

mod common;

use anyhow::{Context, Result};
use common::broker;
use sandy_mcp::{Api, Server};
use serde_json::{Value, json};

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
async fn spawn_forwards_the_request_id_unchanged() -> Result<()> {
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
async fn connection_and_failure_pass_through_unchanged() -> Result<()> {
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
