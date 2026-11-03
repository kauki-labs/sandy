//! Tier-2 acceptance for the broker's environment endpoints (#591): the broker runs
//! over an in-process sandyd (#587 slices A and A2) and a real HTTP client drives it.

mod common;

use anyhow::{Context, Result};
use common::{TOKEN_A, TOKEN_B, fixture};
use reqwest::StatusCode;
use serde_json::{Value, json};

fn spawn_body(request_id: &str) -> Value {
    json!({"request_id": request_id, "profile": "dev", "lifetime": {"kind": "persistent"}})
}

fn ephemeral_body(request_id: &str) -> Value {
    json!({"request_id": request_id, "profile": "dev", "lifetime": {"kind": "ephemeral", "ttl_secs": 600}})
}

async fn spawn(f: &common::Fixture, token: &str, body: Value) -> Result<(StatusCode, Value)> {
    f.call("POST", "/v1/environments", Some(token), Some(body)).await
}

async fn spawn_id(f: &common::Fixture, token: &str, body: Value) -> Result<String> {
    let (status, resp) = spawn(f, token, body).await?;
    assert_eq!(status, StatusCode::ACCEPTED, "spawn failed: {resp}");
    Ok(resp["environment_id"].as_str().context("environment_id")?.to_owned())
}

#[tokio::test]
async fn a_spawned_environment_is_provisioning_and_can_be_read_back() -> Result<()> {
    let f = fixture().await?;
    let id = spawn_id(&f, TOKEN_A, spawn_body("r1")).await?;
    let (status, body) = f
        .call("GET", &format!("/v1/environments/{id}"), Some(TOKEN_A), None)
        .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["environment_id"], id.as_str());
    assert_eq!(body["state"], "provisioning");
    assert!(body["steps"].is_array(), "the contract requires steps: {body}");
    assert!(body.get("connection").is_none(), "no connection before ready: {body}");
    Ok(())
}

#[tokio::test]
async fn two_spawns_with_one_request_id_and_payload_give_one_environment() -> Result<()> {
    let f = fixture().await?;
    let first = spawn_id(&f, TOKEN_A, spawn_body("same")).await?;
    let second = spawn_id(&f, TOKEN_A, spawn_body("same")).await?;
    assert_eq!(first, second);
    let (_, list) = f.call("GET", "/v1/environments", Some(TOKEN_A), None).await?;
    assert_eq!(list["environments"].as_array().map(Vec::len), Some(1));
    Ok(())
}

#[tokio::test]
async fn one_request_id_with_a_different_payload_is_a_typed_conflict() -> Result<()> {
    let f = fixture().await?;
    spawn_id(&f, TOKEN_A, spawn_body("k")).await?;
    let mut other = spawn_body("k");
    other["profile"] = json!("prod");
    let (status, body) = spawn(&f, TOKEN_A, other).await?;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::CONFLICT, &json!("request_id_conflict"))
    );
    Ok(())
}

#[tokio::test]
async fn clients_do_not_share_a_request_id_namespace() -> Result<()> {
    let f = fixture().await?;
    let a = spawn_id(&f, TOKEN_A, spawn_body("shared")).await?;
    let mut different = spawn_body("shared");
    different["profile"] = json!("other");
    let b = spawn_id(&f, TOKEN_B, different).await?;
    assert_ne!(
        a, b,
        "another client's request id must not return or conflict with this one"
    );
    Ok(())
}

#[tokio::test]
async fn a_client_cannot_see_or_change_another_clients_environment() -> Result<()> {
    let f = fixture().await?;
    let id = spawn_id(&f, TOKEN_A, spawn_body("mine")).await?;
    for (method, suffix) in [
        ("GET", ""),
        ("POST", "/stop"),
        ("POST", "/resume"),
        ("POST", "/cancel"),
        ("DELETE", ""),
    ] {
        let (status, body) = f
            .call(method, &format!("/v1/environments/{id}{suffix}"), Some(TOKEN_B), None)
            .await?;
        assert_eq!(
            (status, &body["code"]),
            (StatusCode::NOT_FOUND, &json!("not_found")),
            "{method} {suffix}"
        );
    }
    let (_, list) = f.call("GET", "/v1/environments", Some(TOKEN_B), None).await?;
    assert_eq!(list["environments"].as_array().map(Vec::len), Some(0), "list leaked");
    let (_, own) = f
        .call("GET", &format!("/v1/environments/{id}"), Some(TOKEN_A), None)
        .await?;
    assert_eq!(
        own["state"], "provisioning",
        "a foreign call must not change the environment"
    );
    Ok(())
}

#[tokio::test]
async fn cancel_ends_provisioning_and_delete_is_idempotent() -> Result<()> {
    let f = fixture().await?;
    let id = spawn_id(&f, TOKEN_A, spawn_body("c")).await?;
    let (status, body) = f
        .call("POST", &format!("/v1/environments/{id}/cancel"), Some(TOKEN_A), None)
        .await?;
    assert_eq!(
        (status, body["state"].as_str()),
        (StatusCode::OK, Some("deleted")),
        "{body}"
    );
    for _ in 0..2 {
        let (status, body) = f
            .call("DELETE", &format!("/v1/environments/{id}"), Some(TOKEN_A), None)
            .await?;
        assert_eq!(
            (status, body["state"].as_str()),
            (StatusCode::OK, Some("deleted")),
            "{body}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn stopping_an_ephemeral_environment_is_unsupported_for_its_lifetime() -> Result<()> {
    let f = fixture().await?;
    let id = spawn_id(&f, TOKEN_A, ephemeral_body("e")).await?;
    let (status, body) = f
        .call("POST", &format!("/v1/environments/{id}/stop"), Some(TOKEN_A), None)
        .await?;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::CONFLICT, &json!("unsupported_for_lifetime")),
        "{body}"
    );
    Ok(())
}

#[tokio::test]
async fn the_per_client_quota_counts_distinct_environments_not_replays() -> Result<()> {
    let f = common::fixture_with_env_quota(1).await?;
    spawn_id(&f, TOKEN_A, spawn_body("q1")).await?;
    spawn_id(&f, TOKEN_A, spawn_body("q1")).await?; // a replay is not a second environment
    let (status, body) = spawn(&f, TOKEN_A, spawn_body("q2")).await?;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::TOO_MANY_REQUESTS, &json!("quota_exceeded")),
        "{body}"
    );
    Ok(())
}

#[tokio::test]
async fn a_malformed_or_credential_shaped_request_is_invalid() -> Result<()> {
    let f = fixture().await?;
    let long = "x".repeat(200);
    let bad = [
        json!({"request_id": "", "profile": "dev", "lifetime": {"kind": "persistent"}}),
        json!({"request_id": long, "profile": "dev", "lifetime": {"kind": "persistent"}}),
        json!({"request_id": "has space", "profile": "dev", "lifetime": {"kind": "persistent"}}),
        json!({"request_id": "ok", "profile": "dev", "lifetime": {"kind": "ephemeral"}}),
        json!({"request_id": "ok", "profile": "dev", "lifetime": {"kind": "persistent"}, "token": "x"}),
    ];
    for body in bad {
        let (status, resp) = spawn(&f, TOKEN_A, body.clone()).await?;
        assert_eq!(
            (status, &resp["code"]),
            (StatusCode::BAD_REQUEST, &json!("invalid_request")),
            "{body}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn link_stays_unsupported_until_t3_offers_an_interface() -> Result<()> {
    let f = fixture().await?;
    let id = spawn_id(&f, TOKEN_A, spawn_body("l")).await?;
    let (status, body) = f
        .call(
            "POST",
            &format!("/v1/environments/{id}/link"),
            Some(TOKEN_A),
            Some(json!({"primary": "p"})),
        )
        .await?;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::NOT_IMPLEMENTED, &json!("unsupported"))
    );
    Ok(())
}

#[tokio::test]
async fn one_clients_environments_do_not_use_up_another_clients_quota_and_delete_frees_a_slot() -> Result<()> {
    let f = common::fixture_with_env_quota(1).await?;
    let a = spawn_id(&f, TOKEN_A, spawn_body("a1")).await?;
    // Client b has its own default quota of 4: a's environment does not count against it.
    for n in 0..4 {
        spawn_id(&f, TOKEN_B, spawn_body(&format!("b{n}"))).await?;
    }
    let (status, body) = spawn(&f, TOKEN_A, spawn_body("a2")).await?;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::TOO_MANY_REQUESTS, &json!("quota_exceeded"))
    );
    f.call("DELETE", &format!("/v1/environments/{a}"), Some(TOKEN_A), None)
        .await?;
    spawn_id(&f, TOKEN_A, spawn_body("a2")).await?;
    Ok(())
}

#[tokio::test]
async fn creating_and_deleting_cannot_grow_sandyds_table_past_the_clients_record_cap() -> Result<()> {
    let f = common::fixture_with_limits(4, 3).await?;
    for n in 0..3 {
        let id = spawn_id(&f, TOKEN_A, spawn_body(&format!("r{n}"))).await?;
        f.call("DELETE", &format!("/v1/environments/{id}"), Some(TOKEN_A), None)
            .await?;
    }
    let (status, body) = spawn(&f, TOKEN_A, spawn_body("r3")).await?;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::TOO_MANY_REQUESTS, &json!("quota_exceeded")),
        "{body}"
    );
    // A replay of a request already made is not a new record.
    spawn_id(&f, TOKEN_A, spawn_body("r0")).await?;
    // Another client's cap is its own.
    spawn_id(&f, TOKEN_B, spawn_body("r3")).await?;
    Ok(())
}

#[tokio::test]
async fn a_list_filter_by_state_and_task_ref_and_a_bad_filter() -> Result<()> {
    let f = fixture().await?;
    let mut body = spawn_body("t1");
    body["task_ref"] = json!("task-a");
    let a = spawn_id(&f, TOKEN_A, body).await?;
    spawn_id(&f, TOKEN_A, spawn_body("t2")).await?;
    let (_, by_task) = f
        .call("GET", "/v1/environments?task_ref=task-a", Some(TOKEN_A), None)
        .await?;
    assert_eq!(by_task["environments"].as_array().map(Vec::len), Some(1));
    assert_eq!(by_task["environments"][0]["environment_id"], a.as_str());
    let (_, ready) = f
        .call("GET", "/v1/environments?state=ready", Some(TOKEN_A), None)
        .await?;
    assert_eq!(ready["environments"].as_array().map(Vec::len), Some(0));
    for bad in ["state=nonsense", "task_ref=%00bad"] {
        let (status, resp) = f
            .call("GET", &format!("/v1/environments?{bad}"), Some(TOKEN_A), None)
            .await?;
        assert_eq!(
            (status, &resp["code"]),
            (StatusCode::BAD_REQUEST, &json!("invalid_request")),
            "{bad}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn a_profile_the_client_may_not_use_is_forbidden_and_creates_nothing() -> Result<()> {
    let f = fixture().await?;
    // An unlisted name, and a credential-shaped one: the allow-list refuses both before
    // sandyd sees them.
    for profile in ["admin", "ghp_0123456789abcdef0123456789abcdef0123"] {
        let mut body = spawn_body("p1");
        body["profile"] = json!(profile);
        let (status, resp) = spawn(&f, TOKEN_A, body).await?;
        assert_eq!(
            (status, &resp["code"]),
            (StatusCode::FORBIDDEN, &json!("forbidden")),
            "{profile}: {resp}"
        );
    }
    let (_, list) = f.call("GET", "/v1/environments", Some(TOKEN_A), None).await?;
    assert_eq!(list["environments"].as_array().map(Vec::len), Some(0));
    Ok(())
}
