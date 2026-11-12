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
async fn link_stays_unsupported_until_a_service_offers_an_interface() -> Result<()> {
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

/// Rows owned by nobody the broker knows, enough to need several sandyd list pages. Their ids
/// (`env--foreign-N`) sort before every minted `env-<hex>` id, so a client's own rows are on the
/// last page, never the first. The spec bytes are a
/// valid `EnvironmentSpec` (field 1, `profile`, set to `p`).
fn fill_foreign_rows(f: &common::Fixture, n: usize) -> Result<()> {
    for i in 0..n {
        f.environments.create(
            &format!("foreign-{i}"),
            &format!("env--foreign-{i:06}"),
            b"\x0a\x01p",
            sandyd::environment::SPEC_ENCODING,
        )?;
    }
    Ok(())
}

#[tokio::test]
async fn the_broker_list_and_quota_check_keep_working_over_more_rows_than_one_page() -> Result<()> {
    let f = common::fixture_with_limits(200, 200).await?;
    fill_foreign_rows(&f, 1100)?;
    let a = spawn_id(&f, TOKEN_A, spawn_body("p1")).await?;
    let (status, list) = f.call("GET", "/v1/environments", Some(TOKEN_A), None).await?;
    assert_eq!(status, StatusCode::OK, "{list}");
    let ids: Vec<&str> = list["environments"]
        .as_array()
        .context("environments")?
        .iter()
        .filter_map(|e| e["environment_id"].as_str())
        .collect();
    assert_eq!(
        ids,
        [a.as_str()],
        "only the caller's environment, found past the first page"
    );
    // The quota check lists everything too, so a second spawn proves it works.
    spawn_id(&f, TOKEN_A, spawn_body("p2")).await?;
    Ok(())
}

#[tokio::test]
async fn a_daemon_with_more_rows_than_the_broker_will_scan_is_unavailable_not_truncated() -> Result<()> {
    let f = common::fixture_with_limits(200, 200).await?;
    fill_foreign_rows(&f, 10_001)?;
    let (status, body) = f.call("GET", "/v1/environments", Some(TOKEN_A), None).await?;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::SERVICE_UNAVAILABLE, &json!("unavailable")),
        "{body}"
    );
    Ok(())
}

#[tokio::test]
async fn churn_by_fresh_keys_cannot_fill_sandyds_row_cap_for_other_clients() -> Result<()> {
    let f = common::fixture_with_row_cap(4, 64, Some(2)).await?;
    for n in 0..6 {
        let id = spawn_id(&f, TOKEN_A, spawn_body(&format!("c{n}"))).await?;
        f.call("DELETE", &format!("/v1/environments/{id}"), Some(TOKEN_A), None)
            .await?;
    }
    spawn_id(&f, TOKEN_B, spawn_body("b1")).await?;
    Ok(())
}

#[tokio::test]
async fn a_replay_of_a_key_sandyd_has_collected_counts_against_the_quota_again() -> Result<()> {
    let f = common::fixture_with_limits(2, 64).await?;
    let old = spawn_id(&f, TOKEN_A, spawn_body("old")).await?;
    f.call("DELETE", &format!("/v1/environments/{old}"), Some(TOKEN_A), None)
        .await?;
    f.environments.gc_deleted(
        i64::MAX / 2,
        &sandyd::environment_store::RetentionPolicy {
            window_secs: 1,
            max_deleted: 100,
        },
    )?;
    spawn_id(&f, TOKEN_A, spawn_body("f1")).await?;
    spawn_id(&f, TOKEN_A, spawn_body("f2")).await?;
    // The key is forgotten by sandyd, so this replay would create a third live environment.
    let (status, body) = spawn(&f, TOKEN_A, spawn_body("old")).await?;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::TOO_MANY_REQUESTS, &json!("quota_exceeded")),
        "{body}"
    );
    Ok(())
}

#[tokio::test]
async fn a_replay_inside_the_retention_window_still_skips_the_quota_check() -> Result<()> {
    let f = common::fixture_with_limits(1, 64).await?;
    let first = spawn_id(&f, TOKEN_A, spawn_body("r")).await?;
    let again = spawn_id(&f, TOKEN_A, spawn_body("r")).await?;
    assert_eq!(first, again, "at quota, a replay still returns the same environment");
    Ok(())
}

#[tokio::test]
async fn the_broker_scan_ceiling_is_exactly_10000_rows() -> Result<()> {
    let f = common::fixture_with_limits(200, 200).await?;
    fill_foreign_rows(&f, 9_999)?;
    let a = spawn_id(&f, TOKEN_A, spawn_body("edge")).await?; // the table now holds 10000 rows
    let (status, list) = f.call("GET", "/v1/environments", Some(TOKEN_A), None).await?;
    assert_eq!(status, StatusCode::OK, "10000 rows are within the ceiling: {list}");
    assert_eq!(list["environments"][0]["environment_id"], a.as_str());
    let (status, body) = spawn(&f, TOKEN_A, spawn_body("over")).await?; // scans 10000, creates the 10001st
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    let (status, body) = f.call("GET", "/v1/environments", Some(TOKEN_A), None).await?;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::SERVICE_UNAVAILABLE, &json!("unavailable")),
        "{body}"
    );
    Ok(())
}

/// The retention sweep can collect a replayed key's row between the broker's lookup and the create.
/// The owner table here names `env-seed`, which sandyd still holds under another key, so the lookup
/// succeeds while sandyd has never seen this request's key: the create makes a new environment.
#[tokio::test]
async fn a_replay_that_creates_a_new_environment_after_the_lookup_is_quota_checked_and_undone() -> Result<()> {
    let f = common::fixture_with_owner_table(1, 64, |store| {
        let spec = b"\x0a\x01p";
        store.create("seed-key", "env-seed", spec, sandyd::environment::SPEC_ENCODING)?;
        store.delete("env-seed")?;
        Ok(json!({"environments": {"env-seed": "a"}, "keys": {"a\nrace": "env-seed"}}).to_string())
    })
    .await?;
    let live = spawn_id(&f, TOKEN_A, spawn_body("f1")).await?; // the client is now at quota
    let (status, body) = spawn(&f, TOKEN_A, spawn_body("race")).await?;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::TOO_MANY_REQUESTS, &json!("quota_exceeded")),
        "{body}"
    );
    // The environment sandyd created for the refused request is deleted, and the broker does not own it.
    let rows = f.environments.list()?;
    let undone: Vec<_> = rows
        .iter()
        .filter(|r| r.environment_id != "env-seed" && r.environment_id != live)
        .collect();
    assert_eq!(undone.len(), 1, "{rows:?}");
    assert_eq!(undone[0].state, sandyd::environment_store::EnvironmentState::Deleted);
    let (_, list) = f
        .call("GET", "/v1/environments?state=deleted", Some(TOKEN_A), None)
        .await?;
    let ids: Vec<&str> = list["environments"]
        .as_array()
        .context("environments")?
        .iter()
        .filter_map(|e| e["environment_id"].as_str())
        .collect();
    assert!(
        !ids.contains(&undone[0].environment_id.as_str()),
        "the undone row is not the client's"
    );
    Ok(())
}

#[tokio::test]
async fn a_trusted_only_backend_refuses_an_untrusted_client_and_serves_a_trusted_one() -> Result<()> {
    let f = common::fixture_with_opts(common::Opts {
        trusted_only_backend: true,
        ..common::Opts::default()
    })
    .await?;
    let (status, body) = spawn(&f, TOKEN_B, spawn_body("u1")).await?;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "an untrusted client must not spawn: {body}"
    );
    assert_eq!(body["code"], "forbidden", "{body}");
    let (_, list) = f.call("GET", "/v1/environments", Some(TOKEN_B), None).await?;
    assert_eq!(
        list["environments"].as_array().map(Vec::len),
        Some(0),
        "no row was created: {list}"
    );
    assert_eq!(f.environments.list()?.len(), 0, "sandyd holds no row");
    spawn_id(&f, TOKEN_A, spawn_body("t1")).await?;
    Ok(())
}

#[tokio::test]
async fn without_a_trusted_only_backend_an_untrusted_client_may_still_spawn() -> Result<()> {
    let f = fixture().await?;
    spawn_id(&f, TOKEN_B, spawn_body("u1")).await?;
    Ok(())
}

fn task_body(request_id: &str, task_ref: &str) -> Value {
    let mut body = ephemeral_body(request_id);
    body["task_ref"] = json!(task_ref);
    body
}

async fn state_of(f: &common::Fixture, token: &str, id: &str) -> Result<String> {
    let (status, body) = f
        .call("GET", &format!("/v1/environments/{id}"), Some(token), None)
        .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    Ok(body["state"].as_str().context("state")?.to_owned())
}

/// Ending a task deletes every environment of the caller with that `task_ref` through the delete path, leaves the
/// caller's other environments, and is idempotent (#815).
#[tokio::test]
async fn end_task_deletes_the_callers_environments_of_that_task_only_and_is_idempotent() -> Result<()> {
    let f = fixture().await?;
    let one = spawn_id(&f, TOKEN_A, task_body("e1", "task-a")).await?;
    let two = spawn_id(&f, TOKEN_A, task_body("e2", "task-a")).await?;
    let other = spawn_id(&f, TOKEN_A, task_body("e3", "task-b")).await?;
    let none = spawn_id(&f, TOKEN_A, ephemeral_body("e4")).await?;

    let (status, body) = f
        .call(
            "POST",
            "/v1/tasks/end",
            Some(TOKEN_A),
            Some(json!({"task_ref": "task-a"})),
        )
        .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let mut ended: Vec<String> = body["ended"]
        .as_array()
        .context("ended")?
        .iter()
        .filter_map(|v| v.as_str().map(str::to_owned))
        .collect();
    ended.sort();
    let mut want = vec![one.clone(), two.clone()];
    want.sort();
    assert_eq!(ended, want, "{body}");
    assert_eq!(state_of(&f, TOKEN_A, &one).await?, "deleted");
    assert_eq!(state_of(&f, TOKEN_A, &two).await?, "deleted");
    assert_eq!(
        state_of(&f, TOKEN_A, &other).await?,
        "provisioning",
        "another task is untouched"
    );
    assert_eq!(
        state_of(&f, TOKEN_A, &none).await?,
        "provisioning",
        "an environment without a task is untouched"
    );

    let (status, again) = f
        .call(
            "POST",
            "/v1/tasks/end",
            Some(TOKEN_A),
            Some(json!({"task_ref": "task-a"})),
        )
        .await?;
    assert_eq!(
        (status, &again["ended"]),
        (StatusCode::OK, &json!([])),
        "a repeat is a no-op: {again}"
    );
    Ok(())
}

/// Another client's environment with the same `task_ref` is not the caller's to end.
#[tokio::test]
async fn end_task_never_touches_another_clients_environment_with_the_same_task_ref() -> Result<()> {
    let f = fixture().await?;
    let mine = spawn_id(&f, TOKEN_A, task_body("m1", "shared")).await?;
    let theirs = spawn_id(&f, TOKEN_B, task_body("t1", "shared")).await?;
    let (status, body) = f
        .call(
            "POST",
            "/v1/tasks/end",
            Some(TOKEN_A),
            Some(json!({"task_ref": "shared"})),
        )
        .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["ended"], json!([mine.clone()]), "{body}");
    assert_eq!(state_of(&f, TOKEN_A, &mine).await?, "deleted");
    assert_eq!(
        state_of(&f, TOKEN_B, &theirs).await?,
        "provisioning",
        "b's environment survives a's end_task"
    );
    Ok(())
}

/// A task that has no environment is a successful no-op, not an error.
#[tokio::test]
async fn end_task_of_an_unknown_task_is_a_successful_no_op() -> Result<()> {
    let f = fixture().await?;
    let id = spawn_id(&f, TOKEN_A, task_body("u1", "task-a")).await?;
    let (status, body) = f
        .call(
            "POST",
            "/v1/tasks/end",
            Some(TOKEN_A),
            Some(json!({"task_ref": "nobody-has-this"})),
        )
        .await?;
    assert_eq!((status, &body["ended"]), (StatusCode::OK, &json!([])), "{body}");
    assert_eq!(state_of(&f, TOKEN_A, &id).await?, "provisioning");
    Ok(())
}

/// An empty `task_ref` matches no task (the list filter reads it as "any"), so it is refused and nothing is deleted.
/// So are a too-long one, one with a control character, a missing one and an unknown field.
#[tokio::test]
async fn end_task_refuses_a_bad_task_ref_and_deletes_nothing() -> Result<()> {
    let f = fixture().await?;
    let id = spawn_id(&f, TOKEN_A, task_body("b1", "task-a")).await?;
    let plain = spawn_id(&f, TOKEN_A, ephemeral_body("b2")).await?;
    let long = "x".repeat(257);
    for body in [
        json!({"task_ref": ""}),
        json!({"task_ref": long}),
        json!({"task_ref": "a\nb"}),
        json!({}),
        json!({"task_ref": "task-a", "also": true}),
        json!({"task_ref": 5}),
    ] {
        let (status, resp) = f
            .call("POST", "/v1/tasks/end", Some(TOKEN_A), Some(body.clone()))
            .await?;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}: {resp}");
    }
    assert_eq!(state_of(&f, TOKEN_A, &id).await?, "provisioning");
    assert_eq!(state_of(&f, TOKEN_A, &plain).await?, "provisioning");
    Ok(())
}

#[tokio::test]
async fn end_task_needs_the_bearer_token() -> Result<()> {
    let f = fixture().await?;
    let (status, _) = f
        .call("POST", "/v1/tasks/end", None, Some(json!({"task_ref": "task-a"})))
        .await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    Ok(())
}
