//! Findings from the adversarial review of #604: guard bypasses, path and
//! query injection, hangs, redirects, JSON-RPC edge cases.

use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use sandy_mcp::{Api, Server, check_base_url};
use serde_json::{Value, json};

const TOKEN: &str = "ghp_abcdefghijklmnopqrstuvwxyz0123456789";

/// One canned reply for every request, whatever the route.
#[derive(Clone)]
struct Reply {
    status: u16,
    body: String,
    location: Option<String>,
    delay: Duration,
}

impl Reply {
    fn json(status: u16, v: &Value) -> Self {
        Self {
            status,
            body: v.to_string(),
            location: None,
            delay: Duration::ZERO,
        }
    }
}

/// Serves `reply` to every request and records `METHOD URL` for each.
fn fake(reply: Reply) -> Result<(String, Arc<Mutex<Vec<String>>>)> {
    let server = tiny_http::Server::http("127.0.0.1:0").map_err(|e| anyhow::anyhow!("{e}"))?;
    let url = format!("http://{}", server.server_addr());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    std::thread::spawn(move || {
        for req in server.incoming_requests() {
            log.lock().unwrap().push(format!("{} {}", req.method(), req.url()));
            std::thread::sleep(reply.delay);
            let mut resp = tiny_http::Response::from_string(reply.body.clone())
                .with_status_code(reply.status)
                .with_header(tiny_http::Header::from_bytes("content-type", "application/json").unwrap());
            if let Some(loc) = &reply.location {
                resp = resp.with_header(tiny_http::Header::from_bytes("location", loc.as_str()).unwrap());
            }
            let _ = req.respond(resp);
        }
    });
    Ok((url, seen))
}

async fn call(server: &Server, name: &str, args: Value) -> Result<(bool, Value)> {
    let resp = server
        .handle(json!({"jsonrpc":"2.0","id":1,"method":"tools/call",
                       "params":{"name":name,"arguments":args}}))
        .await
        .context("answer")?;
    let is_err = resp["result"]["isError"].as_bool().unwrap_or(false);
    let text = resp["result"]["content"][0]["text"].as_str().unwrap_or("null");
    Ok((is_err, serde_json::from_str(text).unwrap_or(Value::Null)))
}

fn submit(extra: Value) -> Value {
    let mut a = json!({"manifest":"AA==","manifest_encoding":"m.v1",
                       "required_isolation_class":"trusted"});
    for (k, v) in extra.as_object().into_iter().flatten() {
        a[k] = v.clone();
    }
    a
}

#[tokio::test]
async fn a_secret_in_a_broker_error_is_withheld_with_a_distinct_code() -> Result<()> {
    let (url, _) = fake(Reply::json(
        400,
        &json!({"code":"invalid_request","message":format!("bad {TOKEN}")}),
    ))?;
    let server = Server::new(Api::new(&url, "c"));
    let (e, body) = call(&server, "list", json!({})).await?;
    assert!(e);
    assert_eq!(body["code"], "withheld");
    assert!(!body.to_string().contains("ghp_"));
    Ok(())
}

#[tokio::test]
async fn a_withheld_result_says_the_operation_ran() -> Result<()> {
    let (url, _) = fake(Reply::json(
        200,
        &json!({"job_id":"j1","state":"running","console_tail":TOKEN}),
    ))?;
    let server = Server::new(Api::new(&url, "c"));
    let (e, body) = call(&server, "status", json!({"job_id":"j1"})).await?;
    assert!(e);
    assert_eq!(body["code"], "withheld");
    assert!(body["message"].as_str().unwrap_or_default().contains("ran"));
    Ok(())
}

#[tokio::test]
async fn glued_tokens_and_variant_key_names_are_refused() -> Result<()> {
    let (url, seen) = fake(Reply::json(200, &json!({})))?;
    let server = Server::new(Api::new(&url, "c"));
    for value in [
        format!("GITHUB_TOKEN={TOKEN}"),
        format!("http://x/s?t={TOKEN}"),
        format!("Bearer:{TOKEN}"),
    ] {
        let (e, _) = call(&server, "submit", submit(json!({"manifest_encoding": value}))).await?;
        assert!(e, "must refuse {value}");
    }
    for key in [
        "access_token",
        "client_secret",
        "private_key",
        "pairingCode",
        "credential",
    ] {
        let (e, _) = call(&server, "submit", submit(json!({key: "x"}))).await?;
        assert!(e, "must refuse key {key}");
    }
    assert!(seen.lock().unwrap().is_empty());
    Ok(())
}

#[tokio::test]
async fn variant_key_names_in_a_result_are_withheld() -> Result<()> {
    let (url, _) = fake(Reply::json(200, &json!({"jobs":[],"access_token":"x"})))?;
    let server = Server::new(Api::new(&url, "c"));
    let (e, body) = call(&server, "list", json!({})).await?;
    assert!(e);
    assert_eq!(body["code"], "withheld");
    Ok(())
}

#[tokio::test]
async fn ordinary_words_that_contain_a_token_prefix_are_not_secrets() -> Result<()> {
    let (url, _) = fake(Reply::json(200, &json!({"environments":[]})))?;
    let server = Server::new(Api::new(&url, "c"));
    let (e, body) = call(&server, "list_environments", json!({"task_ref":"task-feature-branch"})).await?;
    assert!(!e, "{body}");
    Ok(())
}

#[tokio::test]
async fn nested_arguments_are_checked_against_the_schema() -> Result<()> {
    let (url, seen) = fake(Reply::json(202, &json!({"job_id":"j","state":"pending"})))?;
    let server = Server::new(Api::new(&url, "c"));
    let bad = submit(json!({"secrets":[{"name":"x","host_path":"/p","value":"hunter2"}]}));
    assert!(call(&server, "submit", bad).await?.0);
    let ok = submit(json!({"secrets":[{"name":"x","host_path":"/p"}]}));
    assert!(!call(&server, "submit", ok).await?.0);
    let wrong_type = submit(json!({"inputs":"not-an-array"}));
    assert!(call(&server, "submit", wrong_type).await?.0);
    assert_eq!(seen.lock().unwrap().len(), 1);
    Ok(())
}

#[tokio::test]
async fn path_arguments_cannot_traverse() -> Result<()> {
    let (url, seen) = fake(Reply::json(200, &json!({})))?;
    let server = Server::new(Api::new(&url, "c"));
    for id in ["..", ".", "..\\environments\\env1", "a b", "a%2Fb", "x\n"] {
        for tool in ["status", "cancel", "attach"] {
            assert!(call(&server, tool, json!({"job_id": id})).await?.0, "{tool} {id:?}");
        }
        assert!(
            call(&server, "delete_environment", json!({"environment_id": id}))
                .await?
                .0
        );
    }
    assert!(seen.lock().unwrap().is_empty());
    Ok(())
}

#[tokio::test]
async fn query_values_are_percent_encoded_not_restricted() -> Result<()> {
    let (url, seen) = fake(Reply::json(200, &json!({"environments":[]})))?;
    let server = Server::new(Api::new(&url, "c"));
    let (e, _) = call(&server, "list_environments", json!({"task_ref":"owner/repo#12 a&b"})).await?;
    assert!(!e);
    assert_eq!(
        seen.lock().unwrap()[0],
        "GET /v1/environments?task_ref=owner%2Frepo%2312%20a%26b"
    );
    Ok(())
}

#[tokio::test]
async fn a_stalled_broker_times_out_with_a_typed_error() -> Result<()> {
    let mut slow = Reply::json(200, &json!({"jobs":[]}));
    slow.delay = Duration::from_secs(3);
    let (url, _) = fake(slow)?;
    let server = Server::new(Api::with_timeout(&url, "c", Duration::from_millis(300)));
    let start = Instant::now();
    let (e, body) = call(&server, "list", json!({})).await?;
    assert!(e);
    assert_eq!(body["code"], "unavailable");
    assert!(start.elapsed() < Duration::from_secs(2));
    Ok(())
}

#[tokio::test]
async fn an_oversized_response_is_refused() -> Result<()> {
    let big = json!({"jobs": [], "pad": "a".repeat(3 * 1024 * 1024)});
    let (url, _) = fake(Reply::json(200, &big))?;
    let server = Server::new(Api::new(&url, "c"));
    let (e, body) = call(&server, "list", json!({})).await?;
    assert!(e);
    assert_eq!(body["code"], "unavailable");
    Ok(())
}

#[tokio::test]
async fn a_redirect_is_not_followed() -> Result<()> {
    let mut r = Reply::json(307, &json!({}));
    r.location = Some("/v1/jobs/other".into());
    let (url, seen) = fake(r)?;
    let server = Server::new(Api::new(&url, "c"));
    let (e, _) = call(&server, "submit", submit(json!({}))).await?;
    assert!(e);
    assert_eq!(seen.lock().unwrap().len(), 1, "a redirect must not replay the request");
    Ok(())
}

#[tokio::test]
async fn jsonrpc_edge_cases_get_an_invalid_request_reply() -> Result<()> {
    let server = Server::new(Api::new("http://127.0.0.1:1", "c"));
    for msg in [
        json!([{"jsonrpc":"2.0","id":1,"method":"ping"}]),
        json!("ping"),
        json!(7),
        json!({"jsonrpc":"2.0","id":null,"method":"ping"}),
    ] {
        let resp = server
            .handle(msg.clone())
            .await
            .with_context(|| format!("reply to {msg}"))?;
        assert_eq!(resp["error"]["code"], -32600, "{msg}");
    }
    Ok(())
}

/// AT-15 for every tool, not only the job tools.
#[tokio::test]
async fn every_tool_makes_exactly_one_api_request() -> Result<()> {
    let (url, seen) = fake(Reply::json(200, &json!({"ok": true})))?;
    let server = Server::new(Api::new(&url, "c"));
    let list = server
        .handle(json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}))
        .await
        .context("list")?;
    let tools = list["result"]["tools"].as_array().context("tools")?;
    assert_eq!(tools.len(), 14);
    for t in tools {
        let schema = &t["inputSchema"];
        let mut args = serde_json::Map::new();
        for r in schema["required"].as_array().into_iter().flatten() {
            let name = r.as_str().context("name")?;
            let v = match schema["properties"][name]["type"].as_str() {
                Some("object") => json!({"kind":"ephemeral","ttl_secs":60}),
                _ if name == "required_isolation_class" => json!("trusted"),
                _ => json!("a1"),
            };
            args.insert(name.to_owned(), v);
        }
        let before = seen.lock().unwrap().len();
        let (e, body) = call(&server, t["name"].as_str().context("n")?, Value::Object(args)).await?;
        assert!(!e, "{t}: {body}");
        assert_eq!(seen.lock().unwrap().len(), before + 1, "{}", t["name"]);
    }
    Ok(())
}

#[test]
fn only_a_loopback_http_broker_is_accepted_until_tls_is_built_in() {
    assert!(check_base_url("http://127.0.0.1:8787").is_ok());
    assert!(check_base_url("http://localhost:8787").is_ok());
    assert!(check_base_url("http://[::1]:8787").is_ok());
    assert!(check_base_url("https://broker.example").is_err());
    assert!(check_base_url("http://broker.example").is_err());
    assert!(check_base_url("ftp://127.0.0.1").is_err());
    assert!(check_base_url("not a url").is_err());
}

#[tokio::test]
async fn a_success_reply_without_a_json_body_is_a_typed_error() -> Result<()> {
    let mut r = Reply::json(200, &json!({}));
    r.body = "not json".into();
    let (url, _) = fake(r)?;
    let server = Server::new(Api::new(&url, "c"));
    let (e, body) = call(&server, "list", json!({})).await?;
    assert!(e);
    assert_eq!(body["code"], "unavailable");
    Ok(())
}

#[tokio::test]
async fn a_gitlab_token_in_an_argument_is_refused() -> Result<()> {
    let (url, seen) = fake(Reply::json(200, &json!({})))?;
    let server = Server::new(Api::new(&url, "c"));
    let tok = "glpat-abcdefghijklmnopqrstuvwxyz";
    let (e, _) = call(&server, "submit", submit(json!({"manifest_encoding": tok}))).await?;
    assert!(e);
    assert!(seen.lock().unwrap().is_empty());
    Ok(())
}

/// `end_task` is one POST to `/v1/tasks/end`, and a call without `task_ref` makes no request. An empty `task_ref` is
/// the broker's to refuse (`end_task_refuses_a_bad_task_ref_and_deletes_nothing`): the tool forwards values unchanged
/// (#815).
#[tokio::test]
async fn end_task_is_one_post_and_a_missing_task_ref_makes_no_request() -> Result<()> {
    let (url, seen) = fake(Reply::json(200, &json!({"ended": ["env-1"]})))?;
    let server = Server::new(Api::new(&url, "c"));
    let (e, body) = call(&server, "end_task", json!({"task_ref": "task-a"})).await?;
    assert!(!e, "{body}");
    assert_eq!(body["ended"], json!(["env-1"]));
    assert_eq!(seen.lock().unwrap().as_slice(), ["POST /v1/tasks/end"]);
    let (e, _) = call(&server, "end_task", json!({})).await?;
    assert!(e, "a missing task_ref must be refused");
    assert_eq!(seen.lock().unwrap().len(), 1, "a refused call made a request");
    Ok(())
}
