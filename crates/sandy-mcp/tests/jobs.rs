//! Job tools over a recording fake API (AT-15), the secret guard (AT-10) and
//! the MCP wire shapes.

use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use sandy_mcp::{Api, Server};
use serde_json::{Value, json};

/// One request the fake API saw.
#[derive(Debug, Clone)]
struct Seen {
    method: String,
    path: String,
    auth: Option<String>,
    body: String,
}

/// Serves canned JSON by `(method, path)` and records every request.
struct FakeApi {
    url: String,
    seen: Arc<Mutex<Vec<Seen>>>,
}

fn fake_api(routes: Vec<(&'static str, &'static str, u16, Value)>) -> Result<FakeApi> {
    let server = tiny_http::Server::http("127.0.0.1:0").map_err(|e| anyhow::anyhow!("{e}"))?;
    let url = format!("http://{}", server.server_addr());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    std::thread::spawn(move || {
        for mut req in server.incoming_requests() {
            let mut body = String::new();
            let _ = req.as_reader().read_to_string(&mut body);
            let method = req.method().to_string();
            let path = req.url().to_string();
            let auth = req
                .headers()
                .iter()
                .find(|h| h.field.equiv("authorization"))
                .map(|h| h.value.to_string());
            log.lock().unwrap().push(Seen {
                method: method.clone(),
                path: path.clone(),
                auth,
                body,
            });
            let (status, payload) = routes
                .iter()
                .find(|(m, p, ..)| *m == method && *p == path)
                .map(|(_, _, s, b)| (*s, b.clone()))
                .unwrap_or((404, json!({"code": "not_found", "message": "no route"})));
            let resp = tiny_http::Response::from_string(payload.to_string())
                .with_status_code(status)
                .with_header(tiny_http::Header::from_bytes("content-type", "application/json").unwrap());
            let _ = req.respond(resp);
        }
    });
    Ok(FakeApi { url, seen })
}

async fn call(server: &Server, name: &str, args: Value) -> Result<Value> {
    let req = json!({"jsonrpc":"2.0","id":1,"method":"tools/call",
        "params":{"name":name,"arguments":args}});
    server.handle(req).await.context("tools/call must answer")
}

fn is_error(resp: &Value) -> bool {
    resp["result"]["isError"].as_bool().unwrap_or(false)
}

fn text(resp: &Value) -> Result<Value> {
    let t = resp["result"]["content"][0]["text"].as_str().context("text content")?;
    Ok(serde_json::from_str(t)?)
}

#[tokio::test]
async fn initialize_and_list_advertise_the_job_tools() -> Result<()> {
    let server = Server::new(Api::new("http://127.0.0.1:1", "t"));
    let init = server
        .handle(json!({"jsonrpc":"2.0","id":0,"method":"initialize","params":{}}))
        .await
        .context("initialize")?;
    assert!(init["result"]["capabilities"]["tools"].is_object());
    let list = server
        .handle(json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}))
        .await
        .context("list")?;
    let names: Vec<_> = list["result"]["tools"]
        .as_array()
        .context("tools")?
        .iter()
        .filter_map(|t| t["name"].as_str())
        .collect();
    for n in ["submit", "status", "cancel", "list", "attach"] {
        assert!(names.contains(&n), "missing tool {n}: {names:?}");
    }
    Ok(())
}

#[tokio::test]
async fn a_notification_gets_no_response() {
    let server = Server::new(Api::new("http://127.0.0.1:1", "t"));
    let out = server
        .handle(json!({"jsonrpc":"2.0","method":"notifications/initialized"}))
        .await;
    assert!(out.is_none());
}

/// AT-15: each tool makes exactly one API request, with the bearer credential.
#[tokio::test]
async fn each_job_tool_makes_exactly_one_api_request() -> Result<()> {
    let job = json!({"job_id":"j1","state":"running"});
    let api = fake_api(vec![
        ("POST", "/v1/jobs", 202, job.clone()),
        ("GET", "/v1/jobs", 200, json!({"jobs":[job.clone()]})),
        ("GET", "/v1/jobs/j1", 200, job.clone()),
        ("POST", "/v1/jobs/j1/cancel", 200, job.clone()),
        ("POST", "/v1/jobs/j1/attach", 200, json!({"stream_url":"http://x/s"})),
    ])?;
    let server = Server::new(Api::new(&api.url, "cred"));
    let submit = json!({"manifest":"AA==","manifest_encoding":"m.v1",
        "required_isolation_class":"untrusted"});
    let cases = [
        ("submit", submit, "POST", "/v1/jobs"),
        ("list", json!({}), "GET", "/v1/jobs"),
        ("status", json!({"job_id":"j1"}), "GET", "/v1/jobs/j1"),
        ("cancel", json!({"job_id":"j1"}), "POST", "/v1/jobs/j1/cancel"),
        ("attach", json!({"job_id":"j1"}), "POST", "/v1/jobs/j1/attach"),
    ];
    for (i, (tool, args, method, path)) in cases.iter().enumerate() {
        let resp = call(&server, tool, args.clone()).await?;
        assert!(!is_error(&resp), "{tool}: {resp}");
        let seen = api.seen.lock().unwrap();
        assert_eq!(seen.len(), i + 1, "{tool} must make exactly one request");
        let last = seen.last().context("request")?;
        assert_eq!((last.method.as_str(), last.path.as_str()), (*method, *path));
        assert_eq!(last.auth.as_deref(), Some("Bearer cred"));
    }
    Ok(())
}

#[tokio::test]
async fn the_submit_body_carries_arguments_and_status_path_args_stay_out_of_it() -> Result<()> {
    let api = fake_api(vec![
        ("POST", "/v1/jobs", 202, json!({"job_id":"j1","state":"pending"})),
        ("GET", "/v1/jobs/j1", 200, json!({"job_id":"j1","state":"pending"})),
    ])?;
    let server = Server::new(Api::new(&api.url, "c"));
    let args = json!({"manifest":"AA==","manifest_encoding":"m.v1",
        "required_isolation_class":"trusted"});
    call(&server, "submit", args.clone()).await?;
    call(&server, "status", json!({"job_id":"j1"})).await?;
    let seen = api.seen.lock().unwrap();
    assert_eq!(serde_json::from_str::<Value>(&seen[0].body)?, args);
    assert!(seen[1].body.is_empty());
    Ok(())
}

#[tokio::test]
async fn an_api_error_is_a_tool_error_carrying_the_typed_code() -> Result<()> {
    let api = fake_api(vec![(
        "GET",
        "/v1/jobs/nope",
        404,
        json!({"code":"not_found","message":"no such job"}),
    )])?;
    let server = Server::new(Api::new(&api.url, "c"));
    let resp = call(&server, "status", json!({"job_id":"nope"})).await?;
    assert!(is_error(&resp));
    assert_eq!(text(&resp)?["code"], "not_found");
    Ok(())
}

#[tokio::test]
async fn an_unreachable_api_is_a_typed_unavailable_error() -> Result<()> {
    let server = Server::new(Api::new("http://127.0.0.1:1", "c"));
    let resp = call(&server, "list", json!({})).await?;
    assert!(is_error(&resp));
    assert_eq!(text(&resp)?["code"], "unavailable");
    Ok(())
}

#[tokio::test]
async fn unknown_tool_and_unknown_argument_are_refused_without_a_request() -> Result<()> {
    let api = fake_api(vec![])?;
    let server = Server::new(Api::new(&api.url, "c"));
    let unknown_tool = call(&server, "nope", json!({})).await?;
    assert_eq!(unknown_tool["error"]["code"], -32602);
    let extra = call(&server, "status", json!({"job_id":"j1","bogus":1})).await?;
    assert!(is_error(&extra));
    let missing = call(&server, "status", json!({})).await?;
    assert!(is_error(&missing));
    assert!(api.seen.lock().unwrap().is_empty());
    Ok(())
}

/// AT-10: secret-looking fields and values are refused before any request.
#[tokio::test]
async fn secret_fields_and_token_shaped_values_are_refused() -> Result<()> {
    let api = fake_api(vec![])?;
    let server = Server::new(Api::new(&api.url, "c"));
    let base = json!({"manifest":"AA==","manifest_encoding":"m.v1",
        "required_isolation_class":"trusted"});
    let mut bad = Vec::new();
    for field in ["secret", "token", "key", "Token", "api_key"] {
        let mut a = base.clone();
        a[field] = json!("x");
        bad.push(a);
    }
    for value in [
        "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
        "github_pat_11AAAAAAA0abcdefghijkl",
        "sk-abcdefghijklmnopqrstuvwxyz",
        "-----BEGIN PRIVATE KEY-----",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijk",
    ] {
        let mut a = base.clone();
        a["manifest_encoding"] = json!(value);
        bad.push(a);
    }
    for args in bad {
        let resp = call(&server, "submit", args.clone()).await?;
        assert!(is_error(&resp), "must refuse {args}");
    }
    assert!(api.seen.lock().unwrap().is_empty(), "no request may be made");
    Ok(())
}

/// O8: a secret in an API result is withheld from the caller.
#[tokio::test]
async fn a_token_shaped_value_in_an_api_result_is_withheld() -> Result<()> {
    let api = fake_api(vec![(
        "GET",
        "/v1/jobs/j1",
        200,
        json!({"job_id":"j1","state":"running",
               "console_tail":"ghp_abcdefghijklmnopqrstuvwxyz0123456789"}),
    )])?;
    let server = Server::new(Api::new(&api.url, "c"));
    let resp = call(&server, "status", json!({"job_id":"j1"})).await?;
    assert!(is_error(&resp));
    assert!(!resp.to_string().contains("ghp_"));
    Ok(())
}
