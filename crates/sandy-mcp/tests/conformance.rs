//! Conformance harness (#585 step 5, tier-2): a stand-in primary client runs
//! one fixed script (`conformance/script.json`) against the real `sandy-mcp`
//! binary over stdio. The target here is the in-memory fake broker. The same
//! script is meant to run against a real broker (tier-3, needs #591 and #587);
//! a script that passes live but fails here, or the reverse, is a bug in the fake.

mod common;

use std::{
    io::{BufRead, BufReader, Write},
    path::Path,
    process::{Child, ChildStdin, Command, Stdio},
    sync::mpsc::{self, Receiver},
    time::Duration,
};

use anyhow::{Context, Result, bail};
use common::{Broker, start};
use serde_json::{Map, Value, json};

const SCRIPT: &str = include_str!("conformance/script.json");
const BIN: &str = env!("CARGO_BIN_EXE_sandy-mcp");
const TIMEOUT: Duration = Duration::from_secs(10);

/// A running `sandy-mcp` process and a line reader on its stdout.
struct Mcp {
    child: Child,
    stdin: ChildStdin,
    lines: Receiver<String>,
    next_id: u64,
    /// Everything the process wrote to stdout, for the canary check.
    transcript: String,
}

impl Mcp {
    fn spawn(api_url: &str, credential_file: &Path) -> Result<Self> {
        let mut child = Command::new(BIN)
            .args(["--api-url", api_url, "--credential-file"])
            .arg(credential_file)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("spawn sandy-mcp")?;
        let stdin = child.stdin.take().context("stdin")?;
        let stdout = child.stdout.take().context("stdout")?;
        let (tx, lines) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        Ok(Self {
            child,
            stdin,
            lines,
            next_id: 0,
            transcript: String::new(),
        })
    }

    fn send(&mut self, msg: &Value) -> Result<()> {
        writeln!(self.stdin, "{msg}").context("write to sandy-mcp")?;
        self.stdin.flush().context("flush")
    }

    fn recv(&mut self) -> Result<Value> {
        let line = self.lines.recv_timeout(TIMEOUT).context("no reply from sandy-mcp")?;
        self.transcript.push_str(&line);
        serde_json::from_str(&line).with_context(|| format!("stdout line is not JSON: {line}"))
    }

    fn rpc(&mut self, method: &str, params: Value) -> Result<Value> {
        self.next_id += 1;
        let id = self.next_id;
        self.send(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}))?;
        let resp = self.recv()?;
        if resp["id"] != json!(id) {
            bail!("reply id mismatch: {resp}");
        }
        Ok(resp)
    }

    fn initialize(&mut self) -> Result<()> {
        let resp = self.rpc(
            "initialize",
            json!({"protocolVersion": "2025-06-18", "capabilities": {}}),
        )?;
        resp["result"]["capabilities"]["tools"]
            .as_object()
            .context("tools capability")?;
        self.send(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
    }

    /// One tool call: `(is_error, parsed result or error JSON)`.
    fn call(&mut self, tool: &str, args: &Value) -> Result<(bool, Value)> {
        let resp = self.rpc("tools/call", json!({"name": tool, "arguments": args}))?;
        let result = resp.get("result").with_context(|| format!("no result: {resp}"))?;
        let text = result["content"][0]["text"].as_str().context("text content")?;
        Ok((
            result["isError"].as_bool().unwrap_or(false),
            serde_json::from_str(text)?,
        ))
    }

    /// Closes stdin and returns `(exit success, stderr)`.
    fn finish(mut self) -> Result<(bool, String)> {
        drop(self.stdin);
        let status = self.child.wait().context("wait")?;
        let mut err = String::new();
        std::io::Read::read_to_string(&mut self.child.stderr.take().context("stderr")?, &mut err)?;
        Ok((status.success(), err))
    }
}

/// Replaces every string equal to `$name` with the captured value.
fn substitute(v: &Value, caps: &Map<String, Value>) -> Value {
    match v {
        Value::String(s) => s
            .strip_prefix('$')
            .and_then(|n| caps.get(n))
            .cloned()
            .unwrap_or_else(|| v.clone()),
        Value::Array(a) => Value::Array(a.iter().map(|x| substitute(x, caps)).collect()),
        Value::Object(o) => Value::Object(o.iter().map(|(k, x)| (k.clone(), substitute(x, caps))).collect()),
        _ => v.clone(),
    }
}

fn matches_all(result: &Value, want: &Value, caps: &Map<String, Value>) -> bool {
    want.as_object()
        .into_iter()
        .flatten()
        .all(|(ptr, v)| result.pointer(ptr) == Some(&substitute(v, caps)))
}

/// Runs every step of `script`; the error names the failing step.
fn run_script(mcp: &mut Mcp, script: &Value) -> Result<()> {
    let mut caps = Map::new();
    for (i, step) in script["steps"].as_array().context("steps")?.iter().enumerate() {
        let tool = step["tool"].as_str().context("tool")?;
        let ctx = || format!("step {i} ({tool}): {}", step["note"].as_str().unwrap_or(""));
        let args = substitute(&step["args"], &caps);
        let (mut is_err, mut result) = mcp.call(tool, &args).with_context(ctx)?;
        if let Some(until) = step.get("until") {
            for _ in 0..step["max_polls"].as_u64().unwrap_or(10) {
                if matches_all(&result, until, &caps) {
                    break;
                }
                (is_err, result) = mcp.call(tool, &args).with_context(ctx)?;
            }
            if !matches_all(&result, until, &caps) {
                bail!("{}: never reached {until}; last result {result}", ctx());
            }
        }
        let expect = &step["expect"];
        let want_ok = expect["ok"].as_bool().unwrap_or(true);
        if is_err == want_ok {
            bail!("{}: expected ok={want_ok}, got isError={is_err}: {result}", ctx());
        }
        if let Some(code) = expect["code"].as_str()
            && result["code"] != code
        {
            bail!("{}: expected error code {code}, got {result}", ctx());
        }
        if !matches_all(&result, &expect["equals"], &caps) {
            bail!("{}: expected {} in {result}", ctx(), expect["equals"]);
        }
        for ptr in expect["present"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
        {
            if result.pointer(ptr).is_none() {
                bail!("{}: {ptr} missing from {result}", ctx());
            }
        }
        for ptr in expect["absent"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
        {
            if result.pointer(ptr).is_some() {
                bail!("{}: {ptr} must be absent from {result}", ctx());
            }
        }
        for (name, ptr) in step["capture"].as_object().into_iter().flatten() {
            let v = result
                .pointer(ptr.as_str().context("pointer")?)
                .with_context(|| format!("{}: capture {ptr}", ctx()))?;
            caps.insert(name.clone(), v.clone());
        }
    }
    Ok(())
}

fn credential_file(dir: &Path, secret: &str) -> Result<std::path::PathBuf> {
    let path = dir.join("credential");
    std::fs::write(&path, format!("{secret}\n"))?;
    Ok(path)
}

#[test]
fn the_real_binary_passes_the_conformance_script_against_the_fake_broker() -> Result<()> {
    let (url, state) = start(Broker {
        ready_after_polls: 1,
        ..Broker::default()
    })?;
    let dir = tempfile::tempdir()?;
    let canary = "canary-8f3a91c2d4e65b70";
    let mut mcp = Mcp::spawn(&url, &credential_file(dir.path(), canary)?)?;
    mcp.initialize()?;
    run_script(&mut mcp, &serde_json::from_str(SCRIPT)?)?;
    let transcript = std::mem::take(&mut mcp.transcript);
    let (clean_exit, stderr) = mcp.finish()?;

    assert!(clean_exit, "sandy-mcp must exit cleanly when stdin closes");
    let b = state.lock().unwrap();
    assert_eq!(
        b.leftovers(),
        0,
        "the script must leave no non-terminal environment or job"
    );
    assert!(b.auth.iter().all(|a| a.as_deref() == Some(&format!("Bearer {canary}"))));
    // AT-11 at tier-2: the credential reaches the broker only, never the MCP's output.
    assert!(!transcript.contains(canary), "credential leaked to stdout");
    assert!(!stderr.contains(canary), "credential leaked to stderr");
    Ok(())
}

#[test]
fn the_script_fails_against_a_broker_that_breaks_idempotent_spawn() -> Result<()> {
    let (url, _) = start(Broker {
        ready_after_polls: 1,
        idempotent: false,
        ..Broker::default()
    })?;
    let dir = tempfile::tempdir()?;
    let mut mcp = Mcp::spawn(&url, &credential_file(dir.path(), "c")?)?;
    mcp.initialize()?;
    let err = run_script(&mut mcp, &serde_json::from_str(SCRIPT)?).expect_err("a broken broker must fail the script");
    let msg = format!("{err:#}");
    assert!(msg.contains("step 6"), "the failing step must be named: {msg}");
    Ok(())
}

#[test]
fn the_script_fails_against_a_broker_that_never_reaches_ready() -> Result<()> {
    let (url, _) = start(Broker::default())?;
    let dir = tempfile::tempdir()?;
    let mut mcp = Mcp::spawn(&url, &credential_file(dir.path(), "c")?)?;
    mcp.initialize()?;
    let err = run_script(&mut mcp, &serde_json::from_str(SCRIPT)?).expect_err("never Ready must fail the script");
    assert!(format!("{err:#}").contains("never reached"));
    Ok(())
}

#[test]
fn the_binary_refuses_a_remote_http_api_url_without_serving() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let out = Command::new(BIN)
        .args(["--api-url", "http://broker.example", "--credential-file"])
        .arg(credential_file(dir.path(), "c")?)
        .stdin(Stdio::null())
        .output()?;
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
    assert!(String::from_utf8_lossy(&out.stderr).contains("loopback"));
    Ok(())
}

#[test]
fn the_binary_refuses_a_missing_credential_file() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let out = Command::new(BIN)
        .args(["--credential-file"])
        .arg(dir.path().join("nope"))
        .stdin(Stdio::null())
        .output()?;
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("cannot read"));
    Ok(())
}

#[test]
fn an_oversized_line_is_refused_and_the_next_message_is_served() -> Result<()> {
    let (url, _) = start(Broker::default())?;
    let dir = tempfile::tempdir()?;
    let mut mcp = Mcp::spawn(&url, &credential_file(dir.path(), "c")?)?;
    mcp.send(&json!("x".repeat(2 * 1024 * 1024)))?;
    let refused = mcp.recv()?;
    assert_eq!(refused["error"]["code"], -32600);
    mcp.initialize()?;
    let (is_err, listed) = mcp.call("list", &json!({}))?;
    assert!(!is_err, "{listed}");
    Ok(())
}

#[test]
fn a_parse_error_is_answered_and_the_server_keeps_serving() -> Result<()> {
    let (url, _) = start(Broker::default())?;
    let dir = tempfile::tempdir()?;
    let mut mcp = Mcp::spawn(&url, &credential_file(dir.path(), "c")?)?;
    writeln!(mcp.stdin, "{{not json")?;
    assert_eq!(mcp.recv()?["error"]["code"], -32700);
    mcp.initialize()?;
    assert!(!mcp.call("list", &json!({}))?.0);
    Ok(())
}
