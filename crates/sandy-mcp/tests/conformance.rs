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
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use common::{Broker, start};
use serde_json::{Map, Value, json};

const SCRIPT: &str = include_str!("conformance/script.json");
const BIN: &str = env!("CARGO_BIN_EXE_sandy-mcp");
const TIMEOUT: Duration = Duration::from_secs(10);

/// A running `sandy-mcp` process and line readers on its stdout and stderr.
/// Dropping it kills the process, so a failing test never leaves one running.
struct Mcp {
    child: Child,
    stdin: Option<ChildStdin>,
    lines: Receiver<String>,
    stderr: Receiver<String>,
    next_id: u64,
    /// Every stdout line read so far, for the canary check.
    transcript: String,
}

impl Drop for Mcp {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Reads `source` to the end on a thread: one message per line.
fn pump(source: impl std::io::Read + Send + 'static) -> Receiver<String> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(source).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    rx
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
        let stdin = child.stdin.take();
        let lines = pump(child.stdout.take().context("stdout")?);
        let stderr = pump(child.stderr.take().context("stderr")?);
        Ok(Self {
            child,
            stdin,
            lines,
            stderr,
            next_id: 0,
            transcript: String::new(),
        })
    }

    fn send(&mut self, msg: &Value) -> Result<()> {
        let stdin = self.stdin.as_mut().context("stdin already closed")?;
        writeln!(stdin, "{msg}").context("write to sandy-mcp")?;
        stdin.flush().context("flush")
    }

    fn send_raw(&mut self, line: &str) -> Result<()> {
        let stdin = self.stdin.as_mut().context("stdin already closed")?;
        writeln!(stdin, "{line}").context("write to sandy-mcp")?;
        stdin.flush().context("flush")
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

    /// Closes stdin, waits (bounded) for a clean exit, and returns everything
    /// the process wrote to stdout and stderr, read or not, joined.
    fn finish(mut self) -> Result<(bool, String)> {
        drop(self.stdin.take());
        let deadline = Instant::now() + TIMEOUT;
        let status = loop {
            if let Some(s) = self.child.try_wait().context("wait")? {
                break s;
            }
            if Instant::now() > deadline {
                bail!("sandy-mcp did not exit within {TIMEOUT:?} of stdin closing");
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        // Give the pump threads a moment to flush the pipes after exit.
        std::thread::sleep(Duration::from_millis(100));
        let rest: Vec<String> = self.lines.try_iter().collect();
        let mut everything = std::mem::take(&mut self.transcript);
        everything.push_str(&rest.join("\n"));
        everything.push_str(&self.stderr.try_iter().collect::<Vec<_>>().join("\n"));
        Ok((status.success(), everything))
    }
}

const STEP_KEYS: &[&str] = &[
    "note",
    "tool",
    "args",
    "capture",
    "expect",
    "until",
    "poll_interval_ms",
    "timeout_ms",
];
const EXPECT_KEYS: &[&str] = &["ok", "code", "equals", "in", "present", "absent", "absent_unless"];

/// Rejects unknown keys and empty conditions, so a typo in the script cannot
/// turn an assertion into a silent pass.
fn check_grammar(script: &Value) -> Result<()> {
    let only = |obj: &Value, allowed: &[&str], what: &str| -> Result<()> {
        for k in obj
            .as_object()
            .with_context(|| format!("{what}: object expected"))?
            .keys()
        {
            if !allowed.contains(&k.as_str()) {
                bail!("{what}: unknown key `{k}`");
            }
        }
        Ok(())
    };
    only(
        script,
        &["name", "description", "fixtures", "steps", "cleanup"],
        "script",
    )?;
    let steps = script["steps"].as_array().context("steps")?;
    if steps.is_empty() {
        bail!("script has no steps");
    }
    for (i, step) in steps.iter().enumerate() {
        let what = format!("step {i}");
        only(step, STEP_KEYS, &what)?;
        step["tool"].as_str().with_context(|| format!("{what}: tool"))?;
        if let Some(expect) = step.get("expect") {
            only(expect, EXPECT_KEYS, &what)?;
            for key in ["present", "absent"] {
                for e in expect[key].as_array().into_iter().flatten() {
                    e.as_str()
                        .with_context(|| format!("{what}: {key} entries must be strings"))?;
                }
            }
            for key in ["equals", "in"] {
                if expect.get(key).is_some_and(|v| v.as_object().is_none_or(Map::is_empty)) {
                    bail!("{what}: `{key}` must be a non-empty object");
                }
            }
        }
        if step
            .get("until")
            .is_some_and(|u| u.as_object().is_none_or(Map::is_empty))
        {
            bail!("{what}: `until` must be a non-empty object");
        }
    }
    for (i, step) in script["cleanup"].as_array().into_iter().flatten().enumerate() {
        only(step, &["tool", "args"], &format!("cleanup {i}"))?;
    }
    Ok(())
}

/// Replaces every string equal to `$name` with the captured value or fixture.
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

/// True when every pointer in `want` has the wanted value; false for an empty `want`.
fn matches_all(result: &Value, want: &Value, caps: &Map<String, Value>) -> bool {
    want.as_object().is_some_and(|m| {
        !m.is_empty()
            && m.iter()
                .all(|(ptr, v)| result.pointer(ptr) == Some(&substitute(v, caps)))
    })
}

/// True when every pointer in `any` holds one of its listed values.
fn matches_in(result: &Value, any: &Value) -> bool {
    any.as_object().is_some_and(|m| {
        m.iter().all(|(ptr, vals)| {
            vals.as_array()
                .is_some_and(|vs| result.pointer(ptr).is_some_and(|r| vs.contains(r)))
        })
    })
}

/// True when a substituted value still names an unmade capture (`"$name"`).
fn has_unbound(v: &Value) -> bool {
    match v {
        Value::String(s) => s.starts_with('$'),
        Value::Array(a) => a.iter().any(has_unbound),
        Value::Object(o) => o.values().any(has_unbound),
        _ => false,
    }
}

/// Runs the script; the error names the failing step. Cleanup steps run after
/// any failure and their own errors are ignored.
fn run_script(mcp: &mut Mcp, script: &Value) -> Result<()> {
    check_grammar(script)?;
    let mut caps = script["fixtures"].as_object().cloned().unwrap_or_default();
    let outcome = run_steps(mcp, script, &mut caps);
    if outcome.is_err() {
        for step in script["cleanup"].as_array().into_iter().flatten() {
            let args = substitute(&step["args"], &caps);
            // A step whose capture was never made still holds a `$name`: skip it.
            if !has_unbound(&args) {
                let _ = mcp.call(step["tool"].as_str().unwrap_or_default(), &args);
            }
        }
    }
    outcome
}

fn run_steps(mcp: &mut Mcp, script: &Value, caps: &mut Map<String, Value>) -> Result<()> {
    for (i, step) in script["steps"].as_array().context("steps")?.iter().enumerate() {
        let tool = step["tool"].as_str().context("tool")?;
        let ctx = || format!("step {i} ({tool}): {}", step["note"].as_str().unwrap_or(""));
        let args = substitute(&step["args"], caps);
        if has_unbound(&args) {
            bail!("{}: an argument names a capture that was never made: {args}", ctx());
        }
        let (mut is_err, mut result) = mcp.call(tool, &args).with_context(ctx)?;
        if let Some(until) = step.get("until") {
            let deadline = Instant::now() + Duration::from_millis(step["timeout_ms"].as_u64().unwrap_or(10_000));
            let every = Duration::from_millis(step["poll_interval_ms"].as_u64().unwrap_or(50));
            while !matches_all(&result, until, caps) && Instant::now() < deadline {
                std::thread::sleep(every);
                (is_err, result) = mcp.call(tool, &args).with_context(ctx)?;
            }
            if !matches_all(&result, until, caps) {
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
        if expect.get("equals").is_some() && !matches_all(&result, &expect["equals"], caps) {
            bail!("{}: expected {} in {result}", ctx(), expect["equals"]);
        }
        if expect.get("in").is_some() && !matches_in(&result, &expect["in"]) {
            bail!("{}: expected one of {} in {result}", ctx(), expect["in"]);
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
        for rule in expect["absent_unless"].as_array().into_iter().flatten() {
            let ptr = rule["pointer"].as_str().context("absent_unless pointer")?;
            if !matches_all(&result, &rule["when"], caps) && result.pointer(ptr).is_some() {
                bail!("{}: {ptr} must be absent unless {}: {result}", ctx(), rule["when"]);
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

/// Runs the script against `broker` and checks the invariants every target must hold.
fn conformant(broker: Broker) -> Result<()> {
    let (url, state) = start(broker)?;
    let dir = tempfile::tempdir()?;
    let canary = "canary-8f3a91c2d4e65b70";
    let mut mcp = Mcp::spawn(&url, &credential_file(dir.path(), canary)?)?;
    mcp.initialize()?;
    run_script(&mut mcp, &serde_json::from_str(SCRIPT)?)?;
    let (clean_exit, output) = mcp.finish()?;

    assert!(clean_exit, "sandy-mcp must exit cleanly when stdin closes");
    let b = state.lock().unwrap();
    assert_eq!(
        b.leftovers(),
        0,
        "the fake's state table must show no non-terminal environment or job"
    );
    assert!(!b.auth.is_empty(), "the broker must have seen requests");
    assert!(b.auth.iter().all(|a| a.as_deref() == Some(&format!("Bearer {canary}"))));
    // AT-11 at tier-2: the credential reaches the broker only, never the MCP's output
    // (every stdout line, read or not, and all of stderr).
    assert!(!output.contains(canary), "credential leaked to stdout or stderr");
    Ok(())
}

#[test]
fn the_real_binary_passes_the_conformance_script_against_the_fake_broker() -> Result<()> {
    conformant(Broker {
        ready_after_polls: 1,
        ..Broker::default()
    })
}

#[test]
fn the_script_also_passes_against_a_broker_that_is_ready_at_once() -> Result<()> {
    conformant(Broker {
        ready_after_polls: 0,
        ..Broker::default()
    })
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
    assert!(
        msg.contains("step 6 (spawn_environment)") && msg.contains("/environment_id"),
        "the O1 retry step must fail on the environment id: {msg}"
    );
    Ok(())
}

/// The script with the Ready poll shortened, so a never-Ready broker fails fast.
fn quick_script() -> Result<Value> {
    let mut script: Value = serde_json::from_str(SCRIPT)?;
    script["steps"][9]["timeout_ms"] = json!(300);
    Ok(script)
}

#[test]
fn the_script_fails_against_a_broker_that_never_reaches_ready_and_cleans_up() -> Result<()> {
    let (url, state) = start(Broker::default())?;
    let dir = tempfile::tempdir()?;
    let mut mcp = Mcp::spawn(&url, &credential_file(dir.path(), "c")?)?;
    mcp.initialize()?;
    let err = run_script(&mut mcp, &quick_script()?).expect_err("never Ready must fail the script");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("step 9 (get_environment)") && msg.contains("never reached"),
        "{msg}"
    );
    // The cleanup steps ran: the environment the failed script created is gone.
    assert_eq!(state.lock().unwrap().leftovers(), 0, "a failed script must not leak");
    Ok(())
}

/// An edit that breaks one script rule.
type Mutation = fn(&mut Value);

#[test]
fn a_typo_in_the_script_is_an_error_not_a_silent_pass() -> Result<()> {
    let (url, _) = start(Broker::default())?;
    let dir = tempfile::tempdir()?;
    let mut mcp = Mcp::spawn(&url, &credential_file(dir.path(), "c")?)?;
    mcp.initialize()?;
    let mutations: [(&str, Mutation); 6] = [
        ("unknown expect key", |s| {
            s["steps"][1]["expect"]["equal"] = json!({"/state": "x"});
        }),
        ("unknown step key", |s| {
            s["steps"][1]["max_poll"] = json!(3);
        }),
        ("empty until", |s| {
            s["steps"][9]["until"] = json!({});
        }),
        ("empty equals", |s| {
            s["steps"][2]["expect"]["equals"] = json!({});
        }),
        ("non-string present entry", |s| {
            s["steps"][0]["expect"]["present"] = json!([1]);
        }),
        ("unknown top-level key", |s| {
            s["setps"] = json!([]);
        }),
    ];
    for (what, mutate) in mutations {
        let mut script: Value = serde_json::from_str(SCRIPT)?;
        mutate(&mut script);
        assert!(run_script(&mut mcp, &script).is_err(), "must refuse: {what}");
    }
    // None of them reached the broker: the grammar check runs before any call.
    assert_eq!(mcp.next_id, 1, "only `initialize` may have been sent");
    Ok(())
}

#[test]
fn an_argument_naming_a_capture_that_was_never_made_is_an_error() -> Result<()> {
    let (url, _) = start(Broker::default())?;
    let dir = tempfile::tempdir()?;
    let mut mcp = Mcp::spawn(&url, &credential_file(dir.path(), "c")?)?;
    mcp.initialize()?;
    let script = json!({"steps": [{"tool": "status", "args": {"job_id": "$job"}}]});
    let err = run_script(&mut mcp, &script).expect_err("an unbound capture must fail");
    assert!(format!("{err:#}").contains("never made"));
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
    mcp.send_raw("{not json")?;
    assert_eq!(mcp.recv()?["error"]["code"], -32700);
    mcp.initialize()?;
    assert!(!mcp.call("list", &json!({}))?.0);
    Ok(())
}
