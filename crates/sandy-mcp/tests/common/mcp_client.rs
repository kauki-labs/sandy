//! The stdio MCP client and the conformance-script runner shared by every target: the tier-2 fake
//! broker (`conformance.rs`) and the tier-3 live stack (`live_broker.rs`).
#![allow(dead_code, reason = "shared by several test binaries; each uses a subset")]

use std::{
    io::{BufRead, BufReader, Write},
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{Child, ChildStdin, Command, Stdio},
    sync::mpsc::{self, Receiver},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use serde_json::{Map, Value, json};

/// The conformance script every target runs.
pub const SCRIPT: &str = include_str!("../conformance/script.json");
pub const BIN: &str = env!("CARGO_BIN_EXE_sandy-mcp");
pub const TIMEOUT: Duration = Duration::from_secs(10);

/// A running `sandy-mcp` process and line readers on its stdout and stderr.
/// Dropping it kills the process, so a failing test never leaves one running.
pub struct Mcp {
    child: Child,
    stdin: Option<ChildStdin>,
    lines: Receiver<String>,
    stderr: Receiver<String>,
    /// Requests sent so far.
    pub next_id: u64,
    /// Every stdout line read so far, for the canary check.
    pub transcript: String,
}

impl Drop for Mcp {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Reads `source` to the end on a thread: one message per line.
pub fn pump(source: impl std::io::Read + Send + 'static) -> Receiver<String> {
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
    pub fn spawn(api_url: &str, credential_file: &Path) -> Result<Self> {
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

    pub fn send(&mut self, msg: &Value) -> Result<()> {
        let stdin = self.stdin.as_mut().context("stdin already closed")?;
        writeln!(stdin, "{msg}").context("write to sandy-mcp")?;
        stdin.flush().context("flush")
    }

    pub fn send_raw(&mut self, line: &str) -> Result<()> {
        let stdin = self.stdin.as_mut().context("stdin already closed")?;
        writeln!(stdin, "{line}").context("write to sandy-mcp")?;
        stdin.flush().context("flush")
    }

    pub fn recv(&mut self) -> Result<Value> {
        let line = self.lines.recv_timeout(TIMEOUT).context("no reply from sandy-mcp")?;
        self.transcript.push_str(&line);
        serde_json::from_str(&line).with_context(|| format!("stdout line is not JSON: {line}"))
    }

    pub fn rpc(&mut self, method: &str, params: Value) -> Result<Value> {
        self.next_id += 1;
        let id = self.next_id;
        self.send(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}))?;
        let resp = self.recv()?;
        if resp["id"] != json!(id) {
            bail!("reply id mismatch: {resp}");
        }
        Ok(resp)
    }

    pub fn initialize(&mut self) -> Result<()> {
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
    pub fn call(&mut self, tool: &str, args: &Value) -> Result<(bool, Value)> {
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
    pub fn finish(mut self) -> Result<(bool, String)> {
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
pub fn check_grammar(script: &Value) -> Result<()> {
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
    // A bad timing fixture fails here, before any call, not as a silent default mid-run.
    let fixtures = script["fixtures"].as_object().cloned().unwrap_or_default();
    for (i, step) in steps.iter().enumerate() {
        for key in ["timeout_ms", "poll_interval_ms"] {
            millis(step, key, &fixtures, 0).with_context(|| format!("step {i}"))?;
        }
    }
    for (i, step) in script["cleanup"].as_array().into_iter().flatten().enumerate() {
        only(step, &["tool", "args"], &format!("cleanup {i}"))?;
    }
    Ok(())
}

/// A step's timing in milliseconds: the literal number or a `$fixture` that names one. `default` when the step
/// has none. Anything else is an error, so a typo in a fixture cannot fall back to a default.
fn millis(step: &Value, key: &str, caps: &Map<String, Value>, default: u64) -> Result<u64> {
    let Some(raw) = step.get(key) else {
        return Ok(default);
    };
    let resolved = substitute(raw, caps);
    resolved
        .as_u64()
        .with_context(|| format!("{key} {raw} must be a whole number of milliseconds, got {resolved}"))
}

/// Replaces every string equal to `$name` with the captured value or fixture.
pub fn substitute(v: &Value, caps: &Map<String, Value>) -> Value {
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
pub fn matches_all(result: &Value, want: &Value, caps: &Map<String, Value>) -> bool {
    want.as_object().is_some_and(|m| {
        !m.is_empty()
            && m.iter()
                .all(|(ptr, v)| result.pointer(ptr) == Some(&substitute(v, caps)))
    })
}

/// True when every pointer in `any` holds one of its listed values.
pub fn matches_in(result: &Value, any: &Value) -> bool {
    any.as_object().is_some_and(|m| {
        m.iter().all(|(ptr, vals)| {
            vals.as_array()
                .is_some_and(|vs| result.pointer(ptr).is_some_and(|r| vs.contains(r)))
        })
    })
}

/// True when a substituted value still names an unmade capture (`"$name"`).
pub fn has_unbound(v: &Value) -> bool {
    match v {
        Value::String(s) => s.starts_with('$'),
        Value::Array(a) => a.iter().any(has_unbound),
        Value::Object(o) => o.values().any(has_unbound),
        _ => false,
    }
}

/// Runs the script; the error names the failing step. Cleanup steps run after
/// any failure and their own errors are ignored.
pub fn run_script(mcp: &mut Mcp, script: &Value) -> Result<()> {
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

pub fn run_steps(mcp: &mut Mcp, script: &Value, caps: &mut Map<String, Value>) -> Result<()> {
    for (i, step) in script["steps"].as_array().context("steps")?.iter().enumerate() {
        let tool = step["tool"].as_str().context("tool")?;
        let ctx = || format!("step {i} ({tool}): {}", step["note"].as_str().unwrap_or(""));
        let args = substitute(&step["args"], caps);
        if has_unbound(&args) {
            bail!("{}: an argument names a capture that was never made: {args}", ctx());
        }
        let (mut is_err, mut result) = mcp.call(tool, &args).with_context(ctx)?;
        if let Some(until) = step.get("until") {
            let deadline = Instant::now() + Duration::from_millis(millis(step, "timeout_ms", caps, 10_000)?);
            let every = Duration::from_millis(millis(step, "poll_interval_ms", caps, 50)?);
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

pub fn credential_file(dir: &Path, secret: &str) -> Result<std::path::PathBuf> {
    let path = dir.join("credential");
    std::fs::write(&path, format!("{secret}\n"))?;
    // The live gate stores the real bearer token here (INV-1: staged secrets are 0600 files).
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    Ok(path)
}
