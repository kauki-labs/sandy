//! Conformance harness (#585 step 5, tier-2): a stand-in primary client runs
//! one fixed script (`conformance/script.json`) against the real `sandy-mcp`
//! binary over stdio. The target here is the in-memory fake broker. The same
//! script is meant to run against a real broker (tier-3, needs #591 and #587);
//! a script that passes live but fails here, or the reverse, is a bug in the fake.

mod common;

use std::process::{Command, Stdio};

use anyhow::Result;
use common::{
    Broker,
    mcp_client::{BIN, Mcp, SCRIPT, credential_file, run_script},
    start,
};
use serde_json::{Value, json};

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
    script["fixtures"]["ready_timeout_ms"] = json!(300);
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

#[test]
fn a_timing_fixture_that_is_not_a_number_is_an_error_not_a_default() -> Result<()> {
    let (url, _) = start(Broker {
        ready_after_polls: 1,
        ..Broker::default()
    })?;
    let dir = tempfile::tempdir()?;
    let mut mcp = Mcp::spawn(&url, &credential_file(dir.path(), "c")?)?;
    mcp.initialize()?;
    for bad in [json!("soon"), json!(-1), json!(1.5)] {
        let mut script: Value = serde_json::from_str(SCRIPT)?;
        script["fixtures"]["ready_timeout_ms"] = bad.clone();
        let err = run_script(&mut mcp, &script).expect_err("a bad timing must fail the script");
        assert!(
            format!("{err:#}").contains("ready_timeout_ms"),
            "the error must name the timing for {bad}: {err:#}"
        );
    }
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
