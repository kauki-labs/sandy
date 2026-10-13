//! End-to-end sandbox-I/O scenario — the whole input/output/secret surface in one
//! real boot.
//!
//! Tier-3 (behind the `live` feature, off by default so CI never runs it). The
//! focused `live_inputs` / `live_outputs` / `live_boot` tests each exercise one
//! channel; this proves they compose: a single credentialless job reads an input,
//! reads a secret from its `$NAME`, and writes an output that is collected to the
//! host and listed in the result envelope — the realistic shape of a real job.
//!
//! Run it on the live host, e.g. on Apple silicon:
//!   nix shell nixpkgs#vfkit -c \
//!     env SANDY_LIVE=1 cargo nextest run -p sandy-cli --features live --test live_e2e
#![cfg(feature = "live")]

use std::{os::unix::fs::PermissionsExt, process::Command};

use anyhow::{Context, Result};

mod common;
use common::{build_guest, guest_flake, require_live};

/// One boot, three channels at once: `--input`, `--secret`, `--out`. The guest job
/// asserts the input is readable and the secret reached `$TOK`, then writes an
/// output; the host checks the output was collected and the envelope lists it.
#[test]
fn input_secret_and_output_compose_in_one_run() -> Result<()> {
    let target = require_live()?;
    build_guest(&target)?;

    let home = tempfile::tempdir().context("temp SANDY_HOME")?;
    let staging = tempfile::tempdir().context("staging")?;

    // An input directory, a 0600 secret file, and an empty output destination.
    let input_dir = staging.path().join("in");
    std::fs::create_dir_all(&input_dir)?;
    std::fs::write(input_dir.join("f"), b"INPUT-MARKER")?;
    let secret_file = staging.path().join("tok");
    std::fs::write(&secret_file, b"SECRET-VALUE")?;
    std::fs::set_permissions(&secret_file, std::fs::Permissions::from_mode(0o600))?;
    let out_dest = staging.path().join("collected");

    // The job: input readable AND secret present under $TOK, then produce an output.
    // Exit 0 only when every channel worked; the output write is the observable
    // effect the host collects.
    let job = "grep -q INPUT-MARKER /run/sandy/inputs/data/f && [ \"$TOK\" = SECRET-VALUE ] && printf done > \
               /run/sandy/outputs/result/out";

    let attr = format!("{}#{}", guest_flake().display(), target.topology_attr);
    let output = Command::new(env!("CARGO_BIN_EXE_sandy"))
        .env("SANDY_HOME", home.path())
        .args([
            "-o",
            "json",
            "run",
            &attr,
            "--timeout",
            "120",
            "--input",
            &format!("{}:data", input_dir.display()),
            "--secret",
            &format!("TOK=@{}", secret_file.display()),
            "--out",
            &format!("result:{}", out_dest.display()),
            "--",
            job,
        ])
        .output()
        .context("run sandy e2e")?;

    let code = output.status.code().unwrap_or(-1);
    let env: serde_json::Value = serde_json::from_slice(&output.stdout).with_context(|| {
        format!(
            "parse envelope (exit {code}); stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        )
    })?;

    // The guest saw all three channels (exit 0), so the run succeeded.
    assert_eq!(env["status"], "succeeded", "e2e run envelope: {env}");
    assert_eq!(
        env["exit_code"], 0,
        "input + secret + output all worked (exit 0): {env}"
    );

    // The output reached the host...
    assert_eq!(
        std::fs::read(out_dest.join("out")).context("collected output")?,
        b"done",
        "the job's output was collected to the host dest"
    );
    // ...and is listed in the envelope.
    let outputs: Vec<String> = env["outputs"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|o| o["path"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    assert!(
        outputs.contains(&"result/out".to_string()),
        "envelope.outputs lists the produced output: {outputs:?}"
    );
    // INV-1: the secret value never leaks into the captured console.
    let tail = env["logs"]["tail"].as_str().unwrap_or_default();
    assert!(
        !tail.contains("SECRET-VALUE"),
        "secret value must not leak into logs.tail"
    );
    Ok(())
}
