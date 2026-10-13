//! Live input round-trip — the guest-side half of #34, on a real boot.
//!
//! Tier-3 (behind the `live` feature, off by default so CI never runs it): a
//! real guest boots with a `--input HOST:data` share, and the job asserts, from
//! inside the guest, that the input is readable at `/run/sandy/inputs/data` and
//! that the share is read-only (a write fails with `EROFS`). Assertions use the
//! guest exit code, so no guest stdout plumbing is needed.
//!
//! Run it on the live host, e.g. on Apple silicon:
//!   nix shell nixpkgs#vfkit -c \
//!     env SANDY_LIVE=1 cargo nextest run -p sandy-cli --features live --test live_inputs
#![cfg(feature = "live")]

use std::{path::Path, process::Command};

use anyhow::Context;

mod common;
use common::{LiveTarget, build_guest, guest_flake, require_live};

/// Run `sandy run <topology> --input <host>:data -- <sh-command>` against a
/// throwaway `$SANDY_HOME`, returning the process exit code and the parsed result
/// envelope. The guest runner space-joins the trailing argv and pipes it to `sh`,
/// so the command is passed as one shell string (not `sh -c`, whose quoting the
/// join would flatten).
fn run_with_input(target: &LiveTarget, host: &Path, sh_command: &str) -> anyhow::Result<(i32, serde_json::Value)> {
    let home = tempfile::tempdir().context("temp SANDY_HOME")?;
    let attr = format!("{}#{}", guest_flake().display(), target.topology_attr);
    let input_arg = format!("{}:data", host.display());
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
            &input_arg,
            "--",
            sh_command,
        ])
        .output()
        .context("run sandy with an input")?;
    let code = output.status.code().unwrap_or(-1);
    let envelope = serde_json::from_slice(&output.stdout).with_context(|| {
        format!(
            "parse sandy run envelope (exit {code}); stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        )
    })?;
    Ok((code, envelope))
}

/// An input directory is readable in-guest at `/run/sandy/inputs/<name>`: the job
/// greps the staged file for its known content and exits 0.
#[test]
fn an_input_is_readable_in_guest() -> anyhow::Result<()> {
    let target = require_live()?;
    build_guest(&target)?;
    let src = tempfile::tempdir().context("input source dir")?;
    std::fs::write(src.path().join("file"), b"sandy-input-ok")?;

    let (_, env) = run_with_input(
        &target,
        src.path(),
        "grep -q sandy-input-ok /run/sandy/inputs/data/file",
    )?;

    assert_eq!(env["status"], "succeeded", "input-readable run envelope: {env}");
    assert_eq!(env["exit_code"], 0, "guest read the input (exit 0): {env}");
    Ok(())
}

/// The input share is read-only: a write into it fails with `EROFS`. The job
/// confirms readability first (so a write failure is EROFS, not a missing mount),
/// then asserts the write is rejected, exiting 0.
#[test]
fn an_input_is_read_only_erofs() -> anyhow::Result<()> {
    let target = require_live()?;
    build_guest(&target)?;
    let src = tempfile::tempdir().context("input source dir")?;
    std::fs::write(src.path().join("file"), b"ro")?;

    // read must succeed, then a write must fail; exit 0 only when both hold.
    let probe = "cat /run/sandy/inputs/data/file >/dev/null && { touch /run/sandy/inputs/data/x 2>/dev/null && exit \
                 10; exit 0; }";
    let (_, env) = run_with_input(&target, src.path(), probe)?;

    assert_eq!(env["status"], "succeeded", "ro-input run envelope: {env}");
    assert_eq!(
        env["exit_code"], 0,
        "input is readable and a write is rejected (EROFS): {env}"
    );
    Ok(())
}
