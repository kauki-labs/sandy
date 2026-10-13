//! Live output round-trip — the outputs half of #34, on a real boot.
//!
//! Tier-3 (behind the `live` feature, off by default so CI never runs it): a
//! real guest boots with a writable `--out result:DEST` share, the job writes
//! under `/run/sandy/outputs/result`, and after teardown the bytes appear at the
//! host destination. Proves guest→host collection end to end.
//!
//! Run it on the live host, e.g. on Apple silicon:
//!   nix shell nixpkgs#vfkit -c \
//!     env SANDY_LIVE=1 cargo nextest run -p sandy-cli --features live --test live_outputs
#![cfg(feature = "live")]

use std::{path::Path, process::Command};

use anyhow::Context;

mod common;
use common::{LiveTarget, build_guest, guest_flake, require_live};

/// Run `sandy run <topology> --out result:<dest> -- <sh-command>` against a
/// throwaway `$SANDY_HOME`, returning the process exit code and the parsed
/// envelope. The guest runner space-joins the trailing argv and pipes it to `sh`,
/// so the command is passed as one shell string.
fn run_with_output(target: &LiveTarget, dest: &Path, sh_command: &str) -> anyhow::Result<(i32, serde_json::Value)> {
    let home = tempfile::tempdir().context("temp SANDY_HOME")?;
    let attr = format!("{}#{}", guest_flake().display(), target.topology_attr);
    let output_arg = format!("result:{}", dest.display());
    let output = Command::new(env!("CARGO_BIN_EXE_sandy"))
        .env("SANDY_HOME", home.path())
        .args([
            "-o",
            "json",
            "run",
            &attr,
            "--timeout",
            "120",
            "--out",
            &output_arg,
            "--",
            sh_command,
        ])
        .output()
        .context("run sandy with an output")?;
    let code = output.status.code().unwrap_or(-1);
    let envelope = serde_json::from_slice(&output.stdout).with_context(|| {
        format!(
            "parse sandy run envelope (exit {code}); stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        )
    })?;
    Ok((code, envelope))
}

/// What the guest writes under `/run/sandy/outputs/result` is collected to the
/// host destination at teardown: a file and a nested-dir file both land at DEST.
#[test]
fn an_output_is_collected_to_the_host() -> anyhow::Result<()> {
    let target = require_live()?;
    build_guest(&target)?;
    let dest = tempfile::tempdir().context("output dest dir")?;

    let produce = "printf produced > /run/sandy/outputs/result/f && mkdir -p /run/sandy/outputs/result/sub && printf \
                   deep > /run/sandy/outputs/result/sub/g";
    let (_, env) = run_with_output(&target, dest.path(), produce)?;

    assert_eq!(env["status"], "succeeded", "output run envelope: {env}");
    assert_eq!(env["exit_code"], 0, "guest wrote the output (exit 0): {env}");

    assert_eq!(
        std::fs::read(dest.path().join("f")).context("collected output file")?,
        b"produced",
        "the guest's output file was collected to the host dest"
    );
    assert_eq!(
        std::fs::read(dest.path().join("sub").join("g")).context("collected nested output")?,
        b"deep",
        "a nested output file was collected too"
    );
    Ok(())
}
