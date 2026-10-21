//! Live boot acceptance for `sandy run --flake <ref> --from-devshell` (#326).
//!
//! Tier-3, same discipline as `live_boot.rs`: behind the `live` feature, off
//! by default, [`require_live`] refuses off-matrix rather than skip-greening
//! (INV-S9). Run on the live host, e.g. on Apple silicon:
//!   nix shell nixpkgs#vfkit -c env SANDY_LIVE=1 \
//!     cargo nextest run -p sandy-cli --features live --test live_flake_devshell
//!
//! Two fixtures under `nix/guest-wrapper/tests/fixtures/`:
//! - `devshell-hello/`: `buildInputs = [ pkgs.hello ]; shellHook = "echo ready";` — the acceptance-bar positive case
//!   (#326's issue text).
//! - `devshell-host-conditional/`: a `shellHook` that checks `$(uname)` and a host-only path (`/Users`) — the required
//!   negative fixture, pinning down what actually happens (silently different output) rather than asserting it in
//!   prose.
#![cfg(feature = "live")]

use std::{path::PathBuf, process::Command};

use anyhow::Context;
// `require_live` directly, not via `tests/common`: unlike every other
// `live_*` test, this one builds no guest through `common::build_guest` (the
// `--flake` wrapper build is self-contained, #325/#326) — pulling in
// `common`'s full re-export set here would leave `build_guest` itself
// unused in this binary, a `--features live` clippy warning the `cargo
// clippy -p sandy-cli --all-targets --all-features` check gate (#328/#329's
// own standard) would deny.
use sandy_cli::live_target::require_live;

/// This crate's manifest-relative fixture directory.
fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../nix/guest-wrapper/tests/fixtures")
        .join(name)
}

/// `sandy -o json run --flake <fixture> --from-devshell -- <cmd>` against a
/// fresh `$SANDY_HOME`, returning the process exit code and the parsed result
/// envelope.
fn sandy_run_from_devshell(fixture_dir: &std::path::Path, cmd: &[&str]) -> anyhow::Result<(i32, serde_json::Value)> {
    let home = tempfile::tempdir().context("temp SANDY_HOME")?;
    let output = Command::new(env!("CARGO_BIN_EXE_sandy"))
        .env("SANDY_HOME", home.path())
        .args([
            "-o",
            "json",
            "run",
            "--flake",
            &fixture_dir.display().to_string(),
            "--from-devshell",
            "--timeout",
            "180",
            "--",
        ])
        .args(cmd)
        .output()
        .context("run sandy --flake --from-devshell")?;
    let code = output.status.code().unwrap_or(-1);
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout)
        .with_context(|| format!("parse sandy run envelope (exit {code}); stderr: {stderr}"))?;
    Ok((code, envelope))
}

/// The positive acceptance case: `buildInputs = [ pkgs.hello ]; shellHook =
/// "echo ready";` boots, `hello` is reachable (on `environment.systemPackages`
/// via `buildInputs`), and the hook's `echo ready` ran strictly before the
/// SANDY-READY marker — so the job's own command only starts once the hook
/// has finished, not merely "somewhere in the same boot".
#[test]
fn hello_devshell_boots_hello_reachable_hook_runs_before_marker() -> anyhow::Result<()> {
    require_live()?;
    let (code, env) = sandy_run_from_devshell(&fixture("devshell-hello"), &["hello"])?;

    assert_eq!(env["status"], "succeeded", "envelope: {env}");
    assert_eq!(
        env["exit_code"], 0,
        "`hello` must be on PATH via buildInputs; envelope: {env}"
    );
    assert_eq!(code, 0, "process band 0; envelope: {env}");

    let tail = env["logs"]["tail"].as_str().unwrap_or_default();
    let hook_at = tail
        .find("ready")
        .unwrap_or_else(|| panic!("shellHook's `echo ready` did not appear; tail: {tail}"));
    let marker_at = tail
        .find("SANDY-READY")
        .unwrap_or_else(|| panic!("the READY marker did not appear; tail: {tail}"));
    let job_output_at = tail
        .find("Hello, world!")
        .unwrap_or_else(|| panic!("`hello`'s own output did not appear; tail: {tail}"));
    // Adjacency, not just ordering: a plain `hook_at < marker_at` could pass
    // vacuously on an unrelated line that happens to contain "ready" (e.g. a
    // future systemd unit) even if the real hook output landed elsewhere.
    // Nothing but CR/LF may sit between the hook's own "ready" and the
    // marker it must immediately precede.
    let between_hook_and_marker = &tail[hook_at + "ready".len()..marker_at];
    assert!(
        between_hook_and_marker.trim_matches(['\r', '\n']).is_empty(),
        "nothing but line breaks may separate the hook's `ready` from SANDY-READY; between: \
         {between_hook_and_marker:?}"
    );
    assert!(
        marker_at < job_output_at,
        "the job's own command must start only after the READY marker; tail: {tail}"
    );
    Ok(())
}

/// The required negative fixture (#326's issue text): a `shellHook` whose
/// assumptions hold on the host (`nix develop`, macOS, a real `/Users`) and
/// silently do not hold once synthesized into the guest's login shell.
/// Asserts the real observed divergence — `Linux`/`no`, not a crash and not
/// `Darwin`/`yes` — rather than predicting it in prose.
#[test]
fn host_conditional_shellhook_diverges_silently_inside_the_guest() -> anyhow::Result<()> {
    require_live()?;
    let (code, env) = sandy_run_from_devshell(&fixture("devshell-host-conditional"), &["true"])?;

    assert_eq!(
        env["status"], "succeeded",
        "a host-conditional hook must not crash the boot, only diverge; envelope: {env}"
    );
    assert_eq!(code, 0, "process band 0; envelope: {env}");

    let tail = env["logs"]["tail"].as_str().unwrap_or_default();
    assert!(
        tail.contains("HOOK_OS=Linux"),
        "inside the guest `uname` must read Linux, not the host's Darwin; tail: {tail}"
    );
    assert!(!tail.contains("HOOK_OS=Darwin"), "tail: {tail}");
    assert!(
        tail.contains("HOOK_HAS_USERS_DIR=no"),
        "the guest has no host /Users directory; tail: {tail}"
    );
    Ok(())
}
