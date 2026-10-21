//! Hermetic coverage for `sandy run --flake <ref> --from-devshell` (#326): the
//! best-effort warning and the clap wiring around the flag. No `nix` on PATH
//! is needed (or wanted) for any of these — `PATH` is deliberately stripped so
//! the warning's presence is asserted independently of whether the eventual
//! `nix` probe can even run, and so this suite stays in the default (non-live)
//! gate. Boot acceptance (the devShell actually working, the ordering, and the
//! negative host-conditional fixture) is `tests/live_flake_devshell.rs`,
//! tier-3.

use std::process::Command;

use anyhow::Context;

const WARNING_SUBSTRING: &str = "best-effort: synthesizing a nixos-module from --from-devshell";

/// Runs `sandy run --flake <flake_ref> --from-devshell -- true` with `PATH`
/// replaced by a directory with no `nix` binary, so `flake_wrap`'s own `nix`
/// probe fails deterministically regardless of the host. Returns the raw
/// output: the point of this suite is what reached stderr before that
/// failure, not the exit code's exact value.
fn run_from_devshell(flake_ref: &str) -> anyhow::Result<std::process::Output> {
    let home = tempfile::tempdir().context("creating a temp SANDY_HOME")?;
    Command::new(env!("CARGO_BIN_EXE_sandy"))
        .env("SANDY_HOME", home.path())
        .env("PATH", "/nonexistent-sandy-test-path")
        .args(["run", "--flake", flake_ref, "--from-devshell", "--", "true"])
        .output()
        .context("running `sandy run --flake --from-devshell`")
}

/// The best-effort warning is printed before `flake_wrap`'s own `nix eval`
/// probe is even attempted — with `nix` unreachable, the probe must fail, but
/// the warning must already be on stderr regardless (#326's acceptance bar:
/// checked by a real test, not just added and trusted).
#[test]
fn the_best_effort_warning_prints_before_the_nix_probe_can_run() -> anyhow::Result<()> {
    let output = run_from_devshell("/nonexistent-flake")?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(WARNING_SUBSTRING),
        "warning missing even though the probe never had a chance to succeed; stderr: {stderr}"
    );
    assert_ne!(
        output.status.code(),
        Some(0),
        "with no `nix` on PATH this run cannot succeed"
    );
    Ok(())
}

/// "Every invocation": printed on a second, independent run too, not just
/// once per process lifetime or on some stateful first-call path.
#[test]
fn the_best_effort_warning_prints_on_every_invocation() -> anyhow::Result<()> {
    for _ in 0..2 {
        let output = run_from_devshell("/nonexistent-flake")?;
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains(WARNING_SUBSTRING), "stderr: {stderr}");
    }
    Ok(())
}

/// Plain `--flake` (no `--from-devshell`) never prints the devshell warning —
/// it must not read as "best-effort" when kind 1/2/3 auto-detection is what
/// actually ran.
#[test]
fn the_best_effort_warning_is_absent_without_from_devshell() -> anyhow::Result<()> {
    let home = tempfile::tempdir().context("creating a temp SANDY_HOME")?;
    let output = Command::new(env!("CARGO_BIN_EXE_sandy"))
        .env("SANDY_HOME", home.path())
        .env("PATH", "/nonexistent-sandy-test-path")
        .args(["run", "--flake", "/nonexistent-flake", "--", "true"])
        .output()
        .context("running `sandy run --flake` (no --from-devshell)")?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains(WARNING_SUBSTRING),
        "the devshell warning must not print for a plain --flake run; stderr: {stderr}"
    );
    Ok(())
}

/// clap: `--from-devshell` with neither `--flake` nor a template is rejected
/// (both become "required" once `--from-devshell` has no `--flake` to pair
/// with) — never a silent fallback to some other boot path.
#[test]
fn from_devshell_without_flake_or_template_is_a_clap_error() -> anyhow::Result<()> {
    let home = tempfile::tempdir().context("creating a temp SANDY_HOME")?;
    let output = Command::new(env!("CARGO_BIN_EXE_sandy"))
        .env("SANDY_HOME", home.path())
        .args(["run", "--from-devshell", "--", "true"])
        .output()
        .context("running `sandy run --from-devshell` with no --flake or template")?;
    assert_ne!(output.status.code(), Some(0));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("required"),
        "expected clap's missing-required-argument wording; stderr: {stderr}"
    );
    Ok(())
}

/// clap: `--from-devshell` conflicts with a bare `template` too, not only
/// indirectly through `--flake`. Without this, `sandy run <template>
/// --from-devshell` (no `--flake`) would satisfy `template`'s own
/// `required_unless_present = "flake"` and clap would never separately
/// enforce `from_devshell`'s `requires = "flake"` — the flag would be
/// silently ignored and a plain template boot would run instead, which is
/// never acceptable for a flag whose whole contract is "never silent" (#326).
#[test]
fn from_devshell_conflicts_with_a_bare_template() -> anyhow::Result<()> {
    let home = tempfile::tempdir().context("creating a temp SANDY_HOME")?;
    let output = Command::new(env!("CARGO_BIN_EXE_sandy"))
        .env("SANDY_HOME", home.path())
        .args(["run", "some-template", "--from-devshell", "--", "true"])
        .output()
        .context("running `sandy run <template> --from-devshell`")?;
    assert_ne!(output.status.code(), Some(0));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("cannot be used with"),
        "expected clap's conflicts-with wording; stderr: {stderr}"
    );
    Ok(())
}

/// clap: `--from-devshell` conflicts with `--kind` — the flag IS the kind
/// selector for this path, so forcing another one at the same time is
/// nonsensical, not silently one winning.
#[test]
fn from_devshell_conflicts_with_kind() -> anyhow::Result<()> {
    let home = tempfile::tempdir().context("creating a temp SANDY_HOME")?;
    let output = Command::new(env!("CARGO_BIN_EXE_sandy"))
        .env("SANDY_HOME", home.path())
        .args([
            "run",
            "--flake",
            "/nonexistent-flake",
            "--from-devshell",
            "--kind",
            "topology",
            "--",
            "true",
        ])
        .output()
        .context("running `sandy run --flake --from-devshell --kind topology`")?;
    assert_ne!(output.status.code(), Some(0));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("cannot be used with"),
        "expected clap's conflicts-with wording; stderr: {stderr}"
    );
    Ok(())
}
