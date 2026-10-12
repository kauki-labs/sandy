//! Live boot — the native-boot acceptance gate (#26, formerly phase_a).
//!
//! Tier-3: instantiates the *physical* code — a real guest boots through the
//! native backend, output is collected, the box is torn down, and the CLI job
//! ops run over the real journal. Per INV-S9 it is never counted green from a
//! fake: the whole file is behind the `live` feature (off by default, so CI and
//! `nix flake check` never run it), and [`common::require_live`] refuses
//! off-matrix rather than skip-and-greening a live scenario.
//!
//! Run it on the live host (a hypervisor on PATH), e.g. on an Apple-silicon host:
//!   nix shell nixpkgs#vfkit -c \
//!     env SANDY_LIVE=1 cargo nextest run -p sandy-cli --features live --test live_boot
//! or on a Linux/KVM host: `nix shell nixpkgs#qemu -c env SANDY_LIVE=1 …`.
//!
//! The egress-mechanism and scoped-cred rows (#23/#25) bind in here once those
//! blocks land.
#![cfg(feature = "live")]

use anyhow::Context;

mod common;
use common::{build_guest, require_live, sandy, sandy_run, sandy_run_with_secret};

/// A real guest boots, `echo hi` runs, output is collected: succeeded / exit 0 /
/// process band 0 / not retryable.
#[test]
fn real_boot_collect_succeeds() -> anyhow::Result<()> {
    let target = require_live()?;
    build_guest(&target)?;
    let home = tempfile::tempdir().context("temp SANDY_HOME")?;

    let (code, env) = sandy_run(home.path(), &target, &["echo", "hi"])?;
    assert_eq!(code, 0, "process band 0; envelope: {env}");
    assert_eq!(env["status"], "succeeded", "envelope: {env}");
    assert_eq!(env["exit_code"], 0);
    assert_eq!(env["retryable"], false);
    Ok(())
}

/// #50: a staged secret is consumable in-guest as `$NAME` (the login-shell export
/// of the mounted secret share), and matches the staged file. The guest exit code
/// carries the result (the envelope does not surface guest stdout), and the secret
/// value never appears in the guest argv.
#[test]
fn staged_secret_is_exported_to_the_job_env() -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let target = require_live()?;
    build_guest(&target)?;
    let home = tempfile::tempdir().context("temp SANDY_HOME")?;

    // A 0600 secret source (a world/group-readable one is refused by staging).
    let secret_file = home.path().join("tok");
    std::fs::write(&secret_file, "s3cr3t-marker-abc123").context("write secret")?;
    std::fs::set_permissions(&secret_file, std::fs::Permissions::from_mode(0o600)).context("chmod secret")?;

    // Exit 0 iff $TOK is exported, non-empty, and equals the mounted secret file.
    // The comparison is in-guest so the secret value is never in the command argv,
    // and an unmounted/empty share fails the `-n` guard rather than false-passing.
    // sandy joins the command argv and runs it through `sh`, so the probe is a
    // single element (wrapping in `sh -c` would double-nest and mangle the quoting).
    let probe = r#"[ -n "$TOK" ] && [ "$TOK" = "$(cat /run/sandy/secrets/TOK)" ] && exit 0 || exit 7"#;
    let (code, env) = sandy_run_with_secret(home.path(), &target, "TOK", &secret_file, &[probe])?;

    assert_eq!(
        env["status"], "succeeded",
        "the job must see $TOK exported; envelope: {env}"
    );
    assert_eq!(
        env["exit_code"], 0,
        "exit 7 means $TOK was absent or did not match the file; envelope: {env}"
    );
    assert_eq!(code, 0, "process band 0; envelope: {env}");

    // INV-1 leak plane: the secret value must not appear in the captured console
    // (the injected argv + guest output surfaced into logs.tail). It travels the
    // file→env channel only.
    let tail = env["logs"]["tail"].as_str().unwrap_or_default();
    assert!(
        !tail.contains("s3cr3t-marker-abc123"),
        "the secret value must not leak into the guest argv or console; tail: {tail}"
    );
    Ok(())
}

/// A guest command that exits non-zero is a task fault: failed / guest exit 1 /
/// process band 1 / NOT retryable (INV-11 — never conflated with an infra fault).
#[test]
fn guest_failure_is_a_task_fault() -> anyhow::Result<()> {
    let target = require_live()?;
    build_guest(&target)?;
    let home = tempfile::tempdir().context("temp SANDY_HOME")?;

    let (code, env) = sandy_run(home.path(), &target, &["false"])?;
    assert_eq!(code, 1, "process band 1; envelope: {env}");
    assert_eq!(env["status"], "failed");
    assert_eq!(env["exit_code"], 1);
    assert_eq!(env["retryable"], false, "a task fault is never retryable");
    Ok(())
}

/// The CLI job surface over a real run: after a live `run`, the job is on the
/// journal and `ls` / `status` report it; `gc` keeps the terminal record under
/// the default retention.
#[test]
fn cli_lifecycle_over_a_real_job() -> anyhow::Result<()> {
    let target = require_live()?;
    build_guest(&target)?;
    let home = tempfile::tempdir().context("temp SANDY_HOME")?;

    let (code, env) = sandy_run(home.path(), &target, &["echo", "hi"])?;
    assert_eq!(code, 0, "envelope: {env}");
    let job_id = env["job_id"].as_str().context("envelope job_id")?.to_string();

    let (ls_code, ls_out) = sandy(home.path(), &["ls"])?;
    assert_eq!(ls_code, 0);
    assert!(ls_out.contains(&job_id), "ls must list the job {job_id}: {ls_out}");

    let (st_code, st_out) = sandy(home.path(), &["status", &job_id])?;
    assert_eq!(st_code, 0);
    assert!(st_out.contains("Succeeded"), "status must report Succeeded: {st_out}");

    // gc with the default retention keeps the single terminal record.
    let (gc_code, _) = sandy(home.path(), &["gc"])?;
    assert_eq!(gc_code, 0);
    let (_, ls_after) = sandy(home.path(), &["ls"])?;
    assert!(
        ls_after.contains(&job_id),
        "gc must not evict the only kept job: {ls_after}"
    );
    Ok(())
}
