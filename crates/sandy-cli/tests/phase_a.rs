//! Phase A — the live M2/ws01 acceptance gate (#26).
//!
//! Tier-3: instantiates the *physical* code — a real guest boots through the
//! native backend, output is collected, the box is torn down, and the CLI job
//! ops run over the real journal. Per INV-S9 it is never counted green from a
//! fake: the whole file is behind the `live` feature (off by default, so CI and
//! `nix flake check` never run it), and [`common::require_live`] refuses
//! off-matrix rather than skip-and-greening a live scenario.
//!
//! Run it on the live host (a hypervisor on PATH), e.g. on the M2:
//!   nix shell nixpkgs#vfkit -c \
//!     env SANDY_LIVE=1 cargo nextest run -p sandy-cli --features live --test phase_a
//! or on ws01 (x86_64/KVM): `nix shell nixpkgs#qemu -c env SANDY_LIVE=1 …`.
//!
//! The egress-mechanism and scoped-cred rows (#23/#25) bind in here once those
//! blocks land.
#![cfg(feature = "live")]

use anyhow::Context;

mod common;
use common::{build_guest, require_live, sandy, sandy_run};

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
