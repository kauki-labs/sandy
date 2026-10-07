//! Phase A — the live M2/ws01 acceptance gate (#26).
//!
//! Tier-3: instantiates the *physical* code — a real guest boots through the
//! native backend, output is collected, the box is torn down, and the CLI job
//! ops run over the real journal. Per INV-S9 it is never counted green from a
//! fake: the whole file is behind the `live` feature (off by default, so CI and
//! `nix flake check` never run it), and [`require_live`] refuses off-matrix
//! rather than skip-and-greening a live scenario.
//!
//! Run it on the live host (a hypervisor on PATH), e.g. on the M2:
//!   nix shell nixpkgs#vfkit -c \
//!     env SANDY_LIVE=1 cargo nextest run -p sandy-cli --features live --test phase_a
//! or on ws01 (x86_64/KVM): `nix shell nixpkgs#qemu -c env SANDY_LIVE=1 …`.
#![cfg(feature = "live")]

use std::{
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, bail};

/// One live target: the guest runner package to realise and the topology attr
/// sandy boots, chosen by host platform (vfkit on macOS, qemu on Linux).
struct LiveTarget {
    hypervisor: &'static str,
    runner_attr: &'static str,
    topology_attr: &'static str,
}

/// The guest flake directory (`<repo>/nix/guest`), from this crate's manifest.
fn guest_flake() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../nix/guest")
}

/// Refuse unless this is a live matrix host: `SANDY_LIVE=1` and the platform's
/// hypervisor on `PATH`. Returns the [`LiveTarget`]. Panicking here is the
/// refusal — off-matrix never reaches a green assertion (INV-S9).
fn require_live() -> anyhow::Result<LiveTarget> {
    if std::env::var("SANDY_LIVE").ok().as_deref() != Some("1") {
        bail!("refusing: phase_a is a live gate — set SANDY_LIVE=1 on a host with a hypervisor");
    }
    let target = if cfg!(target_os = "macos") {
        LiveTarget {
            hypervisor: "vfkit",
            runner_attr: "packages.aarch64-darwin.guest-runner-vfkit",
            topology_attr: "topologies.aarch64-linux.vfkit",
        }
    } else {
        LiveTarget {
            hypervisor: "qemu-system-x86_64",
            runner_attr: "packages.x86_64-linux.guest-runner",
            topology_attr: "topologies.x86_64-linux.qemu",
        }
    };
    if !on_path(target.hypervisor) {
        bail!(
            "refusing: `{}` is not on PATH — run under `nix shell nixpkgs#{}`",
            target.hypervisor,
            if target.hypervisor.starts_with("qemu") {
                "qemu"
            } else {
                "vfkit"
            }
        );
    }
    Ok(target)
}

/// Whether `program` resolves on `PATH`.
fn on_path(program: &str) -> bool {
    std::env::var_os("PATH").is_some_and(|path| std::env::split_paths(&path).any(|dir| dir.join(program).is_file()))
}

/// Realise the guest closure (kernel/initrd/erofs) so the topology paths exist
/// when the backend boots.
fn build_guest(target: &LiveTarget) -> anyhow::Result<()> {
    let status = Command::new("nix")
        .args(["build", "--no-link"])
        .arg(format!("{}#{}", guest_flake().display(), target.runner_attr))
        .status()
        .context("spawn nix build for the guest")?;
    if !status.success() {
        bail!("nix build of the guest runner failed");
    }
    Ok(())
}

/// Run `sandy run <topology> -- <cmd>` against `home`, returning the process exit
/// code and the parsed result envelope.
fn sandy_run(home: &Path, target: &LiveTarget, cmd: &[&str]) -> anyhow::Result<(i32, serde_json::Value)> {
    let attr = format!("{}#{}", guest_flake().display(), target.topology_attr);
    let output = Command::new(env!("CARGO_BIN_EXE_sandy"))
        .env("SANDY_HOME", home)
        .args(["-o", "json", "run", &attr, "--timeout", "120", "--"])
        .args(cmd)
        .output()
        .context("run sandy")?;
    let code = output.status.code().unwrap_or(-1);
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).with_context(|| {
        format!(
            "parse sandy run envelope (exit {code}); stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        )
    })?;
    Ok((code, envelope))
}

/// Run `sandy <args…>` (a management op) against `home`, returning exit + stdout.
fn sandy(home: &Path, args: &[&str]) -> anyhow::Result<(i32, String)> {
    let output = Command::new(env!("CARGO_BIN_EXE_sandy"))
        .env("SANDY_HOME", home)
        .args(args)
        .output()
        .context("run sandy management op")?;
    Ok((
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).into_owned(),
    ))
}

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
