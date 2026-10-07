//! Shared helpers for the live acceptance gates (live_boot / host_matrix).
//!
//! Only compiled into a gate binary that is itself behind the `live` feature, so
//! these never reach CI. `dead_code` is allowed because not every gate uses every
//! helper.
#![allow(dead_code)]

use std::{
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, bail};

/// One live target: the guest runner package to realise and the topology attr
/// sandy boots, chosen by host platform (vfkit on macOS, qemu on Linux).
pub struct LiveTarget {
    pub hypervisor: &'static str,
    pub runner_attr: &'static str,
    pub topology_attr: &'static str,
    /// The Linux guest arch this host builds and boots (vfkit matches the host
    /// arch; the Linux leg is x86_64).
    pub target_arch: &'static str,
}

/// The guest flake directory (`<repo>/nix/guest`), from this crate's manifest.
pub fn guest_flake() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../nix/guest")
}

/// Refuse unless this is a live matrix host: `SANDY_LIVE=1` and the platform's
/// hypervisor on `PATH`. Returns the [`LiveTarget`]. Bailing here is the refusal
/// — off-matrix never reaches a green assertion (INV-S9).
pub fn require_live() -> anyhow::Result<LiveTarget> {
    if std::env::var("SANDY_LIVE").ok().as_deref() != Some("1") {
        bail!("refusing: this is a live gate — set SANDY_LIVE=1 on a host with a hypervisor");
    }
    let target = if cfg!(target_os = "macos") {
        LiveTarget {
            hypervisor: "vfkit",
            runner_attr: "packages.aarch64-darwin.guest-runner-vfkit",
            topology_attr: "topologies.aarch64-linux.vfkit",
            target_arch: "aarch64-linux",
        }
    } else {
        LiveTarget {
            hypervisor: "qemu-system-x86_64",
            runner_attr: "packages.x86_64-linux.guest-runner",
            topology_attr: "topologies.x86_64-linux.qemu",
            target_arch: "x86_64-linux",
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
pub fn on_path(program: &str) -> bool {
    std::env::var_os("PATH").is_some_and(|path| std::env::split_paths(&path).any(|dir| dir.join(program).is_file()))
}

/// Whether `program` resolves on the given `path` value (a `PATH`-shaped string).
/// The adversarial check for the Nix-free gate: `is_on(path, "nix")` must be false
/// before a "boot invoked no Nix" claim can be trusted.
pub fn is_on(path: &std::ffi::OsStr, program: &str) -> bool {
    std::env::split_paths(path).any(|dir| dir.join(program).is_file())
}

/// This process's `PATH` with every directory that contains a `nix` binary
/// removed — the environment the Nix-free boot (#28) runs under. The hypervisor
/// (vfkit) stays reachable; `nix` does not, so a green can't come from Nix
/// sneaking back onto `PATH`.
pub fn nix_free_path() -> std::ffi::OsString {
    let current = std::env::var_os("PATH").unwrap_or_default();
    let kept: Vec<PathBuf> = std::env::split_paths(&current)
        .filter(|dir| !dir.join("nix").is_file())
        .collect();
    std::env::join_paths(kept).unwrap_or(current)
}

/// Evaluate `<guest-flake>#<topology_attr>` with `nix eval --json` and write the
/// topology JSON to `out`. This is the one Nix step the Nix-free gate takes, at
/// setup time; the boot that follows reads this file with no Nix on `PATH`.
pub fn emit_topology(topology_attr: &str, out: &Path) -> anyhow::Result<()> {
    let attr = format!("{}#{}", guest_flake().display(), topology_attr);
    let output = Command::new("nix")
        .args(["eval", "--json", &attr])
        .output()
        .context("spawn nix eval for the topology")?;
    if !output.status.success() {
        bail!(
            "nix eval of {attr} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    std::fs::write(out, &output.stdout).with_context(|| format!("write topology JSON to {}", out.display()))?;
    Ok(())
}

/// Realise the guest closure (kernel/initrd/erofs) so the topology paths exist
/// when the backend boots.
pub fn build_guest(target: &LiveTarget) -> anyhow::Result<()> {
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
pub fn sandy_run(home: &Path, target: &LiveTarget, cmd: &[&str]) -> anyhow::Result<(i32, serde_json::Value)> {
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
pub fn sandy(home: &Path, args: &[&str]) -> anyhow::Result<(i32, String)> {
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
