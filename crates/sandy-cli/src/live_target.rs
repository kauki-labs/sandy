//! Resolving and building the live host's guest target — shared by the `live`
//! test suites (`tests/common/mod.rs` re-exports these) and the `acceptance-vm`
//! binary (#131 R4b), so both consumers of "boot a real guest on this host" use
//! one implementation. Behind the `live` feature: a non-live build never needs a
//! hypervisor or a guest flake.

use std::{path::PathBuf, process::Command};

use anyhow::{Context, bail};

/// One live target: the guest runner package to realise and the topology attr
/// sandy boots, chosen by host platform (vfkit on macOS, qemu on Linux).
pub struct LiveTarget {
    /// The hypervisor binary this target needs on `PATH` — on macOS, the
    /// `SANDY_VFKIT_BIN`-configured vfkit path (default `"vfkit"`), the same
    /// resolution `VfkitBackend`'s factory uses, so the live gate checks the
    /// binary that actually runs.
    pub hypervisor: String,
    /// The guest flake attr that builds the runner package.
    pub runner_attr: &'static str,
    /// The guest flake attr that evaluates to the typed `Topology` sandy boots.
    pub topology_attr: &'static str,
    /// The Linux guest arch this host builds and boots (vfkit matches the host
    /// arch; the Linux leg is x86_64).
    pub target_arch: &'static str,
}

/// The guest flake directory (`<repo>/nix/guest`), from this crate's manifest.
#[must_use]
pub fn guest_flake() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../nix/guest")
}

/// Refuse unless this is a live matrix host: `SANDY_LIVE=1` and the platform's
/// hypervisor on `PATH`. Returns the [`LiveTarget`]. Bailing here is the refusal
/// — off-matrix never reaches a green assertion (INV-S9).
///
/// # Errors
/// Returns an error naming what is missing: `SANDY_LIVE` unset, or the
/// platform's hypervisor not on `PATH`.
pub fn require_live() -> anyhow::Result<LiveTarget> {
    if std::env::var("SANDY_LIVE").ok().as_deref() != Some("1") {
        bail!("refusing: this is a live gate — set SANDY_LIVE=1 on a host with a hypervisor");
    }
    let target = if cfg!(target_os = "macos") {
        LiveTarget {
            hypervisor: std::env::var("SANDY_VFKIT_BIN").unwrap_or_else(|_| "vfkit".to_string()),
            runner_attr: "packages.aarch64-darwin.guest-runner-vfkit",
            topology_attr: "topologies.aarch64-linux.vfkit",
            target_arch: "aarch64-linux",
        }
    } else {
        LiveTarget {
            hypervisor: "qemu-system-x86_64".to_string(),
            runner_attr: "packages.x86_64-linux.guest-runner",
            topology_attr: "topologies.x86_64-linux.qemu",
            target_arch: "x86_64-linux",
        }
    };
    if !on_path(&target.hypervisor) {
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
#[must_use]
pub fn on_path(program: &str) -> bool {
    std::env::var_os("PATH").is_some_and(|path| std::env::split_paths(&path).any(|dir| dir.join(program).is_file()))
}

/// Build `target`'s guest runner package (`nix build --no-link`), so the
/// subsequent boot resolves it from the Nix store without building on the hot
/// path.
///
/// # Errors
/// Returns an error if `nix` cannot be spawned or the build fails.
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
