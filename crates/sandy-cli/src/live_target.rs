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
    // The host->guest pairing shared with `doctor`'s macOS builder-prereq
    // check and `flake_wrap`'s `--flake` auto-detection (#325) — the two
    // previously disagreed (this hardcoded `aarch64-linux`; `doctor` used the
    // host's actual arch), now one definition.
    let host = crate::host_target::host_target();
    let target = if host.hypervisor == "vfkit" {
        vfkit_target(&host.guest_system)?
    } else {
        LiveTarget {
            hypervisor: "qemu-system-x86_64".to_string(),
            runner_attr: "packages.x86_64-linux.guest-runner",
            topology_attr: "topologies.x86_64-linux.qemu",
            target_arch: "x86_64-linux",
        }
    };
    ensure_arch_matches(target.target_arch, &host.guest_system)?;
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

/// vfkit's live target for `guest_system` (derived from `host_target()`, not
/// hardcoded — vfkit requires a matching host/guest arch, #325). Only
/// `aarch64-linux` is wired into `nix/guest/flake.nix` today
/// (`packages.aarch64-darwin.guest-runner-vfkit`, `topologies.aarch64-linux.vfkit`);
/// an x86_64 Mac's `guest_system` is `x86_64-linux`, which has no built attrs
/// to select, so it refuses with a named error instead of silently reusing
/// the aarch64 ones (what the hardcoded version did before this fix).
fn vfkit_target(guest_system: &str) -> anyhow::Result<LiveTarget> {
    match guest_system {
        "aarch64-linux" => Ok(LiveTarget {
            hypervisor: std::env::var("SANDY_VFKIT_BIN").unwrap_or_else(|_| "vfkit".to_string()),
            runner_attr: "packages.aarch64-darwin.guest-runner-vfkit",
            topology_attr: "topologies.aarch64-linux.vfkit",
            target_arch: "aarch64-linux",
        }),
        other => bail!(
            "refusing: no vfkit live target for guest system `{other}` — only aarch64-linux (Apple Silicon) is wired \
             into nix/guest/flake.nix today"
        ),
    }
}

/// Refuses (never panics) if `target_arch` and `guest_system` disagree —
/// extracted so this check is unit-testable (CodeRabbit finding on this PR):
/// the old `debug_assert_eq!` here compiled out of release builds and
/// panicked in debug ones (how `cargo nextest` runs the live suites), on any
/// host where the two legitimately disagree (an Intel Mac: vfkit pairs with
/// `host.guest_system == "x86_64-linux"`, but the vfkit branch above
/// hardcodes `target_arch: "aarch64-linux"`). The live gate's contract is to
/// refuse off-matrix, not to crash (INV-S9).
fn ensure_arch_matches(target_arch: &str, guest_system: &str) -> anyhow::Result<()> {
    if target_arch != guest_system {
        bail!("refusing: this host's guest system `{guest_system}` is not on the live matrix (`{target_arch}`)");
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use anyhow::Context;

    use super::{ensure_arch_matches, vfkit_target};

    /// The only guest arch `nix/guest/flake.nix` actually builds for vfkit.
    #[test]
    fn vfkit_target_resolves_aarch64_linux() -> anyhow::Result<()> {
        let target = vfkit_target("aarch64-linux").context("resolve the aarch64 vfkit target")?;
        assert_eq!(target.runner_attr, "packages.aarch64-darwin.guest-runner-vfkit");
        assert_eq!(target.topology_attr, "topologies.aarch64-linux.vfkit");
        assert_eq!(target.target_arch, "aarch64-linux");
        Ok(())
    }

    /// An Intel Mac's `guest_system` (`x86_64-linux`) has no vfkit attrs built
    /// anywhere — this must refuse by name, not silently reuse the aarch64
    /// ones or panic on a debug-only assertion.
    #[test]
    fn vfkit_target_refuses_an_unsupported_guest_system() {
        // `LiveTarget` carries no `Debug` impl, so `unwrap_err()` isn't available;
        // match instead.
        let err = match vfkit_target("x86_64-linux") {
            Err(err) => err,
            Ok(_) => panic!("expected an unsupported-target error for x86_64-linux"),
        };
        assert!(err.to_string().contains("x86_64-linux"), "{err}");
    }

    #[test]
    fn matching_archs_are_accepted() -> anyhow::Result<()> {
        ensure_arch_matches("aarch64-linux", "aarch64-linux").context("matching arches must not refuse")?;
        Ok(())
    }

    /// Regression: this used to be a `debug_assert_eq!`, which panics instead
    /// of refusing — reachable on a real host (an Intel Mac pairs vfkit's
    /// hardcoded `aarch64-linux` target against `host.guest_system ==
    /// "x86_64-linux"`), not just a hypothetical.
    #[test]
    fn mismatched_archs_refuse_instead_of_panicking() {
        let err = ensure_arch_matches("aarch64-linux", "x86_64-linux").expect_err("a mismatch must refuse");
        let message = err.to_string();
        assert!(message.contains("aarch64-linux"), "message was: {message}");
        assert!(message.contains("x86_64-linux"), "message was: {message}");
    }
}
