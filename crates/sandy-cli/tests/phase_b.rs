//! Phase B — the host-matrix acceptance gate (#27).
//!
//! Tier-3: the *real* router (`classify`) over a *real* boot observation decides
//! the strategy, and the live legs run a job through the native backend (S9).
//! Behind the `live` feature (off by default) with [`common::require_live`]
//! refusing off-matrix.
//!
//! Matrix coverage:
//! - **NixOS / Nix-present host** (ws01 x86_64, and the M2 via the linux-builder): a real trivial boot → `classify` →
//!   `HostNix` → a job runs. Covered live here.
//! - **arch mismatch** → `Refuse` naming `arch`, no build: covered here via the real `classify`.
//! - **BuilderVM / RemoteBuild selected at stage B → Refuse "requires stage C/D"**, and **Refuse propagation**: covered
//!   tier-1 by the router's own tests (`sandy::provision` in `provision/router.rs`).
//! - **non-NixOS Linux (+Nix / install→HostNix) and an unbootable host**: need host classes not available here; they
//!   bind in when those nodes exist (the router logic for them is already classify-tested).
//!
//! Run (M2): `nix shell nixpkgs#vfkit -c env SANDY_LIVE=1 cargo nextest run -p sandy-cli --features live --test
//! phase_b` or ws01: `nix shell nixpkgs#qemu  -c env SANDY_LIVE=1 …`.
#![cfg(feature = "live")]

use anyhow::Context;
use sandy::{BootAxis, BuildAxis, HostFacts, ProvisioningStrategy, classify};

mod common;
use common::{build_guest, require_live, sandy_run};

/// The live Nix-present leg: a real trivial boot is the boot observation that
/// feeds the real router, which routes `HostNix` for this host's arch — and a job
/// actually runs through the backend. Not a fabricated `BootAxis` (S9).
#[test]
fn nixos_leg_boot_observation_routes_hostnix_and_runs() -> anyhow::Result<()> {
    let target = require_live()?;
    build_guest(&target)?;
    let home = tempfile::tempdir().context("temp SANDY_HOME")?;

    // The boot axis is a real observation: run a trivial guest and read the result.
    let (code, env) = sandy_run(home.path(), &target, &["true"])?;
    let boot = if code == 0 && env["status"] == "succeeded" {
        BootAxis::Ok
    } else {
        BootAxis::Failed
    };
    assert_eq!(
        boot,
        BootAxis::Ok,
        "the live host must boot a trivial guest; envelope: {env}"
    );

    // The real router over the observed facts for a Nix-present, arch-matching host.
    let facts = HostFacts {
        boot,
        build: BuildAxis::HostNix,
        target_arch: target.target_arch.to_string(),
        build_can_produce_target: true,
        seed: None,
        remote_builder: None,
    };
    match classify(&facts) {
        ProvisioningStrategy::HostNix { arch } => assert_eq!(arch, target.target_arch),
        other => anyhow::bail!("expected HostNix for a Nix-present host, got {other:?}"),
    }
    Ok(())
}

/// A producing build axis that cannot target the requested arch refuses naming
/// `arch`, with no build attempted (B-REQ-4) — the real router, no host needed.
#[test]
fn arch_mismatch_refuses_without_building() {
    let facts = HostFacts {
        boot: BootAxis::Ok,
        build: BuildAxis::HostNix,
        target_arch: "riscv64-linux".to_string(),
        build_can_produce_target: false,
        seed: None,
        remote_builder: None,
    };
    match classify(&facts) {
        ProvisioningStrategy::Refuse { reason } => {
            assert!(reason.contains("arch"), "refusal must name the arch axis: {reason}");
        }
        other => panic!("expected Refuse(arch), got {other:?}"),
    }
}
