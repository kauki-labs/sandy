//! phase_c — the "erofs hinge / Nix-free Mac" acceptance gate (#28).
//!
//! Tier-3, macOS-only: proves sandy can boot a *prebuilt* erofs guest through
//! the vfkit backend with `nix` entirely off the child's `PATH`. Nix runs once,
//! at setup, to realise the guest closure and emit the topology JSON; the boot
//! itself reads that JSON file and spawns no Nix — the Nix-free path from
//! `sandy::topology` (#28).
//!
//! Per INV-S9 this is never counted green from a fake or from a skip: the whole
//! file is behind the `live` feature (off by default, so CI and `nix flake
//! check` never run it), [`common::require_live`] refuses without `SANDY_LIVE=1`
//! and vfkit on PATH, and the gate bails on any non-macOS host rather than
//! skip-and-greening the Mac hinge.
//!
//! Run it on an Apple-silicon host:
//!   nix shell nixpkgs#vfkit -c \
//!     env SANDY_LIVE=1 cargo nextest run -p sandy-cli --features live --test phase_c
#![cfg(feature = "live")]

use std::process::Command;

use anyhow::{Context, bail};

mod common;
use common::{build_guest, emit_topology, is_on, nix_free_path, require_live};

/// A prebuilt erofs guest boots Nix-free: `nix` is stripped from the child's
/// `PATH`, yet `sandy run <topology.json> -- echo hi` boots the vfkit guest and
/// collects success (succeeded / exit 0). The topology JSON is realised and
/// emitted with Nix at setup; the boot touches no Nix.
#[test]
fn prebuilt_erofs_boots_without_nix_on_path() -> anyhow::Result<()> {
    let target = require_live()?;
    if !cfg!(target_os = "macos") {
        bail!("refusing: phase_c is the Nix-free *Mac* hinge (#28) — run it on macOS with vfkit");
    }

    // The one Nix step, at build time: realise the erofs store + kernel/initrd,
    // then evaluate the topology to a JSON file the boot will read.
    build_guest(&target)?;
    let home = tempfile::tempdir().context("temp SANDY_HOME")?;
    let topo_file = tempfile::Builder::new()
        .suffix(".json")
        .tempfile()
        .context("temp topology JSON file")?;
    emit_topology(target.topology_attr, topo_file.path())?;

    // The boot runs with vfkit reachable but `nix` removed from PATH.
    let child_path = nix_free_path();
    assert!(
        !is_on(&child_path, "nix"),
        "adversarial: `nix` must be unreachable on the child PATH before the Nix-free boot — a green is only honest \
         if Nix cannot sneak in"
    );
    assert!(
        is_on(&child_path, target.hypervisor),
        "the hypervisor `{}` must still be reachable on the stripped PATH",
        target.hypervisor
    );

    let topo_path = topo_file.path().to_str().context("topology path is utf-8")?;
    let output = Command::new(env!("CARGO_BIN_EXE_sandy"))
        .env("PATH", &child_path)
        .env("SANDY_HOME", home.path())
        .args(["-o", "json", "run", topo_path, "--timeout", "120", "--", "echo", "hi"])
        .output()
        .context("run sandy Nix-free")?;

    let code = output.status.code().unwrap_or(-1);
    let env: serde_json::Value = serde_json::from_slice(&output.stdout).with_context(|| {
        format!(
            "parse sandy run envelope (exit {code}); stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        )
    })?;

    assert_eq!(code, 0, "process band 0 — erofs guest booted Nix-free; envelope: {env}");
    assert_eq!(env["status"], "succeeded", "envelope: {env}");
    assert_eq!(env["exit_code"], 0);
    Ok(())
}
