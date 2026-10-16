//! `acceptance-vm`: the real-hypervisor acceptance gate (#131 R4b).
//!
//! The VM-side counterpart to `acceptance-local`: proves the generic, fake-free
//! seam contract suites ([`sandy_api::contract`]) hold for the real VM impls
//! (`QemuBackend`/`VfkitBackend`, `VirtiofsdTransport`/`VirtioFsTransport`), then
//! drives one real job through the fully composed [`profiles::host_no_cred`]
//! [`Profile`] via [`run_with_profile`] — the same no-forge-credential entry point
//! `acceptance-local` uses, this time over a real hypervisor boot. The egress seam
//! check always uses `NoEgress`, even here: the real `NftablesApplier` manages one
//! fixed, shared host table and is not a safe GENERIC-contract target (see
//! `egress_applier_suite`'s doc) — its enforcement is proven by the dedicated,
//! root-gated `live_egress.rs` (#29), never by this binary. Deep end-to-end VM
//! behaviour (inputs, outputs, secrets, credential refresh, the real `nft`
//! boundary) is already proven by the existing `live_*` test suites; this
//! binary's unique job is the seam-contract level plus one composed end-to-end
//! boot, not re-proving every live KPI.
//!
//! Live-gated: behind the `live` feature (`required-features` in `Cargo.toml`),
//! so this binary is not even built, let alone run, in a default CI build. Run on
//! a live host with a hypervisor on `PATH`:
//! `SANDY_LIVE=1 cargo run -p sandy-cli --features live --bin acceptance-vm`.
//! Refuses (nonzero exit, no guest ever boots) off the live matrix — INV-S9, a
//! live gate is never counted green from a skip.

use sandy::{Grants, Journal, Status};
use sandy_api::contract::{egress_applier_suite, guest_share_transport_suite, vmbackend_suite};
use sandy_backend::{VirtioFsTransport, VirtiofsdTransport};
use sandy_cli::{
    live_target::{build_guest, guest_flake, require_live},
    plan::JobPlan,
    profiles,
    supervisor::run_with_profile,
};

fn main() {
    match run() {
        Ok(()) => println!("acceptance-vm: PASS"),
        Err(msg) => {
            eprintln!("acceptance-vm: FAIL: {msg}");
            std::process::exit(1);
        }
    }
}

fn run() -> Result<(), String> {
    let target = require_live().map_err(|e| e.to_string())?;
    build_guest(&target).map_err(|e| format!("build guest: {e}"))?;
    let template = format!("{}#{}", guest_flake().display(), target.topology_attr);

    vmbackend_suite(&template, host_backend).map_err(|e| format!("VmBackend: {e}"))?;

    // The share-transport contract is PURE (plan() only, no daemon spawn — see
    // sandy_api::contract's doc), so both VM transports run it with no live boot.
    if cfg!(target_os = "macos") {
        guest_share_transport_suite(|| VirtioFsTransport).map_err(|e| format!("{e}"))?;
    } else {
        guest_share_transport_suite(|| VirtiofsdTransport).map_err(|e| format!("{e}"))?;
    }

    // Always NoEgress here, never the real NftablesApplier: its revert()
    // unconditionally deletes one FIXED, shared host table, so it is not a safe
    // generic-contract target (see egress_applier_suite's doc) — running it here
    // would either fail the idempotent-revert check or risk colliding with another
    // run's live boundary. The real applier's enforcement is live_egress.rs's job
    // (#29, root-gated, its own matrix), not this seam-contract check.
    egress_applier_suite(|| sandy_backend::NoEgress).map_err(|e| format!("{e}"))?;

    end_to_end(&template)
}

/// Drive one real job through the composed, no-forge-credential host profile: a
/// real hypervisor boot end to end (the same `run_with_profile` entry point
/// `acceptance-local` exercises for the process backend).
fn end_to_end(template: &str) -> Result<(), String> {
    let home = tempfile::Builder::new()
        .prefix("sandy-acceptance-vm-")
        .tempdir()
        .map_err(|e| format!("create temp SANDY_HOME: {e}"))?;
    let journal = Journal::new(home.path());
    journal
        .ensure_dirs()
        .map_err(|e| format!("journal ensure_dirs at {}: {e}", home.path().display()))?;

    let plan = JobPlan {
        template: template.to_string(),
        command: vec!["true".to_string()],
        inputs: vec![],
        outputs: vec![],
        secrets: vec![],
        env: vec![],
        allow: sandy::AllowList::default(),
        cpu: None,
        mem: None,
        timeout_secs: 120,
        grants: Grants {
            secrets: false,
            agent: false,
            shares: false,
        },
        secret_dir: None,
    };

    let report = run_with_profile(&profiles::host_no_cred(), &journal, &plan, None)
        .map_err(|e| format!("run_with_profile: {e}"))?;
    if report.envelope.status != Status::Succeeded {
        return Err(format!("end-to-end job did not succeed: {:?}", report.envelope));
    }
    Ok(())
}

/// The live host's VM backend, platform-selected for the raw contract check
/// ([`vmbackend_suite`] needs a concrete, constructible type, not the type-erased
/// `Box<dyn VmBackend>` behind [`profiles::host_no_cred`]'s `Profile`). Mirrors
/// `main.rs`'s private `host_backend`.
#[cfg(target_os = "macos")]
fn host_backend() -> sandy_backend::VfkitBackend {
    let vfkit_bin = std::env::var("SANDY_VFKIT_BIN").unwrap_or_else(|_| "vfkit".to_string());
    sandy_backend::VfkitBackend::new(vfkit_bin)
}

#[cfg(not(target_os = "macos"))]
fn host_backend() -> sandy_backend::QemuBackend {
    sandy_backend::QemuBackend::new()
}
