//! `acceptance-local`: the no-hypervisor capstone acceptance gate (#131 R4b).
//!
//! Proves the #131 restructure's run plane holds together end to end with no
//! VM: runs the generic, fake-free seam contract suites
//! ([`sandy_api::contract`]) against the REAL all-local impls (`ProcessBackend`,
//! `LocalDirTransport`, `NoEgress`), then drives one real job through the fully
//! composed [`profiles::all_local`] [`Profile`] via [`run_with_profile`] — the
//! same entry point the `sandy` binary's `run` command uses.
//!
//! Ungated (no `live` feature): this binary builds and runs in every default CI
//! run (`cargo run --bin acceptance-local`), unlike its live-gated VM
//! counterpart `acceptance-vm`. It is a standalone release-acceptance gate, not
//! a `#[test]` — exits `0` on success, `1` with a diagnostic on any failure.

use sandy::{Grants, Journal, Status};
use sandy_api::contract::{egress_applier_suite, guest_share_transport_suite, vmbackend_suite};
use sandy_backend::{LocalDirTransport, NoEgress, ProcessBackend};
use sandy_cli::{plan::JobPlan, profiles, supervisor::run_with_profile};

fn main() {
    match run() {
        Ok(()) => println!("acceptance-local: PASS"),
        Err(msg) => {
            eprintln!("acceptance-local: FAIL: {msg}");
            std::process::exit(1);
        }
    }
}

/// Run every check, short-circuiting on the first failure (seam-level first,
/// end-to-end last — a seam contract break is a more specific diagnostic than a
/// failed job).
fn run() -> Result<(), String> {
    vmbackend_suite("contract", ProcessBackend::new).map_err(|e| format!("VmBackend: {e}"))?;
    guest_share_transport_suite(|| LocalDirTransport::new(std::env::temp_dir())).map_err(|e| format!("{e}"))?;
    egress_applier_suite(|| NoEgress).map_err(|e| format!("{e}"))?;
    end_to_end()
}

/// Drive one real job through the composed all-local profile: no hypervisor, no
/// forge credential, the raw-process backend end to end.
fn end_to_end() -> Result<(), String> {
    let home = tempfile::Builder::new()
        .prefix("sandy-acceptance-local-")
        .tempdir()
        .map_err(|e| format!("create temp SANDY_HOME: {e}"))?;
    let journal = Journal::new(home.path());
    journal
        .ensure_dirs()
        .map_err(|e| format!("journal ensure_dirs at {}: {e}", home.path().display()))?;

    let plan = JobPlan {
        template: "acceptance-local".to_string(),
        command: vec!["true".to_string()],
        inputs: vec![],
        outputs: vec![],
        secrets: vec![],
        env: vec![],
        allow: sandy::AllowList::default(),
        cpu: None,
        mem: None,
        timeout_secs: 30,
        grants: Grants {
            secrets: false,
            agent: false,
            shares: false,
        },
        secret_dir: None,
    };

    let report = run_with_profile(&profiles::all_local(), &journal, &plan, None)
        .map_err(|e| format!("run_with_profile: {e}"))?;
    if report.envelope.status != Status::Succeeded {
        return Err(format!("end-to-end job did not succeed: {:?}", report.envelope));
    }
    Ok(())
}
