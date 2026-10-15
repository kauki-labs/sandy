//! The shared `VmBackend` seam contract: one suite every implementation passes
//! (#131 / #103 seam-first). Run here against the two CI-safe impls — the scripted
//! `FakeBackend` (sandy) and the real `ProcessBackend` (this crate). The VM impls
//! (`QemuBackend`/`VfkitBackend`) satisfy the same contract but need a hypervisor,
//! so they are proven in the live tier, not here.

use sandy::{FakeBackend, Grants, Outcome, RunSpec, VmBackend};
use sandy_backend::ProcessBackend;

/// Build a `RunSpec` that runs `command` with no inputs/outputs/secrets.
fn spec<'a>(command: &'a [String], grants: &'a Grants) -> RunSpec<'a> {
    RunSpec {
        template: "contract",
        command,
        inputs: &[],
        outputs: &[],
        secrets: &[],
        env: &[],
        cpu: None,
        mem: None,
        timeout_secs: 30,
        grants,
        outcome_file: None,
        secret_dir: None,
    }
}

/// The behaviours every `VmBackend` must uphold, regardless of impl. `make`
/// yields a backend configured so a trivially-successful job returns exit 0 (the
/// scripted outcome for the fake, running `true` for a real backend).
fn vmbackend_contract<B: VmBackend>(label: &str, make: impl Fn() -> B) -> anyhow::Result<()> {
    // A fresh backend reports no running boxes.
    let backend = make();
    assert!(backend.boxes()?.is_empty(), "{label}: a fresh backend has no boxes");

    // kill() of an unknown box is defined (no panic) and leaves the registry empty.
    backend.kill("does-not-exist")?;
    assert!(
        backend.boxes()?.is_empty(),
        "{label}: killing an unknown box leaves no boxes"
    );

    // A trivially-successful run returns a well-formed Outcome, and leaves no
    // lingering box (the run is synchronous — the box lives only for the call).
    let backend = make();
    let grants = Grants {
        secrets: false,
        agent: false,
        shares: false,
    };
    let command = ["true".to_string()];
    let outcome = backend.run(&spec(&command, &grants))?;
    assert!(outcome.booted, "{label}: a successful run booted");
    assert_eq!(outcome.guest_exit, Some(0), "{label}: a successful run exits 0");
    assert!(
        outcome.transport_error.is_none(),
        "{label}: success is not a transport fault"
    );
    assert!(!outcome.timed_out, "{label}: a completed run did not time out");
    assert!(
        backend.boxes()?.is_empty(),
        "{label}: no box lingers after a synchronous run"
    );
    Ok(())
}

#[test]
fn fake_backend_satisfies_the_contract() -> anyhow::Result<()> {
    let success = Outcome {
        booted: true,
        guest_exit: Some(0),
        transport_error: None,
        timed_out: false,
        console: String::new(),
    };
    vmbackend_contract("fake", || FakeBackend::new().with_outcome(success.clone()))
}

#[test]
fn process_backend_satisfies_the_contract() -> anyhow::Result<()> {
    vmbackend_contract("process", ProcessBackend::new)
}
