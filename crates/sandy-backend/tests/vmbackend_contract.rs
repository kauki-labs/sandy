//! The shared `VmBackend` seam contract: one suite every implementation passes
//! (#131 / #103 seam-first). Run here against the two CI-safe impls — the scripted
//! `FakeBackend` (sandy-test-support) and the real `ProcessBackend` (this crate). The VM impls
//! (`QemuBackend`/`VfkitBackend`) satisfy the same contract but need a hypervisor,
//! so they are proven in the live tier, not here.
//!
//! The suite itself lives in `sandy_api::contract::vmbackend_suite` (the
//! `acceptance` feature), shared with `sandy-cli`'s acceptance binaries (#131 R4b)
//! so the real impl and the fake run the identical checks the capstone binaries do.

use sandy::{Grants, Outcome, OutputStatus, ProcessExit, RunControl, RunSpec, Status, VmBackend, classify_outcome};
use sandy_api::contract::vmbackend_suite;
use sandy_backend::ProcessBackend;
use sandy_test_support::FakeBackend;

/// A shared, reusable control handle for tests that don't exercise
/// cancellation/deadline behavior themselves (#340).
fn test_control() -> &'static RunControl {
    static CONTROL: std::sync::OnceLock<RunControl> = std::sync::OnceLock::new();
    CONTROL.get_or_init(|| RunControl::with_timeout_secs(30))
}

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
        control: test_control(),
    }
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
    vmbackend_suite("contract", || FakeBackend::new().with_outcome(success.clone())).map_err(|e| anyhow::anyhow!("{e}"))
}

#[test]
fn process_backend_satisfies_the_contract() -> anyhow::Result<()> {
    vmbackend_suite("contract", ProcessBackend::new).map_err(|e| anyhow::anyhow!("{e}"))
}

/// INV-11 guard: a non-zero process exit classifies as a task failure (band 1,
/// not retryable), never an infra fault. The process backend must not collapse a
/// clean non-zero exit into a transport/infra fault.
#[test]
fn process_nonzero_exit_classifies_as_task_failure_not_infra() -> anyhow::Result<()> {
    let grants = Grants {
        secrets: false,
        agent: false,
        shares: false,
    };
    let command = ["sh".to_string(), "-c".to_string(), "exit 3".to_string()];
    let outcome = ProcessBackend::new().run(&spec(&command, &grants))?;

    assert_eq!(outcome.guest_exit, Some(3), "the real exit is carried");
    let classification = classify_outcome(&outcome, OutputStatus::Complete);
    assert_eq!(classification.status, Status::Failed, "a non-zero exit failed");
    assert_eq!(
        classification.process_exit,
        ProcessExit::TaskFailure,
        "band 1 (task), not an infra fault"
    );
    assert!(!classification.retryable, "a task failure is not platform-retryable");
    Ok(())
}
