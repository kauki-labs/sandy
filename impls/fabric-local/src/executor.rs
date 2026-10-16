//! The Executor seam's generic adapter over any [`VmBackend`] (spec §3.1, #108).
//!
//! `VmBackend` stays the host's native, synchronous run plane (process, qemu,
//! vfkit); [`VmBackendExecutor`] wraps any impl of it into the fabric's async
//! [`Executor`] seam. This is purely additive: `VmBackend` is not renamed, and
//! none of its existing callers or tests move.
//!
//! `capabilities()` is derived, never caller-settable: `kind` self-reports via
//! [`VmBackend::kind`] (already on the trait); `arch` is the compiled host
//! target ([`std::env::consts::ARCH`]), since every backend here (process,
//! qemu, vfkit) boots a guest matching the host's architecture. A
//! caller-settable capability would let a backend claim something it cannot
//! honor — exactly the bug the contract suite's adversarial case exists to
//! catch — so there is no production knob to override it; a false claim can
//! only come from a bug in this adapter, not a caller mistake. If a future
//! backend emulates a foreign guest arch (qemu cross-arch), `capabilities().arch`
//! must report the GUEST arch, not the host's — this adapter does not need to
//! change for that until it happens.
//!
//! `run`/`kill`/`observe` bridge the synchronous `VmBackend` into the fabric's
//! async trait via [`tokio::task::block_in_place`], so the backend's call runs
//! to completion without starving the runtime. `block_in_place` panics outside
//! a multi-thread Tokio runtime, so whatever composes a [`VmBackendExecutor`]
//! (the fabric composition root, #115) must run on one.

use sandy_api::backend::{BackendError, BoxState, Outcome, RunSpec, VmBackend};
use sandy_fabric::executor::{Arch, Capabilities, Executor, ExecutorError};

/// Adapts a synchronous [`VmBackend`] into the fabric's async [`Executor`] seam.
pub struct VmBackendExecutor<B> {
    backend: B,
}

impl<B: VmBackend> VmBackendExecutor<B> {
    /// Wrap `backend`. `capabilities()` derives from it; nothing here is
    /// caller-supplied (see the module doc).
    pub fn new(backend: B) -> Self {
        Self { backend }
    }
}

impl<B: VmBackend + Send + Sync> Executor for VmBackendExecutor<B> {
    async fn run(&self, spec: &RunSpec<'_>) -> Result<Outcome, ExecutorError> {
        tokio::task::block_in_place(|| self.backend.run(spec)).map_err(map_err)
    }

    async fn kill(&self, box_id: &str) -> Result<(), ExecutorError> {
        tokio::task::block_in_place(|| self.backend.kill(box_id)).map_err(map_err)
    }

    async fn observe(&self) -> Result<Vec<BoxState>, ExecutorError> {
        tokio::task::block_in_place(|| self.backend.boxes()).map_err(map_err)
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            kind: self.backend.kind(),
            arch: host_arch(),
            attestation: None,
        }
    }
}

/// Map an infra-level [`BackendError`] onto the coarser [`ExecutorError`] space.
/// `Protocol` (a malformed console exchange) folds into `Transport`: both are
/// infra faults the Executor contract treats identically, never a task failure.
fn map_err(err: BackendError) -> ExecutorError {
    match err {
        BackendError::Spawn(msg) => ExecutorError::Spawn(msg),
        BackendError::Transport(msg) | BackendError::Protocol(msg) => ExecutorError::Transport(msg),
    }
}

/// The compiled host architecture, as the fabric's [`Arch`].
///
/// # Panics
///
/// Panics on a host triple this isn't `x86_64` or `aarch64` — the project's
/// flake only ever builds for `x86_64-linux` or `aarch64-darwin` (see
/// `AGENTS.md`), so any other value means this binary was built outside that
/// matrix, not a reachable runtime condition.
fn host_arch() -> Arch {
    match std::env::consts::ARCH {
        "x86_64" => Arch::X86_64,
        "aarch64" => Arch::Aarch64,
        other => panic!("unsupported host architecture for a fabric executor: {other}"),
    }
}

#[cfg(test)]
mod tests {
    //! Mirrors `vmbackend_contract.rs`'s shape (#108): the same real
    //! `ProcessBackend`, the same adversarial cases, run through the Executor
    //! seam instead of `VmBackend` directly. `VmBackend`'s own contract tests
    //! (in `sandy-backend`) are untouched.

    use sandy_api::backend::{Grants, SandboxKind};
    use sandy_backend::ProcessBackend;
    use sandy_fabric::contract::executor_suite;

    use super::*;

    fn expected_caps() -> Capabilities {
        Capabilities {
            kind: SandboxKind::Process,
            arch: host_arch(),
            attestation: None,
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn vm_backend_executor_satisfies_the_executor_contract() -> anyhow::Result<()> {
        executor_suite(expected_caps(), "contract", || {
            VmBackendExecutor::new(ProcessBackend::new())
        })
        .await
        .map_err(Into::into)
    }

    /// INV mirror of `process_nonzero_exit_classifies_as_task_failure_not_infra`
    /// (`vmbackend_contract.rs`): a non-zero exit through the adapter is still a
    /// carried exit code, never collapsed into an infra fault.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_nonzero_exit_through_the_adapter_is_not_an_infra_fault() -> anyhow::Result<()> {
        let executor = VmBackendExecutor::new(ProcessBackend::new());
        let grants = Grants {
            secrets: false,
            agent: false,
            shares: false,
        };
        let command = ["sh".to_owned(), "-c".to_owned(), "exit 3".to_owned()];
        let spec = RunSpec {
            template: "contract",
            command: &command,
            inputs: &[],
            outputs: &[],
            secrets: &[],
            env: &[],
            cpu: None,
            mem: None,
            timeout_secs: 30,
            grants: &grants,
            outcome_file: None,
            secret_dir: None,
        };
        let outcome = executor.run(&spec).await?;
        assert_eq!(outcome.guest_exit, Some(3), "the real exit is carried");
        assert!(outcome.transport_error.is_none(), "not collapsed into an infra fault");
        Ok(())
    }

    /// Test-local only: a wrapper that delegates to the real adapter but lies
    /// about its capability, to prove the suite catches a false claim made
    /// through the production `run`/`kill`/`observe` plumbing, not just
    /// `sandy-fabric`'s `FakeExecutor`. There is no equivalent production API —
    /// `VmBackendExecutor::capabilities()` stays non-forgeable (see module doc).
    struct LyingExecutor<B> {
        inner: VmBackendExecutor<B>,
        claims: Capabilities,
    }

    impl<B: VmBackend + Send + Sync> Executor for LyingExecutor<B> {
        async fn run(&self, spec: &RunSpec<'_>) -> Result<Outcome, ExecutorError> {
            self.inner.run(spec).await
        }

        async fn kill(&self, box_id: &str) -> Result<(), ExecutorError> {
            self.inner.kill(box_id).await
        }

        async fn observe(&self) -> Result<Vec<BoxState>, ExecutorError> {
            self.inner.observe().await
        }

        fn capabilities(&self) -> Capabilities {
            self.claims
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_false_capability_claim_through_the_real_adapter_fails_the_suite() {
        let lying_caps = Capabilities {
            kind: SandboxKind::Vm,
            ..expected_caps()
        };
        let result = executor_suite(expected_caps(), "contract", || LyingExecutor {
            inner: VmBackendExecutor::new(ProcessBackend::new()),
            claims: lying_caps,
        })
        .await;
        let violation = result.expect_err("a false capability claim must fail the suite");
        assert!(
            violation.rule.contains("capabilities()"),
            "violated `{}`, expected a capabilities() rule",
            violation.rule
        );
    }
}
