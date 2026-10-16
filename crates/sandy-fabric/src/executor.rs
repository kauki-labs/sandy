//! The executor seam (spec §3.1): what provides a sandbox, fleet-wide.
//!
//! The fleet-level generalization of [`sandy_api::backend::VmBackend`], added
//! alongside it rather than replacing it: `VmBackend` stays the sync run plane,
//! and an adapter wraps any `VmBackend` (process, qemu, vfkit) into an
//! [`Executor`]. The run data types are `sandy-api`'s, so both seams speak one
//! contract. [`Executor::capabilities`] is the host's self-registration: what kind
//! of sandbox it provides, matched against a job with [`capabilities_satisfy`].

use std::future::Future;

pub use sandy_api::backend::SandboxKind;
use sandy_api::backend::{BoxState, Outcome, RunSpec};
use serde::{Deserialize, Serialize};

/// A host CPU architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Arch {
    /// x86-64.
    X86_64,
    /// 64-bit ARM.
    Aarch64,
}

/// A platform attestation the executor can produce. A stub until the
/// platform-native (mobile) executor lands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attestation;

/// What an executor can run: its self-registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capabilities {
    /// The kind of sandbox provided.
    pub kind: SandboxKind,
    /// The architecture jobs run on.
    pub arch: Arch,
    /// The attestation available, if any.
    pub attestation: Option<Attestation>,
}

/// What a job needs from an executor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Requirements {
    /// The sandbox kind the job must run in.
    pub kind: SandboxKind,
    /// The architecture required; `None` accepts any.
    pub arch: Option<Arch>,
}

/// Whether `provided` can run a job needing `required`.
///
/// Kind is an exact match for now (a VM-only job must never land on the raw
/// process executor); arch matches when required. Shaped to admit subsumption
/// later, such as a VM executor hosting a process job.
pub fn capabilities_satisfy(provided: &Capabilities, required: &Requirements) -> bool {
    provided.kind == required.kind && required.arch.is_none_or(|arch| arch == provided.arch)
}

/// An executor failure: an infra fault, never a job's own non-zero exit (that is
/// carried in [`Outcome::guest_exit`]).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ExecutorError {
    /// The sandbox could not be started.
    #[error("spawn failed: {0}")]
    Spawn(String),
    /// The executor's control channel failed.
    #[error("executor transport: {0}")]
    Transport(String),
}

/// Provides sandboxes and runs jobs in them.
pub trait Executor: Send + Sync {
    /// Run `spec` to completion and return its physical outcome.
    fn run(&self, spec: &RunSpec<'_>) -> impl Future<Output = Result<Outcome, ExecutorError>> + Send;
    /// Tear down the box `box_id`. Killing an unknown box is not an error.
    fn kill(&self, box_id: &str) -> impl Future<Output = Result<(), ExecutorError>> + Send;
    /// Report the boxes currently running.
    fn observe(&self) -> impl Future<Output = Result<Vec<BoxState>, ExecutorError>> + Send;
    /// What this executor can run. Static per instance, so synchronous.
    fn capabilities(&self) -> Capabilities;
}
