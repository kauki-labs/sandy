//! `sandy-host-client`: the M2 remote executor (epic #205, #269's design).
//!
//! A per-host component that detects its own environment and declares its
//! capabilities to the orchestrator (kubelet-style registration, spec D2),
//! then receives dispatches against that declaration and runs them locally.
//! Two independent concerns, kept as separate modules of one binary rather
//! than two crates (infra-f3's ruling, #275): [`capability`] detects and
//! declares; [`dispatch`] holds the manifest decode and the isolation-class
//! gate. The full `Dispatch` → `ProcessBackend::with_agent` composition is
//! #283, a follow-on once `RunSpec`'s own fields (timeout, grants,
//! inputs/outputs) have a real design against what `Dispatch` actually
//! carries.

pub mod capability;
pub mod dispatch;
