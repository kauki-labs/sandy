//! `sandy-host-client`: the M2 remote executor (epic #205, #269's design).
//!
//! A per-host component that detects its own environment and declares its
//! capabilities to the orchestrator (kubelet-style registration, spec D2),
//! then receives dispatches against that declaration and runs them locally.
//! Two independent concerns, kept as separate modules of one binary rather
//! than two crates (infra-f3's ruling, #275): [`capability`] detects and
//! declares; [`dispatch`] decodes a `Dispatch`, re-checks the isolation
//! class, and runs it via `ProcessBackend::with_agent`, forwarding the
//! agent's link back over the mesh.

pub mod capability;
pub mod dispatch;
