//! `sandy-host-client`: the M2 remote executor (epic #205, #269's design).
//!
//! A per-host component that detects its own environment and declares its
//! capabilities to the orchestrator (kubelet-style registration, spec D2),
//! then receives dispatches against that declaration and runs them locally.
//! Four modules of one binary rather than separate crates (infra-f3's ruling,
//! #275): [`capability`] detects and declares; [`dispatch`] decodes a
//! `Dispatch`, re-checks the isolation class, and runs it via
//! `ProcessBackend::with_agent`, forwarding the agent's link back over the
//! mesh; [`client_config`] resolves where to find the orchestrator and which
//! agent binary to launch; [`run`] is the main loop that ties the others
//! together — register once, then handle dispatches sequentially (decision
//! 13) until the connection closes or shutdown is requested.

pub mod capability;
pub mod client_config;
pub mod dispatch;
pub mod run;
