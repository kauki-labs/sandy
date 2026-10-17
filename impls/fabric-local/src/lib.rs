//! Trivial local implementations of the sandy agent-fabric seams.
//!
//! The all-local MVP profile (spec `sandy-agent-fabric.md` §2, §6): every seam's
//! trivial, process-local impl, one module per seam, each proven against
//! `sandy_fabric`'s shared contract-test harness. No impl here depends on a VM
//! or another impl's module. [`mesh_link`] is the one exception to "no
//! network": it is the executor-host counterpart to [`link`]'s
//! orchestrator-side relay when the agent is not on the orchestrator's own
//! machine (#159), and is itself transport-agnostic — it forwards over
//! whatever `AsyncRead + AsyncWrite` the caller dials.

mod capauth;

pub mod agent;
pub mod channel;
pub mod escalation_sink;
pub mod executor;
pub mod inmem;
pub mod link;
pub mod mesh_link;
pub mod minter;
pub mod placement;
pub mod roles;
pub mod telemetry;

pub use capauth::LocalCapAuthority;
