//! Trivial local implementations of the sandy agent-fabric seams.
//!
//! The all-local MVP profile (spec `sandy-agent-fabric.md` §2, §6): every seam's
//! trivial, process-local impl, one module per seam, each proven against
//! `sandy_fabric`'s shared contract-test harness. No impl here depends on a VM,
//! a network, or another impl's module.

mod capauth;

pub mod agent;
pub mod channel;
pub mod executor;
pub mod inmem;
pub mod link;
pub mod minter;
pub mod placement;
pub mod roles;
pub mod telemetry;

pub use capauth::LocalCapAuthority;
