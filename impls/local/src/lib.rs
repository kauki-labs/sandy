//! Local (no-VM) sandy seam implementations.
//!
//! The raw-process [`VmBackend`](sandy::VmBackend) ([`ProcessBackend`]), the
//! local-dir [`GuestShareTransport`](sandy_api::share::GuestShareTransport)
//! ([`LocalDirTransport`]), the host [`Containment`](sandy::Containment)
//! ([`SystemdRunContainment`]), and the no-op [`EgressApplier`](sandy::EgressApplier)
//! ([`NoEgress`]) for platforms with no per-VM egress boundary. Each is a concrete
//! impl of a seam whose contract lives in `sandy-api`; the runtime helpers they
//! use (staging, collection) live in the `sandy` core.

mod containment;
mod egress;
mod process;
mod share;

pub use containment::SystemdRunContainment;
pub use egress::NoEgress;
pub use process::ProcessBackend;
/// The agent-launch contract, now in `sandy_api::agent` (#238); re-exported
/// here so existing imports keep compiling.
pub use sandy_api::agent::{AgentLaunch, AgentReport, OnLink};
pub use share::LocalDirTransport;
