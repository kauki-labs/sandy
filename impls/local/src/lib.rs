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
pub use process::{AgentLaunch, OnLink, ProcessBackend};
pub use share::LocalDirTransport;
