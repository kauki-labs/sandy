//! `sandy-test-support`: in-memory test doubles for sandy's seam traits.
//!
//! Each fake implements a [`sandy_api`] seam trait with scripted, inspectable
//! behavior, so tier-2 tests across the workspace drive the pipeline without a
//! hypervisor, a forge, or the host. The crate depends ONLY on `sandy-api` (the
//! contract), never the core (`sandy`) or an impl crate, so it stays a thin,
//! api-only test dependency any crate can take without pulling heavy deps.

mod backend;
mod containment;
mod cred;
mod egress;
mod trust_root;

pub use backend::FakeBackend;
pub use containment::FakeContainment;
pub use cred::FakeProvider;
pub use egress::FakeApplier;
pub use trust_root::FakeProvisioner;
