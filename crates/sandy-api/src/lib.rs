//! `sandy-api`: the pinned contract between sandy's core and its seam impls.
//!
//! This crate defines only **traits and types** — the seam traits, their data
//! transfer types, and their error enums. It holds no concrete behavior: no host
//! impls, no fakes, no orchestration or classification logic. Those live in the
//! core (`sandy`) or in the per-seam implementation crates, which depend on this
//! crate. Keeping the contract here lets an impl crate compile against the seam
//! without pulling the core's heavy implementation dependencies.
//!
//! R0 floor: the run-plane contract ([`backend`]) and the LOCKED result envelope
//! and classification types ([`result`]). Remaining seams move in later nodes.
//!
//! With the `acceptance` feature, [`contract`] exposes one `*_suite` per
//! run-plane seam (`VmBackend`, `GuestShareTransport`, `EgressApplier`) that any
//! impl, trivial or real, runs itself against — the fake-free capstone harness
//! (#131 R4b). This is a different contract crate/feature from `sandy-fabric`'s
//! `contract-tests`: that one covers the agent-fabric seams over `sandy-proto`
//! (a separate epic, #103/#104); this one covers the current sandbox run plane.

pub mod backend;
pub mod console;
pub mod containment;
#[cfg(any(test, feature = "acceptance"))]
pub mod contract;
pub mod cred;
pub mod discovery;
pub mod egress;
pub mod provision;
pub mod result;
pub mod seed;
pub mod share;
pub mod strategy;
pub mod trust_root;
