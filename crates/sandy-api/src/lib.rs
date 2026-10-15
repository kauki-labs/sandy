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

pub mod backend;
pub mod console;
pub mod containment;
pub mod cred;
pub mod discovery;
pub mod egress;
pub mod provision;
pub mod result;
pub mod seed;
pub mod share;
pub mod strategy;
pub mod trust_root;
