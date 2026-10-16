//! The composition root for the agent-fabric all-local MVP profile (spec §2,
//! §6; issue #115).
//!
//! This crate's production code is currently empty. Increment 1 built and
//! proved the composition gate (`validate_profile`, running every seam's own
//! contract suite against the all-local profile's current real/fake mix) —
//! that gate now lives in `tests/acceptance.rs`, not here: running full
//! contract suites is test-time work (`executor_suite` actually dispatches a
//! real process), not something a real `sandyd` would do at its own startup.
//! `sandy_fabric::contract::fakes` has no business in this crate's production
//! dependency graph when there's no real production consumer yet.
//!
//! The real `AllLocalProfile` — the composition root a production binary
//! would actually wire up and run jobs through — lands in a later increment,
//! once a concrete consumer exists. Nothing here has to change for that.
