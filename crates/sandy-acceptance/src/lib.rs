//! `sandy-acceptance` — the Phase A acceptance harness.
//!
//! Scaffold stub. Block 9 (`A-accept`) authors the enumerated `phase_a` host
//! suite in `tests/phase_a.rs` and the sandbox fixtures exercised by
//! `tests/integration.rs`. The two tiers are separate test binaries so they run
//! independently: tier-2 (`--test integration`) always, tier-3 (`--test
//! phase_a`) only under `SANDY_HOST_TESTS=1` on the real M2 (S9 fidelity).
