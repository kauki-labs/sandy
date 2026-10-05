//! Tier-2 (sandbox) acceptance scenarios.
//!
//! Runs with `cargo test --test integration` — no hypervisor. Block 9 fills
//! this with the FakeBackend-driven flows and the Phase 0 fixtures. The scaffold
//! ships one trivial passing case so the target is wired and separately runnable.

#[test]
fn tier2_harness_is_wired() {
    // Placeholder: replaced by Block 9 with the real sandbox scenarios. Asserts
    // the target compiles and runs; a non-constant check keeps clippy happy.
    let scenarios: &[&str] = &[];
    assert!(scenarios.is_empty());
}
