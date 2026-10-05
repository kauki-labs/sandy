//! Tier-3 (host) acceptance suite — the Phase A done-gate.
//!
//! Runs with `cargo test --test phase_a`, but every case is gated behind
//! `SANDY_HOST_TESTS=1`: without it the host flows are skipped (never a false
//! green in a sandbox, S9). Block 9 authors the enumerated REQ-1..12 scenarios
//! here against the real `LauncherBackend` + hypervisor on the M2.

/// True only when the operator opted into the host tier on a real hypervisor.
#[inline]
fn host_tests_enabled() -> bool {
    std::env::var("SANDY_HOST_TESTS").as_deref() == Ok("1")
}

#[test]
fn phase_a_suite_is_host_gated() {
    if !host_tests_enabled() {
        eprintln!("phase_a: skipped (set SANDY_HOST_TESTS=1 on the M2 to run the host tier)");
        return;
    }
    // Block 9 replaces this with the enumerated host scenarios.
    eprintln!("phase_a: host tier enabled — no scenarios authored yet (Block 9)");
}
