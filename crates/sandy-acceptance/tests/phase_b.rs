//! Tier-3 (host matrix) acceptance suite for Phase B — the B done-gate.
//!
//! Runs with `cargo test --test phase_b`, but every case is gated behind
//! `SANDY_HOST_TESTS=1`: without it the host flows are skipped, so the tier-3
//! host-matrix scenarios (B-REQ-5, B-REQ-6) never falsely pass in a sandbox
//! (S9 — a live path is never counted green from a fake). The tier-1
//! `classify` / router logic (B-REQ-1..4, 7) lives in `sandy-core::strategy`
//! and `sandy-provider::router` and runs in the sandbox.
//!
//! The later host author replaces the stub below with the enumerated scenarios,
//! each instantiating the real router + the real backend on a real host:
//!
//! Positive (B-REQ-5 / B-REQ-6):
//! - `nixos_hostnix_runs_job` — NixOS host with `/dev/kvm` + Nix at the target arch: `classify` selects `HostNix`, the
//!   job builds + boots **locally** (no seed, no builder), result `succeeded`, exit 0.
//! - `nonnixos_linux_nix_hostnix_runs_job` — Debian/Arch with Nix + `/dev/kvm`: `HostNix` via the declared-runner path;
//!   job `succeeded`.
//! - `nonnixos_linux_install_then_hostnix` — Linux, no Nix, root-once or user-ns available: Nix is installed, strategy
//!   becomes `HostNix`, job `succeeded` (B-REQ-6).
//! - `mac_via_builder_runs_job` — the M2 with the linux-builder: `HostNix` (-via-builder) routes to Phase A's path; job
//!   `succeeded` (regression-guards Phase A under the new router).
//!
//! Adversarial (B-REQ-3 / B-REQ-6):
//! - `axis_from_observation_not_absence` — a trivial boot is actually *attempted* and observed to fail (no `/dev/kvm`,
//!   or a vfkit entitlement failure); the boot axis is `Failed` from the observation, not from an absent error.
//! - `install_impossible_refuses_named` — Nix-free Linux with no root and no user namespaces: `Refuse` naming the
//!   blocker — never a silent seed fallback.

/// True only when the operator opted into the host tier on a real host.
fn host_tests_enabled() -> bool {
    std::env::var("SANDY_HOST_TESTS").as_deref() == Ok("1")
}

#[test]
fn phase_b_suite_is_host_gated() {
    if !host_tests_enabled() {
        eprintln!("phase_b: skipped (set SANDY_HOST_TESTS=1 on a host in the matrix to run the host tier)");
        return;
    }
    // The B-accept host author replaces this with the enumerated scenarios above
    // (NixOS · non-NixOS Linux · install · Mac), each on the real router + backend.
    // Fail closed until then: a green `phase_b` must mean the scenarios ran, never
    // that the host tier was enabled over an empty gate (S9 — no false-green).
    panic!("phase_b: SANDY_HOST_TESTS=1 but no host scenarios authored yet (B-accept, tier-3)");
}
