//! Tier-3 acceptance suite for Phase D — the D done-gate (remote build +
//! locked-down Linux + hardening).
//!
//! Runs with `cargo test --test phase_d`, but every case is gated behind
//! `SANDY_HOST_TESTS=1`: without it the host flows are skipped, so the tier-3
//! scenarios never falsely pass in a sandbox (S9 — a live path is never counted
//! green from a fake). The tier-1 orchestration/policy logic (D-REQ-1 arch check,
//! D-REQ-2 fallback decision, D-REQ-4 GC policy, D-REQ-5 metric movement, D-REQ-3
//! allow-list→nftables translation) lives in the unit suites of `sandy-provider`,
//! `sandy-egress`, and `sandy-core` and runs in the sandbox; it does not count
//! toward this acceptance gate.
//!
//! The later host author (D-accept) replaces the stub below with the enumerated
//! scenarios, each instantiating the physical code — a real remote build, real
//! nftables enforcement on a Linux node, real boots — never a fake for the live
//! paths:
//!
//! Positive (D-REQ-1/2/3/5):
//! - `remote_build_provisions_runs_job` — no local build path and no valid seed, but a reachable remote NixOS builder
//!   of the right arch: `sandy run tpl -- echo hi` evaluates on the controller, builds **on the remote**, copies
//!   artifacts back, boots the sandbox, result `succeeded` / exit 0 (D-REQ-1).
//! - `locked_down_linux_fallback` — Nix-free Linux where install is impossible but a seed/remote is available: `sandy
//!   run` provisions via the fallback → exit 0 (D-REQ-2).
//! - `linux_egress_enforced_allow_deny` — a Linux target with allow-list=[github.com]: the guest reaches github.com and
//!   is **blocked** from an unlisted host (D-REQ-3).
//! - `observability_signal_moves` — a run transitions running → succeeded; the journal and the named metric reflect the
//!   move (D-REQ-5).
//!
//! Adversarial (D-REQ-1/2/3/4/5/6; INV-1/7):
//! - `remote_unreachable_retryable` — remote unreachable mid-build → a retryable infra fault (INV-7), named, never
//!   confused with a guest exit.
//! - `remote_arch_mismatch_refuses` — remote can't build the target arch → `Refuse{arch}`, no build attempt.
//! - `secret_not_in_remote_store` — a secret routed through the remote build is absent from the remote store plane and
//!   remote argv/env (INV-1, D-REQ-6).
//! - `no_fallback_refuses_named` — locked-down Linux, no seed, no remote → `Refuse` naming the blocker, not a silent
//!   hang (D-REQ-2).
//! - `in_guest_flush_cannot_bypass` — guest root flushes its nftables; host-side rules still block (D-REQ-3).
//! - `macos_warns_trusted_only` — on the M2, sandy warns trusted-only and claims **no** egress boundary (D-REQ-3).
//! - `gc_evict_referenced_blocked` — GC while a sandbox holds an image is blocked by the retain marker (D-REQ-4).
//! - `metric_present_but_dead_fails` — a metric that exists but never moves on a state transition fails the "working"
//!   check, not just presence (D-REQ-5).

/// True only when the operator opted into the host tier on the real D matrix.
fn host_tests_enabled() -> bool {
    std::env::var("SANDY_HOST_TESTS").as_deref() == Ok("1")
}

#[test]
fn phase_d_suite_is_host_gated() {
    if !host_tests_enabled() {
        eprintln!(
            "phase_d: skipped (set SANDY_HOST_TESTS=1 on the D matrix — a Linux node + a reachable remote NixOS \
             builder + an M2 — to run the tier-3 scenarios)"
        );
        return;
    }
    // Fail closed: a green `phase_d` must mean the enumerated scenarios ran, never
    // that the host tier was enabled over an empty gate (S9 — no false-green).
    panic!("phase_d: SANDY_HOST_TESTS=1 but no host scenarios authored yet (D-accept, tier-3)");
}
