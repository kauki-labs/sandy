//! Tier-3 (M2 hinge) acceptance suite for Phase C — the C done-gate.
//!
//! Runs with `cargo test --test phase_c`, but every case is gated behind
//! `SANDY_HOST_TESTS=1`: without it the host flows are skipped, so the tier-3
//! hinge scenarios never falsely pass in a sandbox (S9 — a live path is never
//! counted green from a fake). The tier-1/2 seed-verification logic (C-REQ-2)
//! lives in `sandy-seed` (`tests/verify.rs`) and runs in the sandbox; it does not
//! count toward this acceptance gate.
//!
//! The later M2 host author (C-accept) replaces the stub below with the enumerated
//! scenarios, each instantiating the physical code — the real builder-VM boot, the
//! real erofs handoff, and a real sandbox — never a fake for the hinge:
//!
//! Positive (C-REQ-3/4/5/6/8):
//! - `hinge_sandbox_peer_boots_erofs_runs_job` — Nix-free M2, only vfkit + sandy + a verified seed: `sandy run tpl --
//!   echo hi` boots the builder from the seed, builds the sandbox erofs, the sandbox peer-boots **read-only**, runs the
//!   job, result `succeeded` / exit 0 (C-REQ-3/4/5/8).
//! - `in_guest_nix_shell_on_overlay` — a booted sandbox (RO-erofs + writable overlay + network) runs `nix-shell -p
//!   hello --run hello`: succeeds, new store paths land in the overlay, the erofs base is provably unchanged (C-REQ-6).
//! - `two_peers_read_only` — two sandboxes from one erofs both boot read-only, no corruption (C-REQ-5).
//!
//! Adversarial (C-REQ-4/5/6; INV-P1..P7):
//! - `host_nix_leak_absent` — no `nix` process or daemon ran on the host during the `BuilderVM` run (INV-P1).
//! - `torn_staging_refuses` — a boot raced against an incomplete erofs write refuses on the completeness/hash check;
//!   never boots a partial image (INV-P7).
//! - `rw_multi_attach_rejected` — a read-write attach of one image to two VMs is rejected (INV-P3).
//! - `gc_while_referenced_blocked` — GC while a sandbox holds an image is blocked by the retain marker.
//! - `case_collision_boots_intact` — a closure with case-colliding paths boots intact; the host never interprets the FS
//!   (INV-P2).
//! - `compressed_kernel_rejected_at_stage` — a gz kernel is rejected at stage time, not at boot (INV-P6).
//! - `overlay_writes_dont_leak_to_base` — an in-guest build writing to `/nix/store` lands in the overlay; the erofs
//!   base is unchanged (INV-P3).

/// True only when the operator opted into the host tier on a real M2.
fn host_tests_enabled() -> bool {
    std::env::var("SANDY_HOST_TESTS").as_deref() == Ok("1")
}

#[test]
fn phase_c_suite_is_host_gated() {
    if !host_tests_enabled() {
        eprintln!("phase_c: skipped (set SANDY_HOST_TESTS=1 on a Nix-free M2 to run the tier-3 hinge)");
        return;
    }
    // Fail closed: a green `phase_c` must mean the enumerated scenarios ran, never
    // that the host tier was enabled over an empty gate (S9 — no false-green).
    panic!("phase_c: SANDY_HOST_TESTS=1 but no host scenarios authored yet (C-accept, tier-3)");
}
