# sandy end-to-end KPIs (required functionality)

What sandy must do, end to end, for a release to be sound: each required
behaviour, the live test that proves it, and the invariant it upholds. This is
the acceptance matrix, the fitness functions, not the design. Decisions live in
[`spec.md`](spec.md); the pipeline and seams in [`overview.md`](overview.md).

Every KPI is a tier-3 **live** test: a real guest boots, behind the `live` cargo
feature (off by default, so CI and `nix flake check` never run them). Integration
coverage (tier-2, CI, over `FakeBackend`) is the per-subsystem KPI in `spec.md`;
this page is the **live floor** a build must clear before it ships.

## Definition of green

A KPI counts as met only when all three hold:

- The named test **passes** on a host that meets its matrix (a hypervisor is
  present, plus Linux+root for egress).
- It is **not skipped**: off its matrix the test **refuses** (fails) rather than
  green-skipping (INV-S9). A pass from `FakeBackend` never counts.
- The asserted envelope `status` / `exit_code` / `outputs` match the required
  behaviour, and no secret value appears in `logs.tail`.

## Required functionality

| #   | Capability                    | Required behaviour                                                                                                                      | Proven by                                                                         | Upholds       | Host matrix                           |
| --- | ----------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------- | ------------- | ------------------------------------- |
| K1  | Boot & run                    | A dispatched job boots the guest, runs the command, collects declared outputs, returns `succeeded` / exit 0.                            | `live_boot.rs::real_boot_collect_succeeds`                                        | INV-6, INV-11 | qemu or vfkit                         |
| K2  | Guest-failure band            | A nonzero guest exit classifies as a task fault (band 1, not retryable), never infra.                                                   | `live_boot.rs::guest_failure_is_a_task_fault`                                     | INV-11        | qemu or vfkit                         |
| K3  | CLI lifecycle                 | `ls`/`status`/`wait`/`kill`/`gc` operate over a real running job and reconcile it through the seam.                                     | `live_boot.rs::cli_lifecycle_over_a_real_job`                                     | INV-3, INV-6  | qemu or vfkit                         |
| K4  | Input readable                | An `--input` is readable in-guest at `/run/sandy/inputs/NAME`.                                                                          | `live_inputs.rs`                                                                  | INV-1         | qemu or vfkit                         |
| K5  | Input write denied            | A write to an input fails `EROFS` (RO enforced at the host boundary).                                                                   | `live_inputs.rs`                                                                  | INV-1         | qemu or vfkit                         |
| K6  | Outputs collected             | Named + catch-all outputs under `/run/sandy/outputs` reach the host `DEST` and are listed in `envelope.outputs`.                        | `live_outputs.rs`                                                                 | INV-11        | qemu or vfkit                         |
| K7  | Secret share RO               | The secret share mounts read-only virtiofs; a guest write is denied.                                                                    | `live_boot.rs::secret_share_mounts_read_only_virtiofs`                            | INV-1         | qemu or vfkit                         |
| K8  | Secret export                 | A staged secret is exported as `$NAME` in the job env, never on argv or the console.                                                    | `live_boot.rs::staged_secret_is_exported_to_the_job_env`                          | INV-1         | qemu or vfkit                         |
| K9  | No secret leak                | No secret value appears in `logs.tail`.                                                                                                 | `live_e2e.rs`                                                                     | INV-1         | qemu or vfkit                         |
| K10 | Credential lifecycle          | A minted token is served via `git credential fill`, refreshed mid-run, and revoked at teardown.                                         | `live_cred.rs`, `live_refresh.rs`                                                 | INV-7         | qemu or vfkit [^1]                    |
| K11 | Mid-run rotation              | A token rotated mid-run reaches the already-running guest.                                                                              | `live_refresh.rs`                                                                 | INV-7         | qemu or vfkit [^1]                    |
| K12 | Real App adapter              | The GitHub App mints and revokes a real installation token.                                                                             | `cred_e2e.rs`, `sandy/tests/cred_github_live.rs`                                  | INV-7         | operator-gated [^2]                   |
| K13 | Egress allow-list             | A boot applies the guest-scoped nftables allow-list and reverts it on every path.                                                       | `live_egress.rs`                                                                  | INV-7, #29    | Linux + root + nft                    |
| K14 | Compose                       | Input + secret + output (and the full cred + secret + input + output run) compose in one job, envelope asserted.                        | `live_e2e.rs`, `live_cred.rs`                                                     | INV-1, INV-11 | qemu or vfkit [^1]                    |
| K15 | Process containment           | A `setsid`-escaped descendant of a process-backend job is reaped by the cgroup scope (not left a host orphan).                          | `sandy-backend/tests/live_containment.rs`                                         | INV-7, #135   | Linux + user systemd + cgroup v2 [^3] |
| K16 | Share path fidelity           | A confined process job reads its input at the VM-faithful fixed path `/run/sandy/inputs/data` (bwrap bind).                             | `sandy-backend/tests/live_containment.rs`                                         | INV-1, #142   | + bwrap + userns [^4]                 |
| K17 | Hard read-only                | A write to a read-only share is denied by the kernel (EROFS/EACCES), not cooperatively; the host source is intact.                      | `sandy-backend/tests/live_containment.rs`                                         | INV-1, #142   | + bwrap + userns [^4]                 |
| K18 | User-bus isolation            | Inside the namespace the session bus is gone (`XDG_RUNTIME_DIR` unset, `systemctl --user` unreachable).                                 | `sandy-backend/tests/live_containment.rs`                                         | INV-7, #142   | + bwrap + userns [^4]                 |
| K19 | Unlimited while attached (VM) | Suspending a VM job's `RunControl` deadline lets it survive well past its original `timeout_secs`; cancelling ends it promptly instead. | `impls/vm` live tests (`boots_a_trivial_job_on_kvm`-adjacent, `#[ignore]`d, #185) | #340          | qemu or vfkit                         |

[^1]:
    The refresh KPIs (K10/K11) additionally need `SANDY_REFRESH_MARGIN_SECS` +
    `SANDY_REFRESH_TICK_SECS` set to force a mid-run refresh; they refuse on the
    defaults (INV-S9).

[^2]:
    K12 drives the real GitHub App, so it needs a registered trust root
    (`SANDY_CRED_LIVE_TRUST_ROOT`) and is run by an operator, not in the standard
    live sweep.

[^3]:
    K15 is the process backend's containment gate (#135), run from `sandy-backend`
    (not `sandy-cli`) and needs a user `systemd` instance + cgroup v2, not a
    hypervisor: `SANDY_LIVE=1 cargo nextest run -p sandy-backend --features live
--test live_containment`. It refuses off its matrix (unavailable containment
    fails, never green-skips, INV-S9).

[^4]:
    K16-K18 are the #142 bwrap confinement rows: same command as K15 plus `bwrap`
    and permitted unprivileged user namespaces (`kernel.unprivileged_userns_clone`,
    no blocking AppArmor profile). They refuse off-matrix — a host without bwrap/userns
    fails loudly rather than green-skipping (INV-S9). They verify confinement
    hardening, NOT untrusted-safety: `isolates_untrusted` stays false (the gate-flip
    is #150).

## Running the KPI suite

The core sweep (K1-K11, K14) on a host with a hypervisor, e.g. Apple silicon:

```sh
nix shell nixpkgs#vfkit -c \
  env SANDY_LIVE=1 cargo nextest run -p sandy-cli --features live
```

Force the refresh KPIs (K10/K11) with a tiny tick:

```sh
nix shell nixpkgs#vfkit -c \
  env SANDY_LIVE=1 SANDY_REFRESH_MARGIN_SECS=3600 SANDY_REFRESH_TICK_SECS=1 \
  cargo nextest run -p sandy-cli --features live
```

K13 (egress) runs on Linux as root with `nft` on `PATH`; K12 (real App) needs
`SANDY_CRED_LIVE_TRUST_ROOT` and is operator-run.

## Not yet a KPI

Deferred capability with no live floor yet, so a reader does not mistake its
absence for a gap:

- **Receipts / provenance** in the envelope are placeholders (not asserted).
- **No-copy / arbitrary-path inputs** (#82): inputs are copied under their name.
- **S3 object source + sink** (#67): no object-store input/output path.
