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

The M2 control-plane rows below (KM1, KA1) are the one named exception: they
are real `SANDY_LIVE=1` process-level tests (a real `sandyd` binary, real TCP/UDS
connections), but run the job itself through `handle_dispatch` against
`FakeContainment`, not a real container or VM. They count toward the
control-plane and attach-data-plane floor only, never toward containment or
VM-boot KPIs, which K1-K19 and KA3-KA4 already cover.

## Required functionality

| #   | Capability                    | Required behaviour                                                                                                                                                                                 | Proven by                                                                                                                                                                                                                                                                                   | Upholds          | Host matrix                           |
| --- | ----------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------- | ------------------------------------- |
| K1  | Boot & run                    | A dispatched job boots the guest, runs the command, collects declared outputs, returns `succeeded` / exit 0.                                                                                       | `live_boot.rs::real_boot_collect_succeeds`                                                                                                                                                                                                                                                  | INV-6, INV-11    | qemu or vfkit                         |
| K2  | Guest-failure band            | A nonzero guest exit classifies as a task fault (band 1, not retryable), never infra.                                                                                                              | `live_boot.rs::guest_failure_is_a_task_fault`                                                                                                                                                                                                                                               | INV-11           | qemu or vfkit                         |
| K3  | CLI lifecycle                 | `ls`/`status`/`wait`/`kill`/`gc` operate over a real running job and reconcile it through the seam.                                                                                                | `live_boot.rs::cli_lifecycle_over_a_real_job`                                                                                                                                                                                                                                               | INV-3, INV-6     | qemu or vfkit                         |
| K4  | Input readable                | An `--input` is readable in-guest at `/run/sandy/inputs/NAME`.                                                                                                                                     | `live_inputs.rs`                                                                                                                                                                                                                                                                            | INV-1            | qemu or vfkit                         |
| K5  | Input write denied            | A write to an input fails `EROFS` (RO enforced at the host boundary).                                                                                                                              | `live_inputs.rs`                                                                                                                                                                                                                                                                            | INV-1            | qemu or vfkit                         |
| K6  | Outputs collected             | Named + catch-all outputs under `/run/sandy/outputs` reach the host `DEST` and are listed in `envelope.outputs`.                                                                                   | `live_outputs.rs`                                                                                                                                                                                                                                                                           | INV-11           | qemu or vfkit                         |
| K7  | Secret share RO               | The secret share mounts read-only virtiofs; a guest write is denied.                                                                                                                               | `live_boot.rs::secret_share_mounts_read_only_virtiofs`                                                                                                                                                                                                                                      | INV-1            | qemu or vfkit                         |
| K8  | Secret export                 | A staged secret is exported as `$NAME` in the job env, never on argv or the console.                                                                                                               | `live_boot.rs::staged_secret_is_exported_to_the_job_env`                                                                                                                                                                                                                                    | INV-1            | qemu or vfkit                         |
| K9  | No secret leak                | No secret value appears in `logs.tail`.                                                                                                                                                            | `live_e2e.rs`                                                                                                                                                                                                                                                                               | INV-1            | qemu or vfkit                         |
| K10 | Credential lifecycle          | A minted token is served via `git credential fill`, refreshed mid-run, and revoked at teardown.                                                                                                    | `live_cred.rs`, `live_refresh.rs`                                                                                                                                                                                                                                                           | INV-7            | qemu or vfkit [^1]                    |
| K11 | Mid-run rotation              | A token rotated mid-run reaches the already-running guest.                                                                                                                                         | `live_refresh.rs`                                                                                                                                                                                                                                                                           | INV-7            | qemu or vfkit [^1]                    |
| K12 | Real App adapter              | The GitHub App mints and revokes a real installation token.                                                                                                                                        | `cred_e2e.rs`, `sandy/tests/cred_github_live.rs`                                                                                                                                                                                                                                            | INV-7            | operator-gated [^2]                   |
| K13 | Egress allow-list             | A boot applies the guest-scoped nftables allow-list on the forward chain, and a fixed DHCP-only input chain that drops every other host-destined packet from the guest; both revert on every path. | `live_egress.rs`                                                                                                                                                                                                                                                                            | INV-7, #29, #376 | Linux + root + nft                    |
| K14 | Compose                       | Input + secret + output (and the full cred + secret + input + output run) compose in one job, envelope asserted.                                                                                   | `live_e2e.rs`, `live_cred.rs`                                                                                                                                                                                                                                                               | INV-1, INV-11    | qemu or vfkit [^1]                    |
| K15 | Process containment           | A `setsid`-escaped descendant of a process-backend job is reaped by the cgroup scope (not left a host orphan).                                                                                     | `sandy-backend/tests/live_containment.rs`                                                                                                                                                                                                                                                   | INV-7, #135      | Linux + user systemd + cgroup v2 [^3] |
| K16 | Share path fidelity           | A confined process job reads its input at the VM-faithful fixed path `/run/sandy/inputs/data` (bwrap bind).                                                                                        | `sandy-backend/tests/live_containment.rs`                                                                                                                                                                                                                                                   | INV-1, #142      | + bwrap + userns [^4]                 |
| K17 | Hard read-only                | A write to a read-only share is denied by the kernel (EROFS/EACCES), not cooperatively; the host source is intact.                                                                                 | `sandy-backend/tests/live_containment.rs`                                                                                                                                                                                                                                                   | INV-1, #142      | + bwrap + userns [^4]                 |
| K18 | User-bus isolation            | Inside the namespace the session bus is gone (`XDG_RUNTIME_DIR` unset, `systemctl --user` unreachable).                                                                                            | `sandy-backend/tests/live_containment.rs`                                                                                                                                                                                                                                                   | INV-7, #142      | + bwrap + userns [^4]                 |
| K19 | Unlimited while attached (VM) | Suspending a VM job's `RunControl` deadline lets it survive well past its original `timeout_secs`; cancelling ends it promptly instead.                                                            | `impls/vm/src/qemu.rs::suspending_the_control_survives_past_the_jobs_timeout_on_kvm`, `::cancelling_the_control_ends_a_running_job_on_kvm`, `impls/vm/src/vfkit.rs::suspending_the_control_survives_past_the_jobs_timeout_on_vfkit`, `::cancelling_the_control_ends_a_running_job_on_vfkit` | #340             | qemu or vfkit [^5]                    |
| K20 | Envelope receipt              | A real boot's terminal envelope carries a populated `receipt`: `who`/`what`/`where`/`egress`/`timing` host-observed, exit code + output sizes guest-reported.                                      | not yet written [^6]                                                                                                                                                                                                                                                                        | INV-1, #361      | qemu or vfkit                         |
| K21 | qemu confinement              | The qemu process of a VM run has a seccomp filter installed (`Seccomp: 2` in `/proc/<pid>/status`) while the guest runs.                                                                           | `live_qemu_sandbox.rs`                                                                                                                                                                                                                                                                      | #392, NV-02      | qemu/KVM x86_64 (Linux)               |
| K22 | virtiofsd seccomp             | A `virtiofsd` serving a share runs under a seccomp filter (`Seccomp: 2` in `/proc/<pid>/status`) while the guest runs.                                                                             | `live_qemu_sandbox.rs::a_virtiofsd_runs_under_a_seccomp_filter`                                                                                                                                                                                                                             | #523, NV-02      | qemu/KVM x86_64 (Linux)               |

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
    hardening, NOT untrusted-safety: `isolates_untrusted` stays false, because
    untrusted jobs are VM-only (`process-containment.md` §6, #150).

[^5]:
    `impls/vm`'s tier-3 tests predate this crate adopting the `live` cargo
    feature + `SANDY_LIVE=1` off-matrix-refusal contract every other row in
    this table uses (INV-S9) — they're plain `#[ignore]`d, and silently skip
    rather than refuse off-matrix. Run only the tests for the hypervisor
    actually present: on Linux/KVM,
    `cargo nextest run -p sandy-impls-vm --run-ignored ignored-only -E 'test(_on_kvm)'`;
    on macOS/vfkit,
    `cargo nextest run -p sandy-impls-vm --run-ignored ignored-only -E 'test(_on_vfkit)'`
    — running both selectors on a host with only one hypervisor also attempts
    the other's tests, which fail for lack of that hypervisor rather than for
    a real regression. That gap predates K19 (it's shared by the crate's other
    tier-3 tests, e.g. `boots_a_trivial_job_on_kvm`) and retrofitting the full
    contract onto the whole crate is a separate, crate-wide change — not done
    here.

[^6]:
    K20 is not yet green: the receipt is integration-tested over `FakeBackend`
    (`cli_jobs.rs`, `result.rs`) but no live test asserts it on a real boot.
    Not counted green until that test exists and passes on its matrix
    (INV-S9).

## M2 control plane and interactive attach (live gates)

The pipeline above (K1-K19) is `sandy run`'s direct-execution path. `sandy
daemon submit`/`attach` dispatches through `sandyd` + (optionally) a remote
`sandy-host-executor` instead (`docs/overview.md`'s "Control plane" section,
`docs/decisions/sandyd.md`). These rows use their own `KM*`/`KA*` prefixes so
they never collide with K1-K19 or the `KP*` egress-proxy block above.
`SANDY_LIVE=1` gates every row here too (INV-S9); KM1/KM2/KA1 need no
hypervisor (`FakeContainment`, see the Definition-of-green note above); KM4,
KA3, and KA4 boot a real guest.

### Acceptance (M2 stage 1)

| #   | Capability                  | Required behaviour                                                                                                                                                                                                                  | Proven by                                                                                             | Upholds    | Host matrix                                               |
| --- | --------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- | ---------- | --------------------------------------------------------- |
| KM1 | Cross-machine dispatch      | `sandy daemon submit` places through real orchestrator placement to a real `Dispatch`, run via `handle_dispatch` against `FakeContainment` (control/data plane only — the real `sandy-host-executor` binary cannot start on macOS). | `live_m2_cross_machine.rs::cross_machine_sandboxes_exchange_a_peer_message_through_the_hub`           | #263, #269 | `SANDY_LIVE=1`, no hypervisor                             |
| KM2 | Register-auth refusal       | An unlisted mesh identity's `Register` gets `RegisterRefused`, no dispatch.                                                                                                                                                         | `live_m2_cross_machine.rs::register_from_an_unlisted_mesh_identity_gets_no_ack_and_no_dispatch`       | #263       | `SANDY_LIVE=1`, no hypervisor                             |
| KM4 | Flake-templated VM dispatch | `sandy daemon submit --flake <ref>` places a `flake/v1` manifest on a remote host declaring `SandboxKind::Vm`, which boots a real qemu VM and succeeds.                                                                             | `live_remote_host_flake_dispatch.rs::a_flake_templated_vm_job_dispatches_and_succeeds_on_remote_host` | #332       | operator-run [^remote-host], not yet green [^vm-redeploy] |

### Interactive attach (#327, #340)

| #   | Capability              | Required behaviour                                                                                                                                                                                                                                                                                                           | Proven by                                                                                                                                                                | Upholds    | Host matrix                                                   |
| --- | ----------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------- | ------------------------------------------------------------- |
| KA1 | Attach round-trips      | Posted bytes echo back through the job's real stdout; a cross-session attach gets observer rights only; detach-then-reattach on the same control session continues interacting with the same live process. Control/data plane against `FakeContainment`, same caveat as KM1.                                                 | `live_attach.rs::real_attach_round_trips_proves_session_fork_and_survives_detach_reattach`, `::the_real_cli_binary_attaches_delivers_output_and_exits_on_job_completion` | #327       | `SANDY_LIVE=1`, no hypervisor                                 |
| KA2 | Durable reattach token  | A separate `sandy daemon attach` process, started after `submit`, gets post rights via the persisted attach token — against a REAL registered host-executor over the mesh (also the acceptance for "a real remote host registers and accepts dispatch," folded in here since no separate test exercises registration alone). | `live_remote_host_attach.rs::a_real_remote_host_executor_grants_post_rights_to_a_separate_attach_process`                                                                | #263, #327 | operator-run: `SANDY_M2_REMOTE_HOST` + `SANDY_M2_REMOTE_PEER` |
| KA3 | VM-backed remote attach | `sandy daemon submit --flake` places a VM job on the remote host; a separate attach process types into the booted guest and reads real output, detaches, and a second separate process reattaches with the same durable token.                                                                                               | `live_remote_host_flake_attach.rs::a_separate_attach_process_drives_a_real_vm_booted_on_remote_host`                                                                     | #327, #332 | operator-run [^remote-host], not yet green [^vm-redeploy]     |
| KA4 | Sandbox-agent TTY       | A VM job runs behind the guest's sandbox agent over vsock, with TTY both ways, no link or cap left in the guest, and a forged cap never starts the job.                                                                                                                                                                      | `live_agent.rs::a_vm_job_runs_behind_the_guest_agent_with_tty_both_ways`, `::a_forged_cap_never_starts_the_vm_job`                                                       | #238       | qemu (`/dev/vhost-vsock`) or vfkit                            |

### Flake-templated direct execution (#325, #326)

Not attach or M2 dispatch — `sandy run --flake` boots locally, like K1 — but
also not yet in the "Required functionality" table above, so it gets its own
`KF*` prefix rather than a `K20` this page does not own (#366, open, already
claims K19/K20 if it merges; see "Not yet a KPI" below).

| #   | Capability                     | Required behaviour                                                                                                                                                    | Proven by                                                                              | Upholds | Host matrix   |
| --- | ------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------- | ------- | ------------- |
| KF1 | `--flake --from-devshell` boot | A devshell-based flake target boots with its `shellHook` run before the ready marker; a host-conditional hook diverges silently in-guest (pinned, not asserted away). | `live_flake_devshell.rs::hello_devshell_boots_hello_reachable_hook_runs_before_marker` | #326    | qemu or vfkit |

Not asserted by a live KPI yet: the archived-transcript delivery path
(`SANDY_HISTORY_LINES`, `attach.rs::write_archive`) and the
unlimited-while-attached deadline suspension are covered at integration tier
only (`sandyd`/`sandy-cli` unit and contract tests); no live row exercises
either end to end. The VM-backend half of "unlimited while attached" has no
KPI at all yet — see the "Not yet a KPI" note below.

[^remote-host]:
    KM4 and KA3 need a remote host already configured and reachable: both
    `SANDY_M2_REMOTE_HOST` (this orchestrator's own mesh address) and
    `SANDY_M2_REMOTE_PEER` (the remote host's mesh address), plus a standing
    `sandy-host-executor` systemd service on that host already dialing this
    orchestrator. Neither test starts the remote executor itself.

[^vm-redeploy]:
    KM4 and KA3 are blocked on the remote host's deployed `sandy-host-executor`
    being rebuilt with #332's VM-capability detection and redeployed; today it
    still registers `Process` only, so Submit is refused fail-closed ("no
    registered host declares `SandboxKind::Vm` capability") rather than
    placing anything. Not counted green until that redeploy happens and the
    test passes on its matrix (INV-S9).

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

The sweep above also runs KM1/KM2/KA1 (no extra env needed beyond
`SANDY_LIVE=1`) and KA4 if a hypervisor is present. KM3/KM4/KA2/KA3 live
in the three `live_remote_host_*` test binaries, in the same `-p sandy-cli
--features live` sweep, but **fail** (`require_remote_executor` bails, not
skips, per INV-S9) unless `SANDY_M2_REMOTE_HOST` and `SANDY_M2_REMOTE_PEER`
are also set. Filter them out of a non-operator run:

```sh
cargo nextest run -p sandy-cli --features live -E 'not binary(~remote_host)'
```

or run them deliberately with those two variables set.

## Planned: egress proxy

The parity gate for the NIC-less guest with a vsock host proxy
([`egress-proxy.md`](../decisions/egress-proxy.md) decision 5, #360). **KP1q to KP7q are green. On vfkit KP1v to KP7v are green**, and none counts toward
the floor above until its test exists and passes on its matrix. Each capability needs both its qemu and its vfkit row to pass
before the nftables path (K13) is deleted. All tests live in
`sandy-cli/tests/live_egress_proxy.rs`.

| #    | Capability            | Required behaviour                                                                                                                                                                                                      | Proven by                                                                                                                                                                                               | Upholds | Host matrix | Status                                                                                                                                                                                                                                                     |
| ---- | --------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------- | ----------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| KP1q | Proxy allow           | An allow-listed `host:port` is reachable through the guest relay (a CONNECT through the relay at `127.0.0.1:3128` gets `200`; the image has no `curl`).                                                                 | `live_egress_proxy.rs::allowed_target_is_reachable_through_the_proxy`                                                                                                                                   | INV-7   | qemu        | green (the Linux KVM host, 2026-10-28)                                                                                                                                                                                                                     |
| KP1v | Proxy allow           | An allow-listed `host:port` is reachable through the guest relay (a CONNECT through the relay at `127.0.0.1:3128` gets `200`; the image has no `curl`).                                                                 | `live_egress_proxy.rs::allowed_target_is_reachable_through_the_proxy`                                                                                                                                   | INV-7   | vfkit       | green (Apple silicon, vfkit 0.6.3, linux-builder, 2026-10-30)                                                                                                                                                                                              |
| KP2q | Proxy deny            | A target not on the allow-list gets `403` from the proxy and no connection leaves the host.                                                                                                                             | `live_egress_proxy.rs::denied_target_gets_403`, `live_egress_proxy.rs::a_denied_target_is_never_dialed_by_the_proxy`                                                                                    | INV-7   | qemu        | green (Linux x86_64 KVM, 2026-10-30): 403 in the guest, and the host samples no proxy connection to the denied target                                                                                                                                      |
| KP2v | Proxy deny            | A target not on the allow-list gets `403` from the proxy and no connection leaves the host.                                                                                                                             | `live_egress_proxy.rs::denied_target_gets_403`, `live_egress_proxy.rs::a_denied_target_is_never_dialed_by_the_proxy`                                                                                    | INV-7   | vfkit       | green (Apple silicon, vfkit 0.6.3, linux-builder, 2026-10-30): 403 in the guest, and the host samples no proxy connection to the denied target                                                                                                             |
| KP3q | Proxy empty list      | An empty allow-list refuses every CONNECT; the guest has no other route out.                                                                                                                                            | `live_egress_proxy.rs::empty_allow_list_blocks_all_egress`                                                                                                                                              | INV-7   | qemu        | green (the Linux KVM host, 2026-10-28)                                                                                                                                                                                                                     |
| KP3v | Proxy empty list      | An empty allow-list refuses every CONNECT; the guest has no other route out.                                                                                                                                            | `live_egress_proxy.rs::empty_allow_list_blocks_all_egress`                                                                                                                                              | INV-7   | vfkit       | green (Apple silicon, vfkit 0.6.3, linux-builder, 2026-10-30)                                                                                                                                                                                              |
| KP4q | Proxy bypass          | As root in the guest: a direct connect by IP fails (no NIC), and a raw vsock stream to the proxy port meets the same allow-list. A stream from another CID is refused (vhost-vsock stamps the source CID).              | `live_egress_proxy.rs::in_guest_bypass_attempts_fail`, `live_egress_proxy.rs::a_raw_vsock_stream_meets_the_same_allow_list`, `live_egress_proxy.rs::a_vsock_peer_with_another_cid_is_closed_unanswered` | INV-7   | qemu        | green (Linux x86_64 KVM, 2026-10-31): direct dial, route tampering and relay deny pass; a raw vsock stream from inside the guest meets the same allow-list; a vsock peer with another CID is closed unanswered (checked over vsock loopback, no second VM) |
| KP4v | Proxy bypass          | As root in the guest: a direct connect by IP fails (no NIC), and a raw vsock stream to the proxy port meets the same allow-list. There is no shared CID space to restrict: only the ports the backend configures exist. | `live_egress_proxy.rs::in_guest_bypass_attempts_fail`, `live_egress_proxy.rs::a_raw_vsock_stream_meets_the_same_allow_list`                                                                             | INV-7   | vfkit       | green (Apple silicon, vfkit 0.6.3, linux-builder, 2026-10-31): direct dial, route tampering and relay deny pass; a raw vsock stream from inside the guest meets the same allow-list                                                                        |
| KP5q | Proxy address filter  | An allow-listed name that resolves to loopback (`localhost:<port>`) gets `403`.                                                                                                                                         | `live_egress_proxy.rs::allowed_name_resolving_to_loopback_is_refused`                                                                                                                                   | INV-7   | qemu        | green (the Linux KVM host, 2026-10-28)                                                                                                                                                                                                                     |
| KP5v | Proxy address filter  | An allow-listed name that resolves to loopback (`localhost:<port>`) gets `403`.                                                                                                                                         | `live_egress_proxy.rs::allowed_name_resolving_to_loopback_is_refused`                                                                                                                                   | INV-7   | vfkit       | green (Apple silicon, vfkit 0.6.3, linux-builder, 2026-10-30)                                                                                                                                                                                              |
| KP6q | Proxy death           | Killing the proxy mid-run classifies the run as band 3, whatever the guest's exit.                                                                                                                                      | `live_egress_proxy.rs::proxy_death_mid_run_is_band_3`                                                                                                                                                   | INV-7   | qemu        | green (the Linux KVM host, 2026-10-28)                                                                                                                                                                                                                     |
| KP6v | Proxy death           | Killing the proxy mid-run classifies the run as band 3, whatever the guest's exit.                                                                                                                                      | `live_egress_proxy.rs::proxy_death_mid_run_is_band_3`                                                                                                                                                   | INV-7   | vfkit       | green (Apple silicon, vfkit 0.6.3, linux-builder, 2026-10-30)                                                                                                                                                                                              |
| KP7q | Proxy startup failure | A proxy that cannot start refuses the VM run as band 3, with no boot.                                                                                                                                                   | `live_egress_proxy.rs::proxy_startup_failure_is_band_3`                                                                                                                                                 | INV-7   | qemu        | green (the Linux KVM host, 2026-10-28)                                                                                                                                                                                                                     |
| KP7v | Proxy startup failure | A proxy that cannot start refuses the VM run as band 3, with no boot.                                                                                                                                                   | `live_egress_proxy.rs::proxy_startup_failure_is_band_3`                                                                                                                                                 | INV-7   | vfkit       | green (Apple silicon, vfkit 0.6.3, linux-builder, 2026-10-30)                                                                                                                                                                                              |

## Planned: sandy-mcp

The agent-facing MCP frontend over the broker API ([`sandyd.md`](../decisions/sandyd.md) decision 25, #585).
None of these counts toward the floor above until its test exists and passes on its matrix. Tier-2 rows run
over a fake broker. Tier-3 rows need a Linux/KVM host and a real boot.

| #     | Capability               | Required behaviour                                                                                                                                       | Proven by                                                                                                                                  | Matrix                                       |
| ----- | ------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------- |
| KMCP1 | Idempotent spawn         | One `request_id` and one payload give one environment; `sandy ls` shows one VM. The tool forwards `request_id` unchanged; the API tier owns idempotency. | `crates/sandy-mcp/tests/environments.rs::spawn_forwards_the_request_id_unchanged` (tool side only); API-tier and live rows not yet written | tool side green; API tier and tier-3 pending |
| KMCP2 | Ephemeral teardown       | An ephemeral environment leaves no VM and no live credential after its TTL or its task.                                                                  | not yet written (needs #587 `lifetime`)                                                                                                    | tier-3 pending                               |
| KMCP3 | Canary absent            | A canary placed in a profile secret is absent from every result, log and `ps`; it is present at the guest path only.                                     | not yet written                                                                                                                            | tier-3 pending                               |
| KMCP4 | Delegate round trip      | A stand-in primary links the guest T3 server, runs `delegate_task`, and gets the result.                                                                 | not yet written (needs open point 1)                                                                                                       | tier-3 pending                               |
| KMCP5 | Parent ends after delete | After `delete_environment`, the parent task ends `failed` within 60 s and does not retry.                                                                | not yet written (blocked on open point 1)                                                                                                  | blocked                                      |
| KMCP6 | One request per tool     | Each of the 13 tools makes exactly one API request, follows no redirect and retries nothing.                                                             | `crates/sandy-mcp/tests/hardening.rs::every_tool_makes_exactly_one_api_request`, `::a_redirect_is_not_followed`                            | tier-2 green                                 |
| KMCP7 | Layering                 | `sandy-mcp` never reaches `sandy-control-proto`.                                                                                                         | `crates/sandy-mcp/tests/layering.rs::sandy_mcp_does_not_depend_on_sandy_control_proto`                                                     | tier-2 green                                 |

## Not yet a KPI

Deferred capability with no live floor yet, so a reader does not mistake its
absence for a gap:

- **`Provenance.template_store_path`** in the envelope is a placeholder (not
  asserted). The audit receipt (#361) is integration-tested (`cli_jobs.rs`,
  `result.rs`) but has no live-proven KPI yet (K20 above is not green).
- **Signing receipts relayed from remote executors** (#374, decision 6 of
  `result-classification.md`): design-only, no implementation yet (#472,
  blocked by #413). No KPI row until #472 lands and is asserted on a real
  boot.
- **No-copy / arbitrary-path inputs** (#82): inputs are copied under their name.
- **S3 object source + sink** (#67): no object-store input/output path.
