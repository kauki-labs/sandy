---
title: "Decisions: process-backend containment"
status: accepted
project: sandy
updated: 2026-10-15
---

# Decisions: process-backend containment

How the non-VM executor (the fabric's process backend, #131 / #103) confines a
job so its whole process tree is reaped, and why an uncontained one must refuse an
untrusted job (#135). The VM backend stays the strong isolation boundary; this is
the process backend's weak-isolation story made honest.

## 1. Unprivileged containment via external tools, behind a `Containment` seam

**Status:** accepted. **Upholds:** INV-7.

**Context.** The process backend reaps the process _group_ (common in-group
forks), but a descendant that escapes the group via `setsid`/`setpgid` leaves the
group and survives a `killpg` as a host orphan. Reaping it needs cgroup-level
containment. sandy runs unprivileged and its crates are `forbid(unsafe_code)`, so
raw `clone`/`unshare`/cgroupfs syscalls are out.

**Decision.** A `Containment` trait (sandy lib) with the same pure/IO split as the
share seam: `wrap(id, limits)` returns the launch-command prefix (pure,
tier-1-testable argv) and `reap(id)` destroys the container (IO); `status()`
reports availability. The host impl `SystemdRunContainment` (sandy-backend) runs
the job under `systemd-run --user --scope -p Delegate=yes` — a delegated cgroup v2
subtree — and reaps the whole tree, escapees included, with `systemctl --user
stop` of the scope. No privilege, no `unsafe`. The specific tool is a detail behind
the seam, so it is swappable; the default `NoContainment` keeps the library
hermetic and the composition root injects the host impl.

**Consequences.** The escapee hole closes when containment is Available; the
backend's `kill()`/teardown gain real termination (was deregister-only). Resource
bounds ride along (`MemoryMax`/`CPUQuota` from the run's mem/cpu). Availability is
a capability answer, never a crash: a headless/CI host with no user `systemd` or
cgroup v2 reports `Unavailable`, detected once by `SystemdRunContainment::detect`.

**Set aside.** Relaxing `forbid(unsafe_code)` for a syscall crate (breaks the house
lint); requiring root + `cgroups-rs` (sandy is unprivileged). Both rejected for the
external-tool path.

## 2. A fail-closed gate that refuses an untrusted job without containment

**Status:** accepted. **Upholds:** INV-7.

**Context.** An uncontained process backend can still run (best-effort group reap),
but it is not a safe boundary for untrusted code. A disabled gate must be
observably distinguishable from a working one, not a silent uncontained run.

**Decision.** `admits_untrusted(kind, status)` is a pure dispatch-time admission
check, parallel to `backend_accepts`: a `Vm` backend always admits (strong
boundary); a `Process` backend admits an untrusted job only when its containment is
`Available`. An `Unavailable`/`Unsupported` process backend is refused. The refusal
is asserted directly (the bad path), not only the happy path.

**Consequences.** The process backend is library-only today (no all-local CLI
profile), so the gate is a latent capability the fabric dispatcher will enforce
live; the backend exposes `containment_status()` for it and for `sandy doctor`.

**Set aside.** Adding a trust flag to `RunSpec` and refusing inside `run()`: a
cross-cutting change to the shared wire type with no live caller yet; the
dispatch-level gate matches the existing `backend_accepts` pattern.

## 3. Ship descendant reaping now; defer path-faithful mounts and hard RO

**Status:** accepted. **Upholds:** INV-1.

**Context.** #135 folds three things: descendant reaping (cgroup), path-faithful
`/run/sandy/...` mounts (mount namespace), and hard read-only (not the cooperative
`chmod a-w` of the local-dir transport). A pending crate restructure will move the
process backend into `impls/local/`, so changes should stay localized.

**Decision.** This record covers the cgroup reaping + gate + real `kill()`. The
mount-namespace path fidelity and hard RO (via `bwrap`, Linux-only) are a stacked
follow-up, reconciled with the staging-base permissions work (#138) and the T4
local-dir share RO so the hard-RO mount story is built once, not duplicated.

**Consequences.** The weak-isolation divergence from guest-shares §11 (a process
job reads `SANDY_*_DIR`, not `/run/sandy/...`, and RO is cooperative) persists until
the follow-up. The gate already refuses untrusted jobs, so no untrusted work runs on
the cooperative RO in the meantime.

**Set aside.** Doing all three in one change: larger and harder to relocate cleanly
into `impls/local/`, with no isolation benefit over shipping the reaping first (the
gate covers the gap either way).

## 4. macOS reports containment unsupported, honestly

**Status:** accepted. **Upholds:** INV-7.

**Context.** macOS has no cgroup; `sandbox-exec` is deprecated and cannot reap a
`setsid` escapee. A process backend there cannot meet the containment bar.

**Decision.** `SystemdRunContainment` reports `Unsupported` on any non-Linux host,
mirroring the macOS-egress-honestly-unenforced posture (egress §). The fail-closed
gate then refuses an untrusted process job on macOS; the real macOS isolation
boundary stays the vfkit VM.

**Consequences.** No false sense of containment on macOS, and no half-working
`sandbox-exec` path to maintain. A macOS operator who needs to run untrusted code
uses the VM backend.

**Set aside.** A best-effort `sandbox-exec` profile: deprecated, cannot reap
escapees, and would blur the honest "unsupported" signal.
