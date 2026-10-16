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
Crucially, a `systemd-run` scope **reaps** a tree but is **not** an untrusted
boundary: a job inside the scope can reach the user session bus and
`systemd-run --user` a unit OUTSIDE `sandy-<id>.scope` that teardown never reaps
(CWE-269). So the status splits two capabilities — `is_available` (can reap) and
`is_untrusted_boundary` (reap + bus/namespace isolation); `systemd-run` alone sets
the latter `false`. A failed `systemctl stop` is surfaced, not swallowed (exit 5
"unit not loaded" is the already-exited success; any other non-zero is an error the
backend warn-logs before its fallback group-kill).

**Set aside.** Relaxing `forbid(unsafe_code)` for a syscall crate (breaks the house
lint); requiring root + `cgroups-rs` (sandy is unprivileged). Both rejected for the
external-tool path. Treating `systemd-run` reaping as sufficient for untrusted code:
rejected — the user-bus escape above means reaping is necessary, not sufficient.

## 2. A fail-closed gate keyed off the untrusted boundary, not mere reaping

**Status:** accepted. **Upholds:** INV-7.

**Context.** An uncontained process backend can still run (best-effort group reap),
but it is not a safe boundary for untrusted code. Neither is a reaping-only
`systemd-run` scope (the user-bus escape, decision #1). A disabled gate must be
observably distinguishable from a working one, not a silent uncontained run, and the
gate must not CLAIM containment it does not provide.

**Decision.** `admits_untrusted(kind, status)` is a pure dispatch-time admission
check, parallel to `backend_accepts`: a `Vm` backend always admits (strong
boundary); a `Process` backend admits an untrusted job only when its containment is
an untrusted **boundary** (`is_untrusted_boundary`), i.e. reap PLUS bus/namespace
isolation, not merely `is_available` (reaping). Tree-reaping alone, `Unavailable`,
and `Unsupported` are all refused. As defence in depth the wrapper's user-bus env is
stripped from the job (`env -u`), though that alone is not the boundary (the socket
persists at its default path). The refusal is asserted directly (the bad path).

**Consequences.** A process backend refuses untrusted jobs even where cgroup
reaping is Available — the gate tells the truth. The backend is library-only today
(no all-local CLI profile), so the gate is a latent capability the fabric dispatcher
will enforce live; the backend exposes `containment_status()` for it and for `sandy
doctor`. The untrusted-OK path is NOT delivered by the #142 confinement work (which
is write-confinement hardening, decision #5): under its A1 `--ro-bind / /` the job
can still READ the host filesystem and the net namespace is shared, so flipping
`isolates_untrusted` would over-claim. The flip (A2 minimal-rootfs read-confinement
vs VM-only-by-policy) is a separate platform threat-model decision tracked in **#150**.

**Set aside.** Adding a trust flag to `RunSpec` and refusing inside `run()`: a
cross-cutting change to the shared wire type with no live caller yet; the
dispatch-level gate matches the existing `backend_accepts` pattern.

## 3. Ship descendant reaping now; defer path-faithful mounts and hard RO

**Status:** accepted. **Upholds:** INV-1.

**Context.** #135 folds three things: descendant reaping (cgroup), path-faithful
`/run/sandy/...` mounts (mount namespace), and hard read-only (not the cooperative
`chmod a-w` of the local-dir transport). A pending crate restructure will move the
process backend into `impls/local/`, so changes should stay localized.

**Decision.** This record's §1-2 covered the cgroup reaping + gate + real `kill()`.
The mount-namespace work (via `bwrap`, Linux-only) landed in **#142** as decision #5
below: path-faithful `/run/sandy/...` mounts, hard RO, and user-bus hiding. It did
NOT flip `admits_untrusted` — that gate-flip is a separate threat-model decision
(#150), because the confinement leaves the host filesystem readable (decision #5).

**Consequences.** The weak-isolation divergence from guest-shares §11 (a process
job reads `SANDY_*_DIR`, not `/run/sandy/...`, and RO is cooperative) is closed when
the bwrap confinement is active (decision #5), and remains the fallback when it is
not. The gate still refuses untrusted jobs regardless, pending #150.

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

## 5. bwrap confinement: path fidelity, hard RO, bus-hide — hardening, not a gate-flip (#142)

**Status:** accepted. **Upholds:** INV-1, INV-7.

**Context.** The process job read shares via `SANDY_*_DIR` host paths, not the VM's
fixed `/run/sandy/...`; read-only was cooperative (`chmod a-w`, defeatable by a
same-user job); and the user-session bus was reachable (the CWE-269 escape, §1-2).

**Decision.** Compose `bwrap` INSIDE the `systemd-run --user --scope`
(`systemd-run … -- bwrap … -- <job>`), both unprivileged and Nix-provided, so
`forbid(unsafe_code)` holds. bwrap gives a mount namespace that: binds each share at
its faithful `/run/sandy/<tag>` path (read-only for inputs/secrets via `--ro-bind`,
writable outputs via `--bind`); hides the user bus (`--tmpfs /run` + `--unsetenv` of
the bus vars — `/run` must be the WHOLE tmpfs, not just `/run/user`: under
`--ro-bind / /` the host tree is read-only, so bwrap cannot `mkdir` the `/run/sandy`
mountpoint under a merely-shadowed `/run/user`; a writable `/run` fixes the mkdir and
drops `/run/user` for free, found by the ws01 live run — every job died in under a
second until this landed); and exposes the host rootfs read-only (`--ro-bind / /`,
the **A1** choice) so host binaries resolve. The feature is gated on a `confines_filesystem()`
capability, detected (bwrap present AND unprivileged user namespaces permitted) and
SEPARATE from `isolates_untrusted`. When absent, the backend keeps the `SANDY_*_DIR`
host-path + cooperative-RO fallback. The seam carries the shares as a `Mount{host,
guest, ro}` set passed to `wrap`. The capability probe runs the EXACT
`bwrap_segment` argv the real wrapper uses (every mount, `--unsetenv`, and
`UNSHARE_FLAGS`), not a narrower hand-picked subset — a host that accepts a looser
probe but rejects one of the wrapper's own mounts under its LSM/seccomp policy
would otherwise set `confines_filesystem() == true` while every subsequent job's
`bwrap` dies before `exec`, a setup failure indistinguishable from an ordinary
nonzero guest exit (INV-11). Sharing the literal argv builder, not a duplicated
flag list, closes the whole parity class by construction (caught by sandy-b6's
adversarial pass).

**Consequences.** Write-confinement (a job cannot alter a read-only share or the host
fs), path fidelity (same `/run/sandy/...` as the VM), and bus isolation (no
`systemd-run --user` escape from inside the namespace) — real hardening for the
semi-trusted/cooperative case. It does NOT make the backend untrusted-safe: under A1
the job can still READ the whole host filesystem (`~/.ssh`, operator secrets) and the
net namespace is shared, so it could exfiltrate. Therefore `isolates_untrusted` STAYS
`false` and the gate keeps refusing untrusted jobs. RO reconcile, no duplication:
bwrap `--ro-bind` is the guest-side enforcement; the staging-base validation
(#138/#140/#141) is the host-side source-dir trust; the cooperative `set_dir_readonly`
(guest-shares §11) is the no-bwrap fallback. The live leg (K16-K18) is Linux + bwrap

- userns, operator-run.

**Set aside.** Flipping `isolates_untrusted: true` on bwrap presence: rejected — A1's
readable host fs + shared net is not untrusted-safe, and a caller seeing the flag
would route untrusted work here and leak host secrets. Read-confidentiality (A2
minimal rootfs) vs untrusted-is-VM-only is a load-bearing platform decision tracked
in **#150**, not settled here. Unsharing the net namespace: out of scope (egress is a
separate seam); bwrap keeps net shared.
