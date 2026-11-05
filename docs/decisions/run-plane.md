---
title: "Decisions: run plane (VmBackend)"
status: accepted
project: sandy
updated: 2026-10-14
---

# Decisions: run plane (`VmBackend`)

Launching the guest natively and driving it to a physical `Outcome`. Subsystem
spec: [`../architecture/spec.md#1-run-plane-vmbackend`](../architecture/spec.md#1-run-plane-vmbackend).

## 1. One seam, two native backends

**Status:** accepted.

**Context.** sandy must run guests on Linux and macOS without taking a heavy VM
orchestration library as a dependency.

**Decision.** A single `VmBackend` trait with two native impls: `QemuBackend`
(Linux/KVM, serial on `ttyS0`) and `VfkitBackend`
(macOS/Virtualization.framework, console on `hvc0`). The topology→argv mapping is
a **pure function**, so `qemu_args` / `vfkit_args` are unit-testable without
spawning a process.

**Consequences.** The whole argv assembly is covered in `cargo nextest` with no
hypervisor; a real boot is a separate tier-3 concern. Adding a backend is a new
trait impl, not a change to the library surface.

**Set aside.** An external VM-management crate: rejected to keep the launch path
small, auditable, and pure.

## 2. Topology from Nix, not hard-coded

**Status:** accepted.

**Context.** The VM shape (kernel, initrd, store, cpu/mem, shares, hypervisor)
varies per guest and host and must stay in sync with what Nix actually builds.

**Decision.** The shape is a typed `Topology` read from a guest flake attr via
`nix eval --json`; Nix still builds the artifacts. sandy reads the evaluated
shape rather than carrying its own copy.

**Consequences.** The guest flake is the single source of the VM shape; a drift
between what sandy launches and what Nix builds is not possible.

## 3. Console protocol with framed exit

**Status:** accepted. **Upholds:** INV-11 (no defaulted exit).

**Context.** The guest's exit code and output must be recovered over a serial
console that also carries boot noise.

**Decision.** The driver waits for the `SANDY-READY` marker, injects a
base64-wrapped command bracketed by per-run `<<SANDY-<uuid>-START/END>>`
sentinels, captures the region between them, and parses a trailing `exit=<n>`.

**Consequences.** A garbled or missing `exit=` is a **protocol error**, never a
defaulted `0`, so a transport fault can never masquerade as a clean run (feeds
the band-3 classification).

## 4. macOS needs a linux-builder

**Status:** accepted.

**Context.** vfkit requires a guest whose arch matches the host, and an
aarch64-darwin host cannot build a linux guest locally.

**Decision.** An aarch64-darwin host builds its aarch64-linux guest on a remote
`aarch64-linux` builder (nix-darwin's `nix.linux-builder`). `sandy doctor`
refuses on macOS when nix or that builder is missing and names the fix.

**Consequences.** The macOS failure mode is a clear, actionable doctor message at
setup time rather than an opaque boot failure later.

## 5. A declared service is ready when its probe passes

**Status:** accepted (#589, epic #597).

**Context.** An on-demand environment for T3 Code runs a long-lived service (`t3 serve`), not a job that
ends. Readiness taken from console text breaks on any output change and cannot tell "listening" from
"printed a banner".

**Decision.** The `flake/v1` manifest has an optional `service`: a non-root `user`, a health probe (TCP
connect to `127.0.0.1:<port>` in the guest, or a command that exits 0), and a restart policy. `sandy-host-executor`
puts the spec in the guest agent's `SANDY_SERVICE` env entry (`impls/vm` forwards it beside the history
bound). The agent runs the probe every `interval_secs` and sends one `Ready` or `ProbeFailed { output }` link
frame, before the job's `Exit`. The relay posts the first verdict as an `Output` envelope
(`SERVICE_READY` / `SERVICE_PROBE_FAILED`); `ServiceReadiness::from_envelope` reads it. Probe output is cut
to 4096 bytes in the agent and again in the relay.

**Consequences.**

- A mangled `SANDY_SERVICE` refuses the run. It never runs as a plain job with no probe.
- The decode refuses a root user, a missing command and a probe that cannot pass (`validate_service`). Only
  the host-executor decodes `flake/v1`, so refusing at Submit is a follow-up.
- An older relay or forwarder rejects the new frames and loses the exit report (INV-11). Deploy sandyd and
  `sandy-host-executor` before a guest image whose agent sends them.
- When the agent is root (in a guest) the account must be a plain account: `check_account` reads
  `/etc/passwd` and `/etc/group` and refuses root by uid 0, by primary gid 0, or by membership of a gid-0
  group or `wheel` (another account such as `toor` can share uid 0, and `wheel` is passwordless sudo on many
  images). The job then runs as `setpriv --no-new-privs -- runuser -u <user> -- env -u SANDY_SERVICE -u TMUX`:
  no setuid escalation, uid and groups dropped, HOME set by `runuser`, and the spec (it holds the probe's argv)
  and root's tmux socket kept out of the service. A refused account fails the run before the job starts. A
  command probe runs the same way, as the service user, so a service that can influence the probe's program
  cannot make the root agent execute it. A TCP probe needs no account. When the agent is not root (the process
  backend on a host) there is no privilege to drop and the job runs as the agent's own user, never with more
  than declared. The guest image must define the account and ship `setpriv` and `runuser` (#608 does).
- Probe output is untrusted guest text. Each stream is kept to 4096 bytes in the agent (stderr first), the
  failure is cut to 4096 bytes in the agent and again in the relay, and the relay replaces control characters
  other than newline and tab.
- A restart policy other than `never` is refused at dispatch and by the agent: the agent reports the first
  exit and does not restart, so accepting the field would be a silent no-op.
- Secrets: the service inherits the secret-channel exports of the guest's root login shell, as a plain job does;
  that is how provider keys reach the harnesses (#592). The agent removes only `SANDY_SERVICE` and `TMUX`.
  An env allowlist would drop the keys the harnesses need and the manifest's own `env` does not cross into the
  guest (#527), so scoping which secret names reach the service is #592's job (the identity profile), and
  `/run/sandy/secrets` stays 0700 root so the service reads env, never the files.
- Not covered: the service's own peer channels. The agent's peer socket is a root-owned 0700 directory, so a
  service running as another user cannot use `SANDY_PEER_SOCKET`.
- Not proven by a test in CI: that the guest's `setpriv`, `runuser` and PAM setup really drop to the account.
  The unit tests prove the argv and the account checks; the live boot of the T3 guest proves the rest.

**Set aside.** An external VM-management crate: rejected to keep the launch path
small, auditable, and pure.

## 2. Topology from Nix, not hard-coded

**Status:** accepted.

**Context.** The VM shape (kernel, initrd, store, cpu/mem, shares, hypervisor)
varies per guest and host and must stay in sync with what Nix actually builds.

**Decision.** The shape is a typed `Topology` read from a guest flake attr via
`nix eval --json`; Nix still builds the artifacts. sandy reads the evaluated
shape rather than carrying its own copy.

**Consequences.** The guest flake is the single source of the VM shape; a drift
between what sandy launches and what Nix builds is not possible.

## 3. Console protocol with framed exit

**Status:** accepted. **Upholds:** INV-11 (no defaulted exit).

**Context.** The guest's exit code and output must be recovered over a serial
console that also carries boot noise.

**Decision.** The driver waits for the `SANDY-READY` marker, injects a
base64-wrapped command bracketed by per-run `<<SANDY-<uuid>-START/END>>`
sentinels, captures the region between them, and parses a trailing `exit=<n>`.

**Consequences.** A garbled or missing `exit=` is a **protocol error**, never a
defaulted `0`, so a transport fault can never masquerade as a clean run (feeds
the band-3 classification).

## 4. macOS needs a linux-builder

**Status:** accepted.

**Context.** vfkit requires a guest whose arch matches the host, and an
aarch64-darwin host cannot build a linux guest locally.

**Decision.** An aarch64-darwin host builds its aarch64-linux guest on a remote
`aarch64-linux` builder (nix-darwin's `nix.linux-builder`). `sandy doctor`
refuses on macOS when nix or that builder is missing and names the fix.

**Consequences.** The macOS failure mode is a clear, actionable doctor message at
setup time rather than an opaque boot failure later.

## 5. A declared service is ready when its probe passes

**Status:** accepted (#589, epic #597).

**Context.** An on-demand environment for T3 Code runs a long-lived service (`t3 serve`), not a job that
ends. Readiness taken from console text breaks on any output change and cannot tell "listening" from
"printed a banner".

**Decision.** The `flake/v1` manifest has an optional `service`: a non-root `user`, a health probe (TCP
connect to `127.0.0.1:<port>` in the guest, or a command that exits 0), and a restart policy. `sandy-host-executor`
puts the spec in the guest agent's `SANDY_SERVICE` env entry (`impls/vm` forwards it beside the history
bound). The agent runs the probe every `interval_secs` and sends one `Ready` or `ProbeFailed { output }` link
frame, before the job's `Exit`. The relay posts the first verdict as an `Output` envelope
(`SERVICE_READY` / `SERVICE_PROBE_FAILED`); `ServiceReadiness::from_envelope` reads it. Probe output is cut
to 4096 bytes in the agent and again in the relay.

**Consequences.**

- A mangled `SANDY_SERVICE` refuses the run. It never runs as a plain job with no probe.
- The decode refuses a root user, a missing command and a probe that cannot pass (`validate_service`). Only
  the host-executor decodes `flake/v1`, so refusing at Submit is a follow-up.
- An older relay or forwarder rejects the new frames and loses the exit report (INV-11). Deploy sandyd and
  `sandy-host-executor` before a guest image whose agent sends them.
- When the agent is root (in a guest) the service runs as `user` through `runuser`, after the account is
  resolved in `/etc/passwd` to a uid other than 0 (another account such as `toor` can share uid 0). A refused
  account fails the run before the job starts. When the agent is not root (the process backend on a host)
  there is no privilege to drop, so the job runs as the agent's own user, never with more privilege than
  declared. The guest image must define the account (#608 does not yet).
- Not yet done: the restart policy. The agent reports the first exit; a crashed service is not restarted.

**Set aside.** Scraping the console for a ready line: it is not a contract.

## 6. A killed host process leaves a record, and the next start sweeps it (#666)

**Status:** accepted for qemu on Linux (epic #597). Not yet called by a shipped binary: `sandyd` and `sandy run` have to
call `QemuBackend::sweep_orphans()` once at start-up, and until they do only the live gate and the
`sweep_orphans` example run it. The vfkit backend follows.

**Context.** A VM backend keeps its running boxes in memory. A `SIGKILL` of the host process (the `sandyd` daemon or
a `sandy run`) leaves qemu, its virtiofsd daemons and its egress proxy running with ppid 1, still holding the guest
CID and a staging directory that contains a secret share. A restart starts with an empty registry, so `boxes()` and
the driver's orphan check cannot see them.

**Decision.** `run` writes `<run dir>/box.json` with the launching process (the owner) before any secret is staged, and
`launch` rewrites it with each process the box starts, each with its pid, start time and executable, atomically as
processes are added, plus the boot id and pid namespace. `QemuBackend::sweep_orphans()`
reads the records under the staging base at start-up. For each box whose owner is gone, it kills every recorded
process that is still alive, then removes the run directory and its `-inputs` and `-outputs` siblings.

**Consequences.**

- A process is identified by its pid and its start time. The start time survives an `exec`, and a later process that
  reuses the pid always started later, so it never matches. The executable is recorded for a human reader and never
  compared: the live gate showed that nix's qemu execs the real binary after `spawn` returns, so a rule that
  required the recorded executable to match left qemu running.
- A box is swept only when its owner is gone (no such pid, or a different start time). The staging base is shared
  by the daemon and by `sandy run`, so a daemon-lifetime lock was set aside: a live owner protects its box, and
  a second daemon or a running CLI is never touched. Two sweeps that race are harmless: each kill re-checks the start
  time and the wipe ignores a missing directory.
- The processes are plain children of the host, in the host's process group, so the sweep kills each pid and never a
  group. A group kill would hit the host or an unrelated group.
- Nothing without a record is touched. Pid 0 and 1 are never killed, a record that is not a plain file, is over
  64 KiB or has an unknown field leaves its directory alone, and a symlink is never followed.
- When the table cannot tell whether a process exists (a `/proc` read failed for a reason other than "no such process"),
  the box is left for the next sweep. An unreadable owner never reads as a dead one: that would delete a running VM's
  secret share. A kill that cannot be sent (no permission) leaves the box too, and is not counted as killed.
- A record from an earlier boot names no running process (a reboot ends them all), so its directories are removed and
  nothing is killed: a pid and start time from that boot could match an unrelated process of this one. A record from
  another pid namespace is left alone, since its pids mean nothing here.
- The owner is recorded before staging, so a kill at any point after the secret share exists leaves a record. A kill in
  the few microseconds between a virtiofsd spawn and its entry in the record leaves that one daemon unrecorded.
- A failed record write is logged and does not fail the run. That box goes unrecorded and would still be orphaned by
  a kill.
- The sweep reads `/proc` on Linux. Off Linux it is a no-op until the vfkit backend writes records with a macOS
  start-time source.

**Set aside.** Scanning command lines for qemu: it can hit a process we did not start. A process group kill (above).
A daemon-lifetime lock on the staging base (above). Comparing the executable (above).
