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
- Not yet done: launching the service as `user` (non-root) and the restart policy. Until then the declared
  `user` is validated and carried but not applied.

**Set aside.** Scraping the console for a ready line: it is not a contract.
