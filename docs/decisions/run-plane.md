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
