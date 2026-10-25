---
title: "Decisions: egress"
status: accepted
project: sandy
updated: 2026-10-25
---

# Decisions: egress

Bracketing the boot with an allow-list so the guest's network is filtered, never
the host's. Subsystem spec:
[`../architecture/spec.md#5-egress`](../architecture/spec.md#5-egress).

## 1. Guest-scoped, fail-closed

**Status:** accepted. **Upholds:** INV-7, #29.

**Context.** A network boundary applied host-wide could lock the controller off
the network; a boundary that silently fails to apply would boot the guest
unprotected.

**Decision.** On Linux with a bound tap, a guest-scoped nftables **forward**
ruleset filters only the guest. If the boundary cannot be applied, the run fails
closed (band 3) rather than booting unprotected. The ruleset is **always reverted**
on both the ok and the error path.

**Consequences.** The boundary can never lock the host off the network, never
leaves rules up after a boot failure, and never boots unprotected. Proven live by
K13 (`live_egress.rs`, Linux + root + `nft`).

**Set aside.** A host-wide ruleset: rejected, it risks locking out the controller.

## 2. macOS is a no-op

**Status:** accepted.

**Context.** The guest-scoped nftables mechanism is Linux-only; macOS has no
equivalent in this path. The guest also has no network device at all:
`vfkit_args` (`impls/vm/src/vfkit.rs`) emits virtio-blk, virtio-serial,
virtio-fs and virtio-vsock devices, and no `virtio-net`. A macOS guest's egress
is therefore denied by construction, not merely unfiltered: a correction to
this decision's earlier text, which said macOS had "unfiltered network
(vmnet)". A Linux guest with no bound tap has no NIC either, for the same
reason `plan_egress_scoped` gives it `NoBoundary`.

**Decision.** On macOS `plan_egress_scoped` yields `NoBoundary`; the run
proceeds without enforcement, **documented, not silent**. Because there is no
NIC, a non-empty `--allow` list has no effect to grant: the envelope's
`warnings` says so (#358), `egress unavailable: the guest has no network
device, so --allow entries have no effect (see #360)`, for both macOS and a
tap-less Linux guest. An empty allow-list never warns — deny-all already
holds with no NIC to grant anything onto. The decision keys on structure
(`EgressOs::MacOs`, or no tap), never on the `Unenforced` reason string.

**Consequences.** A macOS run (or a tap-less Linux run) has no network to
filter or to grant; the result says so, in both the docs and the envelope,
when `--allow` would otherwise look like it did something. Status stays
`succeeded`: this is a known gap, not a fault.

**Follow-up.** #360 gives guests network (a host-side proxy); #408 then turns
this warning into a refusal once there is something for `--allow` to grant.
