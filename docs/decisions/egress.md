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
equivalent in this path.

**Decision.** On macOS `plan_egress_scoped` yields `NoBoundary`; the run proceeds
without enforcement, **documented, not silent**.

**Consequences.** macOS runs are unfiltered by design; the behaviour is stated in
the result and the docs so it is not mistaken for enforcement.
