---
title: "Decisions: egress"
status: accepted
project: sandy
updated: 2026-10-14
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
equivalent in this path.

**Decision.** On macOS `plan_egress_scoped` yields `NoBoundary`; the run proceeds
without enforcement, **documented, not silent**. The envelope's own `warnings`
carries this too (#358): every macOS run, including one with an empty
allow-list, gets `egress unenforced: macOS has no per-VM boundary; the guest
has unfiltered network (see #360)`. The decision keys on the platform
(`EgressOs::MacOs`), never on the `Unenforced` reason string, so the warning
can't be defeated by a reason that happens not to match a pattern. An empty
allow-list warns too: it reads as "no network", but macOS still grants the
guest full unfiltered network, which is the case most in need of surfacing.

**Consequences.** macOS runs are unfiltered by design; the behaviour is stated
in the result (both the docs and the envelope's `warnings`) so it is not
mistaken for enforcement. Status stays `succeeded`: this is a known gap, not a
fault.

**Follow-up.** This is a warning, not a refusal, because refusing today would
break every macOS run. Once #360 makes macOS egress enforceable, the gate
tightens to match Linux (decision 1): a run whose boundary can't be applied is
refused (INV-7, band 3). The warning here is the interim answer, not the
permanent one.
