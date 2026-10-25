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
without enforcement, **documented, not silent**.

**Consequences.** macOS runs are unfiltered by design; the behaviour is stated in
the result and the docs so it is not mistaken for enforcement.

## 3. nftables matches by IP, not by name

**Status:** accepted. **Upholds:** #359.

**Context.** A live probe (2026-10-25) found that `--allow github.com:443`
compiled to `ip daddr github.com tcp dport 443 accept`, but nft resolves that
name once, at ruleset-load time, and pins the single address it got
(`140.82.121.3`). A name with more than one A record makes nft fail to load the
ruleset (`Error: Hostname resolves to multiple addresses`). Worse, the guest
itself can't resolve names through the boundary: the forward rules pass TCP
only, and DNS is UDP, so a resolver entry in the allow-list doesn't help; and
when a host-local resolver did answer, it gave the guest a different address
than the one nft had pinned, so the connection by name still failed. A hostname
entry in the allow-list therefore only ever helps a job that already connects by
IP — it never does what `--allow <hostname>` implies.

**Decision.** An allow-list entry must be an IPv4 address or IPv4 CIDR; `plan_egress_scoped`
refuses a hostname entry on the nftables (Linux) path as an invalid plan
(band 2, no journal record, no boot), naming the entry and pointing to #377.
macOS enforces no per-VM boundary, so a hostname entry there is inert rather
than misleading, and stays accepted (decision 2, #358).

**Consequences.** This is a breaking change for `--allow <hostname>` on Linux: a
rule that silently never matched is now a clear refusal at plan time. Hostname
support returns with the #360 egress proxy (#377), which resolves names
host-side instead of asking nft or the guest to.

**Set aside.** Keeping the hostname rule and warning only: rejected, because a
rule that looks like it filters by name but doesn't is a worse failure mode than
refusing to boot.
