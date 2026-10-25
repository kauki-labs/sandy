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

Both decisions below stay in force until the vsock egress proxy passes its live
parity gate. The proxy then replaces them:
[`egress-proxy.md`](egress-proxy.md) decision 5 (#360).

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

**Replaced after parity.** The NIC-less guest with a vsock host proxy
([`egress-proxy.md`](egress-proxy.md)) removes this ruleset once both backends
pass the parity gate.

## 1a. The boundary also covers host-destined traffic

**Status:** accepted. **Upholds:** INV-7, #376.

**Context.** The `forward` chain only sees traffic routed through the host; a
packet addressed to the host itself (the tap's gateway address, or any other host
address) is delivered locally through `input` and never reaches it. `to_nftables_forward`
left that chain unfiltered, so an empty allow-list still let the guest reach a
host-local DNS resolver or any other host service — confirmed live (#359 probe,
2026-10-25): with the host's dnsmasq as the guest's advertised resolver, the guest
resolved `github.com` and connected over TCP to the tap address.

**Decision.** `to_nftables_forward` also emits an `input`-hook chain, scoped the
same way: `policy accept` (every other interface's input stays untouched),
`iifname "<iface>" udp dport 67 accept` for the guest's own DHCP request, then
`iifname "<iface>" drop` for everything else from the guest. The allow-list plays
no part in this chain — a host address is never a `forward` destination, so an
entry naming one (e.g. a host-local resolver) has no accept rule to carry over.

**Consequences.** DNS exfiltration through a host-local resolver, and any other
host service reachable from the tap, is closed the same way as forwarded egress:
fail-closed, by default, with an empty allow-list included. Allow-listing a host
address (so a job could legitimately reach a host-local service) is out of scope
here; it arrives, if at all, with #360's proxy, which resolves and brokers names
host-side instead of inside the kernel ruleset.

**Set aside.** Honoring a host-address allow-list entry in the `input` chain: not
implemented. #359's probe showed hostname allow-list entries don't reliably match
what the guest actually resolves, so widening the input chain on the strength of
one would recreate the same mismatch this fix closes.

## 2. macOS is a no-op

**Status:** accepted.

**Context.** The guest-scoped nftables mechanism is Linux-only; macOS has no
equivalent in this path.

**Decision.** On macOS `plan_egress_scoped` yields `NoBoundary`; the run proceeds
without enforcement, **documented, not silent**.

**Consequences.** `NoBoundary` means no egress enforcement is installed, not that
an unfiltered network is available: the current vfkit argv emits no `virtio-net`
device, so a macOS guest has no network interface at all today. The behaviour is
stated in the result and the docs so it is not mistaken for enforcement.

**Replaced after parity.** The vsock host proxy gives macOS guests HTTPS
egress (through HTTP CONNECT) for the first time, enforced the same way as on
Linux ([`egress-proxy.md`](egress-proxy.md) decision 5).
