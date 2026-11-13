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
K13 (`live_egress.rs`, Linux + root + `nft`; the test was removed and K13 retired in #483).

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
tap-less Linux guest. An empty allow-list does not add an envelope warning —
deny-all already
holds with no NIC to grant anything onto. The decision keys on structure
(`EgressOs::MacOs`, or no tap), never on the `Unenforced` reason string.

**Consequences.** `NoBoundary` means no egress enforcement is installed, not
that an unfiltered network is available: the current vfkit argv emits no
`virtio-net` device, so a macOS guest (or a tap-less Linux guest) has no
network interface at all today, and no network to filter or to grant. The
result says so, in both the docs and the envelope, when `--allow` would
otherwise look like it did something. Status stays `succeeded`: this is a
known gap, not a fault.

**Follow-up.** #360 gives guests network (a host-side proxy); #408 then turns
this warning into a refusal once there is something for `--allow` to grant.

**Replaced after parity.** The vsock host proxy gives macOS guests HTTPS
egress (through HTTP CONNECT) for the first time, enforced the same way as on
Linux ([`egress-proxy.md`](egress-proxy.md) decision 5).

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

**Decision.** An allow-list entry must be an IPv4 address or IPv4 CIDR;
`validate_egress_hosts` (called by `run_job` before `plan_egress_scoped`, which
does not itself validate hosts) refuses a hostname entry on the nftables
(Linux) path as an invalid plan (band 2, no journal record, no boot), naming
the entry and pointing to #377. macOS enforces no per-VM boundary, so a
hostname entry there is inert rather than misleading, and stays accepted
(decision 2, #358).

**Consequences.** This is a breaking change for `--allow <hostname>` on Linux: a
rule that silently never matched is now a clear refusal at plan time. Hostname
support returns with the #360 egress proxy (#377), which resolves names
host-side instead of asking nft or the guest to.

**Set aside.** Keeping the hostname rule and warning only: rejected, because a
rule that looks like it filters by name but doesn't is a worse failure mode than
refusing to boot.
