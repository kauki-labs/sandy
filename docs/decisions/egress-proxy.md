---
title: "Decisions: egress proxy (NIC-less guest)"
status: accepted
project: sandy
updated: 2026-10-25
---

# Decisions: egress proxy (NIC-less guest)

The planned egress model: the guest has no NIC, and all guest egress crosses
virtio-vsock to a per-run host proxy that applies the allow-list. It replaces
the nftables boundary in [`egress.md`](egress.md) decisions 1 and 2 once the
parity gate (decision 5) passes. Tracked in #360. Subsystem spec:
[`../architecture/spec.md#5-egress`](../architecture/spec.md#5-egress). Planned
live KPIs: [`../architecture/kpi.md#planned-egress-proxy`](../architecture/kpi.md#planned-egress-proxy).

All decisions here are accepted. Implementation status: the proxy crate (#401), the
guest relay (#402), and the seam and band-3 classification (#403) are merged. The qemu
wiring (#404) and the vfkit wiring (#405) are implemented but not live-verified. The
live parity gate (#406) and the cutover (#407) are pending. The implementation issues are
listed at the end.

## Context

Today the egress boundary is a guest-scoped nftables forward ruleset on a host
tap (`egress.md` decision 1). It has four known gaps:

- It needs Linux, root, and `nft` (K13).
- Hostname entries do not work: nft pins one address at load time, and the guest
  has no DNS (#359).
- Traffic from the guest to the host takes the `input` chain and bypasses the
  allow-list (#376).
- macOS has no boundary at all (`egress.md` decision 2).

The [Agent Compute Engine deep dive](https://cloud.google.com/blog/topics/ai-infrastructure/agent-compute-engine-deep-dive)
(accessed 2026-10-24) describes a different model: "MicroVMs lack standard
virtual network interfaces, default IP gateways, or direct VPC access. Instead,
all inbound and outbound traffic must traverse an isolated, point-to-point IPC
boundary (virtio-vsock). This boundary terminates at a local, unprivileged
mediation proxy." sandy already has the transport. The agent link runs over
vsock on both backends ([`agent-fabric.md`](agent-fabric.md) section 10): vfkit
exposes the guest port as a per-run unix socket, and qemu uses `AF_VSOCK` to a
CID it claims by launching (`impls/vm/src/qemu.rs`, `random_agent_cid`).

What the code does today, as observed on `main` (1a3e1fc):

- The qemu guest has a NIC only when `$SANDY_TAP` is set (`QemuBackend`,
  `TAP_ENV`). Without it the guest boots with no NIC.
- `vfkit_args` emits no `virtio-net` device, and the vfkit guest omits the
  guest flake's `networkingModule`. A macOS guest therefore has no NIC either.
  `egress.md` decision 2 and `macos_egress_statement` describe "unfiltered
  vmnet", which the current argv does not produce. This record does not change
  that decision. It notes the drift so #358 is settled against the code.
- Every guest topology carries `agent_program` (`nix/lib/guest.nix`,
  `mkTopology`), so the `sandy-agent` store path is known even on a run that
  does not use agent mode. Only `sandy-host-executor` launches in agent mode;
  `sandy run` drives the console alone.

The attacker model is #357: a hostile job controls everything inside the guest,
including root.

## 1. Guest side: an HTTP CONNECT relay in `sandy-agent`

**Status:** accepted. The relay is implemented (#402) and qemu (#404) and vfkit (#405) run it; neither is live-verified. **Upholds:** INV-7.

**Context.** The guest has no NIC, so a client needs a local endpoint to reach
the host proxy. The relay must work on every VM run, with or without the agent
link.

**Decision.** `sandy-agent` gains a wrapper mode that the backend's console
command always runs first when the run has an egress proxy:

```text
sandy-agent egress-relay --vsock-port <P> -- <rest>
```

`<rest>` is the job (`sh -c <job>`) on a console-only run, or the existing
`sandy-agent --vsock-listen 5000 -- sh -c <job>` invocation on an agent-mode
run.

- The relay binds `127.0.0.1:3128` before it starts `<rest>`, so no job
  process can start before the listener exists. It binds IPv4 loopback only.
- For each accepted local connection it opens one vsock stream to the host (CID
  2, port `P`) and copies bytes both ways until either side closes. It does not
  parse HTTP. The host proxy is the only enforcement point.
- It starts `<rest>` as its child with these variables added to the inherited
  environment: `HTTPS_PROXY`, `https_proxy`, `HTTP_PROXY`, and `http_proxy`,
  each `http://127.0.0.1:3128`, plus `NO_PROXY` and `no_proxy` set to
  `localhost,127.0.0.1,::1`. Both cases are set because curl honours only the
  lowercase `http_proxy`. `ALL_PROXY` is not set. The agent passes its
  environment to the job unchanged (`agent-fabric.md` section 10), so the job
  sees these variables in both modes.
- `NO_PROXY` keeps loopback traffic inside the guest. A job's own local
  services (a test server on `127.0.0.1`) work as before. The relay never
  forwards a loopback target, because it has no target: it forwards bytes, and
  the host proxy refuses loopback addresses (decision 2).
- The relay exits with `<rest>`'s exit status, so the console protocol's
  `exit=<n>` is unchanged on a console-only run. In agent mode the exit still
  travels over the link (INV-11).
- The backend chooses `P` and passes it on the command line. The port is not a
  secret: the proxy authenticates the peer by transport, not by port (decision
  2).

**Consequences.** git over HTTPS, `curl`, `nix`, and most package managers use
the proxy with no change. A client that ignores the proxy variables has no
network at all, because there is no NIC: the failure is closed by
construction. The relay is a convenience, not a boundary. A root job can kill
it, bind its own listener, or open vsock streams directly, and each of those
reaches the same host-side checks.

**Set aside.** A transparent tun-to-vsock shim (or gvisor-tap-vsock, passt):
it works for every client, but it gives the guest an IP stack again and the
proxy sees only `IP:port`, not a name. Deferred to #372 item 2 until a real job
needs non-HTTP egress. A systemd unit for the relay in the guest image: the
port is chosen per run, so the console command is the only place that knows
it.

## 2. Host side: one proxy process per run, owned by the backend

**Status:** accepted. The proxy crate is implemented (#401) and qemu (#404) and vfkit (#405) run one per launch; neither is live-verified, and the live proof is pending (#406). **Upholds:** INV-7.

**Context.** The proxy is the only thing that touches the network for the
guest. It parses guest-controlled input, so it must be small, unprivileged,
and scoped to one run.

**Decision.** A new crate, `sandy-egress-proxy`, holds a pure core (CONNECT
parsing, the allow-list match, the address filter) and a binary. The backend
spawns one proxy per launch attempt, beside the `virtiofsd` daemons on qemu and
beside `vfkit` on macOS, with an explicit, sanitized environment: never the
staged forge token or other secret bytes. Neither `virtiofsd`
(`spawn_virtiofsd`, `impls/vm/src/share.rs`) nor qemu/vfkit sanitize their
environment today; the proxy needs its own because it is new, guest-adjacent
attack surface that parses guest-controlled input, unlike those two. #404 and
#405 carry this in their acceptance criteria.

_Lifecycle._

- The backend starts the proxy before it launches the hypervisor. The proxy
  binds its listener, reads the policy from stdin, validates it, and only then
  writes one `READY` line to stdout. A malformed policy exits the proxy
  without `READY`, so the backend never launches the hypervisor on it. The
  backend waits for `READY` with a 5 s deadline, the same pattern as waiting
  for a `virtiofsd` socket.
- The allow-list reaches the proxy as JSON on stdin, not on argv. The proxy
  closes stdin after it reads the policy.
- At teardown the backend checks the proxy with `try_wait` before it kills it,
  so the backend's own kill is never read as a proxy death. It kills the proxy
  on both the ok and the error path, like `virtiofsd`.
- A qemu CID collision relaunches with a new CID. The proxy belongs to the
  launch attempt, so the retry restarts it with the new CID.
- The proxy needs no privilege and runs as the backend's user. It logs each
  CONNECT target that passes the host grammar, and its verdict, through
  `tracing` to stderr, which the backend captures at debug level. A malformed
  target is logged only as `malformed`, never as raw bytes. It never logs
  tunnel payload.

_Transport and peer identity._

- **qemu:** the proxy binds `AF_VSOCK` at (`VMADDR_CID_ANY`, `P`). Linux has one
  host vsock port space for every VM, so `P` is random per launch in
  `49152..=2^31-1`, retried on `EADDRINUSE` (8 attempts, then band 3). Every
  accepted stream's peer CID must equal the CID this launch claimed. Any other
  peer, including a local process on loopback CID 1, is closed with no
  response and counted. The check rests on vhost-vsock stamping the source CID
  in the host kernel, so a guest cannot forge it.
- **vfkit:** the backend adds
  `--device virtio-vsock,port=<P>,socketURL=<staging>/eg-<id>.sock,listen`.
  In `listen` mode vfkit dials the unix socket for each guest-initiated
  connection ([vfkit `pkg/vf/vsock.go`](https://github.com/crc-org/vfkit/blob/main/pkg/vf/vsock.go),
  accessed 2026-10-25), so the proxy listens on that socket. The socket lives in
  the 0700 private staging base, like the agent link's socket. Only this VM's
  vfkit dials it. `P` is a fixed constant here, `EGRESS_VSOCK_PORT = 5001`,
  because the port space is per VM.
- The proxy listens on its own port, separate from the agent link (port 5000).
  The two are not multiplexed.

_CONNECT parsing._

- The proxy reads the request head up to the first `CRLFCRLF`, with an 8 KiB
  cap and a 10 s deadline. A head over the cap or the deadline closes the
  connection.
- The request line must be `CONNECT <host>:<port> HTTP/1.1` (or `HTTP/1.0`).
  Header fields are read and ignored, including `Host` and
  `Proxy-Authorization`. The peer transport is the identity.
- Any other method answers `405`. This includes the absolute-form `GET http://...` that `HTTP_PROXY` makes a client send for a plain-HTTP URL, so
  plain HTTP fails with a clear status instead of a DNS error. Plain-HTTP
  forwarding is out of v1.
- `<port>` is a decimal integer in `1..=65535`. A missing or malformed port
  answers `400`.
- `<host>` is classified, in this order:
  1. An IPv4 literal in strict four-part dotted-decimal form, with no leading
     zeros (`Ipv4Addr::from_str`).
  2. A bracketed IPv6 literal. v1 refuses it with `403`, because the allow-list
     is IPv4.
  3. A name: ASCII only, lowercased, one trailing dot stripped, 1 to 253
     octets, each label 1 to 63 octets of `[a-z0-9-]`, not starting or ending
     with `-`, and the last label not all digits.
  4. Anything else answers `400`. This covers every other numeric form
     (`127.1`, `0x7f.0.0.1`, `2130706433`, `010.0.0.1`), userinfo
     (`a@b`), percent-encoding, NUL, and non-ASCII. Such a host is never passed
     to a resolver.
- Bytes the client sent after the head, before the `200`, are forwarded
  upstream once the tunnel opens.

_Allow-list match._ The policy is the run's `AllowList`. An entry is
`name:port`, `IPv4:port`, or `IPv4-CIDR:port`.

- A name target matches a name entry only, by exact equality after the
  normalisation above, and by equal port. There are no wildcards in v1. A name
  never matches an IP or CIDR entry.
- An IP-literal target matches an IP or CIDR entry that contains it, with an
  equal port. It never matches a name entry. A job that connects by IP therefore
  needs the operator to name that IP.
- The match runs **before** any resolution. A denied name is never sent to a
  resolver, so a denied CONNECT cannot carry data out through DNS.
- A denied target answers `403` with a one-line reason that names the target.

_Resolution, host-side._ For an allowed name the proxy resolves on every
CONNECT through the host's resolver (`getaddrinfo`, A and AAAA), bounded by the
same 10 s deadline as the connect attempt below: a resolver call that blocks
past it fails the CONNECT with `504`, the slot is freed, and it counts toward
the 256-connection cap exactly like a slow connect, so a stalled resolver
cannot starve the run's other connections. It pins nothing across connections,
so a name with several addresses or a short TTL works.

_Address filter._ The proxy filters the resolved addresses, connects only to an
address it kept, and connects to that exact address. It never resolves a second
time. This is the DNS-rebinding defence: the address that passes the check is
the address that gets the connection.

- **Always refused:** loopback (`127.0.0.0/8`, `::1`), unspecified (`0.0.0.0/8`,
  `::`), and every address on one of the host's own interfaces, read with
  `getifaddrs` on each CONNECT.
- **Refused unless the allow-list names the address:** RFC 1918
  (`10/8`, `172.16/12`, `192.168/16`), CGNAT `100.64/10`, link-local
  (`169.254/16`, `fe80::/10`), unique-local `fc00::/7`, `192.0.0/24`,
  `198.18/15`, multicast, `240/4`, and broadcast. An IPv4-mapped (`::ffff:0:0/96`)
  or NAT64 (`64:ff9b::/96`) address is judged by its embedded IPv4 address. The
  exception covers an operator who allow-lists `registry.internal:443` and also
  `10.0.0.0/8:443`: the name passes the match, and its private address passes
  because an IP entry with the same port contains it.
- If no address survives, the answer is `403` ("resolves to a non-public
  address"). If resolution fails, `502`.
- The proxy tries the kept addresses in resolver order, one at a time, with a
  10 s connect timeout each. All failing answers `502`, or `504` on timeout.
- An IP-literal target goes through the same filter. An allow-list entry that
  names a private IP explicitly allows it. Loopback and host-interface addresses
  stay refused even when named.

_Limits._ At most 256 concurrent connections per run. A connection over the cap
is closed at accept. An open tunnel with no bytes in either direction for 10
minutes is closed. These are constants in the core, not configuration, until a
job needs otherwise. Bandwidth is not limited in v1.

**Consequences.** One mechanism enforces egress on qemu and vfkit, with no root
and no `nft`. Hostname entries work without DNS in the guest (#377 lifts
#359's plan-time refusal). Every CONNECT verdict is observable at one point,
which #375 records into receipts. The proxy is new host-side attack surface
that parses guest input. It is kept to a small pure core with unit and
property tests, `forbid(unsafe_code)`, and no privilege.

**Set aside.**

- **One shared host proxy daemon.** It would need per-CID identity, carry state
  across runs, and turn one crash into every run's fault. A per-run process
  gives a per-run failure classification.
- **A proxy thread inside the sandy process.** A process is killable and
  observable on its own, and a fault in it cannot take down the supervisor.
- **Multiplexing egress on the agent link.** The link is a framed protocol with
  its own flow control. A job saturating egress could starve the link, and a
  console-only run has no link. A separate port keeps the two planes apart.

## 3. Failure classification: band 3

**Status:** accepted. The seam and the band-3 classification are implemented (#403) and qemu (#404) and vfkit (#405) use them; neither is live-verified. **Upholds:** INV-7, INV-11.

**Context.** The proxy is the egress boundary. A run without its boundary is
not the run the submitter asked for.

**Decision.**

- **Proxy start failure** (spawn error, no `READY` in 5 s, port allocation
  exhausted, a malformed policy): the hypervisor does not launch. The backend
  kills any `virtiofsd` it started and returns `BackendError::Spawn("egress proxy did not start: ...")`. This is an infra fault, band 3, with no boot,
  the same class as an egress-apply failure today.
- **Proxy death mid-run:** at teardown, `try_wait` shows the proxy exited before
  the backend killed it. The backend returns a new
  `BackendError::EgressProxyDied { status, booted, guest_exit }`, classified band 3
  (retryable, like any infra fault) whatever the guest's own exit. The envelope
  message names the proxy's exit status and the guest exit, if one was
  observed, so the record alone is diagnosable.
- The backend does not stop the VM early when the proxy dies. The guest has lost
  network, not gained it, so the boundary still holds.
- **Guest relay start failure** (including failure to bind `127.0.0.1:3128`):
  `<rest>` remains stopped. The backend returns a locked band-3 infrastructure
  result, not a guest job result.
- All three failure paths run inside the `run_job_with_credential` mint-to-revoke
  bracket (spec section 4). Teardown revokes the live lease before removing the
  staged `0600` token file, on this path exactly as on any other backend error;
  the caller-owned credential directory is untouched.

**Consequences.** A job that succeeded while its network was gone cannot be
reported as `succeeded`. A transient proxy fault is retryable rather than blamed
on the job.

## 4. No TLS termination in v1

**Status:** accepted.

**Context.** Swapping the forge token in flight needs the proxy to see
plaintext.

**Decision.** The proxy matches on the CONNECT target and copies opaque bytes.
It never terminates TLS. The minted token stays in the guest. TLS termination
and the in-flight token swap are #372 item 1, the exit for #357's interim
token risk.

**Consequences.** A pinned-certificate client works. The proxy cannot see the
TLS SNI or the HTTP `Host`, so a tunnel to an allowed front can carry traffic
for another tenant behind it (see the adversarial pass).

## 5. Replace nftables, gated on live parity

**Status:** accepted, not yet implemented. **Supersedes on completion:**
[`egress.md`](egress.md) decisions 1 and 2.

**Context.** Two boundaries in parallel must be kept in parity forever. The
nftables path has the gaps in this record's Context. qemu and vfkit share one
guest topology, so they should move together.

**Decision.** The migration runs in this order:

1. The proxy core and binary land, unit-tested, with no wiring.
2. The guest relay lands in `sandy-agent`, unit-tested over a unix-socket
   stand-in for vsock.
3. The seam change lands: `RunSpec` carries the egress policy, the egress plan
   gains a proxy variant, and `BackendError::EgressProxyDied` is classified
   band 3.
4. qemu and vfkit wire the proxy, each behind an opt-in, `SANDY_EGRESS=proxy`.
   On qemu the opt-in and `$SANDY_TAP` are mutually exclusive, and setting both
   is an invalid plan (band 2). The nftables path is unchanged.
5. **The parity gate.** The live egress-proxy suite passes on **both** qemu and
   vfkit. Its cases are the planned KPI rows in `kpi.md`: an allowed host is
   reachable, a denied host is refused, an empty allow-list blocks everything,
   and an in-guest bypass attempt fails. It also covers a name that resolves to
   loopback and a proxy death classified as band 3. A row counts only as a real
   pass on a real boot (INV-S9), never as a skip.
6. Cutover: the proxy becomes the only path. The guest topology drops
   `networkingModule` and the guest `nftables` package. `$SANDY_TAP`, the tap
   argv, `NftablesApplier`, `to_nftables_forward`, and `live_egress.rs` (K13)
   are deleted. `egress.md` decisions 1 and 2 are marked superseded, and K13
   leaves `kpi.md`.
7. With every VM run enforced, #358's warning becomes a refusal: a VM run whose
   proxy cannot start is refused (band 3, decision 3), and no VM path yields
   `NoBoundary`.

**Consequences.** macOS gains enforced HTTPS egress through HTTP CONNECT in
step 6. Given the observation in Context, that is in effect macOS gaining
HTTPS egress at all, enforced from the start; plain HTTP and non-HTTP egress
stay out of scope, deferred to #372.
#376 is closed for sandy's own surface by construction: with no NIC there is no
IP path to the host. The qemu leg still reaches host `AF_VSOCK` listeners (see
the adversarial pass). #359's IP-only semantics and its hostname refusal last
until #377 lands.

**Set aside.** Keeping nftables beside the proxy after parity: two boundaries
to keep in step, root on Linux, and the #376 bypass. Moving qemu first and vfkit
later: one guest topology serves both, and splitting them doubles the
transition state.

## 6. Out of scope: the process backend

**Status:** accepted.

**Decision.** The process backend shares the host's network. It is trusted-only
by policy and refuses untrusted jobs (#150, [`process-containment.md`](process-containment.md)).
It gets no proxy.

**Consequences.** The egress allow-list does not apply to process-backend
runs, which is stated, not silent.

## 7. Opt-in NIC profile (#602)

The default guest has no NIC. A sandbox that needs a routable guest sets `SANDY_NETWORK=nic` (`NetworkMode::Nic`);
an unknown or non-UTF-8 value is refused. Sandboxes that do not set it are unchanged.

- **qemu (Linux):** `nic` is the existing tap + nftables path (#29): the operator binds a tap (`SANDY_TAP`), the guest
  NIC attaches to it, and `sandy run` applies the guest-scoped forward ruleset around the boot. The proxy is not
  involved: a `nic` guest and the proxy guest are exclusive. The user-mode NIC was tried and dropped: with
  `restrict=on` it has no path in either direction, so it only added a dead interface.
- **Plan-time refusals (band 2, no journal record, no boot):** `nic` without a tap, a tap without `nic`, and `nic`
  with `SANDY_EGRESS=proxy` (`validate_network_mode`). A boundary-less NIC is therefore never booted by `sandy run`.
- **Backend refusals (defense in depth):** `qemu_args` refuses the same three combinations, so a caller that skips the
  plan check still cannot boot an unfiltered NIC.
- **Dispatched VMs never get a NIC:** `sandy-host-executor` and sandyd dispatch apply no nftables ruleset, so the
  host-executor refuses a VM dispatch while `SANDY_NETWORK` is set to anything but `none`. A tap alone is refused by
  the backend.
- **vfkit (macOS):** `nic` adds `virtio-net,nat` with **no egress boundary**. macOS has no nftables, and a guest-side
  filter does not survive a guest with root. It is trusted-only: a policy beside it is refused, because it would read
  as filtered. Enforcement is tracked in #603.
- **Limits of the nftables path:** the boundary matches IPv4 addresses and CIDRs and passes TCP only (#359), so a
  `nic` guest cannot allow-list a provider by hostname and has no DNS until #377. The forward chain drops everything
  not allow-listed (IPv6 and UDP included), and the input chain accepts only the guest's DHCP request (#376).
- **No host path into the guest yet:** the tap is the host's to configure. Tailnet reachability of the guest's T3
  port is the host's job (`tailscale serve`), not sandy's.
- The `SANDY_NETWORK` env var is the per-run switch for `sandy run`, one process per run. A per-run `RunSpec` field is
  tracked in #603.

## Adversarial pass

Each attack assumes the #357 model: the job is root in the guest.

| Attack                                                                                                                        | Result                                                                                                                                                                                                                                                                                        |
| ----------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| The guest opens its own vsock stream to the proxy port, bypassing the relay.                                                  | Mitigated. The relay is not a boundary. A direct stream meets the same parser, allow-list, and address filter.                                                                                                                                                                                |
| The guest ignores the proxy and connects directly.                                                                            | Mitigated. There is no NIC, so there is no route (except under `network = nic`, section 7).                                                                                                                                                                                                   |
| The guest kills the relay or binds `127.0.0.1:3128` itself.                                                                   | Mitigated. It denies only itself network.                                                                                                                                                                                                                                                     |
| CONNECT to an IP literal.                                                                                                     | Mitigated. Allowed only if an IP or CIDR entry contains it with the same port. Loopback and host-interface addresses are refused even then. Non-canonical numeric forms answer `400` and are never resolved.                                                                                  |
| CONNECT to an allowed name that resolves to a private or host-local address (DNS rebinding).                                  | Mitigated. The filter runs on the resolved addresses, and the proxy connects to the exact address it checked, so a second lookup cannot swap it. Private addresses pass only when an IP entry names them, and loopback never.                                                                 |
| Data exfiltration through DNS: CONNECT to `<data>.attacker.example`.                                                          | Mitigated. The match runs before resolution, so a denied name never reaches a resolver. An allowed name is resolved as written, with no attacker-chosen labels.                                                                                                                               |
| Slow-loris: many connections that send the head one byte at a time.                                                           | Mitigated. 8 KiB head cap, 10 s head deadline, 256 concurrent connections per run, 10 min idle tunnel timeout. The proxy is per run, so exhaustion denies only that run's own egress.                                                                                                         |
| Request smuggling in the head: `CONNECT a.com:443@b.com:443`, `a.com.b.com`, mixed case, trailing dot, NUL, percent-encoding. | Mitigated. Strict host grammar, ASCII lowercase, one trailing dot stripped, exact equality. Anything outside the grammar answers `400`.                                                                                                                                                       |
| qemu: the guest dials another run's proxy port (one host vsock port space).                                                   | Mitigated. Every stream's peer CID must equal the launch's CID. vhost-vsock stamps the CID in the host kernel.                                                                                                                                                                                |
| qemu: the guest dials some other host `AF_VSOCK` listener on CID 2.                                                           | **Accepted residual risk.** vhost-vsock gives the guest the host's vsock port space, so any host service listening on `AF_VSOCK` is reachable. sandy runs none besides its proxies. Operators check with `ss --vsock -l`. vfkit is not affected: only the ports the backend configures exist. |
| Domain fronting: CONNECT to an allowed CDN front, then a TLS SNI or `Host` for another tenant.                                | **Accepted residual risk.** v1 never sees inside TLS (decision 4). The allow-list names a front, not a tenant. #372 (TLS termination) is the path to closing it.                                                                                                                              |
| Exfiltration through an allowed host (a gist, a push to an allowed repo).                                                     | **Accepted residual risk.** Inherent to any allow-list. Bounded by the operator's list and the token scope (#357).                                                                                                                                                                            |
| The proxy itself is compromised by crafted input.                                                                             | **Accepted residual risk**, reduced. The proxy needs no privilege, runs as the backend's user, and has `forbid(unsafe_code)`, a small parser, and property tests. A compromise is a user-level foothold on the host. Further sandboxing (Landlock, seccomp) is not in v1.                     |
| A same-uid host process connects to the vfkit proxy socket.                                                                   | **Accepted residual risk.** The socket is in the 0700 staging base. A same-uid process already has the host's network, so the proxy grants it nothing new.                                                                                                                                    |
| Bandwidth exhaustion through an allowed host.                                                                                 | **Accepted residual risk.** v1 sets no bandwidth cap.                                                                                                                                                                                                                                         |
| The guest floods egress to starve the agent link.                                                                             | Mitigated. Separate vsock ports and separate host processes (decision 2, set aside).                                                                                                                                                                                                          |
| The proxy dies and the job keeps running.                                                                                     | Mitigated. The guest has no network (fail closed; a `network = nic` guest on vfkit keeps its NAT NIC, section 7), and the run is band 3 (decision 3).                                                                                                                                         |
| Log or receipt injection through the CONNECT target.                                                                          | Mitigated. Only targets that pass the host grammar are logged or recorded (#375). Others are logged as `malformed`.                                                                                                                                                                           |
| An attack on the host kernel's vsock code.                                                                                    | **Accepted residual risk.** The guest kernel no longer has a network driver, but vhost-vsock (qemu) and Virtualization.framework (vfkit) remain host surface. The agent link already depends on them.                                                                                         |

## Implementation issues

Milestone "Hardened egress + provenance". Each issue carries its own acceptance
criteria. Live KPI rows split across issues: #401 and #402 feed KP1-KP6 without
owning rows directly; #403 owns KP6; #404 owns the qemu rows (KP1q, KP2q) for
its slice, #405 the vfkit rows (KP1v, KP2v); #406 proves the full KP1-KP6
parity gate on both backends.

| Issue | Seam                                                        | Blocked by       |
| ----- | ----------------------------------------------------------- | ---------------- |
| #401  | `sandy-egress-proxy`: CONNECT, allow-list, and address core | -                |
| #402  | `sandy-agent egress-relay`: the guest-side relay            | -                |
| #403  | Seam: `RunSpec` egress policy, plan variant, band 3         | -                |
| #404  | qemu: proxy lifecycle, vsock port, peer-CID check           | #401, #402, #403 |
| #405  | vfkit: proxy lifecycle, `listen` socket                     | #401, #402, #403 |
| #406  | Live parity gate on qemu and vfkit                          | #404, #405       |
| #407  | Cutover: delete the nftables path, guest topology drops NIC | #406             |
| #408  | Flip #358's warning to a refusal                            | #407, #358       |

Already filed and fed by this work: #375 (egress attempts in receipts) and #377
(hostname entries), both blocked by #404 and #405. #372 holds the deferred TLS
termination and non-HTTP egress.

#404 settled the CID for every proxy-mode launch. A console-only run does not
launch `agent_program`, so `QemuBackend::run` claims a random CID with
`random_agent_cid` whenever the spec carries an egress policy, with or without
agent mode, and retries on a collision. `qemu_args` emits it as
`vhost-vsock-pci,guest-cid=<CID>` with no NIC, and the proxy receives it as
`--peer-cid`, so it serves only that CID.

#405 wired vfkit the other way round. There is no CID to scope: the proxy runs as
`sandy-egress-proxy --unix <staging>/eg-<id>.sock` (the 0700 private staging base, beside
the agent link socket `ag-<id>.sock`, with the file name kept short to fit macOS's
104-byte `sun_path`), and vfkit gets `--device
virtio-vsock,port=5001,socketURL=<that socket>,listen`, so it dials the socket for each
guest-initiated connection. The guest port is the constant `EGRESS_VSOCK_PORT = 5001`
(the port space is per VM; the agent link keeps 5000). A unix-socket bind failure is not
retried. At teardown the backend `try_wait`s the proxy before killing it, so an early
exit is an `EgressProxyDied` and its own kill is never read as one; then it kills the
proxy and vfkit and removes the socket. The KP1q, KP2q, KP1v and KP2v live rows are still
pending: no VM has booted behind the proxy yet (#406).
