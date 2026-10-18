---
title: "Decisions: sandyd control plane"
status: accepted
project: sandy
updated: 2026-10-17
---

# Decisions: sandyd control plane

The daemon + control RPC for the fabric (epic #205): a per-machine `sandyd`
dispatching jobs into the agent fabric, with thin CLI/MCP frontends. Builds on
the all-local fabric MVP (#103). Operator-confirmed design: (B) a dedicated
control RPC separate from the fabric's data/event channels, (C) a submitter-
bounded job manifest.

This file also carries #214/B0's own decisions (§1-4), landing separately; a
rebase against this entry renumbers rather than drops either side, same as
agent-fabric.md's §10/§11 collision between #202 and #203.

## 1. The control RPC is request/response only; job output rides the fabric channels

**Status:** accepted.

**Context.** Decision (B): control operations (submit/cancel/attach/status/list)
go over a dedicated, versionable RPC; the data/event plane (job output,
telemetry, escalation) rides the fabric's `Channel`/`ChannelBackend`, already
built. A naive design would have `Attach` stream the job's output directly over
the control connection, duplicating what the fabric already does.

**Decision.** `sandy-control-proto` (#211, B0) defines `ControlRequest`/
`ControlResponse` oneofs for Submit/Cancel/Attach/Status/List as pure
request/response: one request, one matching response, per connection, in
order (no pipelining in v1; a `request_id` field exists for forward-compat and
log correlation only). `Attach` hands back a channel id and an attenuated cap
scoped to that job's orchestrator channel; the caller subscribes to output on
the data plane itself via the existing `Channel::join`/`subscribe`.

**Consequences.** No duplicate delivery/ordering/dedup logic between the
control RPC and the fabric channel — that guarantee lives in exactly one
place (`Channel`, already contract-tested). The control RPC's job shrinks to
exactly what it needs to be: start/stop/observe-the-state-of a job, not carry
its output.

**Set aside.** Streaming `Attach` responses over the control connection
itself: it would need the control RPC to support long-lived streaming calls,
duplicating the fabric channel's own delivery semantics for no benefit.

## 2. Length-prefixed protobuf framing, not gRPC/tonic

**Status:** accepted.

**Context.** The RPC needs to be versionable and ride multiple transports over
time: UDS (local) → vsock (VM guest) → TCP/QUIC-over-mesh (cross-machine),
per the one-stream-abstraction plan (B6). gRPC/tonic is the conventional
choice for a versioned protobuf RPC, but is built on HTTP/2 semantics and
pulls in `hyper`/`h2`.

**Decision.** Because the control RPC is pure request/response (decision #1,
above) with no genuine streaming need, `sandy-control-proto` ships a plain
length-prefixed frame instead: a big-endian `u32` byte length, then the
encoded message (`write_frame`/`read_frame` over any `AsyncRead`/`AsyncWrite`).
This carries across the UDS → vsock → TCP/QUIC transport swap without being
wedded to HTTP/2's connection model, and matches the project's existing
lighter-dependency bias (protox over `protoc`, no tonic here either).

**Consequences.** `sandyd` and its clients (CLI, MCP) depend on `tokio`'s I/O
traits and `prost`, nothing heavier. A future genuine streaming need (if one
ever arises) would need its own seam, not a retrofit of this RPC.

`AttachResponse` carries a channel-join `Cap` in plaintext bytes. Fine over
local UDS (filesystem permissions are the boundary); once this rides vsock or
TCP/QUIC-over-mesh (B6), that cap needs the transport's own confidentiality
(TLS/QUIC's encryption, or an equivalent over vsock) — a bearer credential
must never cross a network link in the clear. Flagged here so B6 doesn't lose
it; nothing to build in B0.

**Set aside.** gRPC/tonic: no streaming need to justify the HTTP/2 and
`hyper`/`h2` dependency weight, and it would complicate the vsock/mesh
transport swap.

## 3. The job manifest is opaque bytes in B0; the typed, capped manifest is B3's job

**Status:** accepted.

**Context.** Decision (C): a job's manifest is capped at the submitter's own
attenuation — a job can never be granted more capability than the submitter
holds. Designing that derivation (which needs `CapAuthority`/`Minter`) is a
substantial piece of work on its own (B3), and B0 only needs to define the
RPC envelope, not block on it.

**Decision.** `SubmitRequest.manifest` is `bytes` plus a `manifest_encoding`
string tag (empty/unset is rejected, never a silent default interpretation).
B3 replaces this with the real typed `JobManifest` once its submitter-bounded
derivation is designed; the oneof/field-number shape in `control.proto`
already has room for that without breaking the wire format (a new typed field
added, the opaque one kept for compatibility or deprecated explicitly).

**Consequences.** B0 does not block on B3's cap-derivation design. `sandyd`'s
B1 skeleton stores the opaque bytes as-is (no interpretation, no dispatch)
until B2/B3 land.

**Set aside.** Designing `JobManifest` now, inline with B0: couples an
RPC-envelope block to a capability-derivation design that needs more thought
and is explicitly its own block (B3).

## 4. sqlite via `rusqlite`, not `sqlx`

**Status:** accepted.

**Context.** `sandyd` (B1) persists job state. `sandyd` is a single daemon
process with low write concurrency (one job's lifecycle transitions at a
time, in practice); the state store does not need to be distributed or
horizontally scaled.

**Decision.** `rusqlite` (vendored SQLite, no system dependency, synchronous
API) wrapped in `tokio::task::spawn_blocking` per query, rather than `sqlx`'s
native-async SQLite support. Matches the project's existing lighter-dependency
bias (`protox` over `protoc`, no tonic for the control RPC either) and avoids
coupling the state store to a specific async runtime's I/O model.

**Consequences.** Every query crosses a `spawn_blocking` boundary; acceptable
at `sandyd`'s expected concurrency. `rusqlite` still exposes the full SQLite
feature set B2/B3's richer queries will need.

**Set aside.** `sqlx`: heavier dependency tree for a benefit (native async)
that does not matter at this daemon's scale.

## 5. The CLI's daemon commands are additive (`sandy daemon <op>`), not a reuse of `run`/`status`/…

**Status:** accepted.

**Context.** `sandy`'s existing CLI (pre-#205) already has `run`/`ls`/`status`/
`wait`/`kill`/`gc` for a direct-execution job model: no daemon, a local
`Journal` + `VmBackend` run the job in the foreground. B4 adds `submit`/
`cancel`/`attach`/`status`/`list` against `sandyd` over the control RPC — a
different job model, with names that collide on `status` and come close on
the rest. Routing the existing names through `sandyd` instead was considered
and rejected: B3's `JobManifest` is cap-requests only (no I/O, secrets, or
egress shape), so doing that today would regress `run`'s whole `--input`/
`--out`/`--secret`/`--allow`/`--credential` surface in favor of a daemon that
cannot do what `run` already does.

**Decision.** The daemon commands live under their own `sandy daemon <op>`
subcommand group, leaving `run`/`ls`/`status`/`wait`/`kill`/`gc` untouched.
`daemon` names the control plane directly; `jobs` was considered and rejected
since direct-execution's commands are also about jobs, and that name would
blur the two models together. Issue #221 tracks the eventual convergence:
once `JobManifest` reaches parity with `run`'s flag set, retire direct
execution and promote the daemon commands to the top-level names.

**Consequences.** Two job models coexist under one binary for as long as
`JobManifest` lacks parity — an operator must know which namespace a given
job lives in. The coexistence is explicitly temporary (#221 names the exit
condition), not a permanent fork.

**Set aside.** Reusing `run`/`status`/`wait`/`kill`/`gc` for the daemon path
now: would regress real, working functionality (`run`'s full flag set) in
favor of a daemon that cannot yet replace it. `jobs` as the subcommand group
name: blurs direct-execution's and the daemon's job concepts together.

## 6. Remote agent-link streams must authenticate before `serve_agent_link` writes a frame (hard gate, on the M2 critical path)

**Status:** partially implemented. The authorization logic is built and
tested in isolation (`sandyd::link_auth`: `RemoteLink`, the constant-time
token compare, `JobRegistry::authenticate_remote_link`) — accept-or-refuse
given a job id, a peer IP, and a presented token, with every refusal path
named and tested (wrong peer, wrong token, already-claimed, unknown run) and
a dedicated test proving the token never appears in `Debug` output.
`RemoteLink::invalidate` plus `JobRegistry::invalidate_remote_link`, wired
into the control handler's `Cancel` arm, close #269's token-lifecycle
requirement: cancelling a job invalidates its unclaimed link immediately, so
a stream that arrives after cancellation gets the same zero-byte refusal as
an already-claimed one (regression-tested: a cancelled job's still-valid,
still-unclaimed token must not authenticate a late-arriving stream). What is
NOT yet built: the network accept loop itself (binding a mesh address via
`sandy-conn`, calling this logic per accepted connection, #279) and anything
that calls `RemoteLink::new` to actually bind a run to an executor at
dispatch — both wait on #263's dispatch-RPC design, which decides where that
binding happens and what shape the accept loop's caller takes. Tracked by
#212. Promoted from a cross-machine-safety nicety to the M2 critical path
(decision 8): M2's cross-sandbox peer-group channels depend on this binding
existing.

**Context.** `serve_agent_link` (#216) writes the run's agent cap as its first
frame with no check before it — it assumes its peer is already the legitimate
agent, which holds locally because the link is a private socketpair. Once a
job can run on a remote executor (#159/#231, sandy-conn's mesh tier), B2's
dispatch plane needs to hand a remote peer's stream to `serve_agent_link` the
same way. A naive design (the orchestrator demuxes incoming mesh streams by
an unauthenticated run-id prefix alone) breaks this assumption: any mesh peer
that names run X and gets handed the stream receives X's real cap as frame 1,
passes `Join` trivially (it already holds the cap it was just given), and can
then read the job's stdin, post forged output, or send a forged `Exit` that
B2's report path takes as the job's real result — an INV-11 break. Encryption
alone does not close this: the attacker is a legitimately mesh-authenticated
peer, just not the right one.

**Decision** (architect ruling, infra-f3, full record on issue #212):

- A run id is an addressing label only, never an authorization token.
- At dispatch, B2 records the run's executor mesh IP **and** a fresh 32-byte
  random per-run link token in the `JobRegistry` entry. The token is a bearer
  secret (INV-1 discipline, same as the agent cap): sent to the executor only
  over the encrypted control RPC, held in forwarder memory, never in
  `RunSpec`, an env var, or a log line.
- The mesh accept loop binds the orchestrator's mesh address only (never
  `0.0.0.0` — mesh CGNAT ranges like `100.64.0.0/10` make a wildcard bind
  unsafe) and, before writing any frame, requires: the transport's own peer
  address equals the run's recorded executor IP, the presented token matches
  in constant time, and the run's link slot is unclaimed — claimed atomically
  on accept, which also spends the token (one link per run, ever).
- Any failure (unknown run, wrong peer, wrong token, already-claimed slot)
  closes the stream having written zero bytes — no cap leaks on refusal.
- The mesh-IP check is defense in depth, not the gate by itself: a shared
  executor host means IP alone can't distinguish one run's forwarder from a
  sibling job on the same machine, which is exactly what the token is for.
- An unclaimed token's validity ends the moment its run is cancelled, times
  out, or the executor tears down (#269). `invalidate` reuses the same
  `claimed` flag `authenticate` claims on success — an invalidated link and an
  already-claimed one both need "reject any future attempt, write zero
  bytes," so one flag serves both outcomes with no new refusal variant. The
  call site (e.g. `Cancel`) logs the invalidation itself at the point it
  happens, so a reader does not mistake a later `AlreadyClaimed` refusal for a
  double-claim attack when it was actually a cancellation.

**Consequences.** B2's eventual mesh-accept loop needs a `JobRegistry` entry
shape that carries executor identity + token alongside the channel/caps it
already holds, and the accept path must reject before calling
`serve_agent_link` at all, not after. Acceptance tests (owned by whichever PR
implements this): wrong peer, wrong token, a second stream for an already-
claimed run, and an unknown run id each receive zero bytes; no log line or
error message ever carries the token.

**Set aside.** Trusting the mesh IP alone (WireGuard/Headscale already binds
an IP to a peer's key, so a bare `peer_addr()` looked tempting as sufficient):
rejected because the IP identifies the host, not the process — a second job
on the same executor shares that IP and could otherwise claim a sibling run's
stream before its real forwarder connects. mTLS certificates per run: more
machinery than a per-run token already colocated with the cap it's meant to
gate, for no added guarantee once the token is itself treated as a bearer
secret.

## 7. Frontend build order: CLI first; MCP is a thin layer over a GraphQL/REST API, never a direct control-RPC client

**Status:** accepted (operator directive, relayed by infra-f3).

**Context.** `sandyd` has two eventual client surfaces: the `sandy` CLI (B4,
already building against the control RPC directly) and an MCP frontend for
agents. A direct MCP-to-control-RPC design was the implicit assumption up to
now, since the CLI already works that way.

**Decision.** Build order is CLI → a GraphQL/REST API tier over `sandyd` →
MCP as a thin layer on that API, not on the control RPC. The CLI keeps
talking to `sandyd` directly (decision 1's control RPC is still the right
shape for a synchronous, single-daemon, local-or-one-hop client). The
GraphQL/REST API is a new tier between `sandyd` and anything else: it is
`sandyd`'s client-facing API surface, translating external requests into
control-RPC calls against one or more `sandyd` instances. MCP consumes that
API instead of speaking the control RPC's wire format itself.

**Consequences.** This adds a new crate/service to the architecture (the
GraphQL/REST API over `sandyd`), not yet designed — needs its own design pass
before implementation starts, same bar as #238's VM-agent sketch. The control
RPC itself does not need to grow MCP-specific concerns (auth models, batched
queries, subscriptions) since those live in the API tier instead. CLI
priority means `sandy daemon <op>` (decision 5) keeps shipping ahead of any
API/MCP work.

**Set aside.** MCP talking to the control RPC directly: would duplicate
whatever auth/session/query-shaping logic the API tier needs to do anyway,
and couples MCP's protocol choices to the control RPC's wire format instead
of a purpose-built client API.

## 8. Milestone 2: multiple remote sandboxes, each running the agent, communicating with each other

**Status:** accepted (operator directive, relayed by infra-f3).

**Context.** M2 had been read as "dispatch one job to one remote executor."
The operator's actual bar is bigger: "multiple remote sandboxes communicating,
agent inside each."

**Decision.** M2 is done when all three hold at once:

1. `sandyd` dispatches sandboxes to multiple remote hosts (not just one
   remote executor at a time).
2. Each dispatched sandbox runs the in-guest agent (#238, the VM-backed agent
   work), not just the process-backed agent B2 builds against today.
3. The sandboxes communicate with each other: peer-group channels spanning
   machines, not just each sandbox's own channel back to the orchestrator.

The comms substrate for (3) is decision 6 (per-run token + peer-identity
binding), #234's `forward_agent_link`, and the cross-machine channel transport
(#159). That moves decision 6's enforcement onto the M2 critical path: it is
a prerequisite for cross-machine peer channels to exist safely at all, not
hardening layered on afterward.

**Consequences.** Decision 6 (remote agent-link authentication) is
reprioritized — implementing it is no longer "whenever the mesh-dispatch PR
gets to it," it blocks M2 directly. Any sequencing of B2/B6/#159/#234/#238
work should treat decision 6's accept-loop implementation as a near-term
dependency, not a someday-follow-up.

**Set aside.** Treating M2 as satisfied by one-remote-executor dispatch
(B2's eventual swap of the test-double agent for a real one on a single
remote host): that is necessary but not sufficient — it proves dispatch
works remotely, not that multiple sandboxes can run and talk to each other,
which is the actual M2 bar.

## 9. Job-manifest capability derivation reuses `CapAuthority::attenuate` directly

**Status:** accepted.

**Context.** Decision C: a job's manifest is capped at the submitter's own
attenuation — a job can never be granted more capability than the submitter
holds (B3, #218). `sandy-control-proto`'s `SubmitRequest.manifest` carries the
manifest as opaque bytes today (#211/#214); the typed `JobManifest` and the
derivation are B3's job, independent of that envelope landing, since the
fabric seams it needs (`CapAuthority`, `Cap`, `attenuate`) are already on
main.

**Decision.** `sandy-orchestrator` (new crate, this issue's skeleton):
`JobManifest { entrypoint, requested_caps: Vec<CapRequest> }`, where each
`CapRequest { channel_id, rights }` names what the job wants. `derive_job_caps`
matches each request to the submitter's held `Cap` for that channel and
attenuates it via the existing `CapAuthority::attenuate` — which already
enforces "fail with `Widened` when rights isn't a subset of the parent's"
(#110, contract-tested). B3 adds no independent subset check of its own: a
second, redundant check would risk drifting out of sync with `attenuate`'s
rule, and would not catch the actual risk (B3 misusing the authority, e.g.
constructing a cap directly or swallowing a `Widened` error) — only correct
wiring plus a regression test does. Fail-closed and atomic: any single
un-grantable request fails the whole manifest with zero capabilities
returned, never a partial grant. The same function derives an `Attach`
request's cap too (`sandy-control-proto`'s `AttachResponse`), called with the
job's own held caps as `submitter_caps`.

`JobManifest` is a plain in-process Rust type, no `serde` derive: `sandyd`'s
B1 persists only the raw `SubmitRequest.manifest` bytes as received (no
interpretation at insert time, confirmed with B1's author), so there is no
competing serialized form to collapse against. Once `sandy-control-proto`'s
real typed `JobManifest` protobuf message lands (per its own decision record
§3's transitional plan), this type either becomes that generated type
directly or gains a `TryFrom` conversion from it — not two parallel manifest
representations maintained in sync by hand.

(§11 supersedes the no-`serde` decision above: `Submit` needs to actually
decode a manifest to bound it, so `JobManifest` gains `serde` derives there.
The JSON encoding (`MANIFEST_ENCODING_JSON`) is an interim wire form under
this same transitional plan, not a second permanent representation — it is
retired once the protobuf `JobManifest` lands and this type converts from or
becomes it, same as planned above.)

**Consequences.** The security-critical property (never escalate) lives in
exactly one place (`CapAuthority::attenuate`, already shipped and
contract-tested), not duplicated. `find(|c| c.scope.channel == channel_id)`
picks the first held cap per channel: fine for the MVP's one-cap-per-channel
assumption, which is explicit here rather than a silent limitation — a
submitter holding multiple caps per channel with different rights would need
a superset search instead, deferred until that shape actually exists.

Verified during this design that `Cap`'s fields (`scope`, `proof`) are public
— constructible outside `CapAuthority::mint`/`attenuate` — but this is not an
escalation path: `CapAuthority::verify` and `attenuate` reject a `Cap` whose
proof is altered or otherwise invalid as `Forged` (`capauth_suite`'s
adversarial case proves this) — not every hand-constructed `Cap`, since one
whose fields exactly match an already-valid capability's would still verify,
being indistinguishable from the real thing. Any future consumer of channel
membership must re-verify the proof before trusting scope rather than caching
it. Tracked as a low-priority type-design hygiene improvement, not a security
fix (#217).

**Set aside.** A redundant `is_subset_of` check in `derive_job_caps` before
calling `attenuate`: adds a second rule that can drift from the first, and
does not defend against the actual risk (misuse of the authority, not the
authority being wrong). Privatizing `Cap`'s fields as part of this work: real
and worth doing eventually, but it's `#110`'s capauth.rs, not B3's, and not a
security gap this block needs to fix to be correct (#217).

## 10. `Submit` mints a real per-job channel + caps directly; decision C's submitter-bounded derivation is a tracked follow-up (#226)

**Status:** accepted; the tracked gap is closed by §11.

**Context.** B2 wires `Submit`/`Attach` to the fabric for real: a per-job
`Channel` (spec §3.4's one-channel-per-sandbox) plus an agent cap (post+read)
and an observer cap (read-only, no post — a client that only watches a job's
output never gets to drive its stdin). Two genuine blockers stood between this
and a full dispatch pipeline: `ProcessBackend::with_agent`/the `sandy-agent`
binary (#216, in flight) don't exist yet, so nothing can actually join the
channel and run the job; and the typed `JobManifest` (#219/B3) isn't merged,
so there is no submitter-held-caps concept reaching `Submit` yet.

**Decision.** `mint_job_channel` (`sandyd::dispatch`) mints the job's channel
and caps directly from a fresh `LocalCapAuthority`, with no reference to the
submitter's own held capabilities. `Attach` returns the real channel id and a
decodable observer cap once a job is registered, or an honest, named refusal
otherwise — `no such job` for an id that was never submitted; a distinct
restarted-daemon message for a job the durable store remembers but whose
process-local channel is gone; a distinct expired-cap message when the
registered observer cap's own TTL has passed (`LocalCapAuthority::mint`
defaults every cap to a 24h expiry) — never a fabricated or unusable channel
id. A submitted job stays `Pending` forever in this slice: nothing yet joins
the channel or runs the job, which is the honest state of the remaining gap,
not a fake success.

**Consequences.** Decision C (a job's caps bounded by what its submitter
holds, via #219's `derive_job_caps`) is implemented but not called here —
direct minting bypasses it. That is acceptable only under a trusted-single-
local-operator model where the orchestrator is the only submitter; it stops
being safe the moment a submitter is anything else (a cross-machine client, a
sub-agent submitting a sub-job). Tracked as #226: enforce decision C at
`Submit` once a submitter-identity/held-caps model reaches this layer, in
place of direct minting.

Each job mints its own `CapAuthority` instance (a distinct HMAC key), not a
shared orchestrator-wide one: a cap minted for one job's channel fails
_signature verification_ against another job's channel, not merely a
channel-scope check. Stronger isolation than scope-matching alone, and a
deliberate property of per-job authorities, not an accident of this slice.

**Set aside.** Faking the manifest schema or the agent spawn to ship a
complete-looking dispatch path now: both would hide a fabricated success
behind a convincing surface, which the project's honest-gate discipline rules
out. The scoped slice above is fully real and fully tested; the remaining gap
is tracked, not hidden.

## 11. Decision C-at-Submit: bearer `submitter_caps` in the frame, one persistent orchestrator authority, trust from the connection (#226)

**Status:** accepted.

**Context.** §10 left decision C unenforced at `Submit`: no submitter
identity or held caps reached that layer, and each job minted its channel
from a brand-new `LocalCapAuthority` (§9/§10's own "deliberate property").
Closing it needs an answer to the actual authn question — _how does a
submitter's identity and held caps reach `Submit` over the control RPC_ —
and, once answered, ran into a structural requirement the earlier design
didn't anticipate: `derive_job_caps`'s `attenuate` call re-verifies a held
cap against the authority that originally minted it. Two independent
`LocalCapAuthority` instances can never recognize each other's caps by
construction (distinct HMAC keys, the exact property §9/§10 praised for
job-to-job isolation) — so a fresh-per-job authority makes the bounded path
structurally unreachable for every real submitter, not merely unenforced.

**Decision.**

- **Wire shape.** `SubmitRequest` grows `repeated bytes submitter_caps`, each
  entry an `encode_cap`-encoded `Cap` the submitter holds. No separate
  identity field: a `Cap`'s own `scope.peer` already carries the submitter's
  identity, and `CapAuthority::verify`/`attenuate` already re-check it
  (forged, expired, revoked — all caught the same way). This is the same
  bearer-cap authn every other seam in the fabric already uses
  (`Channel::join`, `AttachResponse`'s cap, the agent bootstrap handoff), not
  a connection-level identity (rejected: `SO_PEERCRED`/uid is a parallel
  trust model with no `CapAuthority` tie-in, and is UDS-only — dead on
  arrival for B6's vsock/mesh) and not a session/handshake (rejected: adds
  state the control RPC's one-request-one-response design, §1, deliberately
  avoids).
- **One persistent orchestrator authority.** `JobRegistry` now holds one
  `SharedCapAuthority` (`impls/fabric-local/src/capauth.rs`: an
  `Arc<LocalCapAuthority>` behind the `CapAuthority` trait), constructed once
  at `sandyd` startup, not a fresh instance per job. Every job's own channel
  (§10, unchanged in shape) mints from this same authority, and
  `submitter_caps` are verified against it too. **The HMAC key itself never
  leaves the process** — `SharedCapAuthority` exposes only `mint`/`verify`/
  `attenuate`/`revoke`/`is_revoked`, never the key; only the caps it mints
  cross any boundary (INV-1).
- **What decision C actually bounds.** The job's own dedicated channel stays
  sandyd's own infrastructure, minted directly regardless of who submits —
  same as every orchestrator channel in the all-local MVP (agent-fabric.md
  §11: a composition-root responsibility, not something a submitter's held
  caps bound). What `derive_job_caps` bounds is a manifest's ADDITIONAL
  `requested_caps`, onto channels the submitter already participates in (its
  own orchestrator channel, a peer group it was invited to). `JobManifest`
  (`sandy-orchestrator`) gains `serde` derives and a recognized
  `manifest_encoding` tag (`MANIFEST_ENCODING_JSON`) so `Submit` can actually
  decode one — its first real consumer.
- **Policy: trust comes from the connection, not from whether
  `submitter_caps` is present in the frame.** In the local-UDS MVP, the 0700
  socket IS the trust boundary — only the local operator reaches it — so
  direct-mint (§10's path, empty `submitter_caps`) stays legitimate there,
  and is not a silent opt-out: there is nothing to bound in that case, since
  the job gets only its own channel either way. The one frame-level refusal
  this block adds is a submitter presenting caps for a manifest `sandyd`
  cannot decode — never silently dropping caps the submitter went to the
  trouble of presenting. An untrusted submitter (cross-machine via B6, or a
  sub-agent submitting a sub-job) must always carry `submitter_caps` and be
  bounded; which connections those are is a future block's gate to add, not
  a property of this frame's contents. #226 builds the bounding MACHINERY,
  verified against a synthetic authority in tests, ready to activate — there
  is no real submitter-cap-issuance flow yet for sandyd's own operator
  either (#232, the CLI side, is the next piece of that).

**Consequences.** A cap minted for one job's channel still cannot join a
different job's channel, but the _reason_ changes from §10's `Forged`
(different signing key) to `WrongChannel` (same key, correctly verified,
scoped elsewhere) — **this is the designed boundedness mechanism, not a
regression to fix by separating authorities again.** Boundedness was always
`Channel::join`'s own channel-id check (agent-fabric.md §11), never the
authority's identity; a shared authority only changes which error a
cross-job cap fails with, not whether it's rejected. A manifest's granted
caps (the output of `derive_job_caps`) are stored on the job's registry entry
(`JobChannel.granted_caps`) but not yet consumed — there is no agent/
dispatch-core wiring to hand them to. Enforcing the bound AT SUBMIT TIME
(refusing an over-broad request before a job is ever created) is this
block's actual deliverable; handing granted caps to a running job is
dispatch-core's job once it exists.

**Set aside.** Requiring `submitter_caps` on every `Submit` regardless of
connection: would break the trusted-local-operator path for no security
gain today (the 0700 socket already is the trust boundary), and bakes in
B6's cross-machine trust model before it exists. Designing the connection-
trust gate itself (distinguishing a trusted UDS caller from an untrusted
mesh one): B6's job, not this block's — #226 only decides what a given
frame is allowed to grant, never which connections must present one.

## 12. The orchestrator side of the host-client contract: `Register`'s allowlist and the persistent dispatch connection (#263)

**Status:** partially implemented. `sandy-executor-proto` (new crate) defines
`HostClientMessage`/`OrchestratorMessage` (`Register`/`Registered`/
`RegisterRefused`/`Dispatch`), riding `sandy-control-proto`'s existing
length-prefixed framing. `sandyd::host_registry` (`ExecutorAllowlist`,
`HostRegistry`) and `sandyd::host_conn::serve_host_client` implement the
orchestrator side end to end: authenticate an incoming `Register` against the
allowlist, reply `Registered`/`RegisterRefused`, then relay `Dispatch`
messages queued for that host down its one persistent connection until it
closes. The executor side (#283, sandy-91) is also done: `sandy-host-client`'s
`handle_dispatch` decodes a `Dispatch`, independently re-checks the isolation
class, launches the trusted-process sandbox, and forwards its agent's link
back over the mesh. What is NOT yet built: anything that calls
`HostRegistry::register` from a real network accept loop (no `sandy-conn`
listener is bound in `sandyd`'s `main.rs` yet, and `sandy-host-client`'s own
`main.rs` doesn't send `Register` or receive `Dispatch` yet either — tracked
as #288), and the nix overlay/service that runs `sandy-host-client` as a
registered executor.

**Context.** #269's spec frames M2 cross-machine dispatch: the orchestrator
stays the single authority (caps, channels, the peer-hub); a remote host is an
_executor_, not an independent orchestrator, so the agent link forwards back
to the orchestrator rather than staying local. #263 is the contract between
them: capability-declaring registration (kubelet-style — the host-client
detects and declares what it can run, the orchestrator dispatches against
that declaration, never a hardcoded host) plus the dispatch RPC.

**Decision.**

- One persistent, bidirectional connection per host-client, not request/
  response (unlike decision 1's control RPC): the host-client sends `Register`
  once, then the orchestrator pushes zero or more `Dispatch` messages down the
  _same_ connection as it places jobs there. The connection staying open is
  the host's liveness signal — no separate heartbeat protocol, and (per #269)
  no re-registration machinery for stage 1.
- `Register`'s `host_id` is self-reported and used for bookkeeping/placement
  only — it is never the authorization boundary (an architect ruling,
  infra-f3, on #263): the orchestrator authenticates the registrant by the
  _transport's_ own peer identity (the mesh IP `sandy_conn::PeerAddr::Tcp`
  reports) against `ExecutorAllowlist`, the same "never trust a self-reported
  value for authorization" discipline decision 6 already applies to the
  agent-link stream. An unknown registrant gets `RegisterRefused`, never
  `Registered`, and is logged — never silently dropped, and never told more
  than "no".
- `Dispatch.required_isolation_class` (added per #269's CodeRabbit-driven spec
  revision): the job's required isolation class travels with the dispatch so
  the orchestrator/executor can refuse fail-closed rather than silently
  downgrade an untrusted job onto stage 1's trusted-process backend.
  `Capabilities.supported_isolation_classes` is the matching declaration on
  the host-client side.
- `sandy-executor-proto` is its own crate (not folded into
  `sandy-control-proto`), landed as a standalone artifact before either side's
  implementation, so the orchestrator half (this slice) and the executor half
  (sandy-91, #263) build against one shared type definition instead of two
  independently-declared, potentially-diverging copies.
- `register` guards against two gaps a CodeRabbit review on this PR caught:
  a `host_id` already claimed by a different allowlisted peer is refused
  (`RegisterError::HostIdClaimedByAnotherPeer`) rather than silently handed
  to whichever peer registers it second, and `remove` takes the
  `RegistrationId` its own `register` call returned so a stale connection's
  teardown can never evict a newer reconnect under the same `host_id`.
  `send_dispatch` enforces the isolation-class gate the `Dispatch` proto's
  own doc comment already promised (the `required_isolation_class` bullet
  above): a dispatch whose
  `required_isolation_class` the target host never declared is refused
  outright, including an unset/`Unspecified` class, which never matches
  anything. `serve_host_client` also bounds how long an accepted connection
  may sit before sending `Register`, so an open-and-never-write peer cannot
  hold a connection slot forever.

**Consequences.** `host_registry`'s module doc states explicitly what it does
NOT do (accept connections, drive the loop) so the authorization logic stays
unit-testable without a real socket — the same shape decision 6's
`link_auth` module already established. The real accept loop (binding a mesh
address, calling `serve_host_client` per accepted connection) and the
placement logic that decides when to call `send_dispatch` are both still
open; tracked by #263 and #269's stage-1 block list, not silently assumed.
There is also no `OrchestratorMessage` variant for cancelling a dispatched
job: a cancelled run's sandbox keeps executing on the host until it finishes
on its own (decision 6's token invalidation, §6, stops a late-arriving
executor stream from claiming the run's agent link, but does nothing to stop
the host-side process itself). Confirmed intentionally deferred past M2, not
a contract break — a future `Cancel`/`Stop` message is an additive `oneof`
variant, not a breaking change to what's shipped here.

**Set aside.** Building the mesh-address accept loop and wiring it into
`main.rs` in this same slice: that needs a decision this PR doesn't own (how
`sandyd` learns its own mesh bind address — CLI flag, config, the nix
overlay's service unit) and isn't needed to prove the `Register`/`Dispatch`
logic correct in isolation, matching the same "test the logic, defer the
wiring" discipline used throughout B2. Resolved by decision 13.

## 13. Mesh bind addresses are environment variables; two separate listeners, not one multiplexed (#291)

**Status:** partially implemented. `sandyd::mesh_config` parses
`$SANDY_MESH_LISTEN` (the host_conn management-channel's bind address) and
`$SANDY_MESH_ALLOWLIST` (comma-separated executor mesh IPs), both pure
functions fully unit-tested against raw string values, not real process
environment. `main.rs`'s `setup_mesh_listener` reads them, refuses to start
if a listen address is configured with an empty allowlist (a listener nobody
could ever pass), binds via `sandy_conn::listen`, and `run_mesh_accept_loop`
serves accepted connections against a dedicated `HostRegistry` as its own
background task. What is NOT yet built: the mesh_accept (agent-link) listener
and its own bind-address env var — that side depends on #290's accept loop
landing on main; this decision's config surface and wiring pattern extend to
it directly once it does, as a small follow-up, not a redesign.

**Context.** #291's architect rulings (relayed by infra-f3): two separate
mesh-bound listeners/ports (the host_conn management channel and the
mesh_accept agent-link accept are different wire protocols — the contract
already keeps them distinct via `Dispatch.forward_back`'s own host:port), not
one multiplexed port demuxing on the first frame (simplicity-first for M2).
Bind address is config-driven, never hardcoded, mesh-only (D5) — an operator
sets it per node, the nix service unit (#287) injects it in production.

**Decision.**

- `sandyd` has no `clap`/CLI-flag surface at all today (`$SANDY_SOCK`,
  `$SANDY_DB` are its only existing config knobs, both environment
  variables) — `$SANDY_MESH_LISTEN`/`$SANDY_MESH_ALLOWLIST` follow that same
  established convention rather than introducing a parallel CLI-args
  mechanism for just this one feature.
- Unset `$SANDY_MESH_LISTEN` is the default and fully supported: `sandyd`
  stays local-only, identical to its behavior before #291. M2 cross-machine
  dispatch is additive, never a requirement to run `sandyd` at all.
- A configured listen address with an empty (or unset) allowlist is a
  startup-time hard refusal (`std::process::exit(1)`), not a listener that
  silently accepts and then refuses every connection forever — the two are
  observably different (a refusing-but-running process looks healthy to
  process supervision; a process that never started does not), and the
  distinction matters for an operator who forgot to set the allowlist
  alongside the listen address.
- The mesh accept loop runs as its own `tokio::spawn`'ed background task
  (not folded into `main`'s existing UDS `select!` loop): it shares no state
  with the control-socket path beyond the process itself, and the
  alternative (threading an `Option<Listener>` through the shared `select!`
  with a `pending()` fallback branch) was tried and discarded as needlessly
  convoluted for two independent accept loops that never need to coordinate.

**Consequences.** `sandyd`'s mesh listener has no graceful-shutdown
coordination with the daemon's own `SIGTERM`/`SIGINT` handling yet — it is a
detached task that the process's own exit simply drops, unlike the UDS
listener's bounded grace period for in-flight connections. Acceptable at
this stage (no live cross-machine traffic exists to lose gracefully yet);
revisit once #272's live e2e exercises this path for real.

**Set aside.** A CLI-flag surface (`clap`) for these two env vars: `sandyd`
has never had one, and introducing `clap` as a dependency for two optional
knobs when the rest of the binary's config is env-var-only would be
inconsistent with the binary's own established shape, not a simplification.
