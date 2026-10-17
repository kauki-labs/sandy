---
title: "Decisions: sandyd control plane"
status: accepted
project: sandy
updated: 2026-10-16
---

# Decisions: sandyd control plane

The daemon + control RPC for the fabric (epic #205): a per-machine `sandyd`
dispatching jobs into the agent fabric, with thin CLI/MCP frontends. Builds on
the all-local fabric MVP (#103). Operator-confirmed design: (B) a dedicated
control RPC separate from the fabric's data/event channels, (C) a submitter-
bounded job manifest.

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

**Status:** planned — this is a requirement on the not-yet-built remote-executor
dispatch path, recorded now so it is designed in from the start rather than
retrofitted. Nothing in the current codebase implements it; tracked by #212.
Promoted from a cross-machine-safety nicety to the M2 critical path (decision
8): M2's cross-sandbox peer-group channels depend on this binding existing.

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
