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
