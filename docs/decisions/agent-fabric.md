---
title: "Decisions: agent-fabric seam contracts (sandy-fabric)"
status: accepted
project: sandy
updated: 2026-10-16
---

# Decisions: agent-fabric seam contracts (`sandy-fabric`)

The contract crate for the agent fabric (epic #103, block 0 / #104): the seam
traits, their types, and the shared contract-test harness every impl passes. Spec:
`~/Fun/specs/sandy/sandy-agent-fabric.md` §2, §3, §5.

## 1. One contract crate, one suite per seam

**Status:** accepted.

**Context.** Every fabric seam ships a trivial local impl and richer ones later
(spec §2). Each must be held to the same behaviour, or the all-local MVP proves
nothing about the VM, remote, or P2P impls that replace it.

**Decision.** `crates/sandy-fabric` holds only traits, types, and the harness,
mirroring `sandy-api`. The `contract` module (feature `contract-tests`) has one
generic `*_suite` per seam; an impl crate passes its impl through a factory and
gets `Err(ContractViolation)` naming the broken rule. In-crate, a reference fake
per seam must pass, and a deliberately broken fake per rule must fail on that
rule, so no suite is a no-op.

**Consequences.** Impls live in their own blocks and cannot weaken the contract
locally. A suite cannot check what it cannot observe, so some suites take extra
inputs: the executor's true `Capabilities` and a telemetry `captured` count.

**Set aside.** Per-impl ad-hoc tests: they drift apart, and a trivial impl
passing its own tests says nothing about a real one.

## 2. The logical `Envelope` lives here; protobuf is a codec

**Status:** accepted.

**Context.** The channel envelope is "a logical contract; protobuf is its default
codec; a text/chat backend re-encodes the same envelope" (spec §3.3).
`ChannelBackend` needs the envelope type.

**Decision.** `Envelope { seq, msg_type, content_type, payload, metadata }` is
defined in `sandy-fabric`. `sandy-proto` (#105) depends on `sandy-fabric` and maps
it to and from the protobuf wire type. `msg_type` is a `String` (the `oneof` tag)
because the per-role message types are still open (spec §8). The content id rides
in `metadata` under `MSG_ID_KEY`.

**Consequences.** #104 and #105 stay independent Wave-0 blocks; any backend can
re-encode the envelope without a protobuf dependency.

**Set aside.** Using #105's generated type as the envelope: it makes the contract
crate depend on its codec and blocks the Wave-1 barrier on #105.

## 3. The channel is not a seam; `ChannelBackend` is

**Status:** accepted.

**Context.** Spec §5 lists no alternative impls for the channel; the backends
(in-memory, vsock, P2P, chat, MQ) are what vary.

**Decision.** No `Channel` trait. The channel is one concrete
`Channel<B: ChannelBackend>` (#106) that layers membership, cap checks,
sequencing, and the content id on top, once. `ChannelBackend` is a dumb,
content-addressed log: idempotent `append` on the content id, `fetch` in `seq`
order for `seq >= from_seq` whatever the arrival order, and `stream_from`, which
replays and then follows as one primitive.

**Consequences.** Every backend inherits dedup and gap-free resubscription,
because the suite checks both, including a stream opened before an append.

**Set aside.** A fetch-then-subscribe composition: it has a window where a
message lands between the two and is missed.

## 4. Async I/O seams, sync compute seams

**Status:** accepted.

**Context.** The fabric targets store-and-forward over links nobody can assume are
live (spec §1). The existing `VmBackend` is sync.

**Decision.** The I/O seams (`Executor`, `ChannelBackend`, `Transport`,
`Discovery`, `Capacity`, `Lifecycle`, `TelemetrySink`) are async and `Send`,
written as `fn … -> impl Future<Output = …> + Send` (bare `async fn` in a public
trait trips `async_fn_in_trait` under deny-warnings). `CapAuthority` and `Minter`
are CPU-bound and sync. Suites are runtime-agnostic and never await an envelope
that is not already stored, so a broken stream fails instead of hanging.

**Consequences.** Real transports and remote executors land without a trait
rewrite. Static dispatch by default; a composition root that needs `dyn` boxes at
its own boundary.

**Set aside.** All-sync traits matching `VmBackend`: they would be rewritten when
the first remote transport lands.

## 5. `Executor` is additive over `VmBackend`

**Status:** accepted.

**Context.** The executor generalizes `VmBackend` to the fleet (spec §3.1), but
reconcile, the supervisor, and the CLI use `VmBackend` directly.

**Decision.** `Executor` (`run`/`kill`/`observe` plus a sync `capabilities()`) is
a new seam reusing `sandy-api`'s `RunSpec`, `Outcome`, `BoxState`, and
`SandboxKind`. An adapter (#108) wraps any `VmBackend`. `capabilities_satisfy`
matches kind exactly, so a VM-only job never lands on the process executor, and
matches arch only when one is required. The suite fails an executor whose
capabilities differ from the caller's truth, or that reports a non-zero exit as an
infra fault.

**Consequences.** No caller migration now; unifying the two seams stays a
separate, deliberate step.

**Set aside.** Renaming `VmBackend` to `Executor`: it forces every caller to
migrate before the fabric needs it.
