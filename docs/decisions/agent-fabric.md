---
title: "Decisions: agent-fabric seam contracts (sandy-fabric)"
status: accepted
project: sandy
updated: 2026-10-16
---

# Decisions: agent-fabric seam contracts (`sandy-fabric`)

The contract crate for the agent fabric (epic #103, block 0 / #104): the seam
traits, their types, and the shared contract-test harness every impl passes. Spec:
[`../design/agent-fabric/spec.md`](../design/agent-fabric/spec.md) §2, §3, §5.

## 1. One contract crate, one suite per seam

**Status:** accepted.

**Context.** Every fabric seam ships a trivial local impl and richer ones later
(spec §2). Each must be held to the same behaviour, or the all-local MVP proves
nothing about the VM, remote, or P2P impls that replace it.

**Decision.** `crates/sandy-fabric` holds only traits, types, and the harness,
mirroring `sandy-api`. The `contract` module (feature `contract-tests`) has one
generic `*_suite` per seam; an impl crate passes its impl through a factory and
gets `Err(ContractViolation)` naming the broken rule. In-crate, a reference fake
per seam must pass, and deliberately broken fakes (at least one per seam, one per
security-relevant rule) must fail on the rule they break, so no suite is a no-op.

**Consequences.** Impls live in their own blocks and cannot weaken the contract
locally. A suite cannot check what it cannot observe, so some suites take extra
inputs: the executor's true `Capabilities` and a bootable template, a telemetry
`captured` count, and a deadline for stream waits. The suites assume
read-your-writes, the step-1 contract; an eventually consistent impl settles
before returning or brings a settle step to the suite when it lands.

**Set aside.** Per-impl ad-hoc tests: they drift apart, and a trivial impl
passing its own tests says nothing about a real one.

## 2. The envelope is `sandy-proto`'s; the fabric depends on it

**Status:** accepted.

**Context.** The spec calls the channel envelope "a logical contract; protobuf is
its default codec; a text/chat backend re-encodes the same envelope" (§3.3). The
only codec today is protobuf; the text/chat backend is deferred (§7).

**Decision.** `ChannelBackend` carries `sandy_proto::Envelope` (#105: `sequence`,
`oneof message_type`, `content_type`, `payload`, `metadata`), re-exported from
`channel_backend`. `sandy-fabric` depends on `sandy-proto`. The content id rides in
`metadata` under `MSG_ID_KEY`, read with `msg_id()`.

**Consequences.** One envelope type across the fabric, and #104 builds on #105. A
second codec, when it lands, maps to and from this type.

**Set aside.** A separate logical envelope in `sandy-fabric` with protobuf as one
codec of several: it builds a split for a codec that is not planned yet. Reopen it
when the text/chat backend lands.

## 3. The channel is not a seam; `ChannelBackend` is

**Status:** accepted.

**Context.** Spec §5 lists no alternative impls for the channel; the backends
(in-memory, vsock, P2P, chat, MQ) are what vary.

**Decision.** No `Channel` trait. The channel is one concrete
`Channel<B: ChannelBackend>` (#106) that layers membership, cap checks,
sequencing, and the content id on top, once. `ChannelBackend` is a dumb,
content-addressed log: idempotent `append` on the content id (keeping the first),
`fetch` in `sequence` order for `sequence >= from_seq` whatever the arrival order,
and `stream_from`, which replays and then follows as one primitive.

**Consequences.** Every backend inherits dedup and gap-free resubscription at a
cursor, because the suite checks both, including a stream opened before an append.
Whether a late envelope below a stream's cursor is emitted live is open (#162).

**Set aside.** A fetch-then-subscribe composition: it has a window where a
message lands between the two and is missed.

## 4. Async I/O seams, sync compute seams

**Status:** accepted.

**Context.** The fabric targets store-and-forward over links nobody can assume are
live (spec §1). The existing `VmBackend` is sync.

**Decision.** The I/O seams (`Executor`, `ChannelBackend`, `Transport`,
`Discovery`, `Capacity`, `Lifecycle`, `TelemetrySink`) and `Minter` are async and
`Send`, written as `fn … -> impl Future<Output = …> + Send` (bare `async fn` in a
public trait trips `async_fn_in_trait` under deny-warnings). `Minter` is async
because its controller-transit impl mints over the network, once per job.
`CapAuthority` stays sync: verify is on the hot path of every join, post and
subscribe and is pure crypto; a chain-backed root verifies against a locally
synced cache. Every seam is `Send + Sync`. `ChannelBackend::stream_from` returns
a `'static` stream, so a subscriber can read it from a spawned task. Suites are
runtime-agnostic; a stream wait races a caller-supplied deadline, so a broken
stream fails instead of hanging and an I/O-backed one gets time to deliver.

**Consequences.** Real transports and remote executors land without a trait
rewrite. Static dispatch by default; a composition root that needs `dyn` boxes at
its own boundary.

**Set aside.** All-sync traits matching `VmBackend`: they would be rewritten when
the first remote transport lands. An async `CapAuthority`: it would add a poll to
every message for impls that never wait.

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

`run` borrows `&RunSpec<'_>`, so the `VmBackend` adapter runs the blocking call
with `block_in_place`: one async worker is held per run (as on today's sync path),
and the composition root needs a multi-thread runtime.

**Set aside.** Renaming `VmBackend` to `Executor`: it forces every caller to
migrate before the fabric needs it. An owned `RunSpec` for `spawn_blocking`: it
would dup the `SecretSource::Fd` into a new fd lifetime, against the secret-channel
discipline (INV-1), and make a deliberately borrowed, non-`Clone` type owned.

## 6. `LocalCapAuthority`: HMAC-SHA256, attenuation through the authority

**Status:** accepted.

**Context.** Spec §3.8 calls the default `CapAuthority` "biscuit-style
(placeholder)"; #110 is the step-1 local impl, landing in the shared
`sandy-fabric-local` crate (`impls/fabric-local`) alongside the other local seam
impls. #129 resolved revocation as a verify-time check against an issuer-owned
set.

**Decision.** `LocalCapAuthority` signs a length-prefixed canonical encoding of
`CapScope` with HMAC-SHA256, keyed by a random 32-byte key generated per instance
and held only by the process that mints and attenuates (a sandbox never holds it,
so a self-minted cap fails `verify` as `Forged`, INV-1). The proof is also the
cap's stable id for #129's revocation set (an in-process `HashSet`, checked in
`verify` after expiry): no new field on `Cap`. `attenuate` verifies the parent
first (a tampered or revoked parent can't be attenuated), narrows rights, and
carries the parent's `expires_at` over unchanged, so a child can never widen scope
or extend its TTL. Attenuation always goes through the authority; there is no
holder-side offline attenuation. A scope minted with `expires_at: None` gets a
concrete expiry (`now + default_ttl`, `default_ttl` injected at construction)
resolved into the signed scope before signing, so "`None` means the authority's
default TTL" is literal, not an unbounded cap (CWE-613).

**Consequences.** "Biscuit-style" means narrowing-only delegation, not the
`biscuit-auth` crate's datalog caveats — swapping in real biscuit tokens, or a
blockchain-backed root, stays entirely behind the seam. Revocation distribution
over the channel/transport (the content-addressed, eventually-delivered half of
#129) is deferred to whichever issue wires it in; a verifier that hasn't seen a
revocation still relies on TTL as the backstop, which now always holds since
minting never leaves an unresolved expiry. Two caps minted for a byte-identical
scope (same peer, channel, rights, and expiry) still share a proof, so revoking
one revokes both; #181 tracks giving independently minted caps independent
proofs without widening `Cap`.

**Set aside.** The real `biscuit-auth` crate, for its offline holder-side
attenuation: spec §3.4 has membership orchestrator-assigned in step 1, and the
orchestrator can already reach the authority, so paying for offline attenuation
now buys nothing yet; it is the deferred, richer impl behind the same seam.

## 7. All-local placement: static registry, direct probe, leases, first fit

**Status:** accepted.

**Context.** Placement needs a default for each of its three seams (spec §3.6,
§3.7) and one policy that combines them, which the composition root (#115) calls
rather than reimplements.

**Decision.** In `sandy-fabric-local` (`placement.rs`, #112):

- `StaticRegistry` is a host list (`localhost` for the all-local profile) filtered
  with `capabilities_satisfy`.
- `ExecutorCapacity` probes an `Executor` directly: free slots are its limit minus
  the boxes `observe()` reports.
- `LeaseTable` is lease soft-state on an injected `Clock`. A lease is live while
  `now < deadline`; at the deadline it lapses and is unknown to every call. A host
  holds one lease: registering again replaces it, so deregistering ends liveness.
- `place` returns the first host `find` yields that has a live lease and a probe
  that `can_accept()`. A failed probe skips that host; if every live candidate's
  probe failed, `place` errors rather than returning `None`, so an unreadable
  capacity plane is not mistaken for a full fleet.

**Consequences.** The crate depends only on `sandy-fabric` (and `sandy-api` in
tests), so it builds without the Executor impls of #108. Any `Executor` plugs into
`ExecutorCapacity`. A probe reserves nothing, so two concurrent placements can take
the same last slot; the executor enforces its own limit, and in-flight accounting
belongs to the composition root (#115).

**Set aside.** Seeding the registry from the nix machines table via
`parse_builder_systems`: that table lists build systems, not hosts with a sandbox
kind, and the parser lives in the heavy `sandy` core. It is M4 cross-machine work.
