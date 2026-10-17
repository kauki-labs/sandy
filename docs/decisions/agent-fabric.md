---
title: "Decisions: agent-fabric seam contracts (sandy-fabric)"
status: accepted
project: sandy
updated: 2026-10-17
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

**Consequences.** Placement needs only `sandy-fabric`'s traits, not #108's
concrete executor, so it builds and tests (with a fake `Executor`) on its own. Any `Executor` plugs into
`ExecutorCapacity`. A probe reserves nothing, so two concurrent placements can take
the same last slot; the executor enforces its own limit, and in-flight accounting
belongs to the composition root (#115).

**Set aside.** Seeding the registry from the nix machines table via
`parse_builder_systems`: that table lists build systems, not hosts with a sandbox
kind, and the parser lives in the heavy `sandy` core. It is M4 cross-machine work.

## 8. Agent-local minting and delivery through the secret channel

**Status:** accepted.

**Context.** A job's work-secret and its channel join cap must reach the sandbox
without touching argv, the environment, or the Nix store, and the sandbox must not
be able to mint its own cap (spec §3.8, INV-1).

**Decision.** In `sandy-fabric-local` (`minter.rs`, #111):

- `LocalMinter` mints 32 bytes from the OS CSPRNG on the host.
- `stage_secret` writes bytes to a `0600` file (unique temp file, sync, rename,
  directory fsync) and returns a `SecretRef` for `RunSpec.secrets`; the backend's
  existing secret channel carries the work-secret into the guest. The staging
  directory must be this user's and not group- or world-writable; names must be
  env-var names; store paths are refused, also after resolving symlinks.
- The channel cap does not ride that channel. The guest exports every staged
  secret into the job's environment from a mount the job can read, so a cap there
  would let the untrusted job act as the agent. The bootstrap orchestrator cap goes
  to the agent out of band over its launch channel: vsock for a VM, the first frame
  on the agent link for the local backend (§10), never an env var (#108, #109).
  `stage_cap` is a host-side writer for an agent-only surface. It returns a path,
  not a `SecretRef`, so the cap cannot be put into `RunSpec.secrets` by accident.

**Consequences.** The minter and staging reuse the one secret path every backend
already supports. The `0600` writer duplicates `sandy::cred::write_secret_0600` to
keep `sandy-fabric-local` free of the `sandy` core; #174 consolidates the two.

**Set aside.** Controller-transit minting as the default: the secret would cross
the network. It stays the opt-in alternative behind the same `Minter` seam. For the
cap: a reserved name the guest's export loop skips (the file stays readable on the
job's mount), and an agent-only subdirectory (it holds only where the backend gives
agent and job a real uid or mount boundary, which the local process backend may not).

## 9. Local-first telemetry: an append log, off by default

**Status:** accepted.

**Context.** Telemetry must survive an unreachable orchestrator, need no network,
and stay off unless asked for (spec §3.5).

**Decision.** In `sandy-fabric-local` (`telemetry.rs`, #114):

- `LocalLog` appends one JSON record per line with `O_APPEND` to a `0600` file and
  syncs it, so a record is durable once `emit` returns. Disabled by default: it
  records nothing and creates no file. On read, an unreadable line is skipped with
  a warning. A crash mid-append leaves a torn line, and the next emit closes it off
  with a newline, so it sits between whole records and every durable record stays
  readable.
- `LocalFirst<S>` writes the local log first and fails only if that fails, then
  forwards to `S` best effort. With telemetry off it neither logs nor forwards.

**Consequences.** A dead orchestrator or channel loses no record. The
channel-routed sink plugs in as `LocalFirst<ChannelSink>` once the channel roles
(#113) land.

**Set aside.** Content-addressed records now: `TelemetryRecord` has no timestamp or
sequence, so hashing would merge repeated identical events. Content-addressed pull
of the log is spec §7 work.

## 10. The sandbox agent: a separate process, TTY over the existing envelope, an honest break-glass stub

**Status:** accepted. The process wiring (#216) supersedes the original fd-3 cap
pipe.

**Context.** The agent is "the only door": the sandbox boundary is the trust
boundary, and a channel must never become a bypass of it (spec §4). The bootstrap
orchestrator-channel cap in particular must never reach the job it supervises — a
job holding it could post as the agent.

**Decision.** In `sandy-fabric-local` (`agent.rs`, `link.rs`) and `sandy-agent`
(`impls/agent`):

- The agent is its own OS process, between the executor and the job. With
  `ProcessBackend::with_agent`, the backend launches `sandy-agent -- <job>` inside
  the containment, and the agent runs the job as its child with fresh stdio pipes.
  "Agent is the only door" means the same thing once a VM-backed agent exists.
- The agent does not hold the channel. Verifying a cap needs the authority's key,
  and an agent with that key could mint its own caps (§8). The channel stays with
  the orchestrator, and `serve_agent_link` relays for one agent over a private link
  the backend creates per run: a close-on-exec unix socket pair, one end as the
  agent's stdin (`AGENT_LINK_FD`, sandy-fabric), the other handed to the caller's
  `on_link`.
- The bootstrap cap is the first frame on that link, read exactly once and
  presented back in `Join`; the relay runs `Channel::join`, so a forged, expired,
  or wrong-channel cap is refused there. One `Join` per link. The agent may post
  only `TTY_STDOUT`/`TTY_STDERR`; the relay delivers `TTY_STDIN`. The cap is never
  a staged file: the guest's login shell exports every file under
  `/run/sandy/secrets` into the job's environment (#177).
- In a VM (#238) the link is one vsock stream. The agent is baked into the
  guest image; the topology names its store path (`agent_program`). The console
  launches it as `agent --vsock-listen 5000 -- sh -c <job>`, and the host
  connects to it, never the other way round, so the relay only ever dials its own
  VM. The agent accepts the first connection from the host (CID 2), rejecting any
  other peer while it keeps listening, closes the listener, and writes one ready
  byte before the relay writes the cap, because vfkit accepts the host's socket
  before it dials the guest. vfkit exposes the port as a per-run unix socket in
  the private staging base (`connect` mode); the qemu leg connects over
  `AF_VSOCK` to a CID it claims by launching. In step 1 secrets keep reaching the
  job through the guest's login-shell export, and the agent passes that
  environment through unchanged; #177 replaces the export with an agent-owned
  allowlist.
- Peer channels (#238 slice 4) ride the same link; there is no guest-to-guest
  networking. A relay started with peer grants (`serve_agent_link_with_peers`)
  announces how many peer caps follow the orchestrator cap and hands each over
  in lockstep: `Cap{channel}`, the agent's `Join{channel}` with exactly that cap,
  `Joined{channel}`. `Post` and `Deliver` carry the channel; frames without one
  are the orchestrator channel, so a link without peers keeps its wire form.
  Every peer post and delivery is authorized against that channel's own
  membership, never against holding the link: a post to a channel the link did
  not join, or TTY traffic on a peer channel, ends the relay, and the relay only
  subscribes to channels it joined. A post the channel refuses on a joined
  channel (its cap expired or was revoked) is logged and dropped, and the relay
  goes on, so the job's exit report still arrives (INV-11); a backend fault
  still ends the relay. The job's `send` is not told of the refusal yet. Peer messages are `PeerMsg`-typed, and the
  agent's own posts come back like any member's. The agent's peer inbox
  (`LinkAgent::take_peer_inbox`) is bounded and drops any delivery that arrives
  while it is full; what it keeps stays in order, and every drop is counted
  (`LinkAgent::peer_dropped`) and logged, so a loss is observable, never silent.
  The count says that deliveries were dropped and how many, not where they fell
  among the kept messages: once the inbox drains, newer deliveries are accepted
  again, so kept messages need not be consecutive. The sender is not told; its post is durable on the
  channel. In v1 membership is fixed for
  the run: sandyd mints each peer cap at dispatch, and a sandbox cannot be added
  to a group mid-run; dynamic invite (`CapRights.invite`) is a later slice.
- The job never inherits the link: the agent keeps a close-on-exec duplicate,
  points its own stdin at `/dev/null`, and gives the job fresh pipes. Its
  environment is the backend's, unchanged.
- The job's result travels over the link, not in the agent's exit status
  (INV-11). After the job exits, the agent sends its code (`128 + signal` for a
  signal death) as the link's last frame; the relay returns it, and the caller
  reports it to the backend through the `AgentReport` that `on_link` received.
  The backend takes `guest_exit` only from that report. No report (the agent was
  refused, faulted, panicked, or was killed) is an infra fault. The agent's
  process status cannot serve: under `bwrap` it is the wrapper's, and the job
  shares the agent's uid and can signal it. The agent tees the job's output to
  its own stdio, so `Outcome.console` is unchanged.
- TTY traffic reuses the existing `Tty` envelope marker with no new wire type:
  `content_type` (`TTY_STDIN`/`TTY_STDOUT`/`TTY_STDERR`) carries the direction,
  raw bytes ride `payload`. In-process (`SandboxAgent`) and as a process
  (`LinkAgent`), the agent bridges through one shared function. Cap-scope
  enforcement (observe vs interact) is never duplicated in the agent:
  `Channel::post` already refuses a non-`post` member before an envelope is
  stored.
- `RawConsole` (sandy-fabric) is the break-glass seam; `UnavailableConsole` is the
  process backend's impl, reporting `Unavailable` and refusing every read/write —
  a bare process has no serial console, and a silent no-op there would be
  indistinguishable from a working fallback until an operator actually needed it.
  The real console wiring (`sandy_api::console::Transport`, already built for the
  VM run path) lands with a VM-backed agent.

**Consequences.** The relay's join and the `Channel`'s own rights enforcement are
the only places INV-1/boundedness is enforced for this surface; no second copy of
either check exists to drift out of sync. An agent-mode `ProcessBackend` runs one
job, and the composition root builds one per sandbox run, with `on_link` closing
over that run's channel and cap: re-joining with a cap replays the channel's
earlier stdin, so neither may be reused across runs (spec §3.4). Known limits of
the local process backend: a job shares the agent's uid, so it can kill its agent
(an infra fault, never a result it chose) and, where `ptrace` is open, read the
agent's memory (the agent marks itself non-dumpable on Linux); on macOS a socket
pair gets close-on-exec in a second call, so another thread's spawn in the same
host process can race it. `UnavailableConsole` means #109's
"break-glass works when the agent is down" positive case is honestly NOT
demonstrated for the process backend; it is deferred to the VM-backed
`RawConsole`, tracked separately.

**Set aside.**

- The cap on a separate pipe at fd 3 (the original `AGENT_CAP_FD`). Under
  `forbid(unsafe_code)` the agent cannot claim a descriptor above 2, and an
  unclaimed inherited one carries no close-on-exec flag into the job. Stdin also
  survives the `systemd-run` and `bwrap` wrappers without fd-passing flags.
- The agent hosting its own `Channel` over a shared backend: it would need the
  authority's key to verify caps.
- Staging the cap under a reserved name or a separate agent-only subdirectory on
  the existing secrets mount: both still share the mount the job reads from and
  depend on the backend giving the agent and the job distinct identities, which
  the local process backend does not (§8).
- Wiring `sandy_api::console::Transport` into `RawConsole` now: no VM-backed agent
  exists yet to wire it to.

## 11. Channel roles are thin wrappers; `EscalationSink` is a new seam

**Status:** accepted.

**Context.** Spec §3.4 names three channel roles (orchestrator, peer-group,
escalation) over `Channel` (#106). The orchestrator channel also carries the
optional-telemetry leg (§3.5); the escalation channel needs to survive the
orchestrator path being the problem.

**Decision.** In `sandy-fabric-local` (`roles.rs`, #113): `OrchestratorRole`,
`PeerGroupRole`, `EscalationRole` wrap `Channel<B, A>` and add nothing to its
boundedness, cap verification, or dedup/ordering — they only name the
operations a given channel is used for.

- `ChannelAssignment { channel_id, cap, role }` (the orchestrator's channel-grow
  message, a `Control`-typed envelope's payload) lives in `sandy-fabric`
  itself, not the impl crate: `Channel` is a concrete layering, not a trait, so
  the payload both #113's role code and #109's agent read has no business
  depending on either side's crate. JSON-encoded, matching `encode_cap`/
  `decode_cap`'s own choice for `Cap`, with an explicit `role` tag rather than
  one inferred from the cap's rights (forward-compatible with a role added
  later).
- `OrchestratorRole` implements `TelemetrySink` directly (not the separate
  `ChannelSink` type §9 anticipated): `LocalFirst::new(log, orchestrator_role)`
  forwards local records as `Telemetry`-typed envelopes. One fewer type, same
  shape as every other role operation.
- `EscalationSink` (`sandy-fabric`, `escalation.rs`) is a new seam mirroring
  `TelemetrySink` exactly (`enabled()`/`notify()`), with its own contract suite
  and `FakeHumanBackend`. `EscalationRole::escalate` posts to its own channel
  AND notifies the sink _concurrently_ (`tokio::join!`), succeeding if either
  delivers. The channel SHAPE (who posts, who's a member, the `Escalate`
  marker) is the in-fabric contract; which concrete sink reaches a human
  (push, IPC, …) is an operator decision, deferred (spec §9).

**Consequences.** A cap scoped to another channel still can't join a role's
channel — `Channel::join`'s existing rejection, not new logic. The escalation
channel surviving a down orchestrator is a composition property (a genuinely
separate `ChannelBackend` instance), not role-level code.

**Load-bearing invariant: one orchestrator channel, one non-orchestrator
membership, per sandbox.** Spec §3.4 calls the orchestrator channel
"dedicated, per sandbox" — 1:1, not shared across sandboxes. Two separate
findings in review (#202's `ChannelAssignment` cap confidentiality, #203's
stdin misdelivery) both trace back to the same assumption: with exactly one
non-orchestrator member, a cap or a byte stream posted on that channel is
readable only by its intended recipient. Neither `Channel` nor the roles
layer enforces this 1:1-ness — it is a composition-root invariant (#115 must
mint exactly one orchestrator channel and one non-orchestrator membership per
sandbox), the same trust boundary as a cap verifying against its issuing
authority rather than something structurally impossible to violate. Flagged
to #115's builder and noted on the sandyd epic (#205) for the real
orchestrator, so this isn't rediscovered as a surprise once a second
principal could plausibly join an orchestrator channel.

Sequential-then-concurrent correctness: the first cut of `escalate` awaited
the channel post before even starting the sink notify (caught in review,
#202) — `ChannelBackend::append` has no timeout contract, and a real
transport is far more likely to hang on an unreachable orchestrator than to
error cleanly, so a hang would have silently defeated the sink's redundant
path. Fixed with `tokio::join!`; proven with a `HangingBackend` (`append`
never resolves) regression test, confirmed to fail against the prior
sequential code before the fix landed.

**Set aside.** Bounded escalation: `tokio::join!` only resolves once _both_
legs finish, so a channel leg that hangs forever still blocks `escalate()`
itself from returning, even though the sink already delivered — moot for the
all-local MVP (`InMem` never hangs), real once a vsock/P2P `ChannelBackend`
lands with no timeout contract of its own. Needs either a per-leg timeout
(`ChannelBackend` seam change) or return-on-first-delivery semantics; a
transport-era question, tracked as #207, same bucket as the cross-machine
transport work.

## 12. `EscalationRelay`: the escalation channel's reading side (#205 B8)

**Status:** accepted.

**Context.** §11's `EscalationRole::escalate` posts to the escalation channel
AND notifies a sink synchronously, at escalation time — a best-effort push.
Epic #205's settled design routes escalations to the operator through a
master-controller client that subscribes to the channel; that client did not
exist yet. Issue #161 scopes the richer version of this (Telegram bot +
subscribed-Claude-session backends, a bidirectional reply path, and a richer
`EscalationRequest{severity,summary,context_ref}` payload from #130), but #130
is an open, unresolved design question, not a built type.

**Decision.** `EscalationRelay<B, A, S>` (`sandy-fabric-local`, `roles.rs`)
wraps a `Channel<B, A>` and subscribes from its own membership's cursor,
notifying an `EscalationSink` for every `Escalate`-typed envelope it decodes.
Built against today's real wire shape (`EscalationMessage{from,reason}`, JSON
payload) — not #130's richer, unbuilt shape, which is a future migration, not
a present blocker. A sink notify failure retries (`DELIVERY_ATTEMPTS = 3`,
a fixed short delay) before being logged at `error` level and skipped; a
payload that fails to decode is likewise logged and skipped. Either case
moves on to the next envelope — one bad or undeliverable message never wedges
the relay, and neither case is silent.

The first concrete `EscalationSink` is `LogEscalationSink`
(`escalation_sink.rs`): always enabled, logs every escalation via
`tracing::error!`. This is a real backend, not a stub: it is exactly the
"escalation reaches me via a subscribed Claude session" path (M4) when that
session's terminal/log stream is what the operator is watching.

**Consequences.** The relay is the durable complement to `escalate`'s
best-effort sink call: because `Channel::subscribe` resumes from a cursor
tied to the relay's own membership, a relay instance that was offline when an
escalation posted still sees it on resubscribe (proven directly — see
`a_relay_subscribing_after_the_fact_still_sees_an_earlier_escalation`). No
real cross-process transport exists yet (vsock/mesh is #205 B6, unbuilt), so
today this wires a relay and a sink within one process over the real
`InMem` backend; a daemon-hosted channel a remote CLI/MCP attaches to needs
B2's orchestrator + B7's attach wiring, not yet built.

**Deferred, tracked separately:**

- Telegram bot backend (#161): needs live bot credentials this work could not
  itself verify against a real bot, so it is not shipped half-tested.
- The operator reply-back path (#161): needs a channel-level mechanism for a
  reply to route back to the escalating sandbox, not yet designed.
- Migrating `EscalationMessage` to #130's richer `EscalationRequest` shape:
  #130 is an open question; the relay/sink migrate once it resolves.

**Set aside.** Building the relay against #130's unbuilt `EscalationRequest`
shape now: would presuppose an answer to an open design question instead of
building against what the system actually carries today.
