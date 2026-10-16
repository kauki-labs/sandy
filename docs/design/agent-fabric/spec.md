# Sandy Agent Fabric — Spec

- **Status:** approved (design); spec-only, not built
- **Project:** sandy
- **Updated:** 2026-10-15
- **Rendered (private artifact):** https://claude.ai/artifact/R2JiXRYDAhtN3D6G4sqnkq
- **Realizes:** #36 (agent-on-machine model — team/service direction confirmed). **Reframes:** #65 (in-guest daemon → the sandbox-agent gateway).

A serverless, intermittency-tolerant medium for agents to communicate and run work across a fleet
of heterogeneous devices. This document is the epic; its build blocks are decomposed into sub-issues
and its unresolved items into separate future issues, all referencing it.

## 1. Premise

The fleet is heterogeneous and often disjoint: a sandbox may land on any device — a server (including
a Proxmox host that hands out VMs), a laptop, a phone, an old box — on any network, reachable by no
one for a while. The fabric is built for the hardest case: **store-and-forward, content-addressed,
eventually-delivered** messaging over a transport nobody can assume is live. A live local link is then
the trivial always-connected case, and the first implementations may use plain non-P2P transports; the
P2P / torrent-like overlay is a deferred transport detail, not a change to the model.

Heterogeneity also reaches the **executor**: a sandbox may be a VM (qemu/vfkit local, Proxmox remote)
or a platform-native sandbox (mobile, with platform signatures / attestation). The executor is a seam;
the fabric abstracts over _what kind of sandbox a host provides_ and matches jobs to it by capability.

## 2. Design discipline — seam-first, local-first

Every seam ships a **trivial local implementation**, so the whole fabric runs on one machine —
sandboxes as plain processes, channels in memory — and is designed, tested, and verified end-to-end
before any VM, network, or P2P exists. A **composition root** selects one implementation per seam (an
all-local profile, a local-VM profile, a remote profile). Each seam carries a **contract with one
shared test suite that every implementation passes**, trivial or real; VM instantiation, remote
transport, and the P2P overlay are special behaviors proven over those contracts, separately.

The first deliverable is the **all-local MVP**: the process executor + in-memory channels + the
composition root + the seam contract tests, proving the entire flow (channels, agents, dispatch, TTY,
escalation) with nothing but processes.

## 3. Architecture

### 3.1 Executor / Sandbox seam

What provides a sandbox. Trivial/MVP impl: a **process backend** (sandbox = a local process). Richer
impls over the same contract: VM family (qemu/vfkit — exist; Proxmox — remote VMs), platform-native
(mobile + attestation). Self-registration advertises what kind of sandbox a host provides (VM vs
platform-native, platform/arch, available attestation). Generalizes the existing `VmBackend`.

### 3.2 Sandbox agent

The per-sandbox **gateway and channel-membership unit**. "Getting inside" a sandbox goes through the
agent; it serves functions (TTY, fs-rpc) and joins channels on behalf of the sandbox. A raw
console/vsock path is the **break-glass fallback** for a dead agent or broken boot. SSH-over-vsock
(never a network sshd) is an optional agent-served function.

### 3.3 The channel — the keystone

A deliberately minimal communication primitive, small enough that an in-memory queue, a vsock stream,
a message queue, a GitHub discussion, or a P2P overlay can each back it.

- **Surface:** `join(cap)` / `leave()` / `invite(sub)` / `post(msg)` / `subscribe() -> stream`.
- **Membership:** a bounded set; non-members cannot post or read (boundedness).
- **Messages:** a **protobuf envelope** (`oneof` message-type + sequence + metadata + an opaque
  `payload` field + `content_type`); payload is text by default, a nested protobuf when structured.
  The envelope is a _logical contract_; protobuf is its default codec; a text/chat backend re-encodes
  the same envelope as structured text.
- **Delivery:** store-and-forward, content-addressed, eventually-delivered (tolerates offline peers).
- **Pluggable `ChannelBackend` seam:** in-memory (MVP), vsock, (future) P2P overlay / chat / MQ /
  GitHub discussion.

### 3.4 Channel roles

- **Orchestrator channel** (dedicated, per sandbox): control (which channels to use) + TTY/output for
  recording + optional telemetry. The orchestrator assigns channels + caps; it is a _means_, not the
  human's endpoint.
- **Peer-group channel:** an explicit **closed** set of agents coordinating directly (the side channel
  for organizing); sub-agents join (via attenuated parent caps) to grow it; bounded, no reaching
  outside. Membership orchestrator-assigned for now.
- **Escalation channel:** **separate** by design; targets a human on _any device_ (a mobile app),
  independent of where the orchestrator sits — so it reaches the human even when the orchestrator is
  the problem. Its own backend seam.

### 3.5 Telemetry

**Local-first:** the agent appends telemetry to a local log (`journal.rs` seed), always available, no
network needed, surviving an unreachable orchestrator. Delivery is a pluggable **`TelemetrySink`
seam** — the channel is one sink. Serverless default: content-addressed, opportunistically
pulled/gossiped. **Optional, off by default.**

### 3.6 Placement & discovery

Requester-driven placement behind a pluggable **`Discovery` seam**. Trivial/MVP + default: a **static
registry** (today's host matrix; `parse_builder_systems` / `HostFacts.remote_builder`). Richer:
tracker / DHT.

### 3.7 Capacity & lifecycle

- **`Capacity` seam:** direct probe at dispatch (default); pluggable to heartbeat / none.
- **`Lifecycle` seam:** lease soft-state (default, register/heartbeat-TTL/deregister); the API is
  shaped to admit a full state-machine (deferred).

### 3.8 Security

- **`CapAuthority` seam:** signs/verifies channel capabilities and supports **attenuated delegation**
  (a sub-agent gets a weaker derivative of its parent's cap — it joins as the parent's
  representative). Default: biscuit-style attenuable tokens (placeholder), `trust_root`/minisign as the
  identity/seed root, platform attestation (mobile) as an alternative root. Fully behind the seam
  (replaceable by blockchain or other crypto); no specifics leak out.
- **`Minter` seam:** mints the job's work-secret. Default: **agent-local** — the secret never leaves
  the host (INV-1). Opt-in alternative: controller-transit.
- **Channel credential** = a **join/use capability** scoped `{peer, channel, caps, TTL}`, minted
  **outside** the sandbox and delivered in via the credential/secret seam (not self-generated, INV-1).
  Work-secrets ride as scoped payloads, never bundled into the join cap.

### 3.9 Transport

A channel rides a **`Transport` seam**. Trivial/MVP: in-memory/local. Step-1: vsock. Deferred: remote
P2P overlay.

## 4. Invariants

- **INV-1:** secrets never on argv/env/the store; minted outside and staged in.
- **The sandbox boundary is the trust boundary and the agent is the only door:** for a VM that is the
  hypervisor + vsock-only (no network ingress); for a platform-native sandbox (mobile) it is the OS
  app-sandbox + platform IPC. A channel cannot become an egress/ingress bypass on either.
- **Boundedness:** a member's capability authorizes exactly its channel.

## 5. Seam reference

| Component          | Step-1 (trivial local) default                                           | Richer impls over the same contract                      |
| ------------------ | ------------------------------------------------------------------------ | -------------------------------------------------------- |
| Executor / Sandbox | process backend (sandbox = a process)                                    | VM: qemu/vfkit (exist) · Proxmox · mobile + attestation* |
| Sandbox agent      | in-guest agent gateway                                                   | raw-console break-glass fallback                         |
| Channel            | join/leave/invite/post/subscribe · protobuf envelope · store-and-forward | —                                                        |
| ChannelBackend     | in-memory / local socket                                                 | vsock · P2P overlay* / chat / MQ / GitHub discussion     |
| Discovery          | static registry                                                          | tracker / DHT*                                           |
| Capacity           | direct probe                                                             | heartbeat / none                                         |
| Lifecycle          | lease soft-state                                                         | full state-machine*                                      |
| Transport          | in-memory, then vsock                                                    | remote P2P overlay*                                      |
| CapAuthority       | biscuit (placeholder); minisign = identity root                          | platform attestation · blockchain / other crypto         |
| Minter             | agent-local (INV-1)                                                      | controller-transit                                       |
| TelemetrySink      | local-first log (off by default)                                         | content-addressed pull* / channel / OTLP                 |

`*` = deferred impl / future issue.

## 6. Step-1 scope — the all-local MVP

- All-local MVP: every seam's trivial impl (process sandbox, in-memory channels).
- Composition root selecting one impl per seam (profiles).
- Seam contract tests — every impl verified against the same contract.
- Minimal channel abstraction + protobuf envelope (`sandy-proto`).
- Orchestrator assigns channels + caps to each sandbox at launch.
- Orchestrator channel: control + TTY/output + optional telemetry.
- Peer-group channel: explicit membership; sub-agents join via attenuated parent caps.
- Escalation channel: separate, one simple backend to start.
- Sandbox agent as gateway; raw-console fallback.
- Telemetry local-first + sink seam (off by default).

## 7. Deferred — filed as separate future issues

VM/Proxmox/mobile executor over the Executor contract; vsock + P2P transport; DHT/tracker discovery;
full agent-lifecycle state-machine; agent self-organization & channel negotiation; sandbox-to-sandbox
triggering; content-addressed telemetry over P2P (+ channel/OTLP sinks); rich human backends for
escalation; CapAuthority alternative impls (blockchain/other crypto).

## 8. Open design questions (future issues)

- Pub/sub topics + delivery semantics within a channel.
- Capability revocation before TTL, and where that governance lives.
- The concrete per-role envelope message-type contracts (orchestrator-control, tty, telemetry,
  escalate, peer-group-message).

## 9. References

- Rendered spec (private): https://claude.ai/artifact/R2JiXRYDAhtN3D6G4sqnkq
- #36 agent-on-machine model (realized by this spec); #65 in-guest daemon (reframed as the agent gateway).
- Related decision records in `products/sandy/docs/decisions/`: run-plane, guest-shares (§8
  content-addressing, §10 pipeline), credential-seam, secret-channel, egress, result-classification.
