# Host-client executor: capability-declaring cross-machine dispatch + overlay delivery

Status: in-flight design, stage 1. Frames #263 (dispatch RPC), decision-6 (the mesh
accept-loop auth gate), the WS01 standup, and the nix overlay. One target is built now
(a NixOS host, trusted process); the seam is designed so later targets slot in without
a contract change.

## Context

The fabric has an `Executor` seam (what provides the sandbox), but every implementation
today (`impls/fabric-local`, `impls/local`, `impls/vm`) is **local** — it runs on the
same host as the orchestrator. The cross-machine primitives are on main: `forward_agent_link`
and sandy-conn's TCP/mesh transport tier (#234); `decision-6` (per-run token +
peer-identity check on the mesh accept loop) is in progress.

The gap: there is **no remote Executor and no orchestrator→executor-host protocol** —
nothing tells a remote host "run this manifest, forward your agent link back to me." That
is the missing piece for M2 cross-machine ("multiple remote sandboxes communicating, agent
inside each," across macOS and an external machine).

## The model

- **Orchestrator** (the macOS `sandyd`): the single authority. It holds the capabilities,
  the channels, and the peer-hub; it decides what runs and dispatches it. It stays
  authoritative across machines — the agent link forwards _back_ to it, and decision-6
  authenticates arriving streams.
- **Host-client** (the remote executor): a per-host component that
  1. **detects** its environment and **declares** its capabilities on contact
     (kubelet-style registration) — which backends it can provide;
  2. receives a dispatch (manifest + backend choice + per-run token + forward-back address);
  3. launches the sandbox locally;
  4. forwards the sandbox agent's link back to the orchestrator over the mesh.

  It hides the backend-specific _how_ behind one uniform interface.

- **Capability declaration**: the orchestrator dispatches against what the client
  declares, never a hardcoded host. Stage 1 declares roughly
  `{ target: nixos, backends: [trusted-process] }`; the shape extends to
  `[kvm, qemu, vfkit, faas, proxmox, …]` with no contract change.
- **Overlay delivery**: the host-client + `sandy-agent` + the sandbox tooling are delivered
  as a **nix overlay** applied on top of a user-specified base — a dev-shell in stage 1,
  the full OS eventually. The user owns the base spec; our infrastructure overlays onto it,
  so a machine becomes a sandy executor without us owning its OS.
- **#263** is the orchestrator↔host-client contract: the capability-declaration
  (registration) plus the dispatch RPC. It rides sandy-conn's TCP/mesh tier; decision-6
  authenticates the arriving agent-link stream.

## Decisions

- **D1 — Host = executor, not orchestrator.** The macOS `sandyd` stays the single
  authority; the host forwards its agent link back. An independent per-host orchestrator
  would keep the link local and break the one-hub model that lets a Mac sandbox and a host
  sandbox share a channel.
- **D2 — The host-client detects and declares capabilities; the orchestrator dispatches
  against the declaration.** So a new target slots in without a contract change — the point
  of the seam. No part of the contract bakes in a specific host or backend.
- **D3 — Overlay delivery on a user-specified base; dev-shell first, full OS later.** The
  user owns their OS/shell spec; we overlay our infra. Decouples "what the machine is" from
  "it can run sandboxes."
- **D4 — Single NixOS target now; trusted process (bwrap), no VM or agent image for stage 1.** One implementation against the seam, for M2 speed. The VM backend / untrusted
  isolation (#150) is a later target capability, not stage 1.
- **D5 — Security.** Mutual auth: the executor authenticates the _orchestrator_ too (only
  the legitimate orchestrator may dispatch — mesh identity, mesh-address-only bind,
  AllowedIPs one /32 per node), not just the orchestrator authenticating the executor.
  Manifest validation: the executor never blindly runs what it is handed; submitter-bounded
  caps apply. Per-run token flow (decision-6): the orchestrator mints the token, sends it
  over the encrypted mesh in the dispatch, the agent presents it forwarding back, decision-6
  verifies. Least privilege: the job runs inside the sandbox, never on the host.
- **D6 — #263 is the capability-declaring orchestrator↔host-client contract**, not a
  WS01-specific one-off.

## Stage-1 blocks (the NixOS target)

| Block                               | What                                                                                                                                                                                            | Owner                           |
| ----------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------- |
| decision-6                          | Orchestrator mesh accept loop + per-run token/identity binding (JobRegistry); verify peer + token before writing the cap, zero bytes on refusal                                                 | sandy-d1                        |
| #263 contract                       | The orchestrator↔host-client contract: capability-declaration (registration) + dispatch RPC (manifest, backend, token, forward-back address), over sandy-conn's TCP/mesh tier                   | sandy-d1 + sandy-91 (co-design) |
| Executor side                       | Receive dispatch, validate the manifest, launch the trusted-process sandbox, dial + `forward_agent_link` back to the orchestrator                                                               | sandy-91                        |
| NixOS overlay + host-client service | The nix overlay (host-client + agent + tooling) on a user-specified base (dev-shell in stage 1); capability detection; the systemd service (mesh-only bind, 0700 runtime dirs, least privilege) | nix-bc                          |

## Acceptance (M2 stage 1)

A sandbox on macOS and a sandbox on the NixOS host, each with the agent inside,
communicating through the macOS orchestrator's peer-hub over the mesh — where the host-client
**detected and declared** its capabilities and the orchestrator dispatched against that
declaration (no hardcoded host). Plus decision-6's assertions: per-run token + peer-identity
checked before the cap is written, and a wrong-peer / wrong-token stream receives zero bytes.

## Out of scope now (seam ready, implementations deferred)

- Other targets: KVM/qemu/vfkit, FaaS, Proxmox. The capability-declaration and dispatch
  contract accommodate them; implementations come later, as new backends the host-client
  can declare.
- The full-OS overlay (dev-shell first).
- The VM backend / untrusted isolation on the remote host (#150) — a later target capability.
