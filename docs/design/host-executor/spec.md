# Host-executor: capability-declaring cross-machine dispatch + overlay delivery

Status: stage 1 implementation is present, but executor-side orchestrator authentication
remains open. The seam this doc designed landed as `sandy-executor-proto`
(the registration + dispatch contract), the `sandyd` control plane, and the
`sandy-host-executor` crate — #310 renamed that crate from the original "host-client".
Frames #263 (dispatch RPC), decision-6 (the mesh accept-loop auth gate), the WS01
standup, and the nix overlay. One target is built (a NixOS host, trusted process); the
seam is designed so later targets slot in without a contract change. The open stage-1
items are executor-side orchestrator authentication and result propagation back to the
orchestrator (#292, see Acceptance).

## Context

The fabric has an `Executor` seam (what provides the sandbox), but every implementation
today (`impls/fabric-local`, `impls/local`, `impls/vm`) is **local** — it runs on the
same host as the orchestrator. The cross-machine primitives are on main: `forward_agent_link`
and sandy-conn's TCP/mesh transport tier (#234); `decision-6` (per-run token +
peer-identity check on the mesh accept loop) has landed in `sandyd`.

The gap this closed: there was **no remote Executor and no orchestrator→executor-host
protocol** — nothing told a remote host "run this manifest, forward your agent link back
to me." That was the missing piece for M2 cross-machine ("multiple remote sandboxes
communicating, agent inside each," across macOS and an external machine), now delivered by
`sandy-executor-proto` + `sandy-host-executor`.

## The model

- **Orchestrator** (the macOS `sandyd`): the single authority. It holds the capabilities,
  the channels, and the peer-hub; it decides what runs and dispatches it. It stays
  authoritative across machines — the agent link forwards _back_ to it, and decision-6
  authenticates arriving streams.
- **Host-executor** (the remote executor): a per-host component that
  1. **detects** its environment and **declares** its capabilities on contact
     (kubelet-style registration) — which backends it can provide;
  2. receives a dispatch (manifest, backend choice, required isolation class, per-run token,
     forward-back address);
  3. launches the sandbox locally;
  4. forwards the sandbox agent's link back to the orchestrator over the mesh.

  It hides the backend-specific _how_ behind one uniform interface.

- **Capability declaration**: the orchestrator dispatches against what the client
  declares, never a hardcoded host. Stage 1 declares roughly
  `{ target: nixos, backends: [trusted-process] }`; the shape extends to
  `[kvm, qemu, vfkit, faas, proxmox, …]` with no contract change.
- **Overlay delivery**: the host-executor + `sandy-agent` + the sandbox tooling are delivered
  as a **nix overlay** applied on top of a user-specified base — a dev-shell in stage 1,
  the full OS eventually. The user owns the base spec; our infrastructure overlays onto it,
  so a machine becomes a sandy executor without us owning its OS.
- **#263** is the orchestrator↔host-executor contract: the capability-declaration
  (registration) plus the dispatch RPC. It rides sandy-conn's TCP/mesh tier; decision-6
  authenticates the arriving agent-link stream.

## Decisions

- **D1 — Host = executor, not orchestrator.** The macOS `sandyd` stays the single
  authority; the host forwards its agent link back. An independent per-host orchestrator
  would keep the link local and break the one-hub model that lets a Mac sandbox and a host
  sandbox share a channel.
- **D2 — The host-executor detects and declares capabilities; the orchestrator dispatches
  against the declaration.** So a new target slots in without a contract change — the point
  of the seam. No part of the contract bakes in a specific host or backend.
- **D3 — Overlay delivery on a user-specified base; dev-shell first, full OS later.** The
  user owns their OS/shell spec; we overlay our infra. Decouples "what the machine is" from
  "it can run sandboxes."
- **D4 — Single NixOS target now; trusted process (bwrap), no VM or agent image for stage 1.** One implementation against the seam, for M2 speed. The VM backend / untrusted
  isolation (VM-only per #150; dispatch routing in #381) is a later target capability, not stage 1. Stage 1 accepts **trusted jobs
  only**: the `bwrap` sandbox shares the host network namespace and egress is intentionally
  **unenforced** (no per-job allow-list). Egress enforcement belongs to the VM / untrusted-isolation
  seam (#150), not stage 1, and the guest-scoped Linux egress rule does not transfer to this
  shared-namespace target. The trusted-only constraint is enforced by the isolation-class gate
  (D5), so "unenforced egress" is never silently applied to an untrusted job.
- **D5 — Security.** Mutual auth: the executor authenticates the _orchestrator_ too (only
  the legitimate orchestrator may dispatch — mesh identity, mesh-address-only bind,
  AllowedIPs one /32 per node), not just the orchestrator authenticating the executor.
  Manifest validation: the executor never blindly runs what it is handed; submitter-bounded
  caps apply. Per-run token flow (decision-6): the orchestrator mints the token and sends it
  over the encrypted control RPC in the dispatch; the **executor-side forwarder** retains it
  in memory and passes it as the opaque prefix to `forward_agent_link` — the sandbox agent
  never receives it through a file, argv, the environment, `RunSpec`, logs, or the Nix store.
  decision-6 verifies it on accept. Least privilege: the job runs inside the sandbox, never
  on the host.
  - **Isolation-class gate (two-sided).** The dispatch (#263) carries the job's **required
    isolation class**. The orchestrator must not dispatch it to a host whose declared backends
    cannot provide that class (`pick_host_for` placement), **and** the executor independently
    re-checks `Dispatch.required_isolation_class` against its actual containment before
    launching — defense in depth, not trusting the orchestrator's placement. Either
    side refusing is explicit and fail-closed: an untrusted job is never run on stage-1's
    `trusted-process` backend, and refusal is never a silent downgrade to a weaker backend.
  - **Token lifecycle.** decision-6 spends the token on accept (one link per run). Beyond
    that, each terminal path — run cancellation, dispatch timeout, executor teardown —
    invalidates its still-unclaimed token, and the mesh accept loop rejects an invalidated
    token before writing any bytes.
- **D6 — #263 is the capability-declaring orchestrator↔host-executor contract**, not a
  WS01-specific one-off.
- **D7 — Sequential dispatch, one job per host-executor process (decision 14, #288).** The
  executor reads one `Dispatch`, runs it to completion (bounded by `STAGE1_TIMEOUT_SECS`) via
  `spawn_blocking`, then reads the next; a second `Dispatch` buffers in the connection as
  backpressure. `Capabilities` declares no slot count, so the orchestrator has no signal to
  place two jobs at once. Concurrent dispatch waits on a capacity declaration plus a
  resource-isolation story between co-resident jobs (`docs/decisions/sandyd.md` §14).
- **D8 — No re-registration; a lost connection exits non-zero (decision 12, #289/#311/#312).**
  The host-executor holds one persistent connection and has no reconnect machinery. A
  disconnected or refused executor **exits non-zero** and leaves restarting it to its
  supervisor (systemd), rather than returning 0 and silently going idle — the dispatch loop
  reports connection-closed distinctly from a clean shutdown so `main` can do so.

## Stage-1 blocks (the NixOS target)

| Block                                 | What                                                                                                                                                                                                                                                                                                                                           | Owner                           |
| ------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------- |
| decision-6                            | Orchestrator mesh accept loop + per-run token/identity binding (JobRegistry); verify peer + token before writing the cap, zero bytes on refusal                                                                                                                                                                                                | sandy-d1                        |
| #263 contract                         | The orchestrator↔host-executor contract: capability-declaration (registration) + dispatch RPC (manifest, backend, required isolation class, token, forward-back address), over sandy-conn's TCP/mesh tier                                                                                                                                      | sandy-d1 + sandy-91 (co-design) |
| Executor side                         | Receive dispatch, validate the manifest + isolation class, launch the trusted-process sandbox, dial + `forward_agent_link` back to the orchestrator; the agent reports the job exit code in its final link frame, returned as `AgentReport` (INV-11) — a refusal or an agent failure with no report is an infrastructure fault, not a job exit | sandy-91                        |
| NixOS overlay + host-executor service | The nix overlay (host-executor + agent + tooling) on a user-specified base (dev-shell in stage 1); capability detection; the systemd service (mesh-only bind, 0700 runtime dirs, least privilege)                                                                                                                                              | nix-bc                          |

## Acceptance (M2 stage 1)

A sandbox on macOS and a sandbox on the NixOS host, each with the agent inside,
communicating through the macOS orchestrator's peer-hub over the mesh — where the host-executor
**detected and declared** its capabilities and the orchestrator dispatched against that
declaration (no hardcoded host).

Plus these assertions, each of which Stage 1 cannot pass without:

- **decision-6 refusal cases** — all four close with zero bytes: wrong-peer, wrong-token,
  **unknown run id**, and an **already-claimed link slot** (one link per run). The per-run
  token and peer identity are checked before the cap is written (`docs/decisions/sandyd.md:183-209`).
- **Token invalidation on terminal paths** — after each of run cancellation, dispatch timeout,
  and executor teardown, a subsequent link claim on that run's still-unclaimed token is
  **refused** (zero bytes). Each terminal path invalidates the token (D5 token lifecycle), so a
  late or replayed claim cannot open a link against a run that is already gone.
- **Unauthorized dispatch refused** — the executor rejects a `#263` dispatch that does not
  arrive from the authenticated orchestrator (mesh identity, mesh-address-only bind, AllowedIPs
  one /32 per node), fail-closed and before launching anything — the executor-side half of D5
  mutual auth, not only decision-6's authentication of the agent-link stream.
- **Isolation-class gate** — a job declaring an isolation class the executor cannot provide is
  refused fail-closed by **both** sides (orchestrator placement and the executor's independent
  re-check), never downgraded onto `trusted-process`.
- **Result path** — the `ResultEnvelope` / `AgentReport` exit-band classification is locked
  (INV-11): an agent failure without a report surfaces as an infrastructure fault, not a job
  exit. Propagation back into the orchestrator's job status now works: `outcome_result_message`
  reports the result over the host-executor's registration connection, and `sandyd`'s
  `record_job_result` resolves the job to its terminal `JobStatus`, observable through `attach`'s
  status watch and through `daemon status`. Confirmed in a manual two-machine run (see below).

## Manual cross-machine smoke test

Three processes, no nix module, for poking at the real binaries by hand. `sandyd` resolves
every knob below from environment variables — there is no CLI flag form.

1. **Orchestrator** (anywhere; the example below is macOS, a Linux host works the same way).
   `SANDY_MESH_LISTEN` is the address a host-executor registers against;
   `SANDY_MESH_AGENT_LINK_LISTEN` is the **separate** address a dispatched job's agent dials
   back on (decision 6) — both are required for a remote run to be reachable at all, and
   each needs a distinct port:

   ```
   SANDY_SOCK=/tmp/sandyd.sock \
   SANDY_MESH_LISTEN=<orchestrator-ip>:4000 SANDY_MESH_ALLOWLIST=<executor-ip> \
   SANDY_MESH_AGENT_LINK_LISTEN=<orchestrator-ip>:4001 \
   sandyd
   ```

   Both addresses must be a specific interface address, never `0.0.0.0`/`::` (D5 refuses an
   unspecified bind). `SANDY_MESH_ALLOWLIST` is a comma-separated IP list; an unset or empty
   allowlist with a listener configured is treated as a misconfiguration and refused, not a
   deliberate allow-no-one policy. This allowlist is the authorization boundary (D5: the
   orchestrator trusts the mesh's own per-peer identity, not a self-reported `host_id`) — the
   underlying mesh (WireGuard/Tailscale) must already bind each node to its own `/32` peer
   address before `sandyd` sees any of this as meaningful.

2. **Executor** (the remote host): `SANDY_AGENT_PATH` **must** resolve inside the `bwrap`
   sandbox the trusted-process backend launches the job in (`--ro-bind / /`, then
   `--tmpfs /tmp` on top). The real root is visible read-only, but `/tmp` specifically is
   replaced by a fresh, empty tmpfs — a path under `/tmp` (a `/tmp`-based dev checkout
   included) is invisible there, and `execvp` fails with a plain "No such file or directory"
   that looks like a missing binary even though it's right there on the real filesystem.
   A path outside `/tmp` works; the Nix store path is the simplest one to reach for:

   ```
   SANDY_AGENT_PATH="$(nix build .#sandy-agent --no-link --print-out-paths)/bin/sandy-agent" \
   SANDY_HOST_EXECUTOR_ORCHESTRATOR=<orchestrator-ip>:4000 \
   SANDY_HOST_EXECUTOR_ID=<any-name> \
   sandy-host-executor
   ```

3. **Submit and attach** (from the orchestrator host):

   ```
   SANDY_SOCK=/tmp/sandyd.sock sandy daemon submit manifest.json --manifest-encoding argv/v1 -o json
   SANDY_SOCK=/tmp/sandyd.sock sandy daemon attach <job_id>
   ```

   For something to watch, use a manifest that keeps producing output
   (`["sh","-c","for i in $(seq 1 20); do echo tick-$i; sleep 1; done"]`) rather than one that
   finishes immediately. `attach`'s status-watch notice lands on **stderr**, not stdout. The
   attached job's own `TTY_STDOUT` and `TTY_STDERR` both land on stdout, though — `attach`
   doesn't split them, so a caller can't capture the job's two streams separately.

   This covers `argv/v1` trusted-process execution only (`ProcessBackend::with_agent`). It does
   not exercise `flake/v1`'s VM dispatch, untrusted-job execution, or per-job egress isolation.

## Out of scope now (seam ready, implementations deferred)

- Other targets: KVM/qemu/vfkit, FaaS, Proxmox. The capability-declaration and dispatch
  contract accommodate them; implementations come later, as new backends the host-executor
  can declare.
- The full-OS overlay (dev-shell first).
- The VM backend / untrusted isolation on the remote host (VM-only per #150; routing in #381) — a later target capability.
