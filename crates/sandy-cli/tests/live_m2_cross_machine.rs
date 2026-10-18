//! M2 cross-machine acceptance scaffold (#269 design, #263 contract, decision-6).
//!
//! Scaffold only: every test here is `#[ignore]`, because most of what it
//! drives doesn't exist on main yet — the orchestrator's full Register/
//! allowlist wiring, the mesh-accept loop (#290/#279), and the host-client
//! executor itself (#284). Per INV-S9 a live
//! scenario is never counted green from a fake, so this file never claims a
//! pass it can't back: it stays `#[ignore]`d until the full hop is wired, so
//! `--features live` runs don't silently skip-and-green it either.
//!
//! What it's for: the shape is settled (#263/#277, merged — `sandy-executor-
//! proto` is real) and this scaffold encodes it as the exact steps the
//! acceptance in `docs/architecture/kpi.md`'s "Acceptance (M2 stage 1)"
//! names, so finishing it is filling in the two `unimplemented!()` bodies
//! against real orchestrator/executor code, not a redesign.
//!
//! Run manually once the real pieces exist:
//!   SANDY_LIVE=1 SANDY_M2_REMOTE_HOST=<mesh addr of a NixOS host-client> \
//!     cargo nextest run -p sandy-cli --features live --test live_m2_cross_machine --run-ignored all
//!
//! ## Acceptance traceability (#269's full list, so nothing falls between test files)
//!
//! | #269 acceptance item                                                  | Asserted where                                                                              |
//! | ---------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
//! | Happy path: capability-declared dispatch, cross-machine peer message   | this file, `cross_machine_sandboxes_exchange_a_peer_message_through_the_hub`                |
//! | Register-auth: unknown mesh identity gets `RegisterRefused` (infra-     | this file, `register_from_an_unlisted_mesh_identity_gets_no_ack_and_no_dispatch`            |
//! | f3's addendum to #263)                                                 |                                                                                              |
//! | decision-6: wrong-peer refused, zero bytes                             | `sandyd::dispatch` / `link_auth` unit tests (#266, merged); re-asserted at the mesh-accept    |
//! |                                                                        | loop by #290 (#279, open, CI-green, holding for a pre-auth decode-deadline fix)               |
//! | decision-6: wrong-token refused, zero bytes                            | `sandyd::dispatch` / `link_auth` unit tests (#266, merged); re-asserted by #290 (#279)         |
//! | decision-6: unknown run id refused, zero bytes                         | `sandyd::dispatch` unit tests (#266, merged) — `LinkAuthError::UnknownRun`; re-asserted by    |
//! |                                                                        | #290 (#279)                                                                                    |
//! | decision-6: already-claimed link slot refused (one link per run)       | `sandyd::link_auth` unit tests (#266, merged) — `concurrent_claims_admit_exactly_one_stream`; |
//! |                                                                        | re-asserted by #290 (#279)                                                                     |
//! | Isolation-class gate, orchestrator side: `send_dispatch` refuses a     | #277 (merged, `bab825a`) — `DispatchSendError::UnsupportedIsolationClass`, tested          |
//! | class the target host didn't declare, fail-closed                     | (`dispatch_requiring_an_undeclared_isolation_class_is_refused`,                            |
//! |                                                                        | `dispatch_with_an_unset_isolation_class_is_refused`). #280 closed as a duplicate of this.    |
//! | Isolation-class gate, executor side: `check_isolation_class` re-checks | #284 (open) — reuses `sandy::admits_untrusted`; `Unspecified` refused, never treated as the   |
//! | `Dispatch.required_isolation_class` (defense in depth), fail-closed   | weaker `Trusted`.                                                                              |
//! | *Not* re-asserted at this file's e2e layer, by explicit scoping call  | infra-f3's ruling: #277's unit coverage is sufficient and this file's `capabilities_of        |
//! | (not an oversight — see #272's thread before adding one)              | (host_id)` happy-path check already covers the one thing e2e uniquely adds (declared          |
//! |                                                                        | capabilities actually reaching the dispatch decision). A negative e2e case here would just    |
//! |                                                                        | re-run unit-proven logic through the same seam. If the declared-caps -> gate wiring regresses  |
//! |                                                                        | later, add one e2e negative then, not for M2.                                                 |
//! | Result path: exit via the locked `ResultEnvelope`/`AgentReport` (INV-  | existing unit coverage (`impls/fabric-local/src/{agent,link,executor}.rs`,                   |
//! | 11); an agent failure with no report is an infra fault, not a job exit | `sandy-cli/tests/live_agent.rs`); reasserted end-to-end, cross-machine, in this file's        |
//! |                                                                        | happy-path test (step 7)                                                                     |
#![cfg(feature = "live")]

// Not `mod common;`: this file doesn't need `build_guest`/`on_path` (no VM
// boot here), and pulling in `tests/common/mod.rs`'s full re-export list would
// warn on the ones this binary never calls (`--deny warnings`, workspace lints).
use sandy_cli::live_target::require_live;
use sandy_executor_proto::{
    Arch, Capabilities, Dispatch, HostClientMessage, IsolationClass, OrchestratorMessage, Register, SandboxKind,
    host_client_message, orchestrator_message,
};

/// Refuse unless `SANDY_M2_REMOTE_HOST` names a reachable NixOS host-client's
/// mesh address, in addition to `SANDY_LIVE=1`'s usual live-matrix checks —
/// this acceptance needs two real machines, not one.
fn require_remote_executor() -> anyhow::Result<String> {
    require_live()?;
    std::env::var("SANDY_M2_REMOTE_HOST")
        .map_err(|_| anyhow::anyhow!("refusing: set SANDY_M2_REMOTE_HOST to a NixOS host-client's mesh address"))
}

/// The M2 stage-1 acceptance floor (`docs/architecture/kpi.md`): a sandbox on
/// macOS and a sandbox on the NixOS host, agent inside each, dispatched by
/// capability declaration (no hardcoded host), communicating through the
/// macOS orchestrator's peer-hub — each job's exit comes from its own agent
/// report, not a backend-mediated outcome.
#[test]
#[ignore = "scaffold: wire to the orchestrator's Register/allowlist handling, the mesh-accept loop (#290), and the \
            host-client executor (#284)"]
fn cross_machine_sandboxes_exchange_a_peer_message_through_the_hub() -> anyhow::Result<()> {
    let _remote = require_remote_executor()?;

    // 1. Host-client probes its own real containment (`detect_register_capabilities`, #284's capability.rs) and dials
    //    the orchestrator over sandy-conn's TCP/mesh tier, declaring what it can run — no hardcoded host on the
    //    orchestrator side.
    let _message = HostClientMessage {
        op: Some(host_client_message::Op::Register(Register {
            host_id: "the-remote-host".to_string(),
            capabilities: Some(Capabilities {
                kind: SandboxKind::Process.into(),
                arch: Arch::X8664.into(),
                attestation: false,
                supported_isolation_classes: vec![IsolationClass::Trusted.into()],
            }),
        })),
    };

    // 2. Orchestrator checks the registrant's mesh identity against `ExecutorAllowlist` (`HostRegistry::register`,
    //    #277, merged), acks with `Registered { host_id }`.
    //
    // 2a. Assert (sandy-7a's addition, not just "an ack arrived"): `HostRegistry::capabilities_of
    //     (host_id)` after `Register` equals what `detect_register_capabilities` produced on the
    //     real host — proves end-to-end storage, not just a handshake. A bug that acks correctly but
    //     drops or mangles the capabilities on the way into the registry must not pass silently.

    // 3. Orchestrator dispatches a job to the registered host-client against the declared capability (`Dispatch`, with
    //    `required_isolation_class` satisfied by what was registered — #277's own unit tests cover the orchestrator
    //    refusing a `Dispatch` the host never declared; not duplicated here), minting a fresh `link_token`. Shape for
    //    reference:
    let _dispatch = OrchestratorMessage {
        op: Some(orchestrator_message::Op::Dispatch(Dispatch {
            job_id: String::new(),
            manifest: Vec::new(),
            manifest_encoding: String::new(),
            backend: SandboxKind::Process.into(),
            link_token: Vec::new(),
            forward_back: String::new(),
            required_isolation_class: IsolationClass::Trusted.into(),
        })),
    };

    // 4. Host-client re-checks `required_isolation_class` independently (`check_isolation_class`, #284, defense in
    //    depth), launches the TrustedProcess sandbox + agent, then `forward_agent_link`s back to `forward_back` on a
    //    fresh stream, prefixed with `job_id` + `link_token`.
    // 5. In parallel, the orchestrator runs a second job locally (macOS sandbox + agent) through the existing local
    //    executor.
    // 6. Both agents join the same fabric hub and exchange a peer message.
    // 7. Assert: both jobs report a status/exit from their own agent's report (INV-11: status/ retryable/exit band
    //    never disagree), and the peer message sent from one agent is observed received by the other.

    unimplemented!(
        "fill in once the orchestrator's Register/allowlist handling, the mesh-accept loop, and the host-client \
         executor land"
    )
}

/// Infra-f3's addendum to #263: an unknown mesh identity gets `RegisterRefused`,
/// never `Registered`, and is never dispatched to (matches `HostRegistry::
/// register`'s `RegisterError::NotAllowed` path, #277, merged, exactly — no
/// other data to assert there, since a refusal carries only `reason`, never
/// capability or job data). This is the orchestrator-level allowlist check,
/// distinct from decision-6's own peer/token checks on the forwarded
/// agent-link stream (that case belongs to decision-6's test suite, not
/// duplicated here).
#[test]
#[ignore = "scaffold: wire to the orchestrator's Register/allowlist handling once the mesh-accept loop (#290) lands"]
fn register_from_an_unlisted_mesh_identity_gets_no_ack_and_no_dispatch() -> anyhow::Result<()> {
    let _remote = require_remote_executor()?;

    // 1. A host-client not on the orchestrator's executor allowlist dials in and sends `Register`.
    // 2. Assert: the orchestrator replies `RegisterRefused`, not `Registered`; the connection never receives a
    //    `Dispatch`; and the refusal is logged.

    unimplemented!("fill in once the mesh-accept loop (#290) and the orchestrator's live Register handling land")
}
