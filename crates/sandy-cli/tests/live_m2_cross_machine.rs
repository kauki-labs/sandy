//! M2 cross-machine acceptance scaffold (#269 design, #263 contract, decision-6).
//!
//! Scaffold only: every test here is `#[ignore]`, because most of what it
//! drives doesn't exist on main yet — `sandy-executor-proto` (#263), the
//! orchestrator's Register-authentication + dispatch handling, and the
//! host-client executor itself. (Decision-6's `LinkToken`, #266, has already
//! merged — `contract::Dispatch::link_token` below is still a local
//! placeholder only because this crate has no dependency on `sandyd` yet.)
//! Per INV-S9 a live
//! scenario is never counted green from a fake, so this file never claims a
//! pass it can't back: it won't even compile against the real wire types until
//! they land, and stays `#[ignore]`d until then so `--features live` runs
//! don't silently skip-and-green it either.
//!
//! What it's for: the shape is settled (issue #263, locked; decision-6's
//! Register-authentication addendum) and this scaffold encodes it as the exact
//! steps the acceptance in `docs/architecture/kpi.md`'s "Acceptance (M2 stage
//! 1)" names, so wiring it to real code is a mechanical swap of the `contract`
//! module below for `sandy_executor_proto`, not a redesign.
//!
//! Run manually once the real pieces exist:
//!   SANDY_LIVE=1 SANDY_M2_REMOTE_HOST=<mesh addr of a NixOS host-client> \
//!     cargo nextest run -p sandy-cli --features live --test live_m2_cross_machine --run-ignored all
#![cfg(feature = "live")]

// Not `mod common;`: this file doesn't need `build_guest`/`on_path` (no VM
// boot here), and pulling in `tests/common/mod.rs`'s full re-export list would
// warn on the ones this binary never calls (`--deny warnings`, workspace lints).
use sandy_cli::live_target::require_live;
use sandy_fabric::{
    executor::{Arch, Capabilities},
    placement::HostDescriptor,
    types::HostId,
};

/// Placeholder wire types standing in for `sandy_executor_proto` (#263) until
/// that crate lands. Field shapes match the contract locked on #263 and
/// decision-6's addendum; delete this module and `use sandy_executor_proto::*`
/// once it exists.
#[allow(
    dead_code,
    reason = "scaffold types the ignored tests below document fields on, not yet constructed"
)]
mod contract {
    use super::{Capabilities, HostId};

    /// Host-client -> orchestrator, opening the persistent Register/dispatch
    /// connection. Orchestrator checks the registrant's mesh identity against
    /// an allowlist before ever sending `Registered` (infra-f3's addendum).
    pub struct Register {
        pub capabilities: Capabilities,
    }

    /// Orchestrator -> host-client, ack of a trusted `Register`.
    pub struct Registered {
        pub host_id: HostId,
    }

    /// Orchestrator -> host-client, pushed over the still-open connection
    /// (kubelet-watch style; connection-open is the liveness signal).
    pub struct Dispatch {
        pub job_id: String,
        pub manifest: Vec<u8>,
        pub manifest_encoding: String,
        pub backend: Backend,
        /// 32 bytes (`sandyd::link_auth::LINK_TOKEN_LEN`, decision-6 #266, merged);
        /// carries `sandyd::link_auth::LinkToken::as_bytes()`'s value once this
        /// crate exists and can depend on `sandyd`.
        pub link_token: [u8; 32],
        /// The orchestrator's mesh accept-loop address, dialed by the
        /// host-client on a *fresh* `ConnAddr::Tcp` stream for
        /// `forward_agent_link` — never the Register/dispatch connection.
        pub forward_back: String,
    }

    /// Extensible oneof; stage 1 carries only `TrustedProcess`.
    pub enum Backend {
        TrustedProcess,
    }
}

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
#[ignore = "scaffold: wire to sandy-executor-proto (#263), decision-6 (#266), and the host-client executor"]
fn cross_machine_sandboxes_exchange_a_peer_message_through_the_hub() -> anyhow::Result<()> {
    let _remote = require_remote_executor()?;

    // 1. Host-client dials the orchestrator over sandy-conn's TCP/mesh tier and declares what it can run — no hardcoded
    //    host on the orchestrator side.
    let _register = contract::Register {
        capabilities: Capabilities {
            kind: sandy_fabric::executor::SandboxKind::Process,
            arch: Arch::X86_64,
            attestation: None,
        },
    };

    // 2. Orchestrator checks the registrant's mesh identity against its executor allowlist, acks with `Registered {
    //    host_id }`.
    let _advertised = HostDescriptor {
        host: HostId("todo-from-registered-ack".to_string()),
        capabilities: Capabilities {
            kind: sandy_fabric::executor::SandboxKind::Process,
            arch: Arch::X86_64,
            attestation: None,
        },
    };

    // 3. Orchestrator dispatches a job to the registered host-client against the declared capability (`Dispatch`),
    //    minting a fresh `link_token`.
    // 4. Host-client validates the manifest against its own declared capabilities, launches the TrustedProcess sandbox
    //    + agent, then `forward_agent_link`s back to `forward_back` on a fresh stream, prefixed with `job_id` +
    //    `link_token`.
    // 5. In parallel, the orchestrator runs a second job locally (macOS sandbox + agent) through the existing local
    //    executor.
    // 6. Both agents join the same fabric hub and exchange a peer message.
    // 7. Assert: both jobs report a status/exit from their own agent's report (INV-11: status/retryable/exit band never
    //    disagree), and the peer message sent from one agent is observed received by the other.

    unimplemented!("fill in once sandy-executor-proto, decision-6, and the host-client executor land")
}

/// Infra-f3's addendum to #263: an unknown mesh identity gets no `Registered`
/// ack and is never dispatched to — refused and logged, the same honest-refusal
/// discipline as decision-6's bad paths. This is the orchestrator-level
/// allowlist check, distinct from decision-6's own peer/token checks on the
/// forwarded agent-link stream (that case belongs to decision-6's test suite,
/// not duplicated here).
#[test]
#[ignore = "scaffold: wire to sandy-executor-proto (#263) once the orchestrator's Register handling lands"]
fn register_from_an_unlisted_mesh_identity_gets_no_ack_and_no_dispatch() -> anyhow::Result<()> {
    let _remote = require_remote_executor()?;

    // 1. A host-client not on the orchestrator's executor allowlist dials in and sends `Register`.
    // 2. Assert: the orchestrator sends no `Registered` ack, and the connection never receives a `Dispatch`, and the
    //    refusal is logged.

    unimplemented!("fill in once the orchestrator's Register-authentication lands")
}
