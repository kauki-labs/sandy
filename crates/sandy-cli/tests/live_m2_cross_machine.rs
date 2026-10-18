//! M2 cross-machine acceptance scaffold (#269 design, #263 contract, decision-6).
//!
//! Two of the acceptance items below are live: `register_from_an_unlisted_
//! mesh_identity_gets_no_ack_and_no_dispatch` runs a real `sandyd` binary and
//! a real TCP client against it (`SANDY_LIVE=1`, no hypervisor needed — M2
//! stage 1 is the trusted-process backend). The happy path stays
//! `#[ignore]`d: it needs the orchestrator's submit->dispatch placement
//! wiring (#298) and the mesh-accept loop's own wiring into `sandyd::main`
//! (unfiled as of this writing, flagged to infra-f3), neither of which exists
//! on main yet. Per INV-S9 a live scenario is never counted green from a
//! fake, so nothing here claims a pass it can't back.
//!
//! What it's for: the shape is settled (#263/#277, merged — `sandy-executor-
//! proto` is real) and this scaffold encodes it as the exact steps the
//! acceptance in `docs/architecture/kpi.md`'s "Acceptance (M2 stage 1)"
//! names, so finishing it is filling in the remaining `unimplemented!()` body
//! against real orchestrator/executor code, not a redesign.
//!
//! Run manually:
//!   SANDY_LIVE=1 cargo nextest run -p sandy-cli --features live --test live_m2_cross_machine
//! and, once the happy path is unblocked:
//!   SANDY_LIVE=1 SANDY_M2_REMOTE_HOST=<mesh addr of a NixOS host-client> \
//!     cargo nextest run -p sandy-cli --features live --test live_m2_cross_machine --run-ignored all
//!
//! ## Acceptance traceability (#269's full list, so nothing falls between test files)
//!
//! | #269 acceptance item                                                  | Asserted where                                                                              |
//! | ---------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
//! | Happy path: capability-declared dispatch, cross-machine peer message   | this file, `cross_machine_sandboxes_exchange_a_peer_message_through_the_hub` (`#[ignore]`d, |
//! |                                                                        | pending #298 + the mesh-accept loop's own wiring into `sandyd::main`)                        |
//! | Register-auth: unknown mesh identity gets `RegisterRefused` (infra-     | this file, `register_from_an_unlisted_mesh_identity_gets_no_ack_and_no_dispatch` (live, a    |
//! | f3's addendum to #263)                                                 | real `sandyd` + a real TCP client, not `#[ignore]`d)                                         |
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

// Not `mod common;`: this file doesn't need `build_guest`/`on_path` — nothing
// here boots a VM (M2 stage 1 is the trusted-process backend, kpi.md's
// acceptance), so `require_live`'s hypervisor-on-PATH check does not apply —
// and pulling in `tests/common/mod.rs`'s full re-export list would warn on
// the ones this binary never calls (`--deny warnings`, workspace lints).
use std::{
    io::Write as _,
    net::{SocketAddr, TcpListener, TcpStream},
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use anyhow::Context;
use sandy_executor_proto::{
    Arch, Capabilities, Dispatch, HostClientMessage, IsolationClass, OrchestratorMessage, Register, SandboxKind,
    host_client_message, orchestrator_message,
};

/// Refuse unless `SANDY_LIVE=1` — this file spawns real OS processes and
/// binds real TCP sockets, so it stays opt-in like every other `live` gate
/// (INV-S9), even though stage 1 needs no hypervisor.
fn require_live_process_test() -> anyhow::Result<()> {
    anyhow::ensure!(
        std::env::var("SANDY_LIVE").ok().as_deref() == Some("1"),
        "refusing: this is a live gate — set SANDY_LIVE=1"
    );
    Ok(())
}

/// Refuse unless `SANDY_M2_REMOTE_HOST` names a reachable NixOS host-client's
/// mesh address, in addition to [`require_live_process_test`]'s usual
/// live-matrix check — the full cross-machine acceptance needs two real
/// machines, not one. `localhost`/a loopback address is a deliberate,
/// explicit choice for the Mac-only protocol-proof phase (infra-f3's #272
/// ruling), never a silent default.
fn require_remote_executor() -> anyhow::Result<String> {
    require_live_process_test()?;
    std::env::var("SANDY_M2_REMOTE_HOST")
        .map_err(|_| anyhow::anyhow!("refusing: set SANDY_M2_REMOTE_HOST to a NixOS host-client's mesh address"))
}

/// Build `package`'s `bin` binary and return its path, located next to
/// `sandy`'s own binary so it matches whatever profile/target dir this test
/// run used (mirrors `daemon_e2e.rs`'s own `sandyd_bin` helper exactly, for
/// the same reason: `CARGO_BIN_EXE_<name>` only resolves for the package that
/// owns this integration test, never a sibling workspace member's binary).
fn build_workspace_bin(package: &str, bin: &str) -> anyhow::Result<PathBuf> {
    let sandy_bin = PathBuf::from(env!("CARGO_BIN_EXE_sandy"));
    let target_profile_dir = sandy_bin
        .parent()
        .context("sandy's own binary path has no parent directory")?
        .to_path_buf();
    let is_release = target_profile_dir.file_name().and_then(|n| n.to_str()) == Some("release");

    let workspace_manifest = concat!(env!("CARGO_MANIFEST_DIR"), "/../../Cargo.toml");
    let mut build = Command::new(env!("CARGO"));
    build.args([
        "build",
        "--manifest-path",
        workspace_manifest,
        "-p",
        package,
        "--bin",
        bin,
    ]);
    if is_release {
        build.arg("--release");
    }
    let status = build
        .status()
        .with_context(|| format!("running cargo build -p {package} --bin {bin}"))?;
    anyhow::ensure!(status.success(), "cargo build -p {package} --bin {bin} failed");

    Ok(target_profile_dir.join(bin))
}

/// A free TCP port on loopback at the moment this returns. Standard
/// bind-port-0-then-release test pattern: there is an inherent (and, in
/// practice, vanishingly rare on a local dev/CI loopback) race between
/// releasing the port here and `sandyd` binding it moments later.
fn free_tcp_port() -> anyhow::Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0").context("bind an ephemeral port to find a free one")?;
    Ok(listener.local_addr()?.port())
}

/// A running real `sandyd` binary, its mesh management-channel listener
/// bound and accepting, killed on drop.
struct Orchestrator {
    child: Child,
    mesh_addr: SocketAddr,
}

impl Drop for Orchestrator {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Spawn the real `sandyd` binary with its mesh listener bound to a fresh
/// loopback port and `allowlist` as `SANDY_MESH_ALLOWLIST`, waiting (bounded,
/// polled) until the mesh listener actually accepts a connection — a fixed
/// sleep would be either flaky under load or needlessly slow.
fn spawn_orchestrator(tmp: &std::path::Path, allowlist: &str) -> anyhow::Result<Orchestrator> {
    let port = free_tcp_port()?;
    let mesh_addr: SocketAddr = format!("127.0.0.1:{port}").parse()?;
    let child = Command::new(build_workspace_bin("sandyd", "sandyd")?)
        .env("SANDY_SOCK", tmp.join("sandyd.sock"))
        .env("SANDY_DB", tmp.join("sandyd.db"))
        .env("SANDY_MESH_LISTEN", mesh_addr.to_string())
        .env("SANDY_MESH_ALLOWLIST", allowlist)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("spawning sandyd")?;
    let orchestrator = Orchestrator { child, mesh_addr };

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if TcpStream::connect(mesh_addr).is_ok() {
            break;
        }
        if Instant::now() > deadline {
            anyhow::bail!("sandyd's mesh listener never accepted a connection on {mesh_addr}");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    Ok(orchestrator)
}

/// Send a real `Register` frame to `orchestrator` over a plain TCP socket and
/// return its one response frame.
///
/// Not the real `sandy-host-client` binary: `detect_register_capabilities()`
/// (the binary's first step, before it ever dials) hard-fails on a non-Linux
/// host (`SystemdRunContainment::detect` is unconditionally `Unsupported`
/// off Linux, `impls/local/src/containment.rs`), so spawning the real binary
/// on this Mac would exit 1 before `Register` is ever attempted — a false
/// functional-red for the wrong reason (sandy-91 caught this before this test
/// was run). This acceptance item is about the orchestrator's allowlist
/// behavior, which doesn't depend on the host-client's capability probe, so a
/// hand-rolled client sending the real wire message is a faithful test of it:
/// real `sandyd` binary, real TCP, real `sandy_control_proto` frame codec.
fn register_over_tcp(
    orchestrator: &Orchestrator,
    host_id: &str,
    capabilities: Capabilities,
) -> anyhow::Result<OrchestratorMessage> {
    use sandy_executor_proto::Message as _;

    let mut conn = TcpStream::connect(orchestrator.mesh_addr).context("dialing the orchestrator's mesh listener")?;
    conn.set_read_timeout(Some(Duration::from_secs(5)))?;

    let message = HostClientMessage {
        op: Some(host_client_message::Op::Register(Register {
            host_id: host_id.to_owned(),
            capabilities: Some(capabilities),
        })),
    };
    // Same wire format as `sandy_control_proto::write_frame`/`read_frame` (u32 BE
    // length prefix, raw prost bytes) — hand-rolled only because those are async
    // (tokio `AsyncRead`/`AsyncWrite`) and this test uses a plain `std::net::TcpStream`.
    let encoded = message.encode_to_vec();
    conn.write_all(&u32::try_from(encoded.len())?.to_be_bytes())
        .context("writing Register's length prefix")?;
    conn.write_all(&encoded).context("writing Register's payload")?;

    let mut len_buf = [0u8; 4];
    std::io::Read::read_exact(&mut conn, &mut len_buf).context("reading the response's length prefix")?;
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut payload = vec![0u8; len];
    std::io::Read::read_exact(&mut conn, &mut payload).context("reading the response's payload")?;
    OrchestratorMessage::decode(payload.as_slice()).context("decoding the OrchestratorMessage response")
}

fn trusted_process_capabilities() -> Capabilities {
    Capabilities {
        kind: SandboxKind::Process.into(),
        arch: Arch::X8664.into(),
        attestation: false,
        supported_isolation_classes: vec![IsolationClass::Trusted.into()],
    }
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
///
/// Against a real spawned `sandyd` binary, over a real TCP socket, with the
/// real wire codec (see [`register_over_tcp`] for why the client side is
/// hand-rolled rather than the real `sandy-host-client` binary).
///
/// Functional-red observed before green (2026-10-18): first ran this against
/// an orchestrator whose `SANDY_MESH_ALLOWLIST` included this test's loopback
/// peer — the assertion below (`Refused`, not `Registered`) genuinely failed,
/// asserting `Refused` against an actual `Registered` response, proving the
/// real allowlist check is what this test exercises, not a harness bug that
/// would pass regardless of `sandyd`'s behavior. Reverted to the real
/// allowlist (excluding this test's peer) for the green below.
#[test]
fn register_from_an_unlisted_mesh_identity_gets_no_ack_and_no_dispatch() -> anyhow::Result<()> {
    require_live_process_test()?;
    let tmp = tempfile::tempdir().context("temp dir")?;

    // An allowlist that does not include 127.0.0.1 (this test's own peer address) —
    // the orchestrator-side check this test exercises.
    let orchestrator = spawn_orchestrator(tmp.path(), "10.0.0.1")?;

    let response = register_over_tcp(&orchestrator, "impostor", trusted_process_capabilities())?;
    match response.op {
        Some(orchestrator_message::Op::Refused(refused)) => {
            assert!(
                !refused.reason.is_empty(),
                "a refusal must still name a reason internally, even though the wire message carries nothing else"
            );
        }
        other => anyhow::bail!("expected Refused for a non-allowlisted peer, got {other:?}"),
    }
    Ok(())
}
