//! M2 cross-machine acceptance scaffold (#269 design, #263 contract, decision-6).
//!
//! Both tests below are live, no `#[ignore]`s left: `register_from_an_
//! unlisted_mesh_identity_gets_no_ack_and_no_dispatch` runs a real `sandyd`
//! binary and a real TCP client against it; `cross_machine_sandboxes_
//! exchange_a_peer_message_through_the_hub` drives a real `sandy daemon
//! submit` through the real orchestrator placement path (#298/#301, merged)
//! to a real `Dispatch`, then runs it via `handle_dispatch` with
//! `FakeContainment` standing in for real containment (sandy-91: the real
//! `sandy-host-executor` binary can't start on non-Linux). `SANDY_LIVE=1`, no
//! hypervisor needed — M2 stage 1 is the trusted-process backend. Per INV-S9
//! a live scenario is never counted green from a fake, so nothing here
//! claims a pass it can't back; see each test's own doc for its observed
//! functional-red.
//!
//! What's left, not in scope for this file: the second local job / peer-
//! message-through-the-hub half of #269's acceptance, and real (non-fake)
//! containment + a real second machine — the remote-host cross-machine run, gated
//! on #299 (the nix overlay) and the operator's remote-host apply (#287). Tracked on
//! #303, so landing this file's proven leg doesn't drop that remaining scope.
//!
//! What it's for: the shape is settled (#263/#277/#298/#301, merged) and
//! this scaffold encodes it as the exact steps the acceptance in
//! `docs/architecture/kpi.md`'s "Acceptance (M2 stage 1)" names.
//!
//! Run manually:
//!   SANDY_LIVE=1 cargo nextest run -p sandy-cli --features live --test live_m2_cross_machine
//! and, once the real remote-host run is written:
//!   SANDY_LIVE=1 SANDY_M2_REMOTE_HOST=<mesh addr of the remote host> \
//!     cargo nextest run -p sandy-cli --features live --test live_m2_cross_machine
//!
//! ## Acceptance traceability (#269's full list, so nothing falls between test files)
//!
//! | #269 acceptance item                                                  | Asserted where                                                                              |
//! | ---------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
//! | Submit -> placement -> send_dispatch -> host-executor runs the job       | this file, `cross_machine_sandboxes_exchange_a_peer_message_through_the_hub` (live, real     |
//! | (host-executor leg; not the second local job / hub-exchange half, nor    | `sandyd` + real `sandy daemon submit` + `handle_dispatch`; `FakeContainment` stands in for    |
//! | real containment — tracked on #303, gated on #287/#299)                | real containment)                                                                              |
//! | Register-auth: unknown mesh identity gets `RegisterRefused` (infra-     | this file, `register_from_an_unlisted_mesh_identity_gets_no_ack_and_no_dispatch` (live, a    |
//! | f3's addendum to #263)                                                 | real `sandyd` + a real TCP client)                                                            |
//! | decision-6: wrong-peer refused, zero bytes                             | `sandyd::dispatch` / `link_auth` unit tests (#266); re-asserted at the mesh-accept loop by    |
//! |                                                                        | #290 (merged, `a8d7655`)                                                                       |
//! | decision-6: wrong-token refused, zero bytes                            | `sandyd::dispatch` / `link_auth` unit tests (#266); re-asserted by #290                       |
//! | decision-6: unknown run id refused, zero bytes                         | `sandyd::dispatch` unit tests (#266) — `LinkAuthError::UnknownRun`; re-asserted by #290        |
//! | decision-6: already-claimed link slot refused (one link per run)       | `sandyd::link_auth` unit tests (#266) — `concurrent_claims_admit_exactly_one_stream`;         |
//! |                                                                        | re-asserted by #290                                                                            |
//! | Isolation-class gate, orchestrator side: `send_dispatch` refuses a     | #277 (merged, `bab825a`) — `DispatchSendError::UnsupportedIsolationClass`, tested             |
//! | class the target host didn't declare, fail-closed                     | (`dispatch_requiring_an_undeclared_isolation_class_is_refused`,                               |
//! |                                                                        | `dispatch_with_an_unset_isolation_class_is_refused`). #280 closed as a duplicate of this.      |
//! | Isolation-class gate, executor side: `check_isolation_class` re-checks | #284 (merged, `945dd2e`) — reuses `sandy::admits_untrusted`; `Unspecified` refused, never     |
//! | `Dispatch.required_isolation_class` (defense in depth), fail-closed   | treated as the weaker `Trusted`.                                                               |
//! | *Not* re-asserted at this file's e2e layer, by explicit scoping call  | infra-f3's ruling: #277's unit coverage is sufficient and this file's `capabilities_of        |
//! | (not an oversight — see #272's thread before adding one)              | (host_id)` happy-path check already covers the one thing e2e uniquely adds (declared          |
//! |                                                                        | capabilities actually reaching the dispatch decision). A negative e2e case here would just    |
//! |                                                                        | re-run unit-proven logic through the same seam. If the declared-caps -> gate wiring regresses  |
//! |                                                                        | later, add one e2e negative then, not for M2.                                                 |
//! | Result path: exit via the locked `ResultEnvelope`/`AgentReport` (INV-  | existing unit coverage (`impls/fabric-local/src/{agent,link,executor}.rs`,                    |
//! | 11); an agent failure with no report is an infra fault, not a job exit | `sandy-cli/tests/live_agent.rs`); reasserted end-to-end in this file's happy-path test         |
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
    Arch, Capabilities, HostExecutorMessage, IsolationClass, OrchestratorMessage, Register, SandboxKind,
    host_executor_message, orchestrator_message,
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

/// Refuse unless `SANDY_M2_REMOTE_HOST` names a reachable NixOS host-executor's
/// mesh address, in addition to [`require_live_process_test`]'s usual
/// live-matrix check — the full cross-machine acceptance needs two real
/// machines, not one. Not called yet: the real remote-host run (#287/#299) is the
/// last remaining gate, still pending the operator's apply; kept here as the
/// gate that run will use, not speculative.
#[allow(
    dead_code,
    reason = "the real remote-host cross-machine run (#287/#299) will call this once it's written"
)]
fn require_remote_executor() -> anyhow::Result<String> {
    require_live_process_test()?;
    std::env::var("SANDY_M2_REMOTE_HOST")
        .map_err(|_| anyhow::anyhow!("refusing: set SANDY_M2_REMOTE_HOST to a NixOS host-executor's mesh address"))
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

/// A running real `sandyd` binary — its control socket, mesh management-
/// channel listener (Register/Dispatch), and mesh agent-link accept listener
/// (decision 6, where a dispatched job's executor forwards its agent link
/// back) all bound and accepting — killed on drop. `link_addr` isn't kept: no
/// caller needs to dial it directly, since `forward_back` always arrives via
/// a real `Dispatch` message instead.
struct Orchestrator {
    child: Child,
    sock: PathBuf,
    mesh_addr: SocketAddr,
}

impl Drop for Orchestrator {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Spawn the real `sandyd` binary with all three listeners bound to fresh
/// loopback ports/a fresh socket and `allowlist` as `SANDY_MESH_ALLOWLIST`,
/// waiting (bounded, polled) until each actually accepts a connection — a
/// fixed sleep would be either flaky under load or needlessly slow.
fn spawn_orchestrator(tmp: &std::path::Path, allowlist: &str) -> anyhow::Result<Orchestrator> {
    let mesh_addr: SocketAddr = format!("127.0.0.1:{}", free_tcp_port()?).parse()?;
    let link_addr: SocketAddr = format!("127.0.0.1:{}", free_tcp_port()?).parse()?;
    let sock = tmp.join("sandyd.sock");
    let child = Command::new(build_workspace_bin("sandyd", "sandyd")?)
        .env("SANDY_SOCK", &sock)
        .env("SANDY_DB", tmp.join("sandyd.db"))
        .env("SANDY_MESH_LISTEN", mesh_addr.to_string())
        .env("SANDY_MESH_ALLOWLIST", allowlist)
        .env("SANDY_MESH_AGENT_LINK_LISTEN", link_addr.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("spawning sandyd")?;
    let orchestrator = Orchestrator { child, sock, mesh_addr };

    let deadline = Instant::now() + Duration::from_secs(5);
    for addr in [mesh_addr, link_addr] {
        loop {
            if TcpStream::connect(addr).is_ok() {
                break;
            }
            if Instant::now() > deadline {
                anyhow::bail!("sandyd's listener on {addr} never accepted a connection");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if std::os::unix::net::UnixStream::connect(&orchestrator.sock).is_ok() {
            break;
        }
        if Instant::now() > deadline {
            anyhow::bail!("sandyd's control socket never accepted a connection");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    Ok(orchestrator)
}

/// Send a real `Register` frame to `orchestrator` over a plain TCP socket and
/// return its one response frame.
///
/// Not the real `sandy-host-executor` binary: `detect_register_capabilities()`
/// (the binary's first step, before it ever dials) hard-fails on a non-Linux
/// host (`SystemdRunContainment::detect` is unconditionally `Unsupported`
/// off Linux, `impls/local/src/containment.rs`), so spawning the real binary
/// on this Mac would exit 1 before `Register` is ever attempted — a false
/// functional-red for the wrong reason (sandy-91 caught this before this test
/// was run). This acceptance item is about the orchestrator's allowlist
/// behavior, which doesn't depend on the host-executor's capability probe, so a
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

    let message = HostExecutorMessage {
        op: Some(host_executor_message::Op::Register(Register {
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
        supported_sandbox_kinds: vec![SandboxKind::Process.into()],
        arch: Arch::X8664.into(),
        attestation: false,
        supported_isolation_classes: vec![IsolationClass::Trusted.into()],
    }
}

/// Run the real `sandy` binary's `daemon submit` against `orchestrator`'s
/// control socket, returning the parsed `job_id`.
fn submit_job(orchestrator: &Orchestrator, tmp: &std::path::Path, argv: &[&str]) -> anyhow::Result<String> {
    let manifest = tmp.join("manifest.json");
    std::fs::write(&manifest, serde_json::to_vec(argv)?).context("write the argv/v1 manifest")?;

    let output = Command::new(env!("CARGO_BIN_EXE_sandy"))
        .env("SANDY_SOCK", &orchestrator.sock)
        .args([
            "daemon",
            "submit",
            manifest.to_str().context("manifest path is utf8")?,
            "--manifest-encoding",
            "argv/v1",
            "-o",
            "json",
        ])
        .output()
        .context("running sandy daemon submit")?;
    anyhow::ensure!(
        output.status.success(),
        "sandy daemon submit failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).context("parse submit json")?;
    json["job_id"]
        .as_str()
        .map(str::to_owned)
        .context("submit json must carry a job_id")
}

/// The M2 stage-1 acceptance floor (`docs/architecture/kpi.md`), minus the
/// peer-message/second-job half: a registered host-executor receives a real
/// `Dispatch` from a real `sandy daemon submit`, placed there by the real
/// orchestrator (#298/#301's `send_dispatch` path), and actually runs the job
/// — host-executor side only (infra-f3's scoping ruling: the orchestrator-
/// through-real-path proof this test gives doesn't need the second local job
/// / hub-exchange half; that's #269's remaining acceptance once a real remote-host
/// is up, #299 + #287).
///
/// The host-executor side is `handle_dispatch` called directly with
/// `FakeContainment` (sandy-91: the real `sandy-host-executor` binary can't
/// start on this Mac — `detect_register_capabilities` hard-fails off Linux —
/// so this test declares capabilities and runs dispatches itself, in-process,
/// rather than spawning that binary) — real orchestrator binary, real wire
/// protocol, real `ProcessBackend` run, real `sandy-agent`, only the
/// host-executor's own I/O loop and capability probe are stood in for.
///
/// Functional-red observed before green (2026-10-18): first ran this with
/// the registered host declaring `Untrusted` only (not `Trusted`, which
/// `STAGE1_REQUIRED_ISOLATION_CLASS` requires) — `pick_host_for` genuinely
/// found no candidate, `submit_job` still succeeded (placement is
/// best-effort, #298) but the test's own read of the next frame timed out
/// waiting for a `Dispatch` that `send_dispatch` never called, failing for
/// the right reason (no eligible host, not a harness bug). Reverted to
/// declaring `Trusted` for the green below.
#[tokio::test]
async fn cross_machine_sandboxes_exchange_a_peer_message_through_the_hub() -> anyhow::Result<()> {
    require_live_process_test()?;
    let tmp = tempfile::tempdir().context("temp dir")?;

    // An allowlist that DOES include 127.0.0.1 — this leg of the acceptance is about
    // placement/dispatch, not the allowlist refusal (already covered by the other test).
    let orchestrator = spawn_orchestrator(tmp.path(), "127.0.0.1")?;

    // 1. Host-client declares its capabilities and registers — no hardcoded host on the orchestrator side, it places
    //    against whatever's actually registered.
    let mut host_conn = tokio::net::TcpStream::connect(orchestrator.mesh_addr)
        .await
        .context("dialing the orchestrator's mesh listener")?;
    sandy_control_proto::write_frame(
        &mut host_conn,
        &HostExecutorMessage {
            op: Some(host_executor_message::Op::Register(Register {
                host_id: "the-remote-host".to_owned(),
                capabilities: Some(trusted_process_capabilities()),
            })),
        },
    )
    .await
    .context("writing Register")?;
    let registered: OrchestratorMessage = sandy_control_proto::read_frame(&mut host_conn)
        .await
        .context("reading the Register response")?
        .context("connection closed before a Register response")?;
    assert!(
        matches!(registered.op, Some(orchestrator_message::Op::Registered(_))),
        "expected Registered, got {:?}",
        registered.op
    );

    // 2. Submit a real job through the real control socket. The orchestrator's placement (#298/#301) picks the one
    //    registered, Trusted-capable host and calls send_dispatch — this is the real path this test exists to prove,
    //    not re-implemented here.
    let job_id = submit_job(&orchestrator, tmp.path(), &["echo", "hi"])?;

    // 3. Read the Dispatch the real orchestrator placed on this connection.
    let dispatch_message: OrchestratorMessage =
        tokio::time::timeout(Duration::from_secs(5), sandy_control_proto::read_frame(&mut host_conn))
            .await
            .context("timed out waiting for a Dispatch — placement never reached send_dispatch")?
            .context("reading the Dispatch frame")?
            .context("connection closed before a Dispatch arrived")?;
    let dispatch = match dispatch_message.op {
        Some(orchestrator_message::Op::Dispatch(dispatch)) => dispatch,
        other => anyhow::bail!("expected Dispatch, got {other:?}"),
    };
    assert_eq!(dispatch.job_id, job_id, "the dispatch must name the job just submitted");
    assert_eq!(
        dispatch.manifest_encoding, "argv/v1",
        "the dispatch must carry the manifest encoding submitted"
    );

    // 4. Host-client re-checks the isolation class independently (`check_isolation_class`, defense in depth) and runs
    //    the job via the real ProcessBackend + a fake, spawnable containment (sandy-91: real SystemdRunContainment
    //    needs Linux cgroup v2, which this Mac doesn't have — the real containment leg is #299's nixosTest and the
    //    remote-host run).
    let agent_program = build_workspace_bin("sandy-agent", "sandy-agent")?;
    let rt = tokio::runtime::Handle::current();
    // Matches handle_dispatch's own internal stage-1 bound (STAGE1_TIMEOUT_SECS,
    // private to that crate): generous for a real `echo hi` run.
    let control = sandy::RunControl::with_timeout_secs(300);
    let outcome = tokio::task::spawn_blocking(move || {
        sandy_host_executor::dispatch::handle_dispatch(
            &dispatch,
            Box::new(sandy_test_support::FakeContainment::available()),
            agent_program,
            rt,
            false,
            control,
        )
    })
    .await
    .context("the dispatch-handling task panicked")?
    .context("handle_dispatch failed")?;

    // 5. Assert the job's own exit (INV-11): `echo hi` succeeds, and the agent's link delivered that through the real
    //    forward-back dial, not a backend-mediated shortcut.
    assert_eq!(
        outcome.transport_error, None,
        "the agent link to the orchestrator's mesh agent-link listener must not fault: {outcome:?}"
    );
    assert_eq!(outcome.guest_exit, Some(0), "echo hi must exit 0: {outcome:?}");
    assert!(
        !outcome.timed_out,
        "echo hi must not hit the dispatch timeout: {outcome:?}"
    );

    Ok(())
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
/// hand-rolled rather than the real `sandy-host-executor` binary).
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
