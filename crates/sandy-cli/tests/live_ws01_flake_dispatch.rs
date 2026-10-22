//! Live acceptance for #332's flake-templated VM dispatch, alone (acceptance
//! tier 1): `sandy daemon submit --flake <ref>` places on ws01 (the only
//! registered host once it declares `SandboxKind::Vm`), ws01 builds and boots
//! a REAL qemu VM from it, and the job succeeds — proven via the control
//! plane's own `Status`, not reasoning. Mirrors `live_ws01_attach.rs`'s own
//! gating and orchestrator-spawning shape exactly (#327); the only real
//! difference is the manifest this submits (`flake/v1` instead of
//! `argv/v1`) and the backend it must land as (`Vm` instead of `Process`).
//!
//! Gated on `SANDY_M2_REMOTE_HOST` in addition to the usual `SANDY_LIVE=1`
//! (INV-S9): both must be set, or this refuses rather than green-skipping.
//! The remote host-executor is NOT started by this test — a real deployed
//! systemd service on ws01, already configured to dial this orchestrator's
//! address (see `live_ws01_attach.rs`'s own doc for the full picture).
//!
//! BLOCKING DEPENDENCY (named explicitly, not attempted here): this test can
//! only place on ws01 once its DEPLOYED `sandy-host-executor` binary is
//! rebuilt with #332's VM-capability detection (`capability::
//! detect_register_capabilities`) and redeployed — the standing service
//! today still registers `Process` only. Until that redeploy happens, a run
//! of this test will see Submit refused with "no registered host declares
//! SandboxKind::Vm capability" (`handler.rs`'s own #332 refusal), which is
//! the CORRECT, fail-closed behavior for an un-redeployed host, not a bug in
//! this test.
//!
//! Run manually once ws01 is redeployed (the remote host-executor must
//! already be configured to dial the given address and reachable over the
//! mesh):
//!   SANDY_LIVE=1 SANDY_M2_REMOTE_HOST=100.64.0.3 \
//!     cargo nextest run -p sandy-cli --features live --test live_ws01_flake_dispatch
#![cfg(feature = "live")]

use std::{
    net::SocketAddr,
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use anyhow::Context;
use sandy_control_proto::{StatusRequest, SubmitRequest, client::call, control_request, control_response};
use sandy_guest_template::manifest::{FlakeManifestV1, MANIFEST_ENCODING_FLAKE_V1, encode_flake_manifest};

/// Refuse unless both `SANDY_LIVE=1` and `SANDY_M2_REMOTE_HOST` are set
/// (INV-S9) — see `live_ws01_attach.rs`'s identical gate for the full
/// rationale.
fn require_remote_executor() -> anyhow::Result<std::net::IpAddr> {
    anyhow::ensure!(
        std::env::var("SANDY_LIVE").ok().as_deref() == Some("1"),
        "refusing: this is a live gate — set SANDY_LIVE=1"
    );
    std::env::var("SANDY_M2_REMOTE_HOST")
        .context(
            "refusing: set SANDY_M2_REMOTE_HOST to the mesh address this orchestrator should bind, matching what the \
             real remote host-executor is configured to dial",
        )?
        .parse()
        .context("SANDY_M2_REMOTE_HOST is not a valid IP address")
}

/// The flake reference ws01 resolves and builds ITSELF (#332 ground truth:
/// never ship a prebuilt artifact here — a topology built on this Mac
/// (aarch64) is useless on ws01 (x86_64-linux); ws01 must fetch and
/// build its own). Defaults to `main`, where this fixture lives once #332
/// merges — overridable via `SANDY_M2_FLAKE_REF` for a branch not yet merged
/// (this one included, before it lands), or a different fixture.
fn flake_ref() -> String {
    std::env::var("SANDY_M2_FLAKE_REF").unwrap_or_else(|_| {
        "git+https://github.com/kauki-labs/sandy?ref=main&dir=nix/guest-wrapper/tests/fixtures/nixos-module-hello"
            .to_owned()
    })
}

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

struct Orchestrator {
    child: Child,
    sock: PathBuf,
}

impl Drop for Orchestrator {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Spawn a real `sandyd` bound to `host` on the two well-known M2 ports
/// (7777 management, 7778 agent-link) — not loopback, mirroring
/// `live_ws01_attach.rs`'s own `spawn_orchestrator` exactly.
fn spawn_orchestrator(
    tmp: &std::path::Path,
    host: std::net::IpAddr,
    remote_host: std::net::IpAddr,
) -> anyhow::Result<Orchestrator> {
    let mesh_addr: SocketAddr = format!("{host}:7777").parse()?;
    let link_addr: SocketAddr = format!("{host}:7778").parse()?;
    let sock = tmp.join("sandyd.sock");
    let child = Command::new(build_workspace_bin("sandyd", "sandyd")?)
        .env("SANDY_SOCK", &sock)
        .env("SANDY_DB", tmp.join("sandyd.db"))
        .env("SANDY_MESH_LISTEN", mesh_addr.to_string())
        .env("SANDY_MESH_ALLOWLIST", remote_host.to_string())
        .env("SANDY_MESH_AGENT_LINK_LISTEN", link_addr.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("spawning sandyd")?;
    let orchestrator = Orchestrator { child, sock };

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if std::os::unix::net::UnixStream::connect(&orchestrator.sock).is_ok() {
            break;
        }
        anyhow::ensure!(
            Instant::now() <= deadline,
            "sandyd's control socket never accepted a connection"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    Ok(orchestrator)
}

async fn submit_flake(
    conn: &mut tokio::net::UnixStream,
    request_id: u64,
    flake: &str,
    command: Vec<String>,
) -> anyhow::Result<String> {
    let manifest = encode_flake_manifest(&FlakeManifestV1 {
        flake: flake.to_owned(),
        kind: None,
        attr: None,
        command,
        history_lines: sandy_guest_template::manifest::default_history_lines(),
    })
    .context("encode flake/v1 manifest")?;
    let response = call(
        conn,
        request_id,
        control_request::Op::Submit(SubmitRequest {
            manifest,
            manifest_encoding: MANIFEST_ENCODING_FLAKE_V1.to_owned(),
            submitter_caps: Vec::new(),
        }),
    )
    .await
    .context("Submit call")?;
    match response.result {
        Some(control_response::Result::Submit(r)) => Ok(r.job_id),
        // The explanatory suffix is appended ONLY when `e.message` itself
        // names `SandboxKind::Vm` — never unconditionally. CodeRabbit finding
        // on #336: an unconditional suffix made every refusal (including an
        // unrelated one, e.g. a malformed manifest) look like "not yet
        // registered" to `submit_flake_once_registered`'s string-matching
        // retry below, retrying for the full 60s instead of failing fast.
        Some(control_response::Result::Error(e)) => {
            let hint = if e.message.contains("SandboxKind::Vm") {
                " (ws01's deployed sandy-host-executor has not been redeployed with #332's VM-capability detection \
                 yet, a known, documented blocking dependency, not a bug in this test — or it has registered but not \
                 yet declared Vm)"
            } else {
                ""
            };
            anyhow::bail!("Submit was refused: {}{hint}", e.message)
        }
        other => anyhow::bail!("expected a Submit response, got {other:?}"),
    }
}

/// Retry Submit until ws01 has actually registered, instead of a single
/// attempt after a fixed sleep: the real host's `RestartSec=5s` redial loop
/// does not align with any fixed wait, and a too-short one is exactly the
/// race this replaces (observed live: ws01 can take 10-15s to reconnect
/// after its previous orchestrator connection drops, consistently past a
/// flat 10s wait — a "SandboxKind::Vm" refusal right after a connection drop
/// means "not yet registered", not "never will be").
async fn submit_flake_once_registered(
    conn: &mut tokio::net::UnixStream,
    request_id: &mut u64,
    flake: &str,
    command: &[String],
    timeout: Duration,
) -> anyhow::Result<String> {
    let deadline = Instant::now() + timeout;
    loop {
        match submit_flake(conn, *request_id, flake, command.to_vec()).await {
            Ok(job_id) => return Ok(job_id),
            Err(err) if err.to_string().contains("SandboxKind::Vm") && Instant::now() < deadline => {
                *request_id += 1;
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            Err(err) => return Err(err),
        }
    }
}

/// The real-infra acceptance floor for #332 tier 1: a real `sandyd` bound to
/// the actual mesh address, a REAL standing remote host-executor declaring
/// `SandboxKind::Vm`, a `flake/v1` job dispatched, ws01 building and booting
/// a real qemu VM from the flake reference it resolved itself, and the job
/// succeeding — proven via `Status`, not reasoning.
#[tokio::test]
async fn a_flake_templated_vm_job_dispatches_and_succeeds_on_ws01() -> anyhow::Result<()> {
    let host = require_remote_executor()?;
    let tmp = tempfile::tempdir().context("temp dir")?;

    let remote_peer: std::net::IpAddr = std::env::var("SANDY_M2_REMOTE_PEER")
        .unwrap_or_else(|_| "100.64.0.1".to_owned())
        .parse()
        .context("SANDY_M2_REMOTE_PEER is not a valid IP address")?;

    let orchestrator = spawn_orchestrator(tmp.path(), host, remote_peer)?;

    let mut conn = tokio::net::UnixStream::connect(&orchestrator.sock)
        .await
        .context("connect the control socket")?;
    // A deterministic, trivial guest command (`sh -c 'true'` once the VM
    // agent wraps it, see `impls/vm/src/agent.rs::agent_shell_command`) —
    // exit 0 regardless of which fixture flake this resolves, proving the
    // dispatch+boot+run path itself, not any particular guest content.
    let mut request_id = 1;
    let job_id = submit_flake_once_registered(
        &mut conn,
        &mut request_id,
        &flake_ref(),
        &[String::from("true")],
        Duration::from_secs(60),
    )
    .await
    .context("submit the flake-templated VM job")?;
    request_id += 1;

    // A cold `nix build` + a real qemu boot is slow — generous, bounded
    // polling rather than a fixed sleep.
    let deadline = Instant::now() + Duration::from_secs(180);
    let final_status = loop {
        let status = call(
            &mut conn,
            request_id,
            control_request::Op::Status(StatusRequest { job_id: job_id.clone() }),
        )
        .await
        .context("Status call")?;
        request_id += 1;
        match status.result {
            Some(control_response::Result::Status(s)) if s.status != sandy_control_proto::JobStatus::Running as i32 => {
                break s;
            }
            Some(control_response::Result::Status(_)) => {
                anyhow::ensure!(
                    Instant::now() <= deadline,
                    "the flake-templated VM job never left Running within the deadline — a cold `nix build` on ws01 \
                     can be slow; widen the deadline if this is the first run against a fresh ws01 nix store"
                );
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            other => anyhow::bail!("expected a Status response, got {other:?}"),
        }
    };
    assert_eq!(
        final_status.status,
        sandy_control_proto::JobStatus::Succeeded as i32,
        "the flake-templated VM job must boot and exit cleanly on ws01: {final_status:?}"
    );
    assert_eq!(
        final_status.exit_code,
        Some(0),
        "the trivial `true` guest command must exit 0"
    );

    let _ = tmp; // keep tempdir alive through the whole test
    Ok(())
}
