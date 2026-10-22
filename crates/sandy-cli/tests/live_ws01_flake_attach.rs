//! Live acceptance for #332's combined scenario (acceptance tier 3 — the
//! actual end-to-end case this whole chain of work was for): `sandy daemon
//! submit --flake <ref> -- sh` places a flake-templated VM job on ws01, then
//! `sandy daemon attach` from a GENUINELY SEPARATE process types a command
//! into the booted guest and reads real output back, detaches, and
//! reattaches from a second separate process to confirm the durable attach
//! token still grants post rights. Mirrors `live_ws01_attach.rs`'s own
//! gating, orchestrator-spawning, and data-plane join helpers exactly
//! (#327); the only difference is the manifest this submits (`flake/v1`
//! instead of `argv/v1`, landing as `SandboxKind::Vm` instead of `Process`)
//! and that the "real output" comes from inside a REAL qemu VM on ws01, not
//! a bare host process.
//!
//! Gated on `SANDY_M2_REMOTE_HOST` in addition to the usual `SANDY_LIVE=1`
//! (INV-S9): both must be set, or this refuses rather than green-skipping.
//!
//! BLOCKING DEPENDENCY (named explicitly, not attempted here): same as
//! `live_ws01_flake_dispatch.rs` — ws01's deployed `sandy-host-executor`
//! must be rebuilt with #332's VM-capability detection and redeployed before
//! this test can place anything as `SandboxKind::Vm`. Until then, Submit is
//! refused fail-closed with a named reason, not a hang or a silent
//! misbehavior.
//!
//! Run manually once ws01 is redeployed:
//!   SANDY_LIVE=1 SANDY_M2_REMOTE_HOST=100.64.0.3 \
//!     cargo nextest run -p sandy-cli --features live --test live_ws01_flake_attach
#![cfg(feature = "live")]

use std::{
    net::SocketAddr,
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use anyhow::Context;
use sandy_control_proto::{
    AttachRequest, StatusRequest, SubmitRequest, attach_socket_path, client::call, control_request, control_response,
};
use sandy_fabric::capauth::{CapRights, decode_cap};
use sandy_fabric_local::{
    agent::{TTY_STDIN, TTY_STDOUT},
    link::{LinkFrame, read_frame as link_read_frame, write_frame as link_write_frame},
};
use sandy_guest_template::manifest::{FlakeManifestV1, MANIFEST_ENCODING_FLAKE_V1, encode_flake_manifest};

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

/// See `live_ws01_flake_dispatch.rs`'s identical helper for the full
/// rationale: ws01 resolves and builds this itself, never a prebuilt
/// artifact.
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
) -> anyhow::Result<(String, Vec<u8>)> {
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
        Some(control_response::Result::Submit(r)) => Ok((r.job_id, r.attach_token)),
        // See `live_ws01_flake_dispatch.rs`'s identical arm for why the hint
        // is conditional, not unconditional (CodeRabbit finding on #336: an
        // unconditional suffix made every refusal look like "not yet
        // registered" to the retry loop below, which string-matches on it).
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

/// Retry Submit until ws01 has actually registered — see
/// `live_ws01_flake_dispatch.rs`'s identical helper for the full rationale
/// (a real host's `RestartSec=5s` redial loop does not align with any fixed
/// wait; observed live, registration can land 10-15s after a connection
/// drop, consistently past a flat 10s wait).
async fn submit_flake_once_registered(
    conn: &mut tokio::net::UnixStream,
    request_id: &mut u64,
    flake: &str,
    command: &[String],
    timeout: Duration,
) -> anyhow::Result<(String, Vec<u8>)> {
    let deadline = Instant::now() + timeout;
    loop {
        match submit_flake(conn, *request_id, flake, command.to_vec()).await {
            Ok(result) => return Ok(result),
            Err(err) if err.to_string().contains("SandboxKind::Vm") && Instant::now() < deadline => {
                *request_id += 1;
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            Err(err) => return Err(err),
        }
    }
}

async fn attach(
    conn: &mut tokio::net::UnixStream,
    request_id: u64,
    job_id: &str,
    token: Option<Vec<u8>>,
) -> anyhow::Result<(CapRights, Vec<u8>)> {
    let response = call(
        conn,
        request_id,
        control_request::Op::Attach(AttachRequest {
            job_id: job_id.to_owned(),
            attach_token: token,
        }),
    )
    .await
    .context("Attach call")?;
    match response.result {
        Some(control_response::Result::Attach(r)) => {
            let rights = decode_cap(&r.cap).context("decode the attach cap")?.scope().rights;
            Ok((rights, r.cap))
        }
        other => anyhow::bail!("expected an Attach response, got {other:?}"),
    }
}

async fn join_data_plane(
    attach_sock: &std::path::Path,
    cap: &[u8],
) -> anyhow::Result<(
    tokio::io::ReadHalf<tokio::net::UnixStream>,
    tokio::io::WriteHalf<tokio::net::UnixStream>,
)> {
    let stream = tokio::net::UnixStream::connect(attach_sock)
        .await
        .context("connect to the attach data plane")?;
    let (mut rd, mut wr) = tokio::io::split(stream);
    link_write_frame(
        &mut wr,
        &LinkFrame::Join {
            cap: hex::encode(cap),
            channel: None,
            cols: None,
            rows: None,
        },
    )
    .await
    .context("present the cap")?;
    match tokio::time::timeout(Duration::from_secs(5), link_read_frame(&mut rd))
        .await
        .context("timed out waiting for the join handshake")?
        .context("read the join handshake response")?
    {
        Some(LinkFrame::Joined { .. }) => Ok((rd, wr)),
        Some(LinkFrame::Refused { reason }) => anyhow::bail!("attach refused: {reason}"),
        other => anyhow::bail!("expected Joined or Refused, got {other:?}"),
    }
}

async fn post_input(wr: &mut tokio::io::WriteHalf<tokio::net::UnixStream>, bytes: &[u8]) -> anyhow::Result<()> {
    link_write_frame(
        wr,
        &LinkFrame::Post {
            content_type: TTY_STDIN.to_owned(),
            payload: hex::encode(bytes),
            channel: None,
        },
    )
    .await
    .context("post input")
}

async fn read_until(
    rd: &mut tokio::io::ReadHalf<tokio::net::UnixStream>,
    needle: &str,
    timeout: Duration,
) -> anyhow::Result<LinkFrame> {
    let deadline = Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        anyhow::ensure!(!remaining.is_zero(), "timed out waiting for {needle:?}");
        let frame = tokio::time::timeout(remaining, link_read_frame(rd))
            .await
            .context("timed out mid-read")?
            .context("read faulted")?
            .context("connection closed before the needle arrived")?;
        if let LinkFrame::Deliver {
            content_type, payload, ..
        } = &frame
            && content_type == TTY_STDOUT
        {
            let bytes = hex::decode(payload).context("delivered payload was not hex")?;
            if String::from_utf8_lossy(&bytes).contains(needle) {
                return Ok(frame);
            }
        }
        if matches!(frame, LinkFrame::Refused { .. }) {
            return Ok(frame);
        }
    }
}

/// The real end-to-end acceptance floor for #332: a flake-templated VM job
/// booted for real on ws01, then a GENUINELY SEPARATE attach process typing
/// a command into it and reading real output back from INSIDE the VM, then
/// a SECOND separate process reattaching with only the durable token and
/// confirming it still grants post rights.
#[tokio::test]
async fn a_separate_attach_process_drives_a_real_vm_booted_on_ws01() -> anyhow::Result<()> {
    let host = require_remote_executor()?;
    let tmp = tempfile::tempdir().context("temp dir")?;

    let remote_peer: std::net::IpAddr = std::env::var("SANDY_M2_REMOTE_PEER")
        .unwrap_or_else(|_| "100.64.0.1".to_owned())
        .parse()
        .context("SANDY_M2_REMOTE_PEER is not a valid IP address")?;

    let orchestrator = spawn_orchestrator(tmp.path(), host, remote_peer)?;
    let attach_sock = attach_socket_path(&orchestrator.sock);

    let mut submitter_conn = tokio::net::UnixStream::connect(&orchestrator.sock)
        .await
        .context("connect the submitting control connection")?;
    // A bare `sh` (no `-c` script): the VM agent's own
    // `agent_shell_command` wraps whatever command this names as
    // `sh -c '<command.join(" ")>'`, so a bare `sh` here runs a NESTED shell
    // that reads commands interactively from its stdin — connected through
    // the agent channel, exactly the "boot runs an interactive shell"
    // fixture shape the acceptance bar asks for.
    let mut submitter_request_id = 1;
    let (job_id, attach_token) = submit_flake_once_registered(
        &mut submitter_conn,
        &mut submitter_request_id,
        &flake_ref(),
        &[String::from("sh")],
        Duration::from_secs(60),
    )
    .await
    .context("submit a flake-templated VM job with an interactive shell command")?;
    submitter_request_id += 1;

    // A cold `nix build` + a real qemu boot is slow — measured locally
    // (#338 follow-up) at ~115s for just the runner-attr build of this
    // exact fixture on a cold store, well past a flat 20s. 180s leaves
    // margin for that plus boot time without approaching
    // `FLAKE_RESOLVE_TIMEOUT_SECS` (600s, `dispatch.rs`) or this test's own
    // 60s registration-retry budget above.
    tokio::time::sleep(Duration::from_secs(180)).await;

    // THE REALISTIC CASE: a totally fresh connection, no shared session with
    // the submitter, presenting only the durable token — standing in for a
    // genuinely separate `sandy daemon attach <job_id>` process invocation.
    let mut fresh_conn = tokio::net::UnixStream::connect(&orchestrator.sock)
        .await
        .context("connect a fresh connection for the token-based attach")?;
    let (rights, cap) = attach(&mut fresh_conn, 1, &job_id, Some(attach_token.clone()))
        .await
        .context("token-based attach from a fresh connection against the real VM job")?;
    assert!(
        rights.post,
        "a fresh connection presenting the durable attach token must be post-capable against a real VM job"
    );

    let (mut rd, mut wr) = join_data_plane(&attach_sock, &cap)
        .await
        .context("join the real VM job's data plane")?;
    post_input(&mut wr, b"echo hello-from-ws01-vm\n")
        .await
        .context("post a command into the real VM's interactive shell")?;
    read_until(&mut rd, "hello-from-ws01-vm", Duration::from_secs(20))
        .await
        .context("waiting for the real VM's shell to echo the command's real output back")?;

    // Detach (drop the data-plane connection), then reattach from a SECOND
    // genuinely separate process/connection, confirming the durable token
    // still grants post rights after a detach — the issue's own "detach,
    // reattach from another separate process" bar.
    drop(wr);
    drop(rd);

    let mut second_conn = tokio::net::UnixStream::connect(&orchestrator.sock)
        .await
        .context("connect a second, separate connection for the reattach")?;
    let (reattach_rights, reattach_cap) = attach(&mut second_conn, 1, &job_id, Some(attach_token))
        .await
        .context("reattach with the durable token after detaching")?;
    assert!(
        reattach_rights.post,
        "the durable attach token must still grant post rights after a detach and reattach"
    );

    let (mut rd2, mut wr2) = join_data_plane(&attach_sock, &reattach_cap)
        .await
        .context("rejoin the real VM job's data plane after reattaching")?;
    post_input(&mut wr2, b"echo reattached-and-still-post-capable\n")
        .await
        .context("post a second command after reattaching")?;
    read_until(&mut rd2, "reattached-and-still-post-capable", Duration::from_secs(20))
        .await
        .context("waiting for the reattached session's command to echo back")?;

    // Tear the shell down so the job terminates cleanly, then confirm the
    // control plane itself agrees the job finished (not just that its shell
    // echoed output — the full round trip this chain of work was for).
    post_input(&mut wr2, b"exit\n").await.context("exit the guest shell")?;

    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let status = call(
            &mut submitter_conn,
            submitter_request_id,
            control_request::Op::Status(StatusRequest { job_id: job_id.clone() }),
        )
        .await
        .context("Status after the round trip")?;
        submitter_request_id += 1;
        match status.result {
            Some(control_response::Result::Status(s)) if s.status != sandy_control_proto::JobStatus::Running as i32 => {
                assert_eq!(
                    s.status,
                    sandy_control_proto::JobStatus::Succeeded as i32,
                    "the real VM job must have exited cleanly once its interactive shell was told to exit: {s:?}"
                );
                break;
            }
            Some(control_response::Result::Status(_)) => {
                anyhow::ensure!(
                    Instant::now() <= deadline,
                    "the real VM job never left Running after its shell was told to exit"
                );
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
            other => anyhow::bail!("expected a Status response, got {other:?}"),
        }
    }

    let _ = tmp; // keep tempdir alive through the whole test
    Ok(())
}
