//! Live acceptance for #327's interactive attach against a REAL registered
//! host-executor (not `FakeContainment` — `live_attach.rs`'s own loopback
//! stand-in), proving the realistic "submit now, attach later from a
//! genuinely separate process" case over the actual mesh, against real infra.
//!
//! Gated on `SANDY_M2_REMOTE_HOST` in addition to the usual `SANDY_LIVE=1`
//! (INV-S9): both must be set, or this refuses rather than green-skipping.
//! `SANDY_M2_REMOTE_HOST` names the orchestrator's own mesh address as the
//! remote host dials it (e.g. `100.64.0.3`), matching the convention
//! `live_m2_cross_machine.rs`'s unused `require_remote_executor` reserved for
//! this exact run. The remote host-executor itself is NOT started by this
//! test — it's a standing service (systemd on the remote box), already
//! configured to dial this orchestrator's address; this test only has to
//! bind there and wait for its Register.
//!
//! Run manually (the remote host-executor must already be configured to dial
//! the given address and reachable over the mesh):
//!   SANDY_LIVE=1 SANDY_M2_REMOTE_HOST=100.64.0.3 \
//!     cargo nextest run -p sandy-cli --features live --test live_ws01_attach
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

/// Refuse unless both `SANDY_LIVE=1` and `SANDY_M2_REMOTE_HOST` are set
/// (INV-S9) — a run against real cross-machine infra needs both the general
/// live gate and the specific address a real remote host-executor is
/// configured to dial; off either, this refuses rather than green-skipping.
/// Returns the mesh address to bind as (host, port 7777/7778 by convention
/// matching the deployed `SANDY_HOST_EXECUTOR_ORCHESTRATOR` value — see the
/// repo's own operator docs for the remote host's own configured port).
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
/// (7777 management, 7778 agent-link) — not loopback: a real remote
/// host-executor must be able to dial these from across the mesh.
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
        // `inherit`, not `piped`: nothing in this test reads the child's
        // stdout/stderr, and a piped fd nobody drains blocks the child once
        // the OS pipe buffer fills (CodeRabbit, #327's review) -- inherited
        // output still shows up under `--no-capture` and is otherwise
        // discarded by nextest the same way a piped-but-undrained one would
        // have been, without the deadlock risk.
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
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

/// Give the REAL remote host-executor's own restart loop time to notice this
/// orchestrator came up and register (it's a standing service, already
/// configured to dial this address, cycling on its own `RestartSec`, not
/// something this test starts or can observe directly over this socket). The
/// real proof that it actually registered is the Dispatch this test's own
/// `submit`+`attach` round trip depends on below — this is only a bounded
/// wait, not a check.
async fn wait_for_real_registration(timeout: Duration) {
    tokio::time::sleep(timeout).await;
}

async fn submit(
    conn: &mut tokio::net::UnixStream,
    request_id: u64,
    argv: &[&str],
) -> anyhow::Result<(String, Vec<u8>)> {
    let manifest = serde_json::to_vec(argv).context("encode argv manifest")?;
    let response = call(
        conn,
        request_id,
        control_request::Op::Submit(SubmitRequest {
            manifest,
            manifest_encoding: "argv/v1".to_owned(),
            submitter_caps: Vec::new(),
        }),
    )
    .await
    .context("Submit call")?;
    match response.result {
        Some(control_response::Result::Submit(r)) => Ok((r.job_id, r.attach_token)),
        other => anyhow::bail!("expected a Submit response, got {other:?}"),
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

/// The real-infra acceptance floor for #327: a real `sandyd` bound to the
/// actual mesh address, a REAL standing remote host-executor (not
/// `FakeContainment`), a real `sh` job dispatched and run on the remote
/// machine. Proves the realistic case — submit on one connection, then a
/// TOTALLY SEPARATE connection presenting only the durable `attach_token`
/// (standing in for a genuinely separate `sandy daemon attach` process
/// invocation, exactly as a human operator would run it) — gets post-capable
/// rights and a real round trip against the remote process's own stdin/stdout,
/// not a local stand-in.
#[tokio::test]
async fn a_real_remote_host_executor_grants_post_rights_to_a_separate_attach_process() -> anyhow::Result<()> {
    let host = require_remote_executor()?;
    let tmp = tempfile::tempdir().context("temp dir")?;

    // SANDY_M2_REMOTE_PEER names the real remote host-executor's mesh IP, for
    // the allowlist. Defaults to 100.64.0.1 (ws01) if unset, matching this
    // project's documented remote host.
    let remote_peer: std::net::IpAddr = std::env::var("SANDY_M2_REMOTE_PEER")
        .unwrap_or_else(|_| "100.64.0.1".to_owned())
        .parse()
        .context("SANDY_M2_REMOTE_PEER is not a valid IP address")?;

    let orchestrator = spawn_orchestrator(tmp.path(), host, remote_peer)?;
    let attach_sock = attach_socket_path(&orchestrator.sock);

    wait_for_real_registration(Duration::from_secs(10)).await;

    let mut submitter_conn = tokio::net::UnixStream::connect(&orchestrator.sock)
        .await
        .context("connect the submitting control connection")?;
    let (job_id, attach_token) = submit(&mut submitter_conn, 1, &["sh", "-c", "read a; echo \"echo:$a\""])
        .await
        .context("submit a real job to the real remote host-executor")?;

    // Give placement+dispatch+the real remote run a generous window — this
    // crosses a real network to a real machine, not an in-process fake.
    tokio::time::sleep(Duration::from_secs(2)).await;

    // THE REALISTIC CASE: a totally fresh connection, no shared session with
    // the submitter, presenting only the durable token — standing in for a
    // genuinely separate `sandy daemon attach <job_id>` process invocation.
    let mut fresh_conn = tokio::net::UnixStream::connect(&orchestrator.sock)
        .await
        .context("connect a fresh connection for the token-based attach")?;
    let (rights, cap) = attach(&mut fresh_conn, 1, &job_id, Some(attach_token))
        .await
        .context("token-based attach from a fresh connection against the real remote job")?;
    assert!(
        rights.post,
        "a fresh connection presenting the durable attach token must be post-capable against a real remote job"
    );

    let (mut rd, mut wr) = join_data_plane(&attach_sock, &cap)
        .await
        .context("join the real remote job's data plane")?;
    post_input(&mut wr, b"real-remote-infra\n")
        .await
        .context("post input to the real remote process")?;
    read_until(&mut rd, "echo:real-remote-infra", Duration::from_secs(15))
        .await
        .context("waiting for the real remote process to echo the posted input back")?;

    // The echoed output arriving only proves the remote shell printed it, not
    // that it has already exited and that exit's been reported all the way
    // back over the real mesh link — poll briefly rather than asserting on
    // the first check, which raced the real outcome-report round trip.
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut request_id = 2;
    let final_status = loop {
        let status = call(
            &mut submitter_conn,
            request_id,
            control_request::Op::Status(StatusRequest { job_id: job_id.clone() }),
        )
        .await
        .context("Status after the round trip")?;
        request_id += 1;
        match status.result {
            Some(control_response::Result::Status(s)) if s.status != sandy_control_proto::JobStatus::Running as i32 => {
                break s;
            }
            Some(control_response::Result::Status(_)) => {
                anyhow::ensure!(
                    Instant::now() <= deadline,
                    "the real remote job never left Running within the deadline"
                );
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
            other => anyhow::bail!("expected a Status response, got {other:?}"),
        }
    };
    assert_eq!(
        final_status.status,
        sandy_control_proto::JobStatus::Succeeded as i32,
        "the real remote job must have exited cleanly after its one read was satisfied: {final_status:?}"
    );
    assert_eq!(final_status.exit_code, Some(0), "the real remote job must exit 0");

    let _ = tmp; // keep tempdir alive through the whole test
    Ok(())
}
