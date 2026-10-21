//! Live acceptance for #327's interactive attach: a real `sandyd` + a real
//! dispatched job (via `handle_dispatch` with `FakeContainment`, the same
//! M2-stage-1 pattern `live_m2_cross_machine.rs` uses and documents why —
//! sandy-91: the real `sandy-host-executor` binary can't start on this Mac),
//! driven through the REAL attach data plane end to end: post bytes, read
//! them echoed back through the real job's own stdout; a cross-session
//! attach gets observer rights only; detach-then-reattach on the SAME
//! control session continues interacting with the SAME live process.
//!
//! Run manually:
//!   SANDY_LIVE=1 cargo nextest run -p sandy-cli --features live --test live_attach
#![cfg(feature = "live")]

use std::{
    net::{SocketAddr, TcpListener},
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use anyhow::Context;
use sandy_control_proto::{
    AttachRequest, StatusRequest, SubmitRequest, attach_socket_path, client::call, control_request, control_response,
};
use sandy_executor_proto::{
    Arch, Capabilities, HostExecutorMessage, IsolationClass, OrchestratorMessage, Register, SandboxKind,
    host_executor_message, orchestrator_message,
};
use sandy_fabric::capauth::{CapRights, decode_cap};
use sandy_fabric_local::{
    agent::{TTY_STDIN, TTY_STDOUT},
    link::{LinkFrame, read_frame as link_read_frame, write_frame as link_write_frame},
};

/// Refuse unless `SANDY_LIVE=1` (INV-S9) — mirrors `live_m2_cross_machine.rs`'s
/// own gate exactly; this file spawns real OS processes and binds real TCP
/// sockets, M2 stage 1 needs no hypervisor.
fn require_live_process_test() -> anyhow::Result<()> {
    anyhow::ensure!(
        std::env::var("SANDY_LIVE").ok().as_deref() == Some("1"),
        "refusing: this is a live gate — set SANDY_LIVE=1"
    );
    Ok(())
}

/// Build `package`'s `bin` binary and return its path — identical to
/// `live_m2_cross_machine.rs`'s own helper (duplicated, not shared: these
/// live test files are each self-contained, per that file's own doc).
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

fn free_tcp_port() -> anyhow::Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0").context("bind an ephemeral port to find a free one")?;
    Ok(listener.local_addr()?.port())
}

/// A running real `sandyd` binary, killed on drop. Mirrors
/// `live_m2_cross_machine.rs`'s own `Orchestrator`.
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
            if std::net::TcpStream::connect(addr).is_ok() {
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

fn trusted_process_capabilities() -> Capabilities {
    Capabilities {
        kind: SandboxKind::Process.into(),
        arch: Arch::X8664.into(),
        attestation: false,
        supported_isolation_classes: vec![IsolationClass::Trusted.into()],
    }
}

/// Submit `argv` as a direct-mint job over `conn` (this connection's own
/// session — CF-H-1 — becomes the job's recorded submitting session) and
/// return its job id.
async fn submit(conn: &mut tokio::net::UnixStream, request_id: u64, argv: &[&str]) -> anyhow::Result<String> {
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
        Some(control_response::Result::Submit(r)) => Ok(r.job_id),
        other => anyhow::bail!("expected a Submit response, got {other:?}"),
    }
}

/// Attach to `job_id` over `conn` and return the decoded cap's rights plus
/// the raw cap bytes (for presenting on the data plane).
async fn attach(
    conn: &mut tokio::net::UnixStream,
    request_id: u64,
    job_id: &str,
) -> anyhow::Result<(CapRights, Vec<u8>)> {
    let response = call(
        conn,
        request_id,
        control_request::Op::Attach(AttachRequest {
            job_id: job_id.to_owned(),
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

/// Connect to the attach data-plane socket and present `cap`, returning the
/// joined connection's split halves.
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

/// Read delivered frames until one whose decoded `TTY_STDOUT` payload
/// contains `needle`, or the timeout elapses. `Refused` frames are returned
/// to the caller instead of skipped, since a test expecting a refusal needs
/// to see it.
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
        match &frame {
            LinkFrame::Deliver {
                content_type, payload, ..
            } if content_type == TTY_STDOUT => {
                let bytes = hex::decode(payload).context("delivered payload was not hex")?;
                if String::from_utf8_lossy(&bytes).contains(needle) {
                    return Ok(frame);
                }
            }
            LinkFrame::Refused { .. } => return Ok(frame),
            _ => {}
        }
    }
}

/// The M2 stage-1 acceptance floor for #327: real `sandyd`, a real
/// registered host-executor (`handle_dispatch` + `FakeContainment`, same
/// sandy-91 reasoning as `live_m2_cross_machine.rs`), a real
/// `sh`-script job that reads two lines and echoes each — driven through the
/// real attach data plane.
#[tokio::test]
async fn real_attach_round_trips_proves_session_fork_and_survives_detach_reattach() -> anyhow::Result<()> {
    require_live_process_test()?;
    let tmp = tempfile::tempdir().context("temp dir")?;
    let orchestrator = spawn_orchestrator(tmp.path(), "127.0.0.1")?;
    let attach_sock = attach_socket_path(&orchestrator.sock);

    // 1. Register a host-executor stand-in (real wire Register, same as live_m2_cross_machine.rs).
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

    // 2. Submit over OUR OWN control connection, kept open: this connection's session (CF-H-1) is the one `Attach` on
    //    it will match.
    let mut submitter_conn = tokio::net::UnixStream::connect(&orchestrator.sock)
        .await
        .context("connect the submitting control connection")?;
    let job_id = submit(
        &mut submitter_conn,
        1,
        &["sh", "-c", "read a; echo \"echo:$a\"; read b; echo \"echo:$b\""],
    )
    .await
    .context("submit the job")?;

    // 3. Read the real Dispatch the orchestrator placed, then run it for real via handle_dispatch — spawned, not
    //    awaited yet: the job reads two lines before it exits, so it's still alive while this test drives the attach
    //    data plane below.
    let dispatch_message: OrchestratorMessage =
        tokio::time::timeout(Duration::from_secs(5), sandy_control_proto::read_frame(&mut host_conn))
            .await
            .context("timed out waiting for a Dispatch")?
            .context("reading the Dispatch frame")?
            .context("connection closed before a Dispatch arrived")?;
    let dispatch = match dispatch_message.op {
        Some(orchestrator_message::Op::Dispatch(dispatch)) => dispatch,
        other => anyhow::bail!("expected Dispatch, got {other:?}"),
    };
    assert_eq!(dispatch.job_id, job_id);

    let agent_program = build_workspace_bin("sandy-agent", "sandy-agent")?;
    let rt = tokio::runtime::Handle::current();
    let running = tokio::task::spawn_blocking(move || {
        sandy_host_executor::dispatch::handle_dispatch(
            &dispatch,
            Box::new(sandy_test_support::FakeContainment::available()),
            agent_program,
            rt,
        )
    });

    // 4. Attach from the SAME (submitting) session: post-capable.
    let (rights, cap) = attach(&mut submitter_conn, 2, &job_id)
        .await
        .context("same-session attach")?;
    assert!(rights.post, "the submitting session's own attach must be post-capable");
    let (mut rd, mut wr) = join_data_plane(&attach_sock, &cap).await.context("join as submitter")?;

    post_input(&mut wr, b"first\n").await.context("post the first line")?;
    read_until(&mut rd, "echo:first", Duration::from_secs(10))
        .await
        .context("waiting for the first echoed line")?;

    // 5. A DIFFERENT session attaching to the SAME job gets observer rights only: read succeeds (it sees the job is
    //    still alive via Status), post is refused on the wire — the one new behavioral fork, proven directly, while the
    //    job is still genuinely live.
    let mut observer_conn = tokio::net::UnixStream::connect(&orchestrator.sock)
        .await
        .context("connect a different control connection")?;
    let (observer_rights, observer_cap) = attach(&mut observer_conn, 1, &job_id)
        .await
        .context("cross-session attach")?;
    assert!(!observer_rights.post, "a cross-session attach must not be post-capable");
    assert!(
        observer_rights.read,
        "a cross-session attach must still be read-capable"
    );
    let (mut observer_rd, mut observer_wr) = join_data_plane(&attach_sock, &observer_cap)
        .await
        .context("join as observer")?;
    post_input(&mut observer_wr, b"should-be-refused\n")
        .await
        .context("post as observer")?;
    // The needle never matches a real Deliver payload — `read_until` returns
    // on the first `Refused` frame regardless, which is what this waits for.
    let refusal = read_until(
        &mut observer_rd,
        "__never_matches_a_delivered_payload__",
        Duration::from_secs(5),
    )
    .await
    .context("waiting for the observer's post to be refused")?;
    assert!(matches!(refusal, LinkFrame::Refused { .. }), "got {refusal:?}");
    drop(observer_wr);
    drop(observer_rd);
    drop(observer_conn);

    // 6. Detach (drop the data connection) — the job must keep running.
    drop(wr);
    drop(rd);
    let status = call(
        &mut submitter_conn,
        3,
        control_request::Op::Status(StatusRequest { job_id: job_id.clone() }),
    )
    .await
    .context("Status after detach")?;
    match status.result {
        Some(control_response::Result::Status(s)) => {
            assert_eq!(
                s.status,
                sandy_control_proto::JobStatus::Running as i32,
                "the job must still be running after a detach, not affected by it"
            );
        }
        other => anyhow::bail!("expected a Status response, got {other:?}"),
    }

    // 7. Reattach on the SAME (submitting) session, continuing to interact with the SAME live process: a fresh
    //    post-capable cap, a fresh data connection, the job's SECOND `read` still pending from before.
    let (rights, cap) = attach(&mut submitter_conn, 4, &job_id).await.context("reattach")?;
    assert!(
        rights.post,
        "reattaching on the same session must still be post-capable"
    );
    let (mut rd, mut wr) = join_data_plane(&attach_sock, &cap).await.context("join on reattach")?;
    post_input(&mut wr, b"second\n").await.context("post the second line")?;
    read_until(&mut rd, "echo:second", Duration::from_secs(10))
        .await
        .context("waiting for the second echoed line, proving the SAME process continued")?;

    // 8. The job now exits on its own (both reads satisfied); confirm its real exit through `handle_dispatch`'s own
    //    Outcome (INV-11).
    let outcome = tokio::time::timeout(Duration::from_secs(10), running)
        .await
        .context("timed out waiting for the job to exit")?
        .context("the dispatch-handling task panicked")?
        .context("handle_dispatch failed")?;
    assert_eq!(outcome.guest_exit, Some(0), "the job must exit 0: {outcome:?}");
    assert!(
        !outcome.timed_out,
        "the job must not hit the dispatch timeout: {outcome:?}"
    );

    Ok(())
}

/// Smoke-tests the REAL `sandy` binary's `daemon attach` (not the hand-rolled
/// wire client the test above uses): `sandy daemon submit` then `sandy daemon
/// attach` as two separate process invocations — necessarily two separate
/// control connections, so this is itself a real-world instance of #327's
/// cross-session case (the submitter's own later attach is observer-only
/// under today's per-connection session model; see this PR's design notes).
/// The job needs no input to reach a terminal state, so the attach's own
/// background status-watch ends the bridge and the process exits 0 — proving
/// the real binary's raw-mode-skip-on-non-tty path, output delivery, and
/// status-triggered clean exit all work together, piped stdio standing in
/// for a real terminal (this harness has none to give it).
#[tokio::test]
async fn the_real_cli_binary_attaches_delivers_output_and_exits_on_job_completion() -> anyhow::Result<()> {
    require_live_process_test()?;
    let tmp = tempfile::tempdir().context("temp dir")?;
    let orchestrator = spawn_orchestrator(tmp.path(), "127.0.0.1")?;

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
    let _registered: OrchestratorMessage = sandy_control_proto::read_frame(&mut host_conn)
        .await
        .context("reading the Register response")?
        .context("connection closed before a Register response")?;

    let manifest = tmp.path().join("manifest.json");
    std::fs::write(
        &manifest,
        serde_json::to_vec(&["sh", "-c", "echo hello-from-job; sleep 1; echo done"])?,
    )
    .context("write the argv/v1 manifest")?;
    let submit_output = Command::new(env!("CARGO_BIN_EXE_sandy"))
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
        submit_output.status.success(),
        "sandy daemon submit failed: {}",
        String::from_utf8_lossy(&submit_output.stderr)
    );
    let submit_json: serde_json::Value = serde_json::from_slice(&submit_output.stdout).context("parse submit json")?;
    let job_id = submit_json["job_id"]
        .as_str()
        .context("submit json must carry a job_id")?
        .to_owned();

    let dispatch_message: OrchestratorMessage =
        tokio::time::timeout(Duration::from_secs(5), sandy_control_proto::read_frame(&mut host_conn))
            .await
            .context("timed out waiting for a Dispatch")?
            .context("reading the Dispatch frame")?
            .context("connection closed before a Dispatch arrived")?;
    let dispatch = match dispatch_message.op {
        Some(orchestrator_message::Op::Dispatch(dispatch)) => dispatch,
        other => anyhow::bail!("expected Dispatch, got {other:?}"),
    };
    assert_eq!(dispatch.job_id, job_id);

    let agent_program = build_workspace_bin("sandy-agent", "sandy-agent")?;
    let rt = tokio::runtime::Handle::current();
    let dispatch_job_id = job_id.clone();
    let running = tokio::spawn(async move {
        let outcome = tokio::task::spawn_blocking(move || {
            sandy_host_executor::dispatch::handle_dispatch(
                &dispatch,
                Box::new(sandy_test_support::FakeContainment::available()),
                agent_program,
                rt,
            )
        })
        .await
        .context("the dispatch-handling task panicked")?
        .context("handle_dispatch failed")?;
        // The real `sandy-host-executor` binary's own dispatch loop reports
        // this back over the SAME host-registration connection once
        // `handle_dispatch` returns (`run::outcome_result_message`) — this
        // test calls `handle_dispatch` directly (sandy-91: the real binary
        // can't start on this Mac), so it does that one remaining step by
        // hand, or `sandyd`'s own JobStore never leaves `Running` and the
        // CLI's status-watch (this test's whole point) would wait forever.
        sandy_control_proto::write_frame(
            &mut host_conn,
            &sandy_host_executor::run::outcome_result_message(dispatch_job_id, outcome.clone()),
        )
        .await
        .context("reporting the job result back to sandyd")?;
        anyhow::Ok(outcome)
    });

    // The real binary, real subprocess, piped stdio (no tty — RawMode::enable
    // is a no-op here, the one branch a real terminal couldn't exercise in
    // this harness).
    let mut attach_child = Command::new(env!("CARGO_BIN_EXE_sandy"))
        .env("SANDY_SOCK", &orchestrator.sock)
        .args(["daemon", "attach", &job_id])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("running sandy daemon attach")?;

    let stdout_handle = attach_child.stdout.take().context("attach child has no stdout")?;
    let output = tokio::task::spawn_blocking(move || {
        use std::io::Read as _;
        let mut buf = String::new();
        let mut stdout_handle = stdout_handle;
        stdout_handle.read_to_string(&mut buf).map(|_| buf)
    });

    let status = tokio::task::spawn_blocking(move || attach_child.wait());
    let (status, output) = tokio::time::timeout(Duration::from_secs(15), async { tokio::join!(status, output) })
        .await
        .context("timed out waiting for sandy daemon attach to exit on its own")?;
    let status = status
        .context("join the wait task")?
        .context("wait on the attach child")?;
    let output = output
        .context("join the stdout-reading task")?
        .context("read attach stdout")?;

    assert!(
        status.success(),
        "sandy daemon attach must exit 0, got {status:?}; output: {output}"
    );
    assert!(
        output.contains("hello-from-job") && output.contains("done"),
        "the job's real output must have been delivered through attach: {output:?}"
    );
    assert!(
        output.contains("terminal state"),
        "the status watch must have reported the job's terminal state: {output:?}"
    );

    let outcome = tokio::time::timeout(Duration::from_secs(10), running)
        .await
        .context("timed out waiting for the job to exit")?
        .context("the dispatch-handling task panicked")?
        .context("handle_dispatch or the result report failed")?;
    assert_eq!(outcome.guest_exit, Some(0), "the job must exit 0: {outcome:?}");

    Ok(())
}
