//! End-to-end: the isolation-class gate on a real `sandyd` (#505, refs #393,
//! #394, #150). The real `sandy` binary submits to the real `sandyd` binary
//! while a host-executor stand-in is registered over the real mesh wire (the
//! same hand-built `Register` as `live_attach.rs`). No `SANDY_LIVE`: nothing
//! here boots a VM or needs systemd.
//!
//! Two refusals are pinned, both through the real binaries. `sandyd` refuses an
//! untrusted `argv/v1` job at Submit (that encoding means the process backend,
//! which never admits an untrusted job). A `flake/v1` job (the VM backend) is
//! refused at placement unless a host declared both `Vm` and `Untrusted`.
//!
//! The stand-in declares its capabilities itself instead of probing them: the
//! real `sandy-host-executor` binary only registers where `systemd-run --user
//! --scope` over cgroup v2 works (`capability::detect_capabilities`), which a
//! CI sandbox and a Mac do not offer. What this file proves is the
//! orchestrator's gate, through the real binaries: an untrusted job never
//! reaches a host that did not declare `Untrusted`, and is not failed by one
//! that did. The executor's own re-check (`check_isolation_class`) is
//! covered by `handle_dispatch`'s unit tests.

use std::{
    net::{SocketAddr, TcpListener},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use anyhow::Context;
use sandy_conn::{Conn, Fingerprint, TlsIdentity, connect_tls};
use sandy_executor_proto::{
    Arch, Capabilities, HostExecutorMessage, IsolationClass, OrchestratorMessage, Register, SandboxKind,
    host_executor_message, orchestrator_message,
};
use sandy_guest_template::manifest::{FlakeManifestV1, default_history_lines, encode_flake_manifest};

/// A throwaway mesh TLS identity for a stand-in host-executor dialing in over
/// the real mesh wire (decision 20) — this file never completes a real
/// production registration, so an unpersisted, freshly generated identity is
/// fine, the same pattern `live_attach.rs`'s own `test_mesh_tls()` uses.
fn host_identity() -> TlsIdentity {
    TlsIdentity::generate().expect("generate a throwaway test host identity")
}

/// How long to wait for a Dispatch that must not come. Placement is a
/// synchronous step of the Submit handler, so by the time `sandy` has returned
/// the frame is queued to the host's connection task or never will be; this
/// bounds that task's write over loopback. A trusted follow-up on the same
/// connection backs the silence.
const NO_DISPATCH_WINDOW: Duration = Duration::from_millis(1500);

/// `$SANDYD_BIN` if set (the Nix check sandbox cannot `cargo build` mid-test),
/// else build `sandyd` and find it next to `sandy`'s own binary, as
/// `daemon_e2e.rs` does.
fn sandyd_bin() -> anyhow::Result<PathBuf> {
    if let Some(path) = std::env::var_os("SANDYD_BIN") {
        return Ok(PathBuf::from(path));
    }
    let sandy_bin = PathBuf::from(env!("CARGO_BIN_EXE_sandy"));
    let target_profile_dir = sandy_bin
        .parent()
        .context("sandy's own binary path has no parent directory")?
        .to_path_buf();
    let mut build = Command::new(env!("CARGO"));
    build.args([
        "build",
        "--manifest-path",
        concat!(env!("CARGO_MANIFEST_DIR"), "/../../Cargo.toml"),
        "-p",
        "sandyd",
        "--bin",
        "sandyd",
    ]);
    if target_profile_dir.file_name().and_then(|n| n.to_str()) == Some("release") {
        build.arg("--release");
    }
    let status = build.status().context("running cargo build -p sandyd")?;
    anyhow::ensure!(status.success(), "cargo build -p sandyd --bin sandyd failed");
    Ok(target_profile_dir.join("sandyd"))
}

/// Bind an ephemeral loopback port and keep the listener, so the number stays
/// reserved until the caller drops it just before handing the port to `sandyd`.
fn reserve_tcp_port() -> anyhow::Result<(TcpListener, SocketAddr)> {
    let listener = TcpListener::bind("127.0.0.1:0").context("bind an ephemeral port to find a free one")?;
    let addr = listener.local_addr()?;
    Ok((listener, addr))
}

/// A running real `sandyd`, killed on drop.
struct Orchestrator {
    child: Child,
    sock: PathBuf,
    mesh_addr: SocketAddr,
    /// The orchestrator's own pinned-key fingerprint, learned by pre-generating
    /// its persisted mesh TLS identity before spawn (below) — what a stand-in
    /// host-executor pins via `connect_tls`.
    fingerprint: Fingerprint,
}

impl Drop for Orchestrator {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Spawn a real `sandyd`, allowlisting exactly `host_fingerprints` (each
/// paired with loopback, decision 20's `ip=fingerprint` format) as permitted
/// executor hosts.
fn spawn_orchestrator(tmp: &Path, host_fingerprints: &[Fingerprint]) -> anyhow::Result<Orchestrator> {
    let (mesh_reserved, mesh_addr) = reserve_tcp_port()?;
    let (link_reserved, link_addr) = reserve_tcp_port()?;
    let sock = tmp.join("sandyd.sock");
    let stderr_log = tmp.join("sandyd.stderr");
    let bin = sandyd_bin()?;
    // Pre-generate/persist the orchestrator's own mesh identity so this test
    // learns its fingerprint before sandyd starts: sandyd's own
    // `load_or_generate` reads the SAME files back (same fingerprint), the
    // pattern `scripts/cross-machine-smoke.sh` uses to exchange fingerprints
    // ahead of either side starting.
    let identity_dir = tmp.join("mesh-tls");
    let fingerprint = TlsIdentity::load_or_generate(&identity_dir)
        .context("pre-generating the orchestrator's mesh TLS identity")?
        .fingerprint();
    let allowlist = host_fingerprints
        .iter()
        .map(|fp| format!("127.0.0.1={}", fp.to_hex()))
        .collect::<Vec<_>>()
        .join(",");
    drop((mesh_reserved, link_reserved));
    let child = Command::new(bin)
        .env("SANDY_SOCK", &sock)
        .env("SANDY_DB", tmp.join("sandyd.db"))
        .env("SANDY_MESH_LISTEN", mesh_addr.to_string())
        .env("SANDY_MESH_ALLOWLIST", allowlist)
        .env("SANDY_MESH_AGENT_LINK_LISTEN", link_addr.to_string())
        .env("SANDY_MESH_TLS_IDENTITY_DIR", &identity_dir)
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(&stderr_log).context("create the sandyd stderr log")?)
        .spawn()
        .context("spawning sandyd")?;
    // Constructed before any wait below, so a timeout drops it and kills the child.
    let mut orchestrator = Orchestrator {
        child,
        sock,
        mesh_addr,
        fingerprint,
    };

    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(status) = orchestrator.child.try_wait().context("polling sandyd")? {
            anyhow::bail!(
                "sandyd exited early ({status}); stderr: {}",
                std::fs::read_to_string(&stderr_log).unwrap_or_default()
            );
        }
        let ready = std::net::TcpStream::connect(mesh_addr).is_ok()
            && std::net::TcpStream::connect(link_addr).is_ok()
            && std::os::unix::net::UnixStream::connect(&orchestrator.sock).is_ok();
        if ready {
            break;
        }
        anyhow::ensure!(
            Instant::now() <= deadline,
            "sandyd never opened its listeners; stderr: {}",
            std::fs::read_to_string(&stderr_log).unwrap_or_default()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    Ok(orchestrator)
}

/// Register a host that declares exactly `kind` and `classes`, over the real
/// mesh wire (mutual TLS, decision 20, pinned to the orchestrator's
/// fingerprint and dialing under `identity`), and return the open connection
/// (the orchestrator drops the registration when it closes).
async fn register_host(
    orchestrator: &Orchestrator,
    identity: &TlsIdentity,
    host_id: &str,
    kind: SandboxKind,
    classes: &[IsolationClass],
) -> anyhow::Result<Box<dyn Conn>> {
    let mut conn = connect_tls(orchestrator.mesh_addr, identity, orchestrator.fingerprint, None)
        .await
        .context("dialing the orchestrator's mesh listener over TLS")?;
    sandy_control_proto::write_frame(
        &mut conn,
        &HostExecutorMessage {
            op: Some(host_executor_message::Op::Register(Register {
                host_id: host_id.to_owned(),
                capabilities: Some(Capabilities {
                    supported_sandbox_kinds: vec![kind.into()],
                    arch: Arch::X8664.into(),
                    attestation: false,
                    supported_isolation_classes: classes.iter().map(|c| i32::from(*c)).collect(),
                    shares_submitter_filesystem: false,
                }),
            })),
        },
    )
    .await
    .context("writing Register")?;
    let registered: OrchestratorMessage = sandy_control_proto::read_frame(&mut conn)
        .await
        .context("reading the Register response")?
        .context("connection closed before a Register response")?;
    anyhow::ensure!(
        matches!(registered.op, Some(orchestrator_message::Op::Registered(_))),
        "expected Registered, got {:?}",
        registered.op
    );
    Ok(conn)
}

/// Which manifest a submit carries: the encoding decides the backend the job needs.
#[derive(Clone, Copy)]
enum Manifest {
    /// `argv/v1`: the process backend.
    Argv,
    /// `flake/v1`: the VM backend.
    Flake,
}

/// `sandy daemon submit` of a trivial job as `manifest`, with `class` (`trusted` or `untrusted`).
fn submit(
    orchestrator: &Orchestrator,
    tmp: &Path,
    manifest: Manifest,
    class: &str,
) -> anyhow::Result<std::process::Output> {
    let (encoding, bytes) = match manifest {
        Manifest::Argv => ("argv/v1", serde_json::to_vec(&["true"])?),
        Manifest::Flake => (
            "flake/v1",
            encode_flake_manifest(&FlakeManifestV1 {
                flake: "github:example/guest".to_owned(),
                kind: None,
                attr: None,
                command: vec!["true".to_owned()],
                history_lines: default_history_lines(),
                env: Vec::new(),
                cpu: None,
                mem: None,
                timeout_secs: None,
            })
            .context("encode the flake/v1 manifest")?,
        ),
    };
    let path = tmp.join(format!("manifest-{}-{class}.bin", encoding.replace('/', "-")));
    std::fs::write(&path, bytes).context("write the manifest")?;
    Command::new(env!("CARGO_BIN_EXE_sandy"))
        .env("SANDY_SOCK", &orchestrator.sock)
        .args(["daemon", "submit"])
        .arg(&path)
        .args([
            "--manifest-encoding",
            encoding,
            "--isolation-class",
            class,
            "-o",
            "json",
        ])
        .output()
        .context("running sandy daemon submit")
}

/// The Dispatch the orchestrator placed on `conn`: `Some` if one arrives within
/// `window`, `None` if the window passes in silence. A closed connection, a read
/// error or any other frame is an error, so silence never hides a dead host.
async fn next_dispatch(
    conn: &mut Box<dyn Conn>,
    window: Duration,
) -> anyhow::Result<Option<sandy_executor_proto::Dispatch>> {
    let Ok(read) = tokio::time::timeout(window, sandy_control_proto::read_frame::<OrchestratorMessage>(conn)).await
    else {
        return Ok(None);
    };
    let frame = read
        .context("reading a frame from the orchestrator")?
        .context("the orchestrator closed the host connection")?;
    match frame.op {
        Some(orchestrator_message::Op::Dispatch(dispatch)) => Ok(Some(dispatch)),
        other => anyhow::bail!("expected a Dispatch or silence, got {other:?}"),
    }
}

/// The exit code `sandy daemon submit` ends with when `sandyd` refuses the job.
const REFUSED_EXIT: i32 = 2;

fn stderr_of(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[tokio::test]
async fn an_untrusted_argv_job_is_refused_even_when_a_host_declares_untrusted() -> anyhow::Result<()> {
    let tmp = tempfile::tempdir().context("temp dir")?;
    let process_host_identity = host_identity();
    let orchestrator = spawn_orchestrator(tmp.path(), &[process_host_identity.fingerprint()])?;
    let mut host = register_host(
        &orchestrator,
        &process_host_identity,
        "process-host",
        SandboxKind::Process,
        &[IsolationClass::Trusted, IsolationClass::Untrusted],
    )
    .await?;

    let untrusted = submit(&orchestrator, tmp.path(), Manifest::Argv, "untrusted")?;
    assert_eq!(
        untrusted.status.code(),
        Some(REFUSED_EXIT),
        "an untrusted argv job must be refused, stderr: {}",
        stderr_of(&untrusted)
    );
    assert!(
        stderr_of(&untrusted).contains("requires a Vm-backed manifest encoding"),
        "the refusal must say why, stderr: {}",
        stderr_of(&untrusted)
    );
    assert!(
        next_dispatch(&mut host, NO_DISPATCH_WINDOW).await?.is_none(),
        "a refused untrusted job must never be dispatched to the process host"
    );

    // The same host takes the same job as trusted, so the silence above is the
    // gate, not a dead host.
    let trusted = submit(&orchestrator, tmp.path(), Manifest::Argv, "trusted")?;
    assert_eq!(trusted.status.code(), Some(0), "stderr: {}", stderr_of(&trusted));
    let dispatch = next_dispatch(&mut host, Duration::from_secs(5))
        .await?
        .context("the trusted job must be dispatched to the host")?;
    assert_eq!(dispatch.required_isolation_class, i32::from(IsolationClass::Trusted));
    Ok(())
}

#[tokio::test]
async fn an_untrusted_flake_job_is_refused_when_no_vm_host_declares_untrusted() -> anyhow::Result<()> {
    let tmp = tempfile::tempdir().context("temp dir")?;
    let vm_host_identity = host_identity();
    let process_host_identity = host_identity();
    let orchestrator = spawn_orchestrator(
        tmp.path(),
        &[vm_host_identity.fingerprint(), process_host_identity.fingerprint()],
    )?;
    let mut host = register_host(
        &orchestrator,
        &vm_host_identity,
        "trusted-vm-host",
        SandboxKind::Vm,
        &[IsolationClass::Trusted],
    )
    .await?;
    // Declares Untrusted but not Vm: the sandbox kind is part of placement too.
    let mut process_host = register_host(
        &orchestrator,
        &process_host_identity,
        "untrusted-process-host",
        SandboxKind::Process,
        &[IsolationClass::Untrusted],
    )
    .await?;

    let untrusted = submit(&orchestrator, tmp.path(), Manifest::Flake, "untrusted")?;
    assert_eq!(
        untrusted.status.code(),
        Some(REFUSED_EXIT),
        "no host declares Vm and Untrusted, stderr: {}",
        stderr_of(&untrusted)
    );
    assert!(
        stderr_of(&untrusted).contains("no registered host declares the required isolation class"),
        "the refusal must name placement, stderr: {}",
        stderr_of(&untrusted)
    );
    assert!(
        next_dispatch(&mut host, NO_DISPATCH_WINDOW).await?.is_none(),
        "a refused untrusted job must never be dispatched to a host that did not declare Untrusted"
    );
    assert!(
        next_dispatch(&mut process_host, Duration::from_millis(100))
            .await?
            .is_none(),
        "nor to a host that declared Untrusted without Vm"
    );

    let trusted = submit(&orchestrator, tmp.path(), Manifest::Flake, "trusted")?;
    assert_eq!(trusted.status.code(), Some(0), "stderr: {}", stderr_of(&trusted));
    next_dispatch(&mut host, Duration::from_secs(5))
        .await?
        .context("the trusted flake job must be dispatched to the host")?;
    Ok(())
}

#[tokio::test]
async fn an_untrusted_flake_job_is_dispatched_to_a_vm_host_that_declares_untrusted() -> anyhow::Result<()> {
    let tmp = tempfile::tempdir().context("temp dir")?;
    let vm_host_identity = host_identity();
    let orchestrator = spawn_orchestrator(tmp.path(), &[vm_host_identity.fingerprint()])?;
    let mut host = register_host(
        &orchestrator,
        &vm_host_identity,
        "untrusted-vm-host",
        SandboxKind::Vm,
        &[IsolationClass::Untrusted],
    )
    .await?;

    let submitted = submit(&orchestrator, tmp.path(), Manifest::Flake, "untrusted")?;
    assert_eq!(submitted.status.code(), Some(0), "stderr: {}", stderr_of(&submitted));
    let dispatch = next_dispatch(&mut host, Duration::from_secs(5))
        .await?
        .context("the untrusted job must be dispatched to a host that declared Untrusted")?;
    assert_eq!(dispatch.required_isolation_class, i32::from(IsolationClass::Untrusted));
    assert_eq!(dispatch.backend, i32::from(SandboxKind::Vm));
    Ok(())
}
