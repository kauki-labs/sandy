//! Live VM environment (#587, C3b): `sandyd` with `SANDY_ENV_BACKEND=vm-qemu` boots the t3 guest as a qemu microVM,
//! reports the environment Ready at a loopback endpoint that answers HTTP, and leaves no qemu process or
//! `/tmp/sandy-*` entry behind once the environment is deleted.
//!
//! Tier-3, behind the `live` feature like the other live suites (INV-S9). Linux with KVM and `/dev/vhost-vsock`
//! only; the first run builds a 3.7 GB guest image, so the provision timeout is far above the 120 s default.
//!
//!   SANDY_LIVE=1 nix shell nixpkgs#qemu -c cargo nextest run -p sandy-cli --features live --test live_vm_environment
//!
//! `SANDYD_BIN` points at a prebuilt `sandyd`; without it the test builds one.
#![cfg(feature = "live")]
#![cfg(target_os = "linux")]

use std::{
    collections::BTreeSet,
    io::{Read, Write},
    net::TcpStream,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use anyhow::{Context, bail, ensure};
use sandy_control_proto::{
    client,
    v1::{
        CreateEnvironmentRequest, DeleteEnvironmentRequest, EnvironmentLifetime, EnvironmentLifetimeKind,
        EnvironmentResponse, EnvironmentSpec, EnvironmentState, GetEnvironmentRequest, control_request,
        control_response,
    },
};
use tokio::net::UnixStream;

mod common;
use common::{guest_flake, require_live};

/// A cold boot of the t3 guest plus its service; generous, and passed to the daemon as the provision timeout.
const PROVISION_SECS: u64 = 900;

struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn sandyd_bin() -> anyhow::Result<PathBuf> {
    if let Some(path) = std::env::var_os("SANDYD_BIN") {
        return Ok(PathBuf::from(path));
    }
    let sandy = PathBuf::from(env!("CARGO_BIN_EXE_sandy"));
    let status = Command::new(env!("CARGO"))
        .args(["build", "-p", "sandyd", "--bin", "sandyd"])
        .arg("--manifest-path")
        .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/../../Cargo.toml"))
        .status()
        .context("build sandyd")?;
    ensure!(status.success(), "cargo build -p sandyd failed");
    Ok(sandy.parent().context("sandy's binary has no parent")?.join("sandyd"))
}

/// Process ids of every running qemu, from `/proc`.
fn qemu_pids() -> anyhow::Result<BTreeSet<u32>> {
    let mut pids = BTreeSet::new();
    for entry in std::fs::read_dir("/proc").context("read /proc")?.flatten() {
        let Some(pid) = entry.file_name().to_str().and_then(|n| n.parse::<u32>().ok()) else {
            continue;
        };
        if let Ok(comm) = std::fs::read_to_string(entry.path().join("comm"))
            // The nix-wrapped binary reports `.qemu-system-x8`.
            && comm.trim().trim_start_matches('.').starts_with("qemu")
        {
            pids.insert(pid);
        }
    }
    Ok(pids)
}

/// Every `/tmp/sandy-*` entry and its direct children.
fn sandy_tmp_entries() -> BTreeSet<PathBuf> {
    let mut found = BTreeSet::new();
    let Ok(tmp) = std::fs::read_dir("/tmp") else {
        return found;
    };
    for entry in tmp.flatten() {
        if !entry.file_name().to_string_lossy().starts_with("sandy-") {
            continue;
        }
        found.insert(entry.path());
        if let Ok(children) = std::fs::read_dir(entry.path()) {
            found.extend(children.flatten().map(|c| c.path()));
        }
    }
    found
}

/// The status code of `GET /` on `host:port`, over a bare TCP socket.
fn http_status(host: &str, port: u16) -> anyhow::Result<u16> {
    let mut stream = TcpStream::connect((host, port)).context("connect to the endpoint")?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.write_all(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")?;
    let mut head = [0u8; 12];
    stream.read_exact(&mut head).context("read the status line")?;
    std::str::from_utf8(&head)?
        .get(9..12)
        .context("short status line")?
        .parse()
        .context("status code")
}

async fn environment(stream: &mut UnixStream, id: u64, op: control_request::Op) -> anyhow::Result<EnvironmentResponse> {
    match client::call(stream, id, op).await?.result {
        Some(control_response::Result::Environment(e)) => Ok(e),
        other => bail!("expected an environment response, got {other:?}"),
    }
}

fn wait_for_socket(sock: &Path) -> anyhow::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(10);
    while std::os::unix::net::UnixStream::connect(sock).is_err() {
        ensure!(Instant::now() < deadline, "sandyd never accepted on {}", sock.display());
        std::thread::sleep(Duration::from_millis(50));
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_vm_environment_becomes_ready_answers_http_and_leaves_nothing_after_delete() -> anyhow::Result<()> {
    require_live()?;
    let flake = guest_flake();
    let build = Command::new("nix")
        .args(["build", "--no-link"])
        .arg(format!("{}#packages.x86_64-linux.guest-runner-t3", flake.display()))
        .status()
        .context("spawn nix build for the t3 guest")?;
    ensure!(build.success(), "nix build of the t3 guest runner failed");

    let qemu_before = qemu_pids()?;
    let tmp_before = sandy_tmp_entries();
    let dir = tempfile::tempdir().context("temp dir")?;
    let sock = dir.path().join("sandyd.sock");
    let _daemon = Daemon(
        Command::new(sandyd_bin()?)
            .env("SANDY_SOCK", &sock)
            .env("SANDY_DB", dir.path().join("sandyd.db"))
            .env("SANDY_ENV_BACKEND", "vm-qemu")
            .env(
                "SANDY_ENV_VM_TEMPLATE",
                format!("{}#topologies.x86_64-linux.qemu-t3", flake.display()),
            )
            .env("SANDY_ENV_VM_COMMAND", "t3 serve --port {port}")
            .env("SANDY_ENV_VM_SERVICE_PORT", "3773")
            .env("SANDY_ENV_PROVISION_TIMEOUT_SECS", PROVISION_SECS.to_string())
            .stdout(Stdio::null())
            .spawn()
            .context("spawn sandyd")?,
    );
    wait_for_socket(&sock)?;
    let mut stream = UnixStream::connect(&sock).await.context("connect to sandyd")?;

    let created = environment(
        &mut stream,
        1,
        control_request::Op::CreateEnvironment(CreateEnvironmentRequest {
            idempotency_key: "live-vm-environment".to_owned(),
            spec: Some(EnvironmentSpec {
                profile: "live".to_owned(),
                lifetime: Some(EnvironmentLifetime {
                    kind: EnvironmentLifetimeKind::Ephemeral as i32,
                    ttl_secs: 3600,
                }),
                ..EnvironmentSpec::default()
            }),
        }),
    )
    .await?;
    let id = created.environment_id;

    let deadline = Instant::now() + Duration::from_secs(PROVISION_SECS + 60);
    let ready = loop {
        let got = environment(
            &mut stream,
            2,
            control_request::Op::GetEnvironment(GetEnvironmentRequest {
                environment_id: id.clone(),
            }),
        )
        .await?;
        match EnvironmentState::try_from(got.state) {
            Ok(EnvironmentState::Ready) => break got,
            Ok(EnvironmentState::Failed) => bail!("the environment failed: {:?}", got.failure),
            _ => {}
        }
        ensure!(Instant::now() < deadline, "the environment never became Ready: {got:?}");
        tokio::time::sleep(Duration::from_secs(2)).await;
    };

    let url = ready.connection.context("a Ready environment names its endpoint")?.url;
    let authority = url
        .strip_prefix("http://")
        .context("an http endpoint")?
        .trim_end_matches('/');
    let (host, port) = authority.rsplit_once(':').context("host:port")?;
    ensure!(host == "127.0.0.1", "the endpoint must be loopback, got {host}");
    let port: u16 = port.parse().context("endpoint port")?;
    let status = tokio::task::spawn_blocking({
        let host = host.to_owned();
        move || http_status(&host, port)
    })
    .await??;
    ensure!(status < 500, "the service answered {status}");

    let started: Vec<u32> = qemu_pids()?.difference(&qemu_before).copied().collect();
    ensure!(
        !started.is_empty(),
        "no new qemu process while the environment is Ready"
    );

    environment(
        &mut stream,
        3,
        control_request::Op::DeleteEnvironment(DeleteEnvironmentRequest {
            environment_id: id.clone(),
        }),
    )
    .await?;

    let deadline = Instant::now() + Duration::from_secs(120);
    while started.iter().any(|pid| Path::new(&format!("/proc/{pid}")).exists()) {
        ensure!(
            Instant::now() < deadline,
            "qemu {started:?} is still running after delete"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    // The endpoint closes with the run, a moment later: dropping the bridge only signals its stop.
    let deadline = Instant::now() + Duration::from_secs(10);
    while TcpStream::connect((host, port)).is_ok() {
        ensure!(Instant::now() < deadline, "the bridge still listens after delete");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    // A new staging base is the only thing a first run may add: no run directory under it, no stray entry.
    let new_entries: Vec<_> = sandy_tmp_entries().difference(&tmp_before).cloned().collect();
    let strays: Vec<_> = new_entries
        .iter()
        .filter(|p| p.parent() != Some(Path::new("/tmp")) || std::fs::read_dir(p).is_ok_and(|mut d| d.next().is_some()))
        .collect();
    ensure!(strays.is_empty(), "left behind in /tmp: {strays:?}");
    Ok(())
}
