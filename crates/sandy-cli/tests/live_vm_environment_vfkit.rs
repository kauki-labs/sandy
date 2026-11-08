//! Live VM environment on vfkit (#587, C3c, KENV21): `sandyd` with `SANDY_ENV_BACKEND=vm-vfkit` boots the t3 guest as
//! a vfkit microVM, reports the environment Ready at a loopback endpoint that answers HTTP, and leaves no vfkit
//! process, `env-svc-*.sock` socket or staging entry behind once the environment is deleted.
//!
//! Tier-3, behind the `live` feature like the other live suites (INV-S9). macOS on Apple silicon with vfkit on `PATH`
//! (or `SANDY_VFKIT_BIN`) and a linux-builder; the first run builds a 3.7 GB guest image, so the provision timeout is
//! far above the 120 s default.
//!
//!   SANDY_LIVE=1 cargo nextest run -p sandy-cli --features live --test live_vm_environment_vfkit
//!
//! `SANDYD_BIN` points at a prebuilt `sandyd`; without it the test builds one.
#![cfg(feature = "live")]
#![cfg(target_os = "macos")]

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

/// Process ids of every running vfkit, from `ps`.
fn vfkit_pids() -> anyhow::Result<BTreeSet<u32>> {
    let out = Command::new("ps")
        .args(["-axo", "pid=,comm="])
        .output()
        .context("run ps")?;
    ensure!(out.status.success(), "ps failed");
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|line| {
            let (pid, comm) = line.trim().split_once(char::is_whitespace)?;
            (Path::new(comm.trim()).file_name()?.to_str()? == "vfkit")
                .then(|| pid.parse().ok())
                .flatten()
        })
        .collect())
}

fn signal(name: &str, pid: u32) {
    let _ = Command::new("kill")
        .arg(format!("-{name}"))
        .arg(pid.to_string())
        .status();
}

/// Stops the daemon with SIGTERM first and SIGKILL as a fallback, then kills any vfkit the test started, so a
/// failure leaves no orphan.
struct Daemon {
    child: Child,
    vfkit_before: BTreeSet<u32>,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        signal("TERM", self.child.id());
        let deadline = Instant::now() + Duration::from_secs(15);
        while !matches!(self.child.try_wait(), Ok(Some(_))) {
            if Instant::now() > deadline {
                let _ = self.child.kill();
                let _ = self.child.wait();
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        for pid in vfkit_pids().unwrap_or_default().difference(&self.vfkit_before) {
            signal("KILL", *pid);
        }
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

/// The staging base the daemon uses: `<temp dir>/sandy`.
fn staging_base() -> PathBuf {
    std::env::temp_dir().join("sandy")
}

/// Every entry of the staging base and its direct children (a missing base is empty).
fn staging_entries() -> BTreeSet<PathBuf> {
    let mut found = BTreeSet::new();
    let Ok(base) = std::fs::read_dir(staging_base()) else {
        return found;
    };
    for entry in base.flatten() {
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
async fn a_vfkit_environment_becomes_ready_answers_http_and_leaves_nothing_after_delete() -> anyhow::Result<()> {
    require_live()?;
    let flake = guest_flake();
    let build = Command::new("nix")
        .args(["build", "--no-link"])
        .arg(format!(
            "{}#packages.aarch64-darwin.guest-runner-vfkit-t3",
            flake.display()
        ))
        .status()
        .context("spawn nix build for the t3 guest")?;
    ensure!(build.success(), "nix build of the t3 guest runner failed");

    let vfkit_before = vfkit_pids()?;
    let staging_before = staging_entries();
    let dir = tempfile::tempdir().context("temp dir")?;
    let sock = dir.path().join("sandyd.sock");
    let _daemon = Daemon {
        vfkit_before: vfkit_before.clone(),
        child: Command::new(sandyd_bin()?)
            .env("SANDY_SOCK", &sock)
            .env("SANDY_DB", dir.path().join("sandyd.db"))
            .env("SANDY_ENV_BACKEND", "vm-vfkit")
            .env(
                "SANDY_ENV_VM_TEMPLATE",
                format!("{}#topologies.aarch64-linux.vfkit-t3", flake.display()),
            )
            .env("SANDY_ENV_VM_COMMAND", "t3 serve --port {port}")
            .env("SANDY_ENV_VM_SERVICE_PORT", "3773")
            .env("SANDY_ENV_PROVISION_TIMEOUT_SECS", PROVISION_SECS.to_string())
            .stdout(Stdio::null())
            .spawn()
            .context("spawn sandyd")?,
    };
    wait_for_socket(&sock)?;
    let mut stream = UnixStream::connect(&sock).await.context("connect to sandyd")?;

    let created = environment(
        &mut stream,
        1,
        control_request::Op::CreateEnvironment(CreateEnvironmentRequest {
            idempotency_key: "live-vm-environment-vfkit".to_owned(),
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

    let started: Vec<u32> = vfkit_pids()?.difference(&vfkit_before).copied().collect();
    ensure!(
        !started.is_empty(),
        "no new vfkit process while the environment is Ready"
    );
    let sockets = || -> BTreeSet<PathBuf> {
        staging_entries()
            .into_iter()
            .filter(|p| {
                p.file_name()
                    .is_some_and(|n| n.to_string_lossy().starts_with("env-svc-"))
            })
            .collect()
    };
    ensure!(
        sockets().difference(&staging_before).count() == 1,
        "exactly one new env-svc-*.sock must exist while the environment is Ready"
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
    while vfkit_pids()?.iter().any(|pid| started.contains(pid)) {
        ensure!(
            Instant::now() < deadline,
            "vfkit {started:?} is still running after delete"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    // The endpoint closes with the run, a moment later: dropping the bridge only signals its stop.
    let deadline = Instant::now() + Duration::from_secs(10);
    while TcpStream::connect((host, port)).is_ok() {
        ensure!(Instant::now() < deadline, "the bridge still listens after delete");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    // The staging base exists before the run (the daemon creates it at start-up), so any new entry in it is a stray: a
    // run directory, a secret share or an  socket that outlived the environment.
    let strays: Vec<_> = staging_entries().difference(&staging_before).cloned().collect();
    ensure!(
        strays.is_empty(),
        "left behind in {}: {strays:?}",
        staging_base().display()
    );
    Ok(())
}
