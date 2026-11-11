//! Live VM environment (#587, C3b): `sandyd` with `SANDY_ENV_BACKEND=vm-qemu` boots the service guest as a qemu
//! microVM, reports the environment Ready at a loopback endpoint that answers HTTP, and leaves no qemu process or
//! run directory behind once the environment is deleted.
//!
//! Tier-3, behind the `live` feature like the other live suites (INV-S9). Linux with KVM and `/dev/vhost-vsock`
//! only; a cold first run builds the guest image, so the provision timeout is far above the 120 s default.
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
    os::unix::fs::PermissionsExt,
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

/// A cold boot of the service guest plus its service; generous, and passed to the daemon as the provision timeout.
const PROVISION_SECS: u64 = 900;

/// Stops the daemon with SIGTERM first and SIGKILL as a fallback, then kills the qemu it started, so a failure
/// leaves no orphan (a killed daemon leaves its VM running, decision 34). Only a qemu that was a direct child of
/// this daemon is killed, matched by pid and start time: the host is shared, and another session's VM must survive.
struct Daemon(Child);

fn signal(name: &str, pid: u32) {
    let _ = Command::new("kill")
        .arg(format!("-{name}"))
        .arg(pid.to_string())
        .status();
}

/// `(parent pid, start time)` of a process, from `/proc/<pid>/stat`.
fn parent_and_start(pid: u32) -> Option<(u32, u64)> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // The command name may hold spaces and parentheses; the fields after it start past the last `)`.
    let rest: Vec<&str> = stat.get(stat.rfind(')')? + 1..)?.split_whitespace().collect();
    Some((rest.get(1)?.parse().ok()?, rest.get(19)?.parse().ok()?))
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let owned: Vec<(u32, u64)> = qemu_pids()
            .unwrap_or_default()
            .into_iter()
            .filter_map(|pid| {
                parent_and_start(pid)
                    .filter(|(ppid, _)| *ppid == self.0.id())
                    .map(|(_, t)| (pid, t))
            })
            .collect();
        signal("TERM", self.0.id());
        let deadline = Instant::now() + Duration::from_secs(15);
        while !matches!(self.0.try_wait(), Ok(Some(_))) {
            if Instant::now() > deadline {
                let _ = self.0.kill();
                let _ = self.0.wait();
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        for (pid, start) in owned {
            if parent_and_start(pid).is_some_and(|(_, t)| t == start) {
                signal("KILL", pid);
            }
        }
    }
}

fn sandyd_bin() -> anyhow::Result<PathBuf> {
    if let Some(path) = std::env::var_os("SANDYD_BIN") {
        return Ok(PathBuf::from(path));
    }
    let sandy = PathBuf::from(env!("CARGO_BIN_EXE_sandy"));
    let status = Command::new(env!("CARGO"))
        .args([
            "build",
            "-p",
            "sandyd",
            "--bin",
            "sandyd",
            "--features",
            "stub-trust-root",
        ])
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

/// The entries under the daemon's own staging base (`<TMPDIR>/sandy`): a run leaves a directory there while it lives
/// and none once it is deleted. The daemon runs with its own `TMPDIR`, so another session's runs in the host's shared
/// `/tmp/sandy` cannot read as strays of this one.
fn run_dirs_under(base: &Path) -> anyhow::Result<Vec<PathBuf>> {
    let staging = base.join(sandy_fsutil::STAGING_DIR_NAME);
    match std::fs::read_dir(&staging) {
        Ok(entries) => entries
            .map(|e| {
                e.map(|e| e.path())
                    .with_context(|| format!("read an entry of {}", staging.display()))
            })
            .collect(),
        // No base at all is a clean state; an unreadable one is not "no strays".
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(e).with_context(|| format!("read {}", staging.display())),
    }
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
        .arg(format!(
            "{}#packages.x86_64-linux.guest-runner-service",
            flake.display()
        ))
        .status()
        .context("spawn nix build for the service guest")?;
    ensure!(build.success(), "nix build of the service guest runner failed");

    let qemu_before = qemu_pids()?;
    // Under `/tmp`, not `$TMPDIR`: a nix shell's is long, and `sandyd.sock` and the run's sockets live under this dir.
    let dir = tempfile::Builder::new()
        .prefix("s")
        .tempdir_in("/tmp")
        .context("temp dir under /tmp")?;
    // The daemon's own `TMPDIR`: its staging base is `<tmp>/sandy`, apart from the host's shared one.
    let tmp = dir.path().join("t");
    ensure!(
        tmp.as_os_str().len() <= 38,
        "the daemon's TMPDIR {} is over 38 bytes: a run's socket under it could pass the 108-byte `sun_path` limit",
        tmp.display()
    );
    std::fs::create_dir(&tmp)?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o700))?;
    let sock = dir.path().join("sandyd.sock");
    // A create needs a registry naming the profile (#704); the stub trust root named by `SANDYD_STUB_TRUST_ROOT` backs
    // its credential (a feature-gated build of sandyd).
    let profiles = dir.path().join("profiles.json");
    std::fs::write(
        &profiles,
        r#"{"profiles":[{"name":"live","credential":"live","targets":["o/r"],"capabilities":["read_code"]}]}"#,
    )?;
    std::fs::set_permissions(&profiles, std::fs::Permissions::from_mode(0o600))?;
    let _daemon = Daemon(
        Command::new(sandyd_bin()?)
            .env("SANDY_SOCK", &sock)
            .env("TMPDIR", &tmp)
            .env("SANDY_DB", dir.path().join("sandyd.db"))
            .env("SANDY_PROFILES", &profiles)
            .env("SANDYD_STUB_TRUST_ROOT", "live")
            .env("SANDY_ENV_BACKEND", "vm-qemu")
            .env(
                "SANDY_ENV_VM_TEMPLATE",
                format!("{}#topologies.x86_64-linux.qemu-service", flake.display()),
            )
            .env("SANDY_ENV_VM_COMMAND", "sandy-example-service --port {port}")
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
            ..CreateEnvironmentRequest::default()
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
    // No run directory is left under the daemon's own staging base.
    let strays = run_dirs_under(&tmp)?;
    ensure!(strays.is_empty(), "left behind under the staging base: {strays:?}");
    Ok(())
}
