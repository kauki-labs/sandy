//! live_egress_proxy — the live parity gate for the per-run host egress proxy (#406, epic #360).
//!
//! Tier-3. `SANDY_EGRESS=proxy` boots the guest with no NIC. The guest relay listens on
//! `127.0.0.1:3128` and forwards each connection over vsock to a per-run host
//! `sandy-egress-proxy`, the only enforcement point (`docs/decisions/egress-proxy.md`
//! decisions 1, 2 and 5). Each test here is one row of the `KP1..KP6` matrix in
//! `docs/architecture/kpi.md`; the qemu and vfkit legs run the same file.
//!
//! The guest image has no `curl`, so a guest job speaks CONNECT through bash `/dev/tcp`
//! and encodes the outcome in its exit code, the one channel that provably reaches the
//! envelope `exit_code`.
//!
//! ## Running it
//!
//! qemu leg (Linux x86_64 with KVM): needs `/dev/vhost-vsock` access, no root, and no
//! tap, nft or dnsmasq. `SANDY_TAP` must stay unset: on qemu the proxy and a tap are
//! mutually exclusive. From the repo root:
//!
//! ```text
//! cargo build -p sandy-egress-proxy
//! SANDY_LIVE=1 SANDY_EGRESS_PROXY_BIN="$PWD/target/debug/sandy-egress-proxy" \
//!   nix shell nixpkgs#qemu -c \
//!   cargo nextest run -p sandy-cli --features live --test live_egress_proxy --no-capture
//! ```
//!
//! vfkit leg (Apple silicon, with the linux-builder): the same command, with `vfkit` in
//! place of `qemu` on `PATH`.
//!
//! The "allowed" target is `$SANDY_EGRESS_ALLOWED` (default `1.1.1.1`) on port 443 and
//! needs host internet access. The "denied" target is `$SANDY_EGRESS_DENIED` (default
//! `1.0.0.1`).
//!
//! Each test refuses off its matrix (no `SANDY_LIVE=1`, hypervisor or vhost-vsock
//! missing, proxy binary unreachable) rather than skip-greening (INV-S9).
//!
//! ## Not covered
//!
//! KP4's raw `AF_VSOCK` sub-case: the guest has no tool that opens an `AF_VSOCK`
//! stream (bash has none, and the image carries no python or socat), so a raw vsock
//! stream to the proxy port is not attempted. The relay path is covered by KP2/KP3. The
//! qemu "second CID is refused" sub-case needs a second VM and is a TODO.

#![cfg(feature = "live")]

mod common;

use std::{
    net::{Ipv4Addr, TcpListener},
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

use anyhow::{Context, bail};
use common::{LiveTarget, build_guest, guest_flake, on_path, require_live};

/// The port probed on the allowed and denied targets.
const PROBE_PORT: u16 = 443;

/// The allowed target: reachable from the host, and the only entry on the allow-list.
fn allowed_host() -> String {
    std::env::var("SANDY_EGRESS_ALLOWED").unwrap_or_else(|_| "1.1.1.1".to_string())
}

/// The denied target: never on the allow-list.
fn denied_host() -> String {
    std::env::var("SANDY_EGRESS_DENIED").unwrap_or_else(|_| "1.0.0.1".to_string())
}

/// Refuse unless this host can run the proxy gate: [`require_live`], the proxy binary
/// reachable, and on Linux an openable `/dev/vhost-vsock`.
fn require_proxy_live() -> anyhow::Result<LiveTarget> {
    let target = require_live()?;
    match std::env::var_os("SANDY_EGRESS_PROXY_BIN") {
        Some(bin) if Path::new(&bin).is_file() => {}
        Some(bin) => bail!("refusing: SANDY_EGRESS_PROXY_BIN={bin:?} is not a file"),
        None if on_path("sandy-egress-proxy") => {}
        None => bail!("refusing: `sandy-egress-proxy` is not on PATH and SANDY_EGRESS_PROXY_BIN is unset"),
    }
    if cfg!(target_os = "linux") {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/vhost-vsock")
            .context("refusing: the qemu proxy leg needs read/write access to /dev/vhost-vsock")?;
    }
    Ok(target)
}

/// A `sandy run` in proxy mode, ready to spawn: `SANDY_EGRESS=proxy`, `SANDY_TAP` removed
/// (the two are exclusive on qemu), one `--allow` per entry, and `script` as a bash job.
fn sandy_proxy_cmd(home: &Path, target: &LiveTarget, allow: &[String], script: &str) -> Command {
    let attr = format!("{}#{}", guest_flake().display(), target.topology_attr);
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_sandy"));
    cmd.env("SANDY_HOME", home)
        .env("SANDY_EGRESS", "proxy")
        .env_remove("SANDY_TAP")
        .args(["-o", "json", "run", &attr, "--timeout", "120"]);
    for entry in allow {
        cmd.args(["--allow", entry]);
    }
    cmd.args(["--", "bash", "-c", script]);
    cmd
}

/// Run `sandy run` in proxy mode to completion, returning the process band and envelope.
fn sandy_proxy_run(
    home: &Path,
    target: &LiveTarget,
    allow: &[String],
    script: &str,
) -> anyhow::Result<(i32, serde_json::Value)> {
    let output = sandy_proxy_cmd(home, target, allow, script)
        .output()
        .context("run sandy in proxy mode")?;
    parse_envelope(output.status.code().unwrap_or(-1), &output.stdout, &output.stderr)
}

fn parse_envelope(code: i32, stdout: &[u8], stderr: &[u8]) -> anyhow::Result<(i32, serde_json::Value)> {
    let envelope = serde_json::from_slice(stdout).with_context(|| {
        format!(
            "parse sandy run envelope (exit {code}); stderr: {}",
            String::from_utf8_lossy(stderr)
        )
    })?;
    Ok((code, envelope))
}

/// Guest shell that sends `CONNECT host:port` through the relay and sets `$status` to the
/// proxy's status code (`none` when no status line came back). Defines `connect_status`.
const CONNECT_FN: &str = r#"
connect_status() {
  status=none
  exec 3<>/dev/tcp/127.0.0.1/3128 || return 0
  printf 'CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n' "$1" "$1" >&3
  line=
  IFS= read -r -t 15 line <&3 || true
  exec 3<&- 3>&-
  line=${line%$'\r'}
  case $line in
    HTTP/*" "*) status=${line#* }; status=${status%% *} ;;
  esac
}
"#;

/// A guest script that issues one CONNECT to `target` and exits with the outcome:
/// 0 = `want` status, 10 = a different status, 12 = no status line (relay unreachable or silent).
fn connect_expect_script(target: &str, want: u16) -> String {
    format!(
        r#"set -u
{CONNECT_FN}
connect_status {target}
echo "live_egress_proxy: CONNECT {target} -> $status"
[ "$status" = none ] && exit 12
[ "$status" = {want} ] && exit 0
exit 10
"#
    )
}

/// Assert a proxy-mode run exited 0 in the guest (see [`connect_expect_script`] codes).
fn assert_guest_ok(code: i32, env: &serde_json::Value, what: &str) {
    assert_eq!(env["status"], "succeeded", "{what}; envelope: {env}");
    assert_eq!(
        env["exit_code"], 0,
        "{what} (guest exit 10 = unexpected proxy status, 12 = no status line, 20+ = see script); envelope: {env}"
    );
    assert_eq!(code, 0, "process band 0; envelope: {env}");
}

/// KP1: an allow-listed `host:port` is reachable through the guest relay (`200`).
#[test]
fn allowed_target_is_reachable_through_the_proxy() -> anyhow::Result<()> {
    let target = require_proxy_live()?;
    build_guest(&target)?;
    let home = tempfile::tempdir().context("temp SANDY_HOME")?;
    let allowed = allowed_host();
    let allow = vec![format!("{allowed}:{PROBE_PORT}")];

    let script = connect_expect_script(&format!("{allowed}:{PROBE_PORT}"), 200);
    let (code, env) = sandy_proxy_run(home.path(), &target, &allow, &script)?;

    assert_guest_ok(code, &env, &format!("CONNECT {allowed}:{PROBE_PORT} must get 200"));
    Ok(())
}

/// KP2: a target not on the allow-list gets `403`. That no connection leaves the host is not observed
/// here, so `kpi.md` keeps that half of KP2q out of the green claim.
#[test]
fn denied_target_gets_403() -> anyhow::Result<()> {
    let target = require_proxy_live()?;
    build_guest(&target)?;
    let home = tempfile::tempdir().context("temp SANDY_HOME")?;
    let (allowed, denied) = (allowed_host(), denied_host());
    let allow = vec![format!("{allowed}:{PROBE_PORT}")];

    let script = connect_expect_script(&format!("{denied}:{PROBE_PORT}"), 403);
    let (code, env) = sandy_proxy_run(home.path(), &target, &allow, &script)?;

    assert_guest_ok(code, &env, &format!("CONNECT {denied}:{PROBE_PORT} must get 403"));
    Ok(())
}

/// Guest shell fragment that exits 30 when any interface besides `lo` exists.
const ONLY_LOOPBACK: &str = r#"
for i in /sys/class/net/*; do
  n=${i##*/}
  [ "$n" = lo ] && continue
  echo "live_egress_proxy: unexpected interface $n"
  exit 30
done
"#;

/// KP3: an empty allow-list refuses every CONNECT, and the guest has no interface but `lo`.
#[test]
fn empty_allow_list_blocks_all_egress() -> anyhow::Result<()> {
    let target = require_proxy_live()?;
    build_guest(&target)?;
    let home = tempfile::tempdir().context("temp SANDY_HOME")?;
    let (allowed, denied) = (allowed_host(), denied_host());

    // Exit 12 (no status line) fails the test: a dead relay would otherwise look like a block.
    let script = format!(
        r#"set -u
{ONLY_LOOPBACK}
{CONNECT_FN}
for t in {allowed}:{PROBE_PORT} {denied}:{PROBE_PORT}; do
  connect_status $t
  echo "live_egress_proxy: CONNECT $t -> $status"
  [ "$status" = none ] && exit 12
  [ "$status" = 403 ] || exit 10
done
exit 0
"#
    );
    let (code, env) = sandy_proxy_run(home.path(), &target, &[], &script)?;

    assert_guest_ok(
        code,
        &env,
        "an empty allow-list must 403 every CONNECT, with no interface but lo (guest exit 30 = extra interface)",
    );
    Ok(())
}

/// KP4: as root in the guest, a direct connect by IP fails and the allow-list still holds
/// through the relay. The raw-vsock and second-CID sub-cases are not covered (see the
/// module doc).
#[test]
fn in_guest_bypass_attempts_fail() -> anyhow::Result<()> {
    let target = require_proxy_live()?;
    build_guest(&target)?;
    let home = tempfile::tempdir().context("temp SANDY_HOME")?;
    let (allowed, denied) = (allowed_host(), denied_host());
    let allow = vec![format!("{allowed}:{PROBE_PORT}")];

    // A run as non-root would make "direct connect fails" a weaker claim: exit 40.
    let script = format!(
        r#"set -u
[ "$(id -u)" = 0 ] || exit 40
{ONLY_LOOPBACK}
{CONNECT_FN}
# Direct dial by IP, bypassing the relay: there is no NIC and no route, so it must fail.
for t in {allowed} {denied}; do
  if timeout 5 bash -c "exec 3<>/dev/tcp/$t/{PROBE_PORT}" >/dev/null 2>&1; then
    echo "live_egress_proxy: direct connect to $t SUCCEEDED"
    exit 41
  fi
done
# Root tries to flush any guest firewall and add a default route, then dials again.
nft flush ruleset 2>/dev/null || true
ip route add default dev lo || exit 43
if timeout 5 bash -c "exec 3<>/dev/tcp/{denied}/{PROBE_PORT}" >/dev/null 2>&1; then
  echo "live_egress_proxy: direct connect after route tampering SUCCEEDED"
  exit 42
fi
# The relay path still enforces the list after the tampering.
connect_status {denied}:{PROBE_PORT}
echo "live_egress_proxy: CONNECT {denied}:{PROBE_PORT} -> $status"
[ "$status" = none ] && exit 12
[ "$status" = 403 ] || exit 10
exit 0
"#
    );
    let (code, env) = sandy_proxy_run(home.path(), &target, &allow, &script)?;

    assert_guest_ok(
        code,
        &env,
        "bypass attempts must fail (guest exit 40 = not root, 41/42 = a direct connect got out, 43 = the route change \
         failed, so the tampering case did not run)",
    );
    Ok(())
}

/// KP5: an allow-listed name that resolves to loopback gets `403`, and nothing connects
/// to the host listener behind it.
#[test]
fn allowed_name_resolving_to_loopback_is_refused() -> anyhow::Result<()> {
    let target = require_proxy_live()?;
    build_guest(&target)?;
    let home = tempfile::tempdir().context("temp SANDY_HOME")?;
    let listener = TcpListener::bind("127.0.0.1:0").context("bind a host loopback listener")?;
    listener.set_nonblocking(true).context("nonblocking listener")?;
    let port = listener.local_addr().context("listener addr")?.port();
    let allow = vec![format!("localhost:{port}")];

    let script = connect_expect_script(&format!("localhost:{port}"), 403);
    let (code, env) = sandy_proxy_run(home.path(), &target, &allow, &script)?;

    assert_guest_ok(code, &env, &format!("allow-listed localhost:{port} must still get 403"));
    match listener.accept() {
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
        Ok((_, peer)) => bail!("the proxy connected to the host loopback listener (peer {peer})"),
        Err(e) => return Err(e).context("poll the host loopback listener"),
    }
    Ok(())
}

/// The pid of a `sandy-egress-proxy` whose parent is `parent`, if one is running. `ps`
/// keeps this portable across the Linux and macOS legs; `comm` is truncated on Linux and
/// a full path on macOS, so match the basename's prefix.
fn find_proxy_child(parent: u32) -> anyhow::Result<Option<u32>> {
    let out = Command::new("ps")
        .args(["-axo", "pid=,ppid=,comm="])
        .output()
        .context("run ps")?;
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let mut fields = line.split_whitespace();
        let (Some(pid), Some(ppid)) = (fields.next(), fields.next()) else {
            continue;
        };
        let comm = fields.collect::<Vec<_>>().join(" ");
        let base = comm.rsplit('/').next().unwrap_or("");
        if ppid.parse() == Ok(parent) && base.starts_with("sandy-egress") {
            return Ok(pid.parse().ok());
        }
    }
    Ok(None)
}

/// Whether process `pid` holds an established TCP connection to `ip:port`. The proxy dials the target
/// only when the guest job's CONNECT reaches it, so this is a host-side proof that the guest has booted
/// and its job is running behind the relay.
#[cfg(target_os = "linux")]
fn has_tunnel(pid: u32, ip: Ipv4Addr, port: u16) -> anyhow::Result<bool> {
    let inodes: Vec<String> = match std::fs::read_dir(format!("/proc/{pid}/fd")) {
        Ok(dir) => dir
            .filter_map(Result::ok)
            .filter_map(|e| std::fs::read_link(e.path()).ok())
            .filter_map(|l| {
                l.to_str()?
                    .strip_prefix("socket:[")?
                    .strip_suffix(']')
                    .map(str::to_string)
            })
            .collect(),
        Err(_) => return Ok(false),
    };
    let table = std::fs::read_to_string("/proc/net/tcp").context("read /proc/net/tcp")?;
    // `/proc/net/tcp` prints an IPv4 address as the host-order hex of its little-endian bytes.
    let remote = format!("{:08X}:{port:04X}", u32::from_le_bytes(ip.octets()));
    Ok(table.lines().skip(1).any(|line| {
        let f: Vec<&str> = line.split_whitespace().collect();
        f.len() > 9 && f[2] == remote && f[3] == "01" && inodes.iter().any(|i| i == f[9])
    }))
}

#[cfg(not(target_os = "linux"))]
fn has_tunnel(pid: u32, ip: Ipv4Addr, port: u16) -> anyhow::Result<bool> {
    let status = Command::new("lsof")
        .args([
            "-nP",
            "-a",
            "-p",
            &pid.to_string(),
            &format!("-iTCP@{ip}:{port}"),
            "-sTCP:ESTABLISHED",
        ])
        .stdout(Stdio::null())
        .status()
        .context("run lsof")?;
    Ok(status.success())
}

/// Wait for the guest job's tunnel through the proxy, then SIGKILL the proxy. Errors here must not skip
/// reaping `sandy`: the caller waits for it on every path so the CLI runs its normal qemu, proxy and
/// virtiofsd teardown.
///
/// The guest has no channel to the host except the proxy, so the proxy's own connection to the target
/// is the ready signal: the guest has booted and the job is running behind the relay.
fn kill_proxy_once_guest_runs(sandy: &mut std::process::Child, target: Ipv4Addr) -> anyhow::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(100);
    let proxy = loop {
        if let Some(pid) = find_proxy_child(sandy.id())?
            && has_tunnel(pid, target, PROBE_PORT)?
        {
            break pid;
        }
        if let Some(status) = sandy.try_wait().context("poll sandy")? {
            bail!("sandy exited ({status}) before the guest job opened a tunnel through the proxy");
        }
        if Instant::now() > deadline {
            bail!("the guest job opened no tunnel to {target}:{PROBE_PORT} through the proxy within 100s");
        }
        std::thread::sleep(Duration::from_millis(200));
    };
    let killed = Command::new("kill")
        .args(["-KILL", &proxy.to_string()])
        .status()
        .context("kill the proxy")?;
    anyhow::ensure!(killed.success(), "kill -KILL {proxy} failed: {killed}");
    Ok(())
}

/// KP6: killing the proxy while the guest job runs classifies the run as band 3, although
/// the guest exits 0.
#[test]
fn proxy_death_mid_run_is_band_3() -> anyhow::Result<()> {
    let target = require_proxy_live()?;
    build_guest(&target)?;
    let home = tempfile::tempdir().context("temp SANDY_HOME")?;
    let stderr_path = home.path().join("sandy.stderr");
    let allowed = allowed_host();
    let ip: Ipv4Addr = allowed
        .parse()
        .with_context(|| format!("KP6 needs SANDY_EGRESS_ALLOWED to be an IPv4 literal, got {allowed}"))?;
    let allow = vec![format!("{allowed}:{PROBE_PORT}")];

    // The job holds a tunnel open to the allowed target, then outlives the kill by a wide margin and exits 0.
    let script = format!(
        r#"set -u
exec 3<>/dev/tcp/127.0.0.1/3128
printf 'CONNECT {t} HTTP/1.1\r\nHost: {t}\r\n\r\n' >&3
IFS= read -r -t 15 line <&3 || true
sleep 45
exit 0
"#,
        t = format_args!("{allowed}:{PROBE_PORT}")
    );
    let mut child = sandy_proxy_cmd(home.path(), &target, &allow, &script)
        .stdout(Stdio::piped())
        .stderr(std::fs::File::create(&stderr_path).context("create stderr file")?)
        .spawn()
        .context("spawn sandy")?;

    let killed = kill_proxy_once_guest_runs(&mut child, ip);
    // Always reap sandy, bounded by its own --timeout, so its teardown runs even when the kill failed.
    let output = child.wait_with_output().context("wait for sandy")?;
    killed?;
    let stderr = std::fs::read(&stderr_path).unwrap_or_default();
    let (code, env) = parse_envelope(output.status.code().unwrap_or(-1), &output.stdout, &stderr)?;

    assert_eq!(code, 3, "a dead proxy is an infra fault, band 3; envelope: {env}");
    assert_ne!(
        env["status"], "succeeded",
        "a run without its boundary must not succeed; envelope: {env}"
    );
    // `BackendError::EgressProxyDied` names whether the guest had booted and how it exited. The kill came
    // after the guest's tunnel was up, so the guest had booted; its job then ran on to exit 0.
    let text = env.to_string();
    assert!(
        text.contains("after the guest booted") && text.contains("guest exit 0"),
        "the proxy must die after the guest booted, with the job exiting 0; envelope: {env}"
    );
    Ok(())
}
