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
    net::{IpAddr, Ipv4Addr, TcpListener, ToSocketAddrs},
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

/// A hostname setting from `var`, or `default`, lower-cased and without a trailing dot (the form the proxy
/// matches). An IP literal is refused: the proxy keeps IP and name entries
/// apart, so a literal here would make a hostname test run on an IP entry and prove nothing.
fn hostname_setting(var: &str, default: &str) -> anyhow::Result<String> {
    let raw = std::env::var(var).unwrap_or_else(|_| default.to_string());
    normalise_hostname(&raw).with_context(|| format!("refusing: {var}={raw}"))
}

/// The pure core of [`hostname_setting`]: `raw` as the proxy would match it, or an error. This mirrors the
/// proxy's own `normalise_name` (`sandy-egress-proxy/src/head.rs`): ASCII, lower-cased, at most one trailing dot
/// removed, at most 253 bytes, labels of 1 to 63 bytes from `[a-z0-9-]` that neither start nor end with `-`, and a
/// last label that is not all digits. A malformed setting is refused, never rewritten into a valid one.
fn normalise_hostname(raw: &str) -> anyhow::Result<String> {
    if raw.parse::<IpAddr>().is_ok() {
        bail!("an IP literal, but these tests exercise hostname entries");
    }
    anyhow::ensure!(raw.is_ascii(), "not ASCII");
    let lowered = raw.to_ascii_lowercase();
    let name = lowered.strip_suffix('.').unwrap_or(&lowered);
    anyhow::ensure!(!name.is_empty() && name.len() <= 253, "empty or longer than 253 bytes");
    let mut last = "";
    for label in name.split('.') {
        let ok = !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        anyhow::ensure!(ok, "label {label:?} is not valid");
        last = label;
    }
    anyhow::ensure!(
        !last.bytes().all(|b| b.is_ascii_digit()),
        "the last label is all digits"
    );
    Ok(name.to_owned())
}

/// The allow-listed hostname for the name-entry tests. The default, `one.one.one.one`, resolves to several
/// IPv4 addresses, so a pass also shows a multi-address name works (`nft` rejects one).
fn allowed_name() -> anyhow::Result<String> {
    hostname_setting("SANDY_EGRESS_ALLOWED_NAME", "one.one.one.one")
}

/// A hostname that is never on the allow-list.
fn denied_name() -> anyhow::Result<String> {
    hostname_setting("SANDY_EGRESS_DENIED_NAME", "example.com")
}

/// A second hostname that is never on the allow-list but shares an address with [`allowed_name`]. The default
/// resolves to the same addresses as `one.one.one.one`; the test checks that on the host before it relies on it.
fn same_address_name() -> anyhow::Result<String> {
    hostname_setting("SANDY_EGRESS_SAME_ADDRESS_NAME", "1dot1dot1dot1.cloudflare-dns.com")
}

/// The IPv4 addresses `name` resolves to on this host.
fn resolved_ipv4(name: &str) -> anyhow::Result<Vec<Ipv4Addr>> {
    let mut ips: Vec<Ipv4Addr> = (name, PROBE_PORT)
        .to_socket_addrs()
        .with_context(|| format!("resolve {name} on the host"))?
        .filter_map(|addr| match addr.ip() {
            IpAddr::V4(ip) => Some(ip),
            IpAddr::V6(_) => None,
        })
        .collect();
    ips.sort();
    ips.dedup();
    anyhow::ensure!(!ips.is_empty(), "refusing: {name} has no IPv4 address on this host");
    Ok(ips)
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

/// Guest shell that sends `CONNECT host:port` and sets `$status` as [`CONNECT_FN`] does, and also `$reason` to
/// the response body (the proxy writes one reason line and closes the connection after a refusal).
const CONNECT_FULL_FN: &str = r#"
connect_full() {
  status=none
  reason=
  exec 3<>/dev/tcp/127.0.0.1/3128 || return 0
  printf 'CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n' "$1" "$1" >&3
  line=
  IFS= read -r -t 15 line <&3 || true
  line=${line%$'\r'}
  case $line in
    HTTP/*" "*) status=${line#* }; status=${status%% *} ;;
  esac
  while IFS= read -r -t 5 l <&3; do l=${l%$'\r'}; reason="$reason$l|"; done
  exec 3<&- 3>&-
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

/// Assert the whole infra-fault classification: process band 3, status `failed`, `retryable` true. A bare
/// "not succeeded" would also accept `cancelled` or a non-retryable result.
fn assert_infra_fault(code: i32, env: &serde_json::Value, what: &str) {
    assert_eq!(code, 3, "{what}: process band 3; envelope: {env}");
    assert_eq!(env["status"], "failed", "{what}: status failed; envelope: {env}");
    assert_eq!(env["retryable"], true, "{what}: retryable; envelope: {env}");
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

/// KP2: a target not on the allow-list gets `403`. That the proxy dials nothing is observed by
/// `a_denied_target_is_never_dialed_by_the_proxy`.
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

/// #377: a hostname entry is matched by name at the proxy. `--allow <name>:443` lets a CONNECT by that name
/// through (`200`), though the name resolves to several addresses and the guest has no DNS.
#[test]
fn allowed_hostname_is_reachable_by_name() -> anyhow::Result<()> {
    let target = require_proxy_live()?;
    build_guest(&target)?;
    let home = tempfile::tempdir().context("temp SANDY_HOME")?;
    let name = allowed_name()?;
    let allow = vec![format!("{name}:{PROBE_PORT}")];

    let script = connect_expect_script(&format!("{name}:{PROBE_PORT}"), 200);
    let (code, env) = sandy_proxy_run(home.path(), &target, &allow, &script)?;

    assert_guest_ok(code, &env, &format!("CONNECT {name}:{PROBE_PORT} must get 200"));
    Ok(())
}

/// #377: a name entry allows that name only. Three targets all get `403` with only `<name>:443` allowed: a
/// different hostname, one of the allowed name's own resolved IPs (an IP never matches a name entry), and a
/// second hostname that resolves to an address the allowed name also resolves to (the proxy must not authorize
/// by resolved address). The test checks on the host that the shared address really exists.
#[test]
fn a_hostname_entry_does_not_allow_another_name_or_its_ip() -> anyhow::Result<()> {
    let target = require_proxy_live()?;
    build_guest(&target)?;
    let home = tempfile::tempdir().context("temp SANDY_HOME")?;
    let (name, other, same) = (allowed_name()?, denied_name()?, same_address_name()?);
    anyhow::ensure!(
        name != other && name != same && other != same,
        "refusing: the allowed, denied and same-address names must be three different hostnames, got {name}, {other}, \
         {same}"
    );
    let name_ips = resolved_ipv4(&name)?;
    let same_ips = resolved_ipv4(&same)?;
    anyhow::ensure!(
        same_ips.iter().any(|ip| name_ips.contains(ip)),
        "refusing: {same} ({same_ips:?}) shares no address with {name} ({name_ips:?}) on this host, so it cannot show \
         that an unlisted name with the same address is refused"
    );
    let ip = name_ips[0];
    let allow = vec![format!("{name}:{PROBE_PORT}")];

    // Each refusal must be an allow-list refusal: a `403` from the address filter ("non-public address") would
    // also pass a status check on a private address, and prove nothing about name matching. Exit 12 (no status
    // line) fails the test too: a dead relay would otherwise look like a refusal.
    let script = format!(
        r#"set -u
{CONNECT_FULL_FN}
for t in {other}:{PROBE_PORT} {ip}:{PROBE_PORT} {same}:{PROBE_PORT}; do
  connect_full $t
  echo "live_egress_proxy: CONNECT $t -> $status $reason"
  [ "$status" = none ] && exit 12
  [ "$status" = 403 ] || exit 10
  case $reason in
    *"not in the allow-list"*) ;;
    *) exit 11 ;;
  esac
done
exit 0
"#
    );
    let (code, env) = sandy_proxy_run(home.path(), &target, &allow, &script)?;

    assert_guest_ok(
        code,
        &env,
        &format!(
            "with only {name}:{PROBE_PORT} allowed, {other}, {ip} and {same} must all get a 403 that says `not in the \
             allow-list` (guest exit 11 = a 403 for another reason)"
        ),
    );
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

    assert_infra_fault(code, &env, "a dead proxy is an infra fault");
    // `BackendError::EgressProxyDied` names whether the guest had booted and how it exited. The kill came
    // after the guest's tunnel was up, so the guest had booted; its job then ran on to exit 0.
    let text = env.to_string();
    assert!(
        text.contains("after the guest booted") && text.contains("guest exit 0"),
        "the proxy must die after the guest booted, with the job exiting 0; envelope: {env}"
    );
    Ok(())
}

/// KP2, host side: while the guest gets `403` for a denied target, the proxy holds no connection to it. The
/// job first opens a tunnel to the allowed target and keeps it, which proves the observer sees the proxy's
/// connections (a positive control: without it an empty observation would prove nothing). It then asks for the
/// denied target, expects `403`, and waits so the host samples for a while. A dial that opened and closed
/// between two 200 ms samples would be missed; this check does not claim to catch that.
#[test]
fn a_denied_target_is_never_dialed_by_the_proxy() -> anyhow::Result<()> {
    let target = require_proxy_live()?;
    build_guest(&target)?;
    let home = tempfile::tempdir().context("temp SANDY_HOME")?;
    let stderr_path = home.path().join("sandy.stderr");
    let (allowed, denied) = (allowed_host(), denied_host());
    let parse = |name: &str, host: &str| {
        host.parse::<Ipv4Addr>()
            .with_context(|| format!("KP2 needs {name} to be an IPv4 literal, got {host}"))
    };
    let (allowed_ip, denied_ip) = (
        parse("SANDY_EGRESS_ALLOWED", &allowed)?,
        parse("SANDY_EGRESS_DENIED", &denied)?,
    );
    anyhow::ensure!(allowed_ip != denied_ip, "KP2 needs distinct allowed and denied targets");
    let allow = vec![format!("{allowed}:{PROBE_PORT}")];

    let script = format!(
        r#"set -u
exec 3<>/dev/tcp/127.0.0.1/3128
printf 'CONNECT {a}:{PROBE_PORT} HTTP/1.1\r\nHost: {a}:{PROBE_PORT}\r\n\r\n' >&3
IFS= read -r -t 15 line3 <&3 || true
exec 4<>/dev/tcp/127.0.0.1/3128
printf 'CONNECT {d}:{PROBE_PORT} HTTP/1.1\r\nHost: {d}:{PROBE_PORT}\r\n\r\n' >&4
IFS= read -r -t 15 line4 <&4 || true
echo "live_egress_proxy: allowed -> $line3 / denied -> $line4"
sleep 20
case "$line4" in *" 403 "*) exit 0 ;; *) exit 10 ;; esac
"#,
        a = allowed,
        d = denied
    );
    let mut child = sandy_proxy_cmd(home.path(), &target, &allow, &script)
        .stdout(Stdio::piped())
        .stderr(std::fs::File::create(&stderr_path).context("create stderr file")?)
        .spawn()
        .context("spawn sandy")?;

    // Sample the proxy's connections until sandy exits. Every error path still reaps sandy below.
    let mut seen_allowed = false;
    let mut dialed_denied = false;
    let deadline = Instant::now() + Duration::from_secs(400);
    let observed: anyhow::Result<()> = loop {
        match child.try_wait() {
            Ok(Some(_)) => break Ok(()),
            Ok(None) => {}
            Err(e) => break Err(anyhow::Error::new(e).context("poll sandy")),
        }
        if Instant::now() > deadline {
            break Err(anyhow::anyhow!("sandy ran past the 400 s observation budget"));
        }
        let sample = find_proxy_child(child.id()).and_then(|proxy| match proxy {
            Some(pid) => Ok(Some((
                has_tunnel(pid, allowed_ip, PROBE_PORT)?,
                has_tunnel(pid, denied_ip, PROBE_PORT)?,
            ))),
            None => Ok(None),
        });
        match sample {
            Ok(Some((to_allowed, to_denied))) => {
                seen_allowed |= to_allowed;
                dialed_denied |= to_denied;
            }
            Ok(None) => {}
            Err(e) => break Err(e),
        }
        std::thread::sleep(Duration::from_millis(200));
    };
    let output = child.wait_with_output().context("wait for sandy")?;
    observed?;
    let stderr = std::fs::read(&stderr_path).unwrap_or_default();
    let (code, env) = parse_envelope(output.status.code().unwrap_or(-1), &output.stdout, &stderr)?;

    assert_guest_ok(code, &env, &format!("CONNECT {denied}:{PROBE_PORT} must get 403"));
    assert!(
        seen_allowed,
        "the observer never saw the proxy's tunnel to the allowed target, so it proves nothing; envelope: {env}"
    );
    assert!(
        !dialed_denied,
        "the proxy held a connection to the denied target {denied}:{PROBE_PORT}; envelope: {env}"
    );
    Ok(())
}

/// `path` as one single-quoted shell word; an embedded `'` is closed, escaped and reopened.
fn sh_quote(path: &Path) -> String {
    format!("'{}'", path.display().to_string().replace('\'', "'\\''"))
}

/// A `sandy-egress-proxy` listening on vsock `port` for `peer_cid` only, started standalone. Killed on drop.
#[cfg(target_os = "linux")]
struct VsockProxy(std::process::Child);

#[cfg(target_os = "linux")]
impl VsockProxy {
    fn start(port: u32, peer_cid: u32, rules: &[(&str, u16)]) -> anyhow::Result<Self> {
        use std::io::{BufRead, Write};

        let bin = std::env::var_os("SANDY_EGRESS_PROXY_BIN")
            .map(std::path::PathBuf::from)
            .or_else(|| find_on_path("sandy-egress-proxy"))
            .context("refusing: sandy-egress-proxy is neither SANDY_EGRESS_PROXY_BIN nor on PATH")?;
        let policy = serde_json::json!({
            "rules": rules.iter().map(|(host, port)| serde_json::json!({"host": host, "port": port})).collect::<Vec<_>>()
        });
        let child = Command::new(bin)
            .args(["--vsock-port", &port.to_string(), "--peer-cid", &peer_cid.to_string()])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .context("spawn the standalone proxy")?;
        // The guard owns the child before anything can fail, so an early return still reaps it.
        let mut proxy = Self(child);
        proxy
            .0
            .stdin
            .take()
            .context("proxy stdin")?
            .write_all(policy.to_string().as_bytes())
            .context("write the policy")?;
        let mut ready = String::new();
        std::io::BufReader::new(proxy.0.stdout.take().context("proxy stdout")?)
            .read_line(&mut ready)
            .context("read READY")?;
        anyhow::ensure!(ready.trim() == "READY", "the proxy did not print READY, got {ready:?}");
        Ok(proxy)
    }
}

#[cfg(target_os = "linux")]
impl Drop for VsockProxy {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Send one `CONNECT` to the proxy over vsock loopback and return what the proxy answers (empty on a plain
/// close). `VMADDR_CID_LOCAL` (1) is the peer CID the proxy sees for a connection from this host.
#[cfg(target_os = "linux")]
fn vsock_loopback_connect_answer(port: u32, target: &str) -> anyhow::Result<Vec<u8>> {
    use std::io::{Read, Write};

    let mut stream = vsock::VsockStream::connect_with_cid_port(1, port)
        .context("connect over vsock loopback (CID 1): is the `vsock_loopback` kernel module loaded?")?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    // A refused peer may already be closed; a failed write is part of the refusal, not an error here.
    let _ = stream.write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes());
    let mut answer = Vec::new();
    match stream.read_to_end(&mut answer) {
        Ok(_) => {}
        // A reset after the proxy dropped the stream counts as a close with no answer.
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
        Err(e) => return Err(anyhow::Error::new(e).context("read the proxy's answer")),
    }
    Ok(answer)
}

/// KP4, qemu wrong-CID case: the proxy serves only the CID of the guest it was started for. A vsock peer with
/// any other CID is closed unanswered. A second VM is not needed: a connection from this host over vsock
/// loopback arrives with CID 1, which is a CID the proxy was not started for. A control run with the proxy
/// started for CID 1 gets an HTTP answer, so the silent close in the first run is the CID filter and not a
/// broken listener or client.
#[cfg(target_os = "linux")]
#[test]
fn a_vsock_peer_with_another_cid_is_closed_unanswered() -> anyhow::Result<()> {
    require_proxy_live()?;
    #[allow(clippy::cast_possible_truncation, reason = "a pid fits a port offset")]
    let base = 50_000 + (std::process::id() % 10_000);
    let denied = format!("{}:{PROBE_PORT}", denied_host());

    let control = VsockProxy::start(base, 1, &[("203.0.113.9", PROBE_PORT)])?;
    let answered = vsock_loopback_connect_answer(base, &denied)?;
    assert!(
        answered.starts_with(b"HTTP/1.1 403"),
        "control: the proxy for CID 1 must answer a denied CONNECT with 403, got {:?}",
        String::from_utf8_lossy(&answered)
    );
    drop(control);

    let _refusing = VsockProxy::start(base + 1, 4242, &[("203.0.113.9", PROBE_PORT)])?;
    let answered = vsock_loopback_connect_answer(base + 1, &denied)?;
    assert!(
        answered.is_empty(),
        "a peer whose CID is not 4242 must be closed unanswered, got {:?}",
        String::from_utf8_lossy(&answered)
    );
    Ok(())
}

/// Write an executable `#!/bin/sh` script to `path`.
fn write_script(path: &Path, body: &str) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::write(path, format!("#!/bin/sh\n{body}\n")).with_context(|| format!("write {}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
        .with_context(|| format!("chmod {}", path.display()))
}

/// The first `name` found on `PATH`.
fn find_on_path(name: &str) -> Option<std::path::PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|dir| dir.join(name))
        .find(|candidate| candidate.is_file())
}

/// KP7: a proxy that cannot start refuses the run as band 3, and the guest never boots. The proxy binary is
/// swapped for a stub that records that it ran and exits before it prints `READY`. `SANDY_QEMU_BIN` points at
/// a wrapper that records a launch and then runs the real qemu, because a failed run's envelope carries no
/// console to inspect. The same test is both legs (KP7q, KP7v): the wrapper replaces `SANDY_QEMU_BIN` on Linux
/// and `SANDY_VFKIT_BIN` on macOS.
#[test]
fn proxy_startup_failure_is_band_3() -> anyhow::Result<()> {
    let target = require_proxy_live()?;
    build_guest(&target)?;
    let home = tempfile::tempdir().context("temp SANDY_HOME")?;
    let proxy_ran = home.path().join("proxy-ran");
    let qemu_ran = home.path().join("qemu-ran");
    let stub = home.path().join("failing-proxy");
    write_script(&stub, &format!("touch {}\nexit 3", sh_quote(&proxy_ran)))?;
    let hypervisor_env = if cfg!(target_os = "linux") {
        "SANDY_QEMU_BIN"
    } else {
        "SANDY_VFKIT_BIN"
    };
    let qemu_name = &target.hypervisor;
    let real_qemu = find_on_path(qemu_name).with_context(|| format!("refusing: `{qemu_name}` is not on PATH"))?;
    let wrapper = home.path().join("hypervisor-wrapper");
    write_script(
        &wrapper,
        &format!("touch {}\nexec {} \"$@\"", sh_quote(&qemu_ran), sh_quote(&real_qemu)),
    )?;
    let allowed = allowed_host();
    let allow = vec![format!("{allowed}:{PROBE_PORT}")];

    // Positive control: with the real proxy the wrapper must see a launch, or the "never launched" check
    // below could not fail.
    let control = sandy_proxy_cmd(home.path(), &target, &allow, "exit 0")
        .env(hypervisor_env, &wrapper)
        .output()
        .context("run the control sandy")?;
    anyhow::ensure!(
        qemu_ran.exists(),
        "{hypervisor_env} never saw a launch on a healthy run (exit {:?}); stderr: {}",
        control.status.code(),
        String::from_utf8_lossy(&control.stderr)
    );
    // The wrapper writes its marker before qemu runs, so the control must also have booted and succeeded.
    let (control_code, control_env) =
        parse_envelope(control.status.code().unwrap_or(-1), &control.stdout, &control.stderr)?;
    assert_guest_ok(control_code, &control_env, "the control run must boot and exit 0");
    std::fs::remove_file(&qemu_ran).context("reset the qemu marker")?;

    let output = sandy_proxy_cmd(home.path(), &target, &allow, "exit 0")
        .env("SANDY_EGRESS_PROXY_BIN", &stub)
        .env(hypervisor_env, &wrapper)
        .output()
        .context("run sandy with a proxy that cannot start")?;
    let (code, env) = parse_envelope(output.status.code().unwrap_or(-1), &output.stdout, &output.stderr)?;

    assert!(
        proxy_ran.exists(),
        "the failing proxy stub never ran, so no pre-READY exit was tested; envelope: {env}"
    );
    assert_infra_fault(code, &env, "a proxy that cannot start is an infra fault");
    assert!(
        env.to_string().contains("egress proxy"),
        "the envelope must name the proxy failure; envelope: {env}"
    );
    assert!(
        !qemu_ran.exists(),
        "qemu was launched although the proxy could not start; envelope: {env}"
    );
    Ok(())
}

#[test]
fn a_hostname_is_lowercased_and_loses_one_trailing_dot() -> anyhow::Result<()> {
    anyhow::ensure!(normalise_hostname("One.One.One.One.")? == "one.one.one.one");
    anyhow::ensure!(normalise_hostname("a-b.example")? == "a-b.example");
    // The default names the live tests use must pass unchanged.
    for default in ["one.one.one.one", "example.com", "1dot1dot1dot1.cloudflare-dns.com"] {
        anyhow::ensure!(normalise_hostname(default)? == default, "{default} must stay as is");
    }
    Ok(())
}

#[test]
fn a_setting_the_proxy_would_not_accept_is_refused() {
    let too_long_label = format!("{}.example", "a".repeat(64));
    for bad in [
        "one.one.one.one..",
        "",
        ".",
        "a..example",
        "-a.example",
        "a-.example",
        "a_b.example",
        "caf\u{e9}.example",
        "1.2.3",
        "1.1.1.1",
        too_long_label.as_str(),
    ] {
        assert!(normalise_hostname(bad).is_err(), "{bad:?} must be refused");
    }
}

#[test]
fn a_path_with_an_apostrophe_is_one_shell_word() {
    assert_eq!(sh_quote(Path::new("/a/b'c")), r"'/a/b'\''c'");
    assert_eq!(sh_quote(Path::new("/plain")), "'/plain'");
}
