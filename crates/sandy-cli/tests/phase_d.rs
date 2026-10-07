//! phase_d — the live egress-enforcement acceptance gate (#29, with #23/#24).
//!
//! Tier-3, root-only. It sets up a real host tap with NAT + IP forwarding, boots a
//! guest onto it through `sandy run`, and asserts that sandy's **guest-scoped**
//! nftables boundary (the `forward`-hook, `iifname`-matched ruleset from
//! [`sandy::to_nftables_forward`]) actually lets the guest reach an allow-listed
//! host and blocks everything else — including when the in-guest root flushes its
//! own firewall, and when the allow-list is empty.
//!
//! ## Safety
//!
//! The boundary sandy applies here is **guest-scoped**: a `forward` chain with
//! `policy accept` that filters only packets entering from the guest's tap. It can
//! never drop the host's own egress, unlike the OUTPUT-hook `policy drop` that
//! [`sandy::to_nftables`] emits — which is why this gate drives the forward model,
//! never that one. sandy selects the forward model automatically because `$SANDY_TAP`
//! is set (see `supervisor::run_job` + `plan_egress_scoped`).
//!
//! The gate also owns the host plumbing it creates (tap, NAT table, `ip_forward`,
//! a dnsmasq for DHCP) and tears every piece down on exit — success, failure, or
//! panic — via [`HostNet`]'s `Drop`, so a failed run leaves no rules or interfaces
//! behind.
//!
//! ## Running it (root)
//!
//! It refuses off-matrix (not Linux, not root, no `SANDY_LIVE=1`, or `nft`/`qemu`
//! absent) rather than skip-greening. A full invocation, from the repo root:
//!
//! ```text
//! sudo env SANDY_LIVE=1 PATH="$PATH" \
//!   nix shell nixpkgs#qemu nixpkgs#nftables nixpkgs#dnsmasq nixpkgs#iproute2 -c \
//!   cargo nextest run -p sandy-cli --features live --test phase_d --no-capture
//! ```
//!
//! Host-specific knobs (override via env when the defaults don't fit):
//!   - `SANDY_PHASE_D_UPLINK` — the WAN interface to masquerade out of; auto-detected from the default route when
//!     unset.
//!   - `SANDY_PHASE_D_ALLOWED` / `SANDY_PHASE_D_DENIED` — the reachable "allowed" and "denied" IPs probed on :443
//!     (defaults `1.1.1.1` / `1.0.0.1`; the host needs working internet to those addresses).
#![cfg(feature = "live")]

use std::{
    path::Path,
    process::{Child, Command, Stdio},
};

use anyhow::{Context, bail};

mod common;
use common::{build_guest, guest_flake, require_live_root};

/// The host tap sandy attaches the guest NIC to (matches the backend's `$SANDY_TAP`).
const TAP: &str = "sandytap0";
/// The guest subnet routed through the host.
const SUBNET: &str = "10.77.0.0/24";
/// The host-side gateway address on the tap (the guest's default route).
const HOST_ADDR: &str = "10.77.0.1/24";
/// The DHCP range dnsmasq hands the guest.
const DHCP_RANGE: &str = "10.77.0.10,10.77.0.100,5m";
/// The TCP port probed on both the allowed and denied hosts.
const PROBE_PORT: u16 = 443;

/// The "allowed" host: reachable, and the only destination the allow-list permits.
fn allowed_host() -> String {
    std::env::var("SANDY_PHASE_D_ALLOWED").unwrap_or_else(|_| "1.1.1.1".to_string())
}

/// The "denied" host: reachable at the IP level, but never on the allow-list.
fn denied_host() -> String {
    std::env::var("SANDY_PHASE_D_DENIED").unwrap_or_else(|_| "1.0.0.1".to_string())
}

/// Run `cmd` and fail with its stderr when it exits non-zero — the gate's setup
/// steps are host mutations whose failure must be loud, not swallowed.
fn run(cmd: &mut Command) -> anyhow::Result<()> {
    let out = cmd.output().with_context(|| format!("spawn {cmd:?}"))?;
    if !out.status.success() {
        bail!(
            "command {cmd:?} failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(())
}

/// Load an nftables ruleset through `nft -f -`.
fn nft_load(ruleset: &str) -> anyhow::Result<()> {
    use std::io::Write;
    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .spawn()
        .context("spawn nft -f -")?;
    child
        .stdin
        .as_mut()
        .context("nft stdin not captured")?
        .write_all(ruleset.as_bytes())
        .context("write ruleset to nft")?;
    let status = child.wait().context("wait for nft")?;
    if !status.success() {
        bail!("nft -f - exited with {status}");
    }
    Ok(())
}

/// Resolve the WAN interface to masquerade out of: `$SANDY_PHASE_D_UPLINK` or the
/// `dev` of the default route.
fn detect_uplink() -> anyhow::Result<String> {
    if let Ok(iface) = std::env::var("SANDY_PHASE_D_UPLINK") {
        if !iface.is_empty() {
            return Ok(iface);
        }
    }
    let out = Command::new("ip")
        .args(["route", "show", "default"])
        .output()
        .context("ip route show default")?;
    // "default via 192.168.1.1 dev eth0 proto dhcp …" → the token after `dev`.
    let text = String::from_utf8_lossy(&out.stdout);
    let iface = text
        .split_whitespace()
        .skip_while(|t| *t != "dev")
        .nth(1)
        .context("no default-route interface found; set SANDY_PHASE_D_UPLINK")?;
    Ok(iface.to_string())
}

/// The host plumbing for the gate: a tap, its address, IP forwarding, a NAT table,
/// and a dnsmasq DHCP server. Everything is torn down on `Drop` so no path leaves
/// state behind.
struct HostNet {
    prev_ip_forward: String,
    dnsmasq: Option<Child>,
}

impl HostNet {
    /// Build the tap + NAT + forwarding + DHCP. Each step is documented so the gate
    /// can be reproduced by hand.
    fn setup() -> anyhow::Result<Self> {
        let uplink = detect_uplink()?;

        // 1. The tap the guest NIC attaches to, with the host-side gateway address.
        run(Command::new("ip").args(["tuntap", "add", "dev", TAP, "mode", "tap"]))?;
        run(Command::new("ip").args(["addr", "add", HOST_ADDR, "dev", TAP]))?;
        run(Command::new("ip").args(["link", "set", TAP, "up"]))?;

        // 2. Enable IPv4 forwarding (host-specific; remembered for teardown).
        let prev_ip_forward = std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward")
            .unwrap_or_else(|_| "0".to_string())
            .trim()
            .to_string();
        run(Command::new("sysctl").args(["-w", "net.ipv4.ip_forward=1"]))?;

        // 3. Masquerade the guest subnet out of the uplink (sandy's egress filter is a SEPARATE table — this one only
        //    does source NAT, never a drop).
        nft_load(&format!(
            "table ip sandy_phase_d_nat {{\n  chain postrouting {{\n    type nat hook postrouting priority srcnat; \
             policy accept;\n    ip saddr {SUBNET} oifname \"{uplink}\" masquerade\n  }}\n}}\n"
        ))
        .context("load NAT table")?;

        // 4. A DHCP server bound to the tap so the guest comes up (DNS disabled — the probes use IPs).
        let dnsmasq = Command::new("dnsmasq")
            .args([
                "--keep-in-foreground",
                "--bind-interfaces",
                &format!("--interface={TAP}"),
                &format!("--dhcp-range={DHCP_RANGE}"),
                "--dhcp-authoritative",
                "--port=0",
                "--log-facility=-",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("spawn dnsmasq on the tap")?;

        Ok(Self {
            prev_ip_forward,
            dnsmasq: Some(dnsmasq),
        })
    }
}

impl Drop for HostNet {
    fn drop(&mut self) {
        // Best-effort teardown on every path. Order is the reverse of setup; each
        // step tolerates an already-gone resource.
        if let Some(mut child) = self.dnsmasq.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        // sandy reverts its own `sandy_egress` table, but delete it too in case a
        // run was interrupted mid-boot before the revert.
        let _ = Command::new("nft")
            .args(["delete", "table", "inet", "sandy_egress"])
            .status();
        let _ = Command::new("nft")
            .args(["delete", "table", "ip", "sandy_phase_d_nat"])
            .status();
        let _ = Command::new("ip").args(["link", "del", TAP]).status();
        let _ = Command::new("sysctl")
            .arg(format!("-wnet.ipv4.ip_forward={}", self.prev_ip_forward))
            .status();
    }
}

/// Boot the guest through `sandy run` on the tap with the given `--allow` entries
/// and guest command, returning the run's process band and result envelope.
///
/// Sets `SANDY_TAP` so sandy attaches the guest NIC to the tap AND selects the
/// guest-scoped forward egress model (never the host-OUTPUT drop-all).
fn sandy_run_on_tap(
    home: &Path,
    topology_attr: &str,
    allow: &[String],
    guest_cmd: &str,
) -> anyhow::Result<(i32, serde_json::Value)> {
    let attr = format!("{}#{}", guest_flake().display(), topology_attr);
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_sandy"));
    cmd.env("SANDY_HOME", home)
        .env("SANDY_TAP", TAP)
        .args(["-o", "json", "run", &attr, "--timeout", "120"]);
    for entry in allow {
        cmd.args(["--allow", entry]);
    }
    cmd.args(["--", "bash", "-c", guest_cmd]);

    let output = cmd.output().context("run sandy on the tap")?;
    let code = output.status.code().unwrap_or(-1);
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).with_context(|| {
        format!(
            "parse sandy run envelope (exit {code}); stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        )
    })?;
    Ok((code, envelope))
}

/// A guest shell snippet: wait for the default route, then define a `probe host port`
/// that returns 0 iff a TCP connection opens within 5s (bash `/dev/tcp`, no curl).
fn probe_prelude() -> String {
    r#"set -u
for _ in $(seq 1 30); do ip route 2>/dev/null | grep -q '^default' && break; sleep 1; done
probe() { timeout 5 bash -c "exec 3<>/dev/tcp/$1/$2" >/dev/null 2>&1; }
"#
    .to_string()
}

/// allow + deny: with the allow-list = [allowed:443], the guest CAN reach the
/// allowed host and CANNOT reach an unlisted host. The guest command exits 0 iff
/// both hold, so a succeeded/exit-0 envelope is the assertion.
#[test]
fn allowed_host_reachable_denied_host_blocked() -> anyhow::Result<()> {
    let target = require_live_root()?;
    build_guest(&target)?;
    let _net = HostNet::setup()?;
    let home = tempfile::tempdir().context("temp SANDY_HOME")?;
    let (allowed, denied) = (allowed_host(), denied_host());

    let guest_cmd = format!(
        "{prelude}if probe {allowed} {port} && ! probe {denied} {port}; then exit 0; else exit 1; fi",
        prelude = probe_prelude(),
        port = PROBE_PORT,
    );
    let allow = vec![format!("{allowed}:{PROBE_PORT}")];

    let (code, env) = sandy_run_on_tap(home.path(), target.topology_attr, &allow, &guest_cmd)?;

    assert_eq!(env["status"], "succeeded", "allow+deny must hold; envelope: {env}");
    assert_eq!(
        env["exit_code"], 0,
        "guest must reach {allowed}:{PROBE_PORT} and be blocked from {denied}:{PROBE_PORT}; envelope: {env}"
    );
    assert_eq!(code, 0, "process band 0; envelope: {env}");
    Ok(())
}

/// bypass impossible: the in-guest root flushes the guest's OWN nftables
/// (`nft flush ruleset`), then the host-side boundary STILL blocks the unlisted
/// host while the allowed host stays reachable — proving enforcement is host-side,
/// not guest-side.
#[test]
fn in_guest_firewall_flush_cannot_bypass_the_host_boundary() -> anyhow::Result<()> {
    let target = require_live_root()?;
    build_guest(&target)?;
    let _net = HostNet::setup()?;
    let home = tempfile::tempdir().context("temp SANDY_HOME")?;
    let (allowed, denied) = (allowed_host(), denied_host());

    let guest_cmd = format!(
        "{prelude}nft flush ruleset 2>/dev/null || true\nif probe {allowed} {port} && ! probe {denied} {port}; then \
         exit 0; else exit 1; fi",
        prelude = probe_prelude(),
        port = PROBE_PORT,
    );
    let allow = vec![format!("{allowed}:{PROBE_PORT}")];

    let (_code, env) = sandy_run_on_tap(home.path(), target.topology_attr, &allow, &guest_cmd)?;

    assert_eq!(
        env["exit_code"], 0,
        "after an in-guest `nft flush ruleset`, {denied}:{PROBE_PORT} must STILL be blocked by the host boundary; \
         envelope: {env}"
    );
    Ok(())
}

/// no fail-open: an EMPTY allow-list blocks ALL guest egress — the guest reaches
/// neither host. The guest command exits 0 iff both probes fail.
#[test]
fn empty_allow_list_blocks_all_guest_egress() -> anyhow::Result<()> {
    let target = require_live_root()?;
    build_guest(&target)?;
    let _net = HostNet::setup()?;
    let home = tempfile::tempdir().context("temp SANDY_HOME")?;
    let (allowed, denied) = (allowed_host(), denied_host());

    let guest_cmd = format!(
        "{prelude}if ! probe {allowed} {port} && ! probe {denied} {port}; then exit 0; else exit 1; fi",
        prelude = probe_prelude(),
        port = PROBE_PORT,
    );

    // No --allow entries: sandy applies the forward ruleset with only the drop floor.
    let (_code, env) = sandy_run_on_tap(home.path(), target.topology_attr, &[], &guest_cmd)?;

    assert_eq!(
        env["exit_code"], 0,
        "an empty allow-list must block ALL guest egress (no fail-open); envelope: {env}"
    );
    Ok(())
}
