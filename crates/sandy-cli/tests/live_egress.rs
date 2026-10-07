//! live_egress — the live egress-enforcement acceptance gate (#29, with #23/#24).
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
//!   nix shell nixpkgs#qemu nixpkgs#nftables nixpkgs#iptables nixpkgs#dnsmasq nixpkgs#iproute2 -c \
//!   cargo nextest run -p sandy-cli --features live --test live_egress --no-capture
//! ```
//!
//! On a host with its own firewall (NixOS/Docker), the gate trusts the tap at
//! runtime via `iptables` (accept its input for DHCP + its forwarding) and removes
//! those rules on teardown; it needs `iptables` on PATH for that.
//!
//! Host-specific knobs (override via env when the defaults don't fit):
//!   - `SANDY_EGRESS_UPLINK` — the WAN interface to masquerade out of; auto-detected from the default route when unset.
//!   - `SANDY_EGRESS_ALLOWED` / `SANDY_EGRESS_DENIED` — the reachable "allowed" and "denied" IPs probed on :443
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
    std::env::var("SANDY_EGRESS_ALLOWED").unwrap_or_else(|_| "1.1.1.1".to_string())
}

/// The "denied" host: reachable at the IP level, but never on the allow-list.
fn denied_host() -> String {
    std::env::var("SANDY_EGRESS_DENIED").unwrap_or_else(|_| "1.0.0.1".to_string())
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

/// Resolve the WAN interface to masquerade out of: `$SANDY_EGRESS_UPLINK` or the
/// `dev` of the default route.
fn detect_uplink() -> anyhow::Result<String> {
    if let Ok(iface) = std::env::var("SANDY_EGRESS_UPLINK") {
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
        .context("no default-route interface found; set SANDY_EGRESS_UPLINK")?;
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

        // 0. Clear any state a previously interrupted run left behind. `Drop` does not run on SIGINT/SIGKILL, so a
        //    killed run leaves the tap and tables in place and `ip tuntap add` would fail with "Device or resource
        //    busy". Each delete tolerates an already-absent resource, so this is a no-op on the normal (clean) path and
        //    makes the gate re-runnable.
        preclean();

        // 1. The tap the guest NIC attaches to, with the host-side gateway address.
        run(Command::new("ip").args(["tuntap", "add", "dev", TAP, "mode", "tap"]))?;
        run(Command::new("ip").args(["addr", "add", HOST_ADDR, "dev", TAP]))?;
        run(Command::new("ip").args(["link", "set", TAP, "up"]))?;

        // 1b. Trust the tap in the host firewall. A stock NixOS/Docker host refuses
        //     unsolicited input on a fresh tap (so the guest's DHCP DISCOVER never
        //     reaches dnsmasq) and drops forwarded traffic (Docker sets the FORWARD
        //     policy to DROP). These accept the guest's input and forwarding.
        //     sandy's own `sandy_egress` nft forward-drop still fires for denied
        //     hosts — a `drop` in any base chain is final — so enforcement holds.
        for rule in tap_firewall_rules() {
            run(Command::new("iptables").arg("-w").arg("-I").args(&rule))
                .context("trust the tap in the host firewall (needs `iptables` on PATH)")?;
        }

        // 2. Enable IPv4 forwarding (host-specific; remembered for teardown).
        let prev_ip_forward = std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward")
            .unwrap_or_else(|_| "0".to_string())
            .trim()
            .to_string();
        run(Command::new("sysctl").args(["-w", "net.ipv4.ip_forward=1"]))?;

        // 3. Masquerade the guest subnet out of the uplink (sandy's egress filter is a SEPARATE table — this one only
        //    does source NAT, never a drop).
        nft_load(&format!(
            "table ip sandy_egress_nat {{\n  chain postrouting {{\n    type nat hook postrouting priority srcnat; \
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

/// The iptables rules that trust the gate's tap in the host firewall, given as the
/// args AFTER the `-I`/`-D` op (chain, match, `-j ACCEPT`). Shared by setup (insert)
/// and teardown/preclean (delete) so the exact same rules are added and removed.
fn tap_firewall_rules() -> [[String; 5]; 3] {
    let accept = |chain: &str, dir: &str| {
        [
            chain.to_string(),
            dir.to_string(),
            TAP.to_string(),
            "-j".to_string(),
            "ACCEPT".to_string(),
        ]
    };
    [
        accept("nixos-fw", "-i"),
        accept("FORWARD", "-i"),
        accept("FORWARD", "-o"),
    ]
}

/// Run a best-effort teardown command, ignoring its exit status and swallowing its
/// output — these deletes routinely hit an already-gone resource, and their errors
/// are noise on an otherwise-passing run.
fn silent(cmd: &mut Command) {
    let _ = cmd.stdout(Stdio::null()).stderr(Stdio::null()).status();
}

/// Best-effort removal of the resources [`HostNet::setup`] is about to create,
/// in case a previous run was interrupted before its `Drop` teardown could run.
fn preclean() {
    for rule in tap_firewall_rules() {
        silent(Command::new("iptables").arg("-w").arg("-D").args(&rule));
    }
    silent(Command::new("nft").args(["delete", "table", "inet", "sandy_egress"]));
    silent(Command::new("nft").args(["delete", "table", "ip", "sandy_egress_nat"]));
    silent(Command::new("ip").args(["link", "del", TAP]));
}

impl Drop for HostNet {
    fn drop(&mut self) {
        // Best-effort teardown on every path. Order is the reverse of setup; each
        // step tolerates an already-gone resource.
        if let Some(mut child) = self.dnsmasq.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        // Remove the host-firewall trust rules added in setup (step 1b).
        for rule in tap_firewall_rules() {
            silent(Command::new("iptables").arg("-w").arg("-D").args(&rule));
        }
        // sandy reverts its own `sandy_egress` table, but delete it too in case a
        // run was interrupted mid-boot before the revert.
        silent(Command::new("nft").args(["delete", "table", "inet", "sandy_egress"]));
        silent(Command::new("nft").args(["delete", "table", "ip", "sandy_egress_nat"]));
        silent(Command::new("ip").args(["link", "del", TAP]));
        // Two args, not a bundled "-wnet.ipv4…": sysctl parses the latter as
        // stacked short flags (-w -n -e -t -…) and rejects it, silently skipping
        // the restore. Mirror setup's `-w`, `net.ipv4.ip_forward=…` form.
        silent(Command::new("sysctl").args(["-w", &format!("net.ipv4.ip_forward={}", self.prev_ip_forward)]));
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

/// A guest shell script that checks egress end to end and encodes the outcome in
/// its **exit code** — the one channel that provably reaches the result envelope
/// (`exit_code`), since sandy currently surfaces neither the guest's stdout nor
/// its console back to the test.
///
/// When the guest has no default route it walks the DHCP chain and reports the
/// first broken link, so a failure names its cause in one run:
///
///   0  — route up, allowed reachable, denied blocked        (allow+deny correct)
///   20 — route up, BOTH hosts blocked                       (empty-allow correct)
///   12 — route up, allowed reachable, denied ALSO reachable (enforcement leak)
///   13 — route up, allowed unreachable, denied reachable
///   30 — no non-loopback interface at all (guest NIC never appeared)
///   31 — NIC present but no carrier (qemu tap not linked)
///   32 — carrier up but systemd-networkd not active
///   33 — networkd active but the NIC got no IPv4 address (DHCP server silent)
///   10 — NIC up with an address but still no default route
///
/// The route check is also a positive control: without it a guest with no network
/// at all looks identical to a perfectly enforced boundary (both probes fail), so
/// "blocked" would pass for the wrong reason. `pre` runs before the probes (e.g.
/// an in-guest `nft flush ruleset`). Only shell builtins and `/sys` are used, so
/// the script needs no awk/sed/coreutils-extras in the guest.
fn egress_check_script(pre: &str, allowed: &str, denied: &str, port: u16) -> String {
    format!(
        r#"set -u
{pre}
dev=
for i in /sys/class/net/*; do n=${{i##*/}}; [ "$n" = lo ] && continue; dev=$n; break; done
echo "live_egress: dev=${{dev:-none}}"
[ -z "$dev" ] && exit 30
route=no
for _ in $(seq 1 30); do
  if ip route 2>/dev/null | grep -q '^default'; then route=yes; break; fi
  sleep 1
done
echo "live_egress: route=$route dev=$dev"
ip -o addr show 2>/dev/null || true
ip route 2>/dev/null || true
if [ "$route" = no ]; then
  carrier=$(cat /sys/class/net/$dev/carrier 2>/dev/null || echo 0)
  nwd=$(systemctl is-active systemd-networkd 2>/dev/null || echo unknown)
  haveip=no; ip -4 addr show dev $dev 2>/dev/null | grep -q 'inet ' && haveip=yes
  echo "live_egress: no-route carrier=$carrier networkd=$nwd haveip=$haveip"
  [ "$carrier" != 1 ] && exit 31
  [ "$nwd" != active ] && exit 32
  [ "$haveip" = no ] && exit 33
  exit 10
fi
probe() {{ timeout 5 bash -c "exec 3<>/dev/tcp/$1/$2" >/dev/null 2>&1; }}
if probe {allowed} {port}; then a=ok; else a=fail; fi
if probe {denied} {port}; then d=ok; else d=fail; fi
echo "live_egress: allowed={allowed}:{port}=$a denied={denied}:{port}=$d"
if [ "$a" = ok ] && [ "$d" = fail ]; then exit 0; fi
if [ "$a" = fail ] && [ "$d" = fail ]; then exit 20; fi
if [ "$a" = ok ] && [ "$d" = ok ]; then exit 12; fi
exit 13
"#
    )
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

    let guest_cmd = egress_check_script("", &allowed, &denied, PROBE_PORT);
    let allow = vec![format!("{allowed}:{PROBE_PORT}")];

    let (code, env) = sandy_run_on_tap(home.path(), target.topology_attr, &allow, &guest_cmd)?;

    assert_eq!(env["status"], "succeeded", "allow+deny must hold; envelope: {env}");
    assert_eq!(
        env["exit_code"], 0,
        "guest must reach {allowed}:{PROBE_PORT} and be blocked from {denied}:{PROBE_PORT} (exit codes per \
         egress_check_script: 30-33/10 = guest networking broke, 12 = enforcement leak, 13 = allowed unreachable); \
         envelope: {env}"
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

    let guest_cmd = egress_check_script("nft flush ruleset 2>/dev/null || true", &allowed, &denied, PROBE_PORT);
    let allow = vec![format!("{allowed}:{PROBE_PORT}")];

    let (_code, env) = sandy_run_on_tap(home.path(), target.topology_attr, &allow, &guest_cmd)?;

    assert_eq!(
        env["exit_code"], 0,
        "after an in-guest `nft flush ruleset`, {allowed}:{PROBE_PORT} must stay reachable and {denied}:{PROBE_PORT} \
         must STILL be blocked by the host boundary (exit 12 = the flush bypassed it); envelope: {env}"
    );
    Ok(())
}

/// no fail-open: an EMPTY allow-list blocks ALL guest egress — the guest reaches
/// neither host. Exit 20 means the guest HAD a default route (positive control)
/// yet both probes were blocked; a guest with no network at all exits 10 and
/// fails this test rather than passing it for the wrong reason.
#[test]
fn empty_allow_list_blocks_all_guest_egress() -> anyhow::Result<()> {
    let target = require_live_root()?;
    build_guest(&target)?;
    let _net = HostNet::setup()?;
    let home = tempfile::tempdir().context("temp SANDY_HOME")?;
    let (allowed, denied) = (allowed_host(), denied_host());

    let guest_cmd = egress_check_script("", &allowed, &denied, PROBE_PORT);

    // No --allow entries: sandy applies the forward ruleset with only the drop floor.
    let (_code, env) = sandy_run_on_tap(home.path(), target.topology_attr, &[], &guest_cmd)?;

    assert_eq!(
        env["exit_code"], 20,
        "an empty allow-list must block ALL guest egress with the route up (no fail-open; exit 10=no route, \
         0/12=reached a host); envelope: {env}"
    );
    Ok(())
}
