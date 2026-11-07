#!/usr/bin/env bash
# Start a T3 environment (qemu-t3 guest, 0.1.6) on a Linux/KVM host as a transient systemd unit. Runs as the
# operator with one sudo prompt. guest.sh is the job command and a static busybox httpd publishes the pairing
# code. The host network comes from net.sh until sandy provisions it (#677). The Mac wrapper t3-sandy
# (agent-env) calls this script with --start-script; it also runs by hand.
# Needs: UNIT, NONCE, JOB_TIMEOUT, SANDY_DIR in the environment, and guest.sh next to this file. SANDY_DIR is a
# git checkout of sandy with target/release/sandy built; the trust roots must be root-owned
# with mode 700 and 600, because sandy runs as root here and refuses other owners (crates/sandy/src/cred.rs).
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
: "${UNIT:?}" "${NONCE:?}" "${JOB_TIMEOUT:?}" "${SANDY_DIR:?}"

tools="$(nix build nixpkgs#qemu nixpkgs#virtiofsd nixpkgs#nftables nixpkgs#iptables nixpkgs#iproute2 --no-link --print-out-paths | sed 's|$|/bin|' | tr '\n' ':')"
bb="$(nix build nixpkgs#pkgsStatic.busybox --no-link --print-out-paths)/bin/busybox"
ip link show sandytap0 >/dev/null 2>&1 || {
  echo "sandytap0 missing: run net.sh up first" >&2
  exit 1
}

# systemd-run resolves the command in sudo's secure_path, not in --setenv=PATH, so the binary is
# called by absolute path. The PATH below is for the tools sandy starts (qemu, virtiofsd, nft).
# SUDO_UID: sandy runs as root on a checkout this user owns; libgit2 accepts that only when SUDO_UID
# names the owner, and systemd-run does not carry it into the unit (nix eval: "not owned by current user").
sudo systemd-run --unit="$UNIT" --collect \
  --setenv=HOME="$HOME" --setenv=SUDO_UID="$(id -u)" \
  --setenv=PATH="${tools}${SANDY_DIR}/target/release:/run/current-system/sw/bin" \
  --setenv=SANDY_NETWORK=nic --setenv=SANDY_TAP=sandytap0 \
  "$SANDY_DIR/target/release/sandy" run "$SANDY_DIR/nix/guest#topologies.x86_64-linux.qemu-t3" \
  --cpu 2 --mem 2304 --timeout "$JOB_TIMEOUT" \
  --allow 0.0.0.0/0:443 --allow 0.0.0.0/0:53 \
  --credential external-actor --cred-capability read-code \
  --input "$here/guest.sh:guest.sh" --input "$bb:busybox" \
  -- bash /run/sandy/inputs/guest.sh "$NONCE"
