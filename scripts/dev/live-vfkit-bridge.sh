#!/usr/bin/env bash
# Live gate for the guest service bridge on vfkit (#590, KSB4), tier-3, never counted green from a fake (INV-S9).
#
# The macOS counterpart of live-vsock-bridge.sh. Boots the T3 guest (nix/guest, topology vfkit-t3) through
# `VfkitBackend::with_service_socket`, so vfkit's `connect` device exposes the guest's relay port at a host unix
# socket. The guest runs `sandy-agent port-relay` and `t3 serve`; the sandy-conn live test then runs a Bridge over a
# UnixDialer to that socket, polls a GET until the status is below 500, then shuts the bridge down.
#
# Needs: an Apple-silicon macOS host with nix and the aarch64-linux builder (`sandy doctor` names what is missing).
# No root. Run from the repo root:
#
#   scripts/dev/live-vfkit-bridge.sh
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$repo_root"

if [ "$(uname -s)" != "Darwin" ]; then
  echo "refusing: the vfkit bridge gate needs a macOS host (the Linux gate is live-vsock-bridge.sh)" >&2
  exit 2
fi

# Short, fixed base: a unix socket path holds at most 103 bytes on macOS, and the service socket sits under it.
work=$(mktemp -d /tmp/slv.XXXXXX)
chmod 0700 "$work"
sandy_pid=""
cleanup() {
  if [ -n "$sandy_pid" ] && kill -0 "$sandy_pid" 2>/dev/null; then
    kill "$sandy_pid" 2>/dev/null || true
    wait "$sandy_pid" 2>/dev/null || true
  fi
  # vfkit is a plain child of the driver; every process of this run carries the private work dir.
  pkill -f -- "$work/" 2>/dev/null || true
  for _ in $(seq 20); do
    pgrep -f -- "$work/" >/dev/null 2>&1 || break
    sleep 0.5
  done
  pkill -9 -f -- "$work/" 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

# The job the guest runs: the relay as root (port 1000, the privileged relay port) and t3 as the service user.
# It holds the guest open past the host test's poll bound (120 s) plus its 60 s read timeout, then exits.
cat >"$work/guest.sh" <<'GUEST'
set -u
agent=$(ls -d /nix/store/*-sandy-agent-*/bin/sandy-agent 2>/dev/null | head -1)
echo "SK> agent=$agent"
"$agent" port-relay --vsock-port 1000 --to 127.0.0.1:3773 >/tmp/relay.log 2>&1 &
relay_pid=$!
mkdir -p /var/lib/t3/data
chown -R t3:t3 /var/lib/t3
runuser -u t3 -- t3 serve --host 127.0.0.1 --port 3773 --base-dir /var/lib/t3/data --no-browser >/tmp/t3.log 2>&1 &
t3_pid=$!
i=0
until sandy-t3-ready; do
  i=$((i + 1))
  if [ "$i" -gt 120 ]; then echo "SK> t3 never ready"; exit 3; fi
  sleep 1
done
echo "SK> t3 ready after ${i}s"
# Hold the guest open, and fail if the relay or t3 dies while the host test may still be using them.
for _ in $(seq 180); do
  kill -0 "$relay_pid" 2>/dev/null || { echo "SK> relay exited"; exit 4; }
  kill -0 "$t3_pid" 2>/dev/null || { echo "SK> t3 exited"; exit 5; }
  sleep 1
done
echo "SK> done"
GUEST

echo "== building the driver and the live test"
# Cargo's target directory may be overridden (CARGO_TARGET_DIR, build.target-dir); run the binary just built.
target_dir=$(cargo metadata --format-version 1 --no-deps | python3 -I -c 'import json, sys; print(json.load(sys.stdin)["target_directory"])')
cargo build -q -p sandy-cli --features live --bin live-vfkit-guest
cargo nextest run -p sandy-conn --features live --test live_vsock_bridge --no-run

echo "== building the T3 guest"
nix build --no-link "$repo_root/nix/guest#packages.aarch64-darwin.guest-runner-vfkit-t3"

echo "== booting the guest"
socket="$work/svc.sock"
(
  TMPDIR="$work" SANDY_LIVE=1 \
    nix shell nixpkgs#vfkit -c \
    "$target_dir/debug/live-vfkit-guest" "$socket" "$work/guest.sh" \
    >"$work/outcome.log" 2>"$work/stderr.log"
) &
sandy_pid=$!

# vfkit creates the socket as it boots; the host test dials it with a long window, so only its appearance is awaited.
for _ in $(seq 150); do
  [ -S "$socket" ] && break
  if ! kill -0 "$sandy_pid" 2>/dev/null; then
    echo "the driver exited before the guest started:" >&2
    tail -n 12 "$work/stderr.log" >&2
    tail -n 5 "$work/outcome.log" >&2
    exit 1
  fi
  sleep 2
done
if [ ! -S "$socket" ]; then
  echo "no service socket appeared within 300 s" >&2
  exit 1
fi
echo "== service socket $socket; running the live test"

status=0
SANDY_LIVE_GUEST_SOCKET="$socket" cargo nextest run -p sandy-conn --features live --test live_vsock_bridge --no-capture || status=$?

# The driver's own exit decides too: a guest job that fails after the host test passed (t3 never ready, a crash)
# must not read as green.
driver=0
wait "$sandy_pid" || driver=$?
sandy_pid=""

echo "== guest output"
grep -a "SK>" "$work/outcome.log" || echo "(no SK> lines in the outcome)"
tail -n 5 "$work/stderr.log" >&2 || true
if [ "$driver" -ne 0 ]; then
  echo "the guest driver exited $driver" >&2
  status=1
fi
exit "$status"
