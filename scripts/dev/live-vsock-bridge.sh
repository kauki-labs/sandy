#!/usr/bin/env bash
# Live gate for the guest service bridge (#590, epic #597), tier-3, never counted green from a fake (INV-S9).
#
# Boots the T3 guest (nix/guest, topology qemu-t3) on a Linux KVM host, runs `sandy-agent port-relay` and
# `t3 serve` inside it, and runs the sandy-conn live test against the guest's vsock CID: a Bridge over a
# VsockDialer, a GET through the bridge's loopback address polled until the status is below 500, then shutdown.
# It also checks from inside the guest that a non-root process cannot bind the relay's privileged vsock port.
#
# Needs: a Linux host with KVM and /dev/vhost-vsock access, nix, a built tree (it builds what it needs).
# No root, tap or nft. Run from the repo root:
#
#   scripts/dev/live-vsock-bridge.sh
#
# The guest runs in egress-proxy mode (SANDY_EGRESS=proxy) only because that is what gives a plain `sandy run`
# guest a vsock device (qemu adds one when the run has an egress policy); the `EnvironmentBackend` will use
# agent mode instead.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$repo_root"

if [ "$(uname -s)" != "Linux" ]; then
  echo "refusing: the vsock bridge gate needs a Linux KVM host" >&2
  exit 2
fi
if [ ! -r /dev/vhost-vsock ] || [ ! -w /dev/vhost-vsock ]; then
  echo "refusing: /dev/vhost-vsock is not accessible to this user" >&2
  exit 2
fi

# Short, fixed base: sandy puts virtiofsd sockets under $TMPDIR/sandy/<run id>/, and a unix socket path holds
# at most 108 bytes, which a nix-shell TMPDIR plus a long prefix exceeds.
work=$(mktemp -d /tmp/slb.XXXXXX)
chmod 0700 "$work"
mkdir -p "$work/home"
printf 'sk-secret-value' >"$work/secret.txt"
chmod 0600 "$work/secret.txt"
sandy_pid=""
cleanup() {
  if [ -n "$sandy_pid" ] && kill -0 "$sandy_pid" 2>/dev/null; then
    kill "$sandy_pid" 2>/dev/null || true
    wait "$sandy_pid" 2>/dev/null || true
  fi
  # qemu and virtiofsd are plain children of sandy; every one of them carries this run's private work dir.
  pkill -f -- "$work/" 2>/dev/null || true
  for _ in $(seq 20); do
    pgrep -f -- "$work/" >/dev/null 2>&1 || break
    sleep 0.5
  done
  pkill -9 -f -- "$work/" 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

# The job the guest runs: the relay (as root, before anything untrusted), t3 as the service user, and two
# privileged-port checks as that user. It holds the guest open for the host test, then exits.
cat >"$work/guest.sh" <<'GUEST'
set -u
agent=$(ls -d /nix/store/*-sandy-agent-*/bin/sandy-agent 2>/dev/null | head -1)
echo "SK> agent=$agent"
"$agent" port-relay --vsock-port 1000 --to 127.0.0.1:3773 >/tmp/relay.log 2>&1 &
sleep 1
echo "SK> squat-999-as-t3: $(runuser -u t3 -- timeout 3 "$agent" port-relay --vsock-port 999 --to 127.0.0.1:9 2>&1 | head -2 | tr '\n' ' ')"
# The service user binds an unprivileged port; a second bind of it by root must then fail with EADDRINUSE,
# which proves the first bind happened (a bound relay writes one `B` byte to stdout and nothing after).
runuser -u t3 -- "$agent" port-relay --vsock-port 2000 --to 127.0.0.1:9 >/tmp/bind2000.log 2>&1 &
bind_pid=$!
sleep 1
echo "SK> bind-2000-as-t3: alive=$(kill -0 "$bind_pid" 2>/dev/null && echo yes || echo no) second-bind: $(timeout 3 "$agent" port-relay --vsock-port 2000 --to 127.0.0.1:9 2>&1 | head -1)"
pkill -f -- "port-relay --vsock-port 2000" 2>/dev/null || true
echo "SK> secrets-dir: $(stat -c '%a %U' /run/sandy/secrets 2>&1)"
echo "SK> secret-as-root: $(cat /run/sandy/secrets/SKSECRET 2>&1)"
echo "SK> secret-as-t3: $(runuser -u t3 -- cat /run/sandy/secrets/SKSECRET 2>&1 | head -1)"
mkdir -p /var/lib/t3/data
chown -R t3:t3 /var/lib/t3
runuser -u t3 -- t3 serve --host 127.0.0.1 --port 3773 --base-dir /var/lib/t3/data --no-browser >/tmp/t3.log 2>&1 &
i=0
until sandy-t3-ready; do
  i=$((i + 1))
  if [ "$i" -gt 120 ]; then echo "SK> t3 never ready"; exit 3; fi
  sleep 1
done
echo "SK> t3 ready after ${i}s"
# Keep the guest up past the host test's poll bound (120 s) plus its 60 s read timeout.
sleep 180
echo "SK> done"
GUEST

echo "== building sandy, the egress proxy and the live test"
cargo build -q -p sandy-cli --bin sandy
cargo build -q -p sandy-egress-proxy
cargo nextest run -p sandy-conn --features live --test live_vsock_bridge --no-run

echo "== building the T3 guest"
nix build --no-link "$repo_root/nix/guest#packages.x86_64-linux.guest-runner-t3"

echo "== booting the guest"
(
  TMPDIR="$work" SANDY_HOME="$work/home" SANDY_EGRESS=proxy \
    SANDY_EGRESS_PROXY_BIN="$repo_root/target/debug/sandy-egress-proxy" \
    nix shell nixpkgs#qemu nixpkgs#virtiofsd -c \
    "$repo_root/target/debug/sandy" -o json run "$repo_root/nix/guest#topologies.x86_64-linux.qemu-t3" \
    --timeout 900 --allow example.com:443 --secret "SKSECRET=@$work/secret.txt" --input "$work/guest.sh:guest.sh" -- bash /run/sandy/inputs/guest.sh \
    >"$work/result.json" 2>"$work/stderr.log"
) &
sandy_pid=$!

# The guest's CID is on its qemu command line. Match only a process that starts with `qemu-system` and carries
# this run's private TMPDIR, so the script's own command line (which names both) is never mistaken for it.
cid=""
for _ in $(seq 150); do
  cid=$(ps -eww -o args= | grep '^qemu-system' | grep -F "$work/" | grep -o 'guest-cid=[0-9][0-9]*' | head -1 | cut -d= -f2 || true)
  [ -n "$cid" ] && break
  if ! kill -0 "$sandy_pid" 2>/dev/null; then
    echo "sandy exited before the guest started:" >&2
    tail -n 12 "$work/stderr.log" >&2
    head -c 2000 "$work/result.json" >&2
    exit 1
  fi
  sleep 2
done
if [ -z "$cid" ]; then
  echo "no guest vsock CID appeared within 300 s" >&2
  exit 1
fi
echo "== guest cid $cid; running the live test"

status=0
SANDY_LIVE_GUEST_CID="$cid" cargo nextest run -p sandy-conn --features live --test live_vsock_bridge --no-capture || status=$?

wait "$sandy_pid" || true
sandy_pid=""

echo "== guest output"
python3 -I - "$work/result.json" <<'PY' || status=1
import json, re, sys
text = open(sys.argv[1], errors="replace").read()
result, _ = json.JSONDecoder().raw_decode(text[text.index("{"):])
tail = (result.get("logs") or {}).get("tail", "").replace("\r", "\n")
lines = [line.strip() for line in tail.splitlines() if "SK>" in line]
print("\n".join(lines))
if result.get("status") != "succeeded":
    print("the guest run did not succeed:", result.get("status"), result.get("message"), file=sys.stderr)
    sys.exit(1)
joined = "\n".join(lines)
# The kernel lets only a process with CAP_NET_BIND_SERVICE bind a vsock port of 1023 or below.
if not re.search(r"squat-999-as-t3:.*Permission denied", joined):
    print("a non-root process could bind a privileged vsock port", file=sys.stderr)
    sys.exit(1)
# The secrets mount belongs to root: the service user must not read a job secret.
if not re.search(r"secrets-dir: 700 ", joined):
    print("/run/sandy/secrets is not mode 0700", file=sys.stderr)
    sys.exit(1)
if "sk-secret-value" not in joined.split("secret-as-root:", 1)[-1].split("\n", 1)[0]:
    print("root could not read the staged secret", file=sys.stderr)
    sys.exit(1)
if not re.search(r"secret-as-t3:.*Permission denied", joined):
    print("the service user could read a job secret", file=sys.stderr)
    sys.exit(1)
if not re.search(r"bind-2000-as-t3: alive=yes second-bind:.*Address already in use", joined):
    print("an unprivileged vsock port could not be bound as the service user", file=sys.stderr)
    sys.exit(1)
PY

if [ "$status" -eq 0 ]; then
  echo "live-vsock-bridge: OK (cid $cid)"
fi
exit "$status"
