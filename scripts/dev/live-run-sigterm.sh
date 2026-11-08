#!/usr/bin/env bash
# Live gate for #687, tier-3, never counted green from a fake (INV-S9).
#
# Boots the T3 guest under `sandy run`, sends SIGTERM (or SIGHUP) to the `sandy` process while the guest runs, or with
# KILL runs `sandy kill <job-id>` from a second process (#695), and checks that it tears down instead of dying with the default action: sandy exits on its own within the time budget,
# the job record is terminal (`cancelled`, not `running`), every process the box started is gone, and the run
# directory is removed.
#
# Needs: a Linux host with KVM and /dev/vhost-vsock access, or an Apple silicon macOS host with the aarch64-linux
# builder; nix. No root, tap or nft. Run from the repo root:
#
#   scripts/dev/live-run-sigterm.sh [TERM|HUP|KILL]
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$repo_root"
signal=${1:-TERM}
how="SIG$signal"
[ "$signal" = KILL ] && how="sandy kill"
case "$signal" in TERM | HUP | KILL) ;; *)
  echo "usage: $0 [TERM|HUP|KILL]" >&2
  exit 2
  ;;
esac

case "$(uname -s)" in
Linux)
  if [ ! -r /dev/vhost-vsock ] || [ ! -w /dev/vhost-vsock ]; then
    echo "refusing: /dev/vhost-vsock is not accessible to this user" >&2
    exit 2
  fi
  guest_runner=packages.x86_64-linux.guest-runner-t3
  topology=topologies.x86_64-linux.qemu-t3
  tools=(nixpkgs#qemu nixpkgs#virtiofsd)
  ;;
Darwin)
  guest_runner=packages.aarch64-darwin.guest-runner-vfkit-t3
  topology=topologies.aarch64-linux.vfkit-t3
  tools=(nixpkgs#vfkit)
  ;;
*)
  echo "refusing: this gate needs a Linux KVM host or an Apple silicon macOS host" >&2
  exit 2
  ;;
esac

# Short, fixed base: a unix socket path holds at most 108 bytes.
work=$(mktemp -d /tmp/slt.XXXXXX)
chmod 0700 "$work"
mkdir -p "$work/home"
pids=""
launcher=""
# A process and everything it started: the launcher is `nix shell` around `sandy`, around the hypervisor.
kill_tree() {
  local child
  for child in $(pgrep -P "$1" 2>/dev/null || true); do kill_tree "$child"; done
  kill -9 "$1" 2>/dev/null || true
}
cleanup() {
  # Stop the launcher first, so a gate that gave up early leaves no sandy or nix eval running on a deleted work dir.
  if [ -n "$launcher" ]; then kill_tree "$launcher"; fi
  for pid in $pids; do
    case "$(ps -o comm= -p "$pid" 2>/dev/null || true)" in
    qemu-system* | virtiofsd | sandy-egress-pr* | */vfkit | */sandy-egress-proxy) kill -9 "$pid" 2>/dev/null || true ;;
    esac
  done
  pkill -9 -f -- "$work/" 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

target_dir=$(cargo metadata --format-version 1 --no-deps | python3 -I -c 'import json, sys; print(json.load(sys.stdin)["target_directory"])')
echo "== building sandy and the egress proxy"
cargo build -q -p sandy-cli --bin sandy
cargo build -q -p sandy-egress-proxy
echo "== building the T3 guest"
nix build --no-link "$repo_root/nix/guest#$guest_runner"

echo "== starting the guest"
(
  # A stub named by SANDY_QEMU_BIN, SANDY_VIRTIOFSD_BIN or SANDY_VFKIT_BIN must never stand in for the hypervisor.
  env -u SANDY_QEMU_BIN -u SANDY_VIRTIOFSD_BIN -u SANDY_VFKIT_BIN TMPDIR="$work" SANDY_HOME="$work/home" SANDY_EGRESS=proxy \
    SANDY_EGRESS_PROXY_BIN="$target_dir/debug/sandy-egress-proxy" \
    nix shell "${tools[@]}" -c \
    "$target_dir/debug/sandy" -o json run "$repo_root/nix/guest#$topology" \
    --timeout 900 --allow example.com:443 -- sleep 600 \
    >"$work/result.json" 2>"$work/stderr.log"
) &
launcher=$!

record=""
# A first run from a new checkout evaluates and builds the guest topology: allow it time.
for _ in $(seq 450); do
  record=$(find "$work/sandy" -name box.json 2>/dev/null | head -1 || true)
  if [ -n "$record" ] && [ "$(python3 -I -c 'import json, sys; print(len(json.load(open(sys.argv[1]))["procs"]))' "$record" 2>/dev/null || echo 0)" -ge 2 ]; then
    break
  fi
  record=""
  sleep 2
done
if [ -z "$record" ]; then
  echo "no box record with its processes appeared within 900 s" >&2
  tail -n 12 "$work/stderr.log" >&2 || true
  exit 1
fi
owner=$(python3 -I -c 'import json, sys; print(json.load(open(sys.argv[1]))["owner"]["pid"])' "$record")
pids=$(python3 -I -c 'import json, sys; print(" ".join(str(p["pid"]) for p in json.load(open(sys.argv[1]))["procs"]))' "$record")
rundir=$(dirname "$record")
echo "== sandy is pid $owner, the box runs: $pids"

alive() { kill -0 "$1" 2>/dev/null; }

# The box record appears when the processes start, before the guest has booted. Give the guest time to reach its
# command, so the signal lands on a running guest and not on a boot.
echo "== letting the guest boot"
sleep 40

if [ "$signal" = KILL ]; then
  # The job id is the journal record's name. `sandy kill` signals the owner and returns once the owner has finished.
  job_id=$(find "$work/home/jobs" -name '*.json' | head -1 | xargs -n1 basename | sed 's/\.json$//')
  [ -n "$job_id" ] || {
    echo "FAIL: no job record under $work/home/jobs" >&2
    exit 1
  }
  echo "== sandy kill $job_id"
  kill_rc=0
  TMPDIR="$work" SANDY_HOME="$work/home" "$target_dir/debug/sandy" -o json kill "$job_id" >"$work/kill.out" 2>"$work/kill.err" || kill_rc=$?
  if [ "$kill_rc" -ne 0 ]; then
    echo "FAIL: sandy kill exited $kill_rc: $(head -c 300 "$work/kill.err")" >&2
    exit 1
  fi
else
  echo "== sending SIG$signal"
  kill -s "$signal" "$owner"
fi
# The default action would end sandy at once. Teardown stops the guest, so allow a time budget for it.
for _ in $(seq 60); do
  alive "$owner" || break
  sleep 1
done
if alive "$owner"; then
  echo "FAIL: sandy (pid $owner) did not exit within 60 s of $how" >&2
  exit 1
fi

echo "== checking the end state"
state=$(python3 -I -c 'import glob, json, sys
recs = [json.load(open(f)) for f in glob.glob(sys.argv[1] + "/jobs/*.json")]
print(",".join(r["state"] for r in recs) or "none")' "$work/home")
if [ "$state" != "cancelled" ]; then
  echo "FAIL: the job record is '$state', not 'cancelled'" >&2
  tail -n 12 "$work/stderr.log" >&2 || true
  exit 1
fi
if [ "$signal" = KILL ]; then
  # What `sandy kill` printed must be the terminal record the owner wrote, not a stale `running` answer.
  python3 -I -c 'import glob, json, sys
sys.exit(json.load(open(sys.argv[1])) != json.load(open(glob.glob(sys.argv[2] + "/jobs/*.json")[0])))' "$work/kill.out" "$work/home" || {
    echo "FAIL: the output of sandy kill differs from the terminal journal record" >&2
    exit 1
  }
  # `sandy kill` of a live run must hand back the OWNER's record: one it wrote itself would carry no receipt.
  message=$(python3 -I -c 'import glob, json, sys
print(json.load(open(glob.glob(sys.argv[1] + "/jobs/*.json")[0]))["result"]["message"])' "$work/home")
  if [ "$message" = "cancelled by kill" ]; then
    echo "FAIL: the record was written by sandy kill, not by the run" >&2
    exit 1
  fi
fi
for pid in $pids; do
  if alive "$pid"; then
    echo "FAIL: pid $pid of the box is still running after sandy exited" >&2
    exit 1
  fi
done
if [ -d "$rundir" ]; then
  echo "FAIL: the run directory $rundir was not removed" >&2
  exit 1
fi
echo "live-run-sigterm: $how OK (record cancelled, no process left, run directory removed)"
