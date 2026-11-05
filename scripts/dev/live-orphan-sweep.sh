#!/usr/bin/env bash
# Live gate for #666, tier-3, never counted green from a fake (INV-S9).
#
# Boots the T3 guest under `sandy run` with an input share and the egress proxy, so qemu, virtiofsd and the proxy all
# run. Then it:
#   1. runs the start-up sweep while the host process is alive, both directly and as `sandy run` makes it, and checks
#      that it touches nothing;
#   2. SIGKILLs the host process and checks that qemu, virtiofsd and the proxy are still running (the orphans);
#   3. starts another `sandy run` and checks that its sweep stops every one of them and removes the run directory.
#
# Needs: a Linux host with KVM and /dev/vhost-vsock access, nix. No root, tap or nft. Run from the repo root:
#
#   scripts/dev/live-orphan-sweep.sh
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$repo_root"

if [ "$(uname -s)" != "Linux" ]; then
  echo "refusing: the orphan sweep gate needs a Linux KVM host" >&2
  exit 2
fi
if [ ! -r /dev/vhost-vsock ] || [ ! -w /dev/vhost-vsock ]; then
  echo "refusing: /dev/vhost-vsock is not accessible to this user" >&2
  exit 2
fi

# Short, fixed base: a unix socket path holds at most 108 bytes.
work=$(mktemp -d /tmp/slo.XXXXXX)
chmod 0700 "$work"
mkdir -p "$work/home"
printf 'data' >"$work/in.txt"
pids=""
cleanup() {
  # Whatever the gate left running: only a recorded pid whose command is one of ours. Before the gate has read a record
  # (an early exit), take the pids from whatever records exist: the proxy's command line holds no work dir to match.
  if [ -z "$pids" ]; then
    pids=$(python3 -I -c 'import json, sys; print(" ".join(str(p["pid"]) for f in sys.argv[1:] for p in json.load(open(f))["procs"]))' "$work"/sandy/*/box.json 2>/dev/null || true)
  fi
  for pid in $pids; do
    case "$(ps -o comm= -p "$pid" 2>/dev/null || true)" in
    qemu-system* | virtiofsd | sandy-egress-pr*) kill -9 "$pid" 2>/dev/null || true ;;
    esac
  done
  pkill -9 -f -- "$work/" 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

target_dir=$(cargo metadata --format-version 1 --no-deps | python3 -I -c 'import json, sys; print(json.load(sys.stdin)["target_directory"])')
echo "== building sandy, the egress proxy and the sweep"
cargo build -q -p sandy-cli --bin sandy
cargo build -q -p sandy-egress-proxy
cargo build -q -p sandy-impls-vm --example sweep_orphans
echo "== building the T3 guest"
nix build --no-link "$repo_root/nix/guest#packages.x86_64-linux.guest-runner-t3"

# The sweep as `sandy run` makes it (#666): the first thing a run does, before it goes on with its template. A template
# that does not exist ends the run within seconds, so only the sweep has any effect.
sweep_by_run() {
  run_rc=0
  TMPDIR="$work" SANDY_HOME="$work/home" "$target_dir/debug/sandy" -o json run no-such-template --timeout 5 -- true \
    >"$work/sweep-run.json" 2>"$work/sweep-run.log" || run_rc=$?
}

# The run must have got past its sweep and failed at its template (exit 3, an infra fault naming the nix eval), not
# crashed before or inside the sweep. Without this, a run that never reached the sweep would pass step 1.
ran_past_the_sweep() {
  [ "$run_rc" -eq 3 ] && grep -q 'nix eval no-such-template' "$work/sweep-run.json"
}

sweep() {
  TMPDIR="$work" "$target_dir/debug/examples/sweep_orphans"
}

echo "== starting the guest"
(
  # A stub named by SANDY_QEMU_BIN or SANDY_VIRTIOFSD_BIN must never stand in for the hypervisor: this gate is only
  # live with the real one (INV-S9).
  env -u SANDY_QEMU_BIN -u SANDY_VIRTIOFSD_BIN TMPDIR="$work" SANDY_HOME="$work/home" SANDY_EGRESS=proxy \
    SANDY_EGRESS_PROXY_BIN="$target_dir/debug/sandy-egress-proxy" \
    nix shell nixpkgs#qemu nixpkgs#virtiofsd -c \
    "$target_dir/debug/sandy" -o json run "$repo_root/nix/guest#topologies.x86_64-linux.qemu-t3" \
    --timeout 900 --allow example.com:443 --input "$work/in.txt:in.txt" -- sleep 600 \
    >"$work/result.json" 2>"$work/stderr.log"
) &

# The record names the owner (the sandy process) and every process the box started: qemu, virtiofsd, the proxy.
record=""
owner=""
for _ in $(seq 150); do
  record=$(ls "$work"/sandy/*/box.json 2>/dev/null | head -1 || true)
  if [ -n "$record" ]; then
    count=$(python3 -I -c 'import json, sys; print(len(json.load(open(sys.argv[1]))["procs"]))' "$record" 2>/dev/null || echo 0)
    [ "$count" -ge 3 ] && break
  fi
  sleep 2
done
if [ -z "$record" ] || [ "${count:-0}" -lt 3 ]; then
  echo "no box record naming qemu, virtiofsd and the proxy appeared within 300 s" >&2
  tail -n 12 "$work/stderr.log" >&2 || true
  exit 1
fi
owner=$(python3 -I -c 'import json, sys; print(json.load(open(sys.argv[1]))["owner"]["pid"])' "$record")
pids=$(python3 -I -c 'import json, sys; print(" ".join(str(p["pid"]) for p in json.load(open(sys.argv[1]))["procs"]))' "$record")
rundir=$(dirname "$record")
echo "== record names owner $owner and processes: $pids"

alive() { kill -0 "$1" 2>/dev/null; }

echo "== 1. a sweep while the owner is alive touches nothing"
report=$(sweep)
echo "$report"
case "$report" in *"killed: 0"*"live_owner: 1"*) ;; *)
  echo "FAIL: the sweep must leave a live owner's box alone" >&2
  exit 1
  ;;
esac
for pid in $pids; do alive "$pid" || {
  echo "FAIL: pid $pid died during a sweep with a live owner" >&2
  exit 1
}; done
[ -d "$rundir" ] || {
  echo "FAIL: the run directory was removed during a sweep with a live owner" >&2
  exit 1
}
sweep_by_run
ran_past_the_sweep || {
  echo "FAIL: sandy run did not get past its sweep (exit $run_rc): $(head -c 300 "$work/sweep-run.log")" >&2
  exit 1
}
if grep -q 'swept the VMs' "$work/sweep-run.log"; then
  echo "FAIL: sandy run reported a sweep while the owner was alive: $(cat "$work/sweep-run.log")" >&2
  exit 1
fi
for pid in $pids; do alive "$pid" || {
  echo "FAIL: pid $pid died when sandy run swept with a live owner" >&2
  exit 1
}; done
[ -d "$rundir" ] || {
  echo "FAIL: sandy run removed the run directory of a box whose owner is alive" >&2
  exit 1
}

echo "== 2. SIGKILL the owner: its VM is orphaned"
kill -9 "$owner"
sleep 2
alive "$owner" && {
  echo "FAIL: the owner survived SIGKILL" >&2
  exit 1
}
for pid in $pids; do alive "$pid" || {
  echo "FAIL: pid $pid exited with its owner, so there was no orphan to sweep" >&2
  exit 1
}; done
[ -d "$rundir" ] || {
  echo "FAIL: the run directory vanished with its owner" >&2
  exit 1
}

echo "== 3. sandy run sweeps: it stops them and removes the run directory"
sweep_by_run
ran_past_the_sweep || {
  echo "FAIL: sandy run did not get past its sweep (exit $run_rc): $(head -c 300 "$work/sweep-run.log")" >&2
  exit 1
}
# The run itself says what it did: the three processes (qemu, virtiofsd, the proxy) and the one box.
grep -q 'swept the VMs a killed host left behind: 3 process(es) stopped, 1 box(es) removed' "$work/sweep-run.log" || {
  echo "FAIL: sandy run did not report its sweep: $(cat "$work/sweep-run.log")" >&2
  exit 1
}
echo "$(grep 'swept the VMs' "$work/sweep-run.log")"
for _ in $(seq 20); do
  left=""
  for pid in $pids; do alive "$pid" && left="$left $pid"; done
  [ -z "$left" ] && break
  sleep 0.5
done
[ -z "$left" ] || {
  echo "FAIL: still running after the sweep:$left" >&2
  exit 1
}
[ ! -d "$rundir" ] || {
  echo "FAIL: the run directory is still there after the sweep" >&2
  exit 1
}
# Nothing is left for the direct sweep to find.
report=$(sweep)
echo "$report"
case "$report" in *"killed: 0, wiped: 0, live_owner: 0, unreadable: 0, undecided: 0"*) ;; *)
  echo "FAIL: a sweep after sandy run's still found something: $report" >&2
  exit 1
  ;;
esac
echo "live-orphan-sweep: OK"
