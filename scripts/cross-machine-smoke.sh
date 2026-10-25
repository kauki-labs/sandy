#!/usr/bin/env bash
# Cross-machine smoke test (docs/design/host-executor/spec.md's manual
# walkthrough, scripted): starts sandyd locally with a mesh listener, syncs
# this checkout to a remote host and starts sandy-host-executor there over
# SSH, submits a long-running argv/v1 job, and attaches to it. Works for any
# OS pairing — e.g. a macOS orchestrator dispatching to a Linux executor.
#
# Only three things point it at a real network: the orchestrator's (this
# machine's) mesh-visible IP, the executor's mesh-visible IP (sandyd's
# allowlist entry), and an ssh(1) target for the executor host. Everything
# else — building, syncing, starting both processes, submitting, attaching,
# and tearing down on exit (including Ctrl-C) — is handled here.
#
# Usage:
#   scripts/cross-machine-smoke.sh ORCHESTRATOR_IP EXECUTOR_IP EXECUTOR_SSH_TARGET
#
# This exercises the trusted-process path only (argv/v1 dispatch to
# sandy-host-executor) — not `sandy run --flake`'s VM dispatch, which needs a
# host that declares SandboxKind::Vm.
#
# Optional env overrides:
#   SANDY_SOCK           control socket path (default /tmp/sandyd-smoke.sock)
#   MESH_PORT            orchestrator mesh-listen port (default 4000)
#   AGENT_LINK_PORT      orchestrator agent-link port (default 4001)
#   EXECUTOR_REMOTE_DIR  remote checkout path (default /tmp/sandy-smoke-test)
#   EXECUTOR_HOST_ID     the host_id sandy-host-executor registers as
#                        (default: EXECUTOR_SSH_TARGET's host part)
set -euo pipefail

usage() {
  echo "usage: $0 ORCHESTRATOR_IP EXECUTOR_IP EXECUTOR_SSH_TARGET" >&2
  exit 2
}
[ $# -eq 3 ] || usage
orchestrator_ip=$1
executor_ip=$2
executor_ssh=$3

repo_root=$(cd "$(dirname "$0")/.." && pwd)
sock=${SANDY_SOCK:-/tmp/sandyd-smoke.sock}
mesh_port=${MESH_PORT:-4000}
link_port=${AGENT_LINK_PORT:-4001}
remote_dir=${EXECUTOR_REMOTE_DIR:-/tmp/sandy-smoke-test}
host_id=${EXECUTOR_HOST_ID:-${executor_ssh##*@}}

command -v jq >/dev/null 2>&1 || {
  echo "$0: jq is required (parses the submit/attach JSON)" >&2
  exit 2
}

sandyd_log=$(mktemp -t sandyd-smoke.XXXXXX.log)
manifest=$(mktemp -t sandy-manifest.XXXXXX.json)
job_id=
sandyd_pid=

cleanup() {
  local rc=$?
  echo "==> cleaning up" >&2
  if [ -n "$job_id" ]; then
    SANDY_SOCK="$sock" "$repo_root/target/debug/sandy" daemon cancel "$job_id" >/dev/null 2>&1 || true
  fi
  [ -z "$sandyd_pid" ] || kill "$sandyd_pid" >/dev/null 2>&1 || true
  ssh "$executor_ssh" "pkill -f 'target/debug/sandy-host-executor' || true" >/dev/null 2>&1 || true
  rm -f "$sock" "$manifest" "$sandyd_log"
  exit "$rc"
}
trap cleanup EXIT

echo "==> building sandyd + sandy locally" >&2
(cd "$repo_root" && nix develop -c cargo build -p sandyd -p sandy-cli)

echo "==> starting sandyd (orchestrator: $orchestrator_ip, allowing $executor_ip)" >&2
(
  cd "$repo_root"
  SANDY_SOCK="$sock" \
    SANDY_MESH_LISTEN="$orchestrator_ip:$mesh_port" \
    SANDY_MESH_ALLOWLIST="$executor_ip" \
    SANDY_MESH_AGENT_LINK_LISTEN="$orchestrator_ip:$link_port" \
    ./target/debug/sandyd
) >"$sandyd_log" 2>&1 &
sandyd_pid=$!

echo "==> waiting for sandyd to come up" >&2
for _ in $(seq 1 30); do
  grep -q "sandyd listening" "$sandyd_log" 2>/dev/null && break
  kill -0 "$sandyd_pid" 2>/dev/null || {
    echo "sandyd exited early:" >&2
    cat "$sandyd_log" >&2
    exit 1
  }
  sleep 1
done
grep -q "sandyd listening" "$sandyd_log" || {
  echo "sandyd never reported listening:" >&2
  cat "$sandyd_log" >&2
  exit 1
}

echo "==> syncing this checkout to $executor_ssh:$remote_dir" >&2
ssh "$executor_ssh" "mkdir -p '$remote_dir'"
rsync -az --delete \
  --exclude .git --exclude target --exclude .direnv --exclude .claude/worktrees --exclude result \
  "$repo_root/" "$executor_ssh:$remote_dir/"

echo "==> building sandy-agent + sandy-host-executor remotely" >&2
agent_store_path=$(ssh "$executor_ssh" "cd '$remote_dir' && nix build .#sandy-agent --no-link --print-out-paths")
agent_path="$agent_store_path/bin/sandy-agent"
ssh "$executor_ssh" "cd '$remote_dir' && nix develop -c cargo build -p sandy-host-executor"

echo "==> starting sandy-host-executor remotely (host_id=$host_id)" >&2
ssh -f "$executor_ssh" "cd '$remote_dir' && \
  SANDY_AGENT_PATH='$agent_path' \
  SANDY_HOST_EXECUTOR_ORCHESTRATOR='$orchestrator_ip:$mesh_port' \
  SANDY_HOST_EXECUTOR_ID='$host_id' \
  nohup ./target/debug/sandy-host-executor >/tmp/sandy-host-executor-smoke.log 2>&1 &"

echo "==> waiting for the executor to register" >&2
sleep 3

cat >"$manifest" <<'EOF'
["sh", "-c", "i=0; while true; do echo tick-$i; i=$((i+1)); sleep 1; done"]
EOF

echo "==> submitting the job" >&2
submit_json=$(SANDY_SOCK="$sock" "$repo_root/target/debug/sandy" daemon submit "$manifest" --manifest-encoding argv/v1 -o json)
job_id=$(jq -r .job_id <<<"$submit_json")
[ -n "$job_id" ] && [ "$job_id" != null ] || {
  echo "submit did not return a job_id: $submit_json" >&2
  exit 1
}
echo "==> job $job_id submitted, attaching (Ctrl-C to detach, cancel, and clean up)" >&2

SANDY_SOCK="$sock" "$repo_root/target/debug/sandy" daemon attach "$job_id"
