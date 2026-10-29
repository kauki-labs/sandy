#!/usr/bin/env bash
# Cross-machine smoke test (docs/design/host-executor/spec.md's manual
# walkthrough, scripted): starts sandyd locally with a mesh listener, syncs
# this checkout to a remote host and starts sandy-host-executor there over
# SSH, submits a long-running argv/v1 job, and attaches to it. The
# orchestrator runs anywhere (macOS or Linux); the executor is
# NixOS-specific (its trusted-process sandbox is bwrap + systemd-run --user).
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
#   EXECUTOR_REMOTE_DIR  remote checkout path. Default: a fresh directory
#                        from the executor's own `mktemp -d`, removed on
#                        exit — safe for concurrent runs against the same
#                        executor, and immune to a predictable-path race
#                        (CWE-377). Set this to reuse (and wipe-before-sync)
#                        a persistent path instead.
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
remote_dir_is_default=1
remote_dir=${EXECUTOR_REMOTE_DIR:-}
[ -z "$remote_dir" ] || remote_dir_is_default=
host_id=${EXECUTOR_HOST_ID:-${executor_ssh##*@}}

command -v jq >/dev/null 2>&1 || {
  echo "$0: jq is required (parses the submit/attach JSON)" >&2
  exit 2
}

sandyd_log=$(mktemp -t sandyd-smoke.XXXXXX.log)
manifest=$(mktemp -t sandy-manifest.XXXXXX.json)
filelist=$(mktemp -t sandy-smoke-files.XXXXXX)
job_id=
sandyd_pid=
executor_pid=

# Order matters: the executor's own SIGTERM handler cancels any still-running
# job's RunControl before it exits (#369) — stopping it first, and waiting for
# it to actually exit, is what ends the dispatched command. Stopping sandyd
# first would leave the executor to take its Closed path instead, which does
# not cancel anything. Only this run's own recorded PID is ever signaled, not
# a name/pattern match that could hit an unrelated process on the SSH host.
cleanup() {
  local rc=$?
  echo "==> cleaning up" >&2
  if [ -n "$job_id" ]; then
    # Cancel needs the job's attach token (#540); a refusal leaves the job running, so say so.
    SANDY_SOCK="$sock" "$repo_root/target/debug/sandy" daemon cancel "$job_id" >/dev/null 2>&1 ||
      echo "warning: cancel of job $job_id failed or was refused; it may still be running" >&2
  fi
  if [ -n "$executor_pid" ]; then
    ssh "$executor_ssh" "kill -TERM '$executor_pid'" >/dev/null 2>&1 || true
    for _ in $(seq 1 30); do
      ssh "$executor_ssh" "kill -0 '$executor_pid'" >/dev/null 2>&1 || break
      sleep 1
    done
  fi
  [ -z "$sandyd_pid" ] || kill "$sandyd_pid" >/dev/null 2>&1 || true
  # Only the auto-generated per-run dir is removed — an explicit
  # EXECUTOR_REMOTE_DIR is a persistent path the caller chose to reuse.
  [ -z "$remote_dir_is_default" ] || ssh "$executor_ssh" "rm -rf '$remote_dir'" >/dev/null 2>&1 || true
  rm -f "$sock" "$manifest" "$sandyd_log" "$filelist"
  [ -z "${orchestrator_tls_dir:-}" ] || rm -rf "$orchestrator_tls_dir"
  exit "$rc"
}
trap cleanup EXIT

echo "==> building sandyd + sandy locally" >&2
(cd "$repo_root" && nix develop -c cargo build -p sandyd -p sandy-cli)

if [ -n "$remote_dir_is_default" ]; then
  # Remote mktemp -d: atomic and unpredictably named, unlike a PID-based path
  # with a separate rm/mkdir — that race lets another local user on the
  # executor host plant a symlink at the predictable name between the two
  # (CWE-377), redirecting the sync and build onto attacker-controlled files.
  remote_dir=$(ssh "$executor_ssh" "mktemp -d -t sandy-smoke-XXXXXX")
else
  # An explicit, reused EXECUTOR_REMOTE_DIR: wipe it fresh before syncing.
  # `rsync --delete --files-from` only prunes among the listed paths, so a
  # file dropped from git tracking since an earlier run against this same
  # path could otherwise linger there indefinitely, defeating the
  # git-ls-files filter below for exactly the stale leftover case it exists
  # to prevent.
  ssh "$executor_ssh" "rm -rf '$remote_dir' && mkdir -p '$remote_dir'"
fi
echo "==> syncing this checkout to $executor_ssh:$remote_dir" >&2
# Only git-tracked files: rsyncing the whole tree (even with excludes) drops
# .git, so Nix treats the remote dir as a non-git path: flake that ignores
# .gitignore entirely — an untracked secret (.env, a local credential file)
# would otherwise ship into the remote build's flake source verbatim.
git -C "$repo_root" ls-files -z >"$filelist"
rsync -az --from0 --files-from="$filelist" "$repo_root/" "$executor_ssh:$remote_dir/"

echo "==> building sandy-agent + sandy-host-executor + sandy remotely" >&2
agent_store_path=$(ssh "$executor_ssh" "cd '$remote_dir' && nix build .#sandy-agent --no-link --print-out-paths")
agent_path="$agent_store_path/bin/sandy-agent"
ssh "$executor_ssh" "cd '$remote_dir' && nix develop -c cargo build -p sandy-host-executor -p sandy-cli"

# Decision 20: both mesh listeners are mutual TLS, pinned per host — mint/load
# each side's identity and exchange fingerprints before either process
# starts. `sandy mesh key generate` is idempotent (reloads an existing
# identity at DIR unchanged), so re-running this script against the same
# dirs keeps the same pinned fingerprints.
orchestrator_tls_dir=$(mktemp -d -t sandyd-mesh-tls.XXXXXX)
executor_tls_dir="$remote_dir/.sandy-mesh-tls"
echo "==> minting/loading each side's mesh TLS identity" >&2
orchestrator_fp=$(cd "$repo_root" && ./target/debug/sandy mesh key generate "$orchestrator_tls_dir")
executor_fp=$(ssh "$executor_ssh" "cd '$remote_dir' && ./target/debug/sandy mesh key generate '$executor_tls_dir'")

echo "==> starting sandyd (orchestrator: $orchestrator_ip, allowing $executor_ip)" >&2
(
  cd "$repo_root"
  SANDY_SOCK="$sock" \
    SANDY_MESH_LISTEN="$orchestrator_ip:$mesh_port" \
    SANDY_MESH_ALLOWLIST="$executor_ip=$executor_fp" \
    SANDY_MESH_AGENT_LINK_LISTEN="$orchestrator_ip:$link_port" \
    SANDY_MESH_TLS_IDENTITY_DIR="$orchestrator_tls_dir" \
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

echo "==> starting sandy-host-executor remotely (host_id=$host_id)" >&2
# setsid detaches the process from this ssh session's controlling terminal and
# stdio (already redirected below), so ssh returns as soon as it prints the
# PID instead of waiting for the long-running executor to exit.
executor_pid=$(ssh "$executor_ssh" "cd '$remote_dir' && \
  setsid nohup env \
  SANDY_AGENT_PATH='$agent_path' \
  SANDY_HOST_EXECUTOR_ORCHESTRATOR='$orchestrator_ip:$mesh_port' \
  SANDY_HOST_EXECUTOR_ID='$host_id' \
  SANDY_HOST_EXECUTOR_ORCHESTRATOR_FINGERPRINT='$orchestrator_fp' \
  SANDY_HOST_EXECUTOR_TLS_IDENTITY_DIR='$executor_tls_dir' \
  ./target/debug/sandy-host-executor </dev/null >/tmp/sandy-host-executor-smoke.log 2>&1 & echo \$!")

echo "==> waiting for the executor to register" >&2
sleep 3

cat >"$manifest" <<'EOF'
["sh", "-c", "i=0; while true; do echo tick-$i; i=$((i+1)); sleep 1; done"]
EOF

echo "==> submitting the job" >&2
submit_json=$(SANDY_SOCK="$sock" "$repo_root/target/debug/sandy" daemon submit "$manifest" --manifest-encoding argv/v1 --isolation-class trusted -o json)
job_id=$(jq -r .job_id <<<"$submit_json")
[ -n "$job_id" ] && [ "$job_id" != null ] || {
  echo "submit did not return a job_id: $submit_json" >&2
  exit 1
}
echo "==> job $job_id submitted, attaching (Ctrl-C to detach, cancel, and clean up)" >&2

SANDY_SOCK="$sock" "$repo_root/target/debug/sandy" daemon attach "$job_id"
