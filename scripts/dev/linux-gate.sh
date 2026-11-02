#!/usr/bin/env bash
# Runs the x86_64-linux Nix check attrs CI gates on (pr.yaml's Check/Test
# jobs), so a change can be verified against the real platform CI checks
# before opening a PR — not just the caller's own native platform.
#
# On x86_64 Linux, runs locally. Everywhere else, requires SANDY_LINUX_HOST:
# an ssh(1) destination from the CALLER'S OWN ssh config for the Linux host.
# This script and this repo never name that host in any committed text —
# set the alias locally, never commit one here.
#
# Usage:
#   scripts/dev/linux-gate.sh [--all] [--package]
#
#   (default)   nix build the exact checks.x86_64-linux.* attrs pr.yaml's
#               Check/Test jobs reference (derived from pr.yaml itself, so
#               this can't drift from what CI actually runs).
#   --all       nix flake check -L instead of the attr list above (also
#               covers KVM/VM checks CI doesn't gate on).
#   --package   ALSO run the publish-dry-run full verify (cargo package
#               --workspace --all-features), on top of whichever of the
#               above ran — not instead of it.
#
# On success, prints a `linux-gate: x86_64-linux OK @ <rev>` line — paste it
# into the PR body as the evidence a reviewer looks for now that Check and
# Test only run in the merge queue, not on the PR itself.
#
# Env:
#   SANDY_LINUX_HOST  your own ssh alias for the Linux host (required unless
#                     already running on x86_64 Linux)
set -euo pipefail

build_all=0
run_package=0
for arg in "$@"; do
  case "$arg" in
  --all) build_all=1 ;;
  --package) run_package=1 ;;
  *)
    echo "usage: $0 [--all] [--package]" >&2
    exit 2
    ;;
  esac
done

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$repo_root"

# `git stash create` makes a real commit object without touching the
# worktree. Fetching it remotely from a clean clone gives Nix a clean,
# non-dirty source tree — a genuinely dirty working directory is what
# triggers the infinite-recursion bug in #568, not what this does.
rev=$(git stash create || true)
rev=${rev:-$(git rev-parse HEAD)}
short_rev=${rev:0:9}
gate_ref="gate-$short_rev"

attrs() {
  grep -oE '\.#checks\.x86_64-linux\.[A-Za-z0-9_-]+' .github/workflows/pr.yaml | sed 's/^\.#//' | sort -u
}

if [ "$build_all" -eq 0 ]; then
  attr_list=$(attrs)
  if [ -z "$attr_list" ]; then
    echo "error: no checks.x86_64-linux.* attrs found in .github/workflows/pr.yaml" >&2
    echo "       (the grep pattern this script uses may be out of sync with it)" >&2
    exit 1
  fi
fi

run_local() {
  if [ "$build_all" -eq 1 ]; then
    nix flake check -L
  else
    # shellcheck disable=SC2046 # word-splitting the attr list into build args is intended
    nix build -L --no-link $(printf '.#%s\n' "$attr_list")
  fi
  if [ "$run_package" -eq 1 ]; then
    nix develop .#package -c cargo package --workspace --all-features
  fi
}

if [ "$(uname -s)" = "Linux" ] && [ "$(uname -m)" = "x86_64" ]; then
  run_local
  echo "linux-gate: x86_64-linux OK @ $short_rev"
  exit 0
fi

if [ -z "${SANDY_LINUX_HOST:-}" ]; then
  echo "error: set SANDY_LINUX_HOST to your own ssh alias for the Linux host" >&2
  echo "       (this repo never names it — resolve it from your local ssh config)" >&2
  exit 2
fi

# A literal, unexpanded `$HOME` (single-quoted): deliberately deferred to
# the remote shell, since this path must resolve against the Linux host's
# home directory, not the caller's.
remote_repo='$HOME/.cache/sandy-linux-gate/repo.git'
# shellcheck disable=SC2029 # $remote_repo's $HOME is meant to expand remotely
ssh "$SANDY_LINUX_HOST" "git init -q --bare $remote_repo 2>/dev/null || true"
# A ref name scoped to this exact rev, not a shared `gate` branch: two
# concurrent sessions (this repo runs a swarm of them) pushing at once would
# otherwise race, and one could build the other's commit while reporting its
# own rev as the evidence line. Deleted again below, success or failure.
# scp-like syntax (host:path), relative to the remote user's home — not a
# `ssh://` URL, whose `~` handling for git's transport isn't reliable.
git push --quiet --force "$SANDY_LINUX_HOST:.cache/sandy-linux-gate/repo.git" "$rev:refs/heads/$gate_ref"
cleanup() {
  # shellcheck disable=SC2029 # deliberately remote-expanded; see above
  ssh "$SANDY_LINUX_HOST" "git -C $remote_repo branch -D $gate_ref" >/dev/null 2>&1 || true
}
trap cleanup EXIT

remote_cmd() {
  # `&rev=$rev` (the full sha, not the ref name alone) pins Nix to exactly
  # this commit — belt-and-suspenders with the per-rev ref name above, and
  # what actually makes a build fail loudly instead of silently building
  # whatever another concurrent push left on the ref if one somehow reused it.
  local flake_ref="git+file://$remote_repo?ref=$gate_ref&rev=$rev"
  if [ "$build_all" -eq 1 ]; then
    echo "nix --extra-experimental-features 'nix-command flakes' flake check -L \"$flake_ref\""
  else
    # `&` in a sed replacement means "the match", so escape it or the `&rev=` pin is dropped.
    local attr_args sed_ref
    sed_ref=$(printf '%s' "$flake_ref" | sed 's/&/\\&/g')
    attr_args=$(printf '%s\n' "$attr_list" | sed "s|^|\"$sed_ref#|; s|\$|\"|" | paste -sd' ' -)
    echo "nix --extra-experimental-features 'nix-command flakes' build -L --no-link $attr_args"
  fi
  if [ "$run_package" -eq 1 ]; then
    # `cargo package` needs a real on-disk checkout (unlike `nix build`,
    # which resolves a git+file ref internally) — clone the pushed ref into
    # a scratch dir on the remote and run there, cleaned up after.
    echo "tmp=\$(mktemp -d) && git clone --quiet --branch $gate_ref $remote_repo \"\$tmp\" && (cd \"\$tmp\" && nix --extra-experimental-features 'nix-command flakes' develop .#package -c cargo package --workspace --all-features); rc=\$?; rm -rf \"\$tmp\"; exit \$rc"
  fi
}

# shellcheck disable=SC2029 # remote_cmd's own $remote_repo already carries a remote-expanded $HOME
ssh "$SANDY_LINUX_HOST" "$(remote_cmd)"
echo "linux-gate: x86_64-linux OK @ $short_rev"
