#!/usr/bin/env bash
# Runs the x86_64-linux Nix check attrs CI gates on (pr.yaml's Check/Test
# jobs), so a change can be verified against the real platform CI checks
# before opening a PR — not just the caller's own native platform.
#
# On x86_64 Linux, runs locally. Everywhere else, requires SANDY_LINUX_HOST:
# an ssh(1) destination from the CALLER'S OWN ssh config for the Linux host.
# This script and this repo never name that host — set the alias locally,
# never commit one here.
#
# Usage:
#   scripts/dev/linux-gate.sh [--all] [--package]
#
#   (default)   nix build the exact checks.x86_64-linux.* attrs pr.yaml's
#               Check/Test jobs reference (derived from pr.yaml itself, so
#               this can't drift from what CI actually runs).
#   --all       nix flake check -L instead (also covers KVM/VM checks CI
#               doesn't gate on).
#   --package   additionally run the publish-dry-run full verify
#               (cargo package --workspace --all-features).
#
# On success, prints a `linux-gate: x86_64-linux OK @ <rev>` line — paste it
# into the PR body as the evidence a reviewer looks for now that Check and
# Test only run in the merge queue, not on the PR itself.
#
# Env:
#   SANDY_LINUX_HOST  your own ssh alias for the Linux host (required unless
#                     already running on x86_64 Linux)
set -euo pipefail

mode=attrs
for arg in "$@"; do
  case "$arg" in
  --all) mode=all ;;
  --package) mode=package ;;
  *)
    echo "usage: $0 [--all] [--package]" >&2
    exit 2
    ;;
  esac
done

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$repo_root"

rev=$(git stash create || true)
rev=${rev:-$(git rev-parse HEAD)}
short_rev=${rev:0:9}
# `git stash create` makes a real commit object without touching the
# worktree. Fetching it remotely as `git+file://...?ref=gate` gives Nix a
# clean, non-dirty source tree — a genuinely dirty working directory is
# what triggers the infinite-recursion bug in #568, not what this does.

attrs() {
  grep -oE '\.#checks\.x86_64-linux\.[A-Za-z0-9_-]+' .github/workflows/pr.yaml | sed 's/^\.#//' | sort -u
}

run_local() {
  case "$mode" in
  attrs)
    # shellcheck disable=SC2046 # word-splitting into build args is intended
    nix build -L --no-link $(attrs | sed 's/^/\.#/')
    ;;
  all) nix flake check -L ;;
  package) nix develop .#package -c cargo package --workspace --all-features ;;
  esac
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
# scp-like syntax (host:path), relative to the remote user's home — not a
# `ssh://` URL, whose `~` handling for git's transport isn't reliable.
git push --quiet --force "$SANDY_LINUX_HOST:.cache/sandy-linux-gate/repo.git" "$rev:refs/heads/gate"

remote_cmd() {
  case "$mode" in
  attrs)
    local attr_list
    attr_list=$(attrs | sed "s|^|\"git+file://$remote_repo?ref=gate#|; s|\$|\"|" | paste -sd' ' -)
    echo "nix --extra-experimental-features 'nix-command flakes' build -L --no-link $attr_list"
    ;;
  all)
    echo "nix --extra-experimental-features 'nix-command flakes' flake check -L \"git+file://$remote_repo?ref=gate\""
    ;;
  package)
    echo "nix --extra-experimental-features 'nix-command flakes' develop \"git+file://$remote_repo?ref=gate#package\" -c cargo package --workspace --all-features"
    ;;
  esac
}

# shellcheck disable=SC2029 # remote_cmd's own $remote_repo already carries a remote-expanded $HOME
ssh "$SANDY_LINUX_HOST" "$(remote_cmd)"
echo "linux-gate: x86_64-linux OK @ $short_rev"
