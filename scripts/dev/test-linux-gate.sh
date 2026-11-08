#!/usr/bin/env bash
# Regression test for scripts/dev/linux-gate.sh (#611): a failing remote build must fail the gate even when a
# later step (--package) passes, and a passing build must still print the OK line. ssh and nix are stubs; the
# remote home is a scratch dir. Usage: scripts/dev/test-linux-gate.sh
set -euo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
tmp=$(mktemp -d)
trap 'chmod -R u+w "$tmp"; rm -rf "$tmp"' EXIT
mkdir "$tmp/bin" "$tmp/home"

# The fake ssh runs the remote command locally from the fake home. git push uses it too (GIT_SSH).
cat >"$tmp/bin/ssh" <<'STUB'
#!/bin/sh
shift
cd "$HOME"
exec sh -c "$1"
STUB
cat >"$tmp/bin/nix" <<'STUB'
#!/bin/sh
case "$*" in
*" build "*) exit "${STUB_NIX_BUILD_RC:-0}" ;;
*) exit 0 ;;
esac
STUB
# Report a non-Linux host so the script takes its ssh path on every platform, the KVM host included.
cat >"$tmp/bin/uname" <<'STUB'
#!/bin/sh
case "$1" in
-m) echo arm64 ;;
*) echo Darwin ;;
esac
STUB
# Fake the scratch clone of the --package step, so it passes on every filesystem and a masked build failure is
# the only thing that can make the old script exit 0.
real_git=$(command -v git)
cat >"$tmp/bin/git" <<STUB
#!/bin/sh
if [ "\$1" = clone ]; then
  for last; do :; done
  mkdir -p "\$last"
  exit 0
fi
exec "$real_git" "\$@"
STUB
chmod +x "$tmp/bin/ssh" "$tmp/bin/nix" "$tmp/bin/uname" "$tmp/bin/git"

# $1: the stub build's exit status; the rest: linux-gate.sh arguments.
run_gate() {
  local rc=$1
  shift
  (cd "$repo" && HOME="$tmp/home" GIT_SSH_COMMAND="$tmp/bin/ssh" PATH="$tmp/bin:$PATH" SANDY_LINUX_HOST=fake \
    STUB_NIX_BUILD_RC="$rc" bash scripts/dev/linux-gate.sh "$@" 2>&1) || return $?
}

if out=$(run_gate 1 --package); then
  echo "FAIL: a failed build step still exited 0" >&2
  exit 1
fi
if grep -q 'linux-gate: x86_64-linux OK' <<<"$out"; then
  echo "FAIL: a failed build step printed the OK line" >&2
  exit 1
fi
out=$(run_gate 0) || {
  echo "FAIL: a passing gate exited non-zero: $out" >&2
  exit 1
}
grep -q 'linux-gate: x86_64-linux OK' <<<"$out" || {
  echo "FAIL: a passing gate did not print the OK line" >&2
  exit 1
}
echo "test-linux-gate: OK"
