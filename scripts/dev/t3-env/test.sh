#!/usr/bin/env bash
# Static checks for start.sh and guest.sh: each one is a bug that cost a live run on 2026-11-07 (systemd-run
# PATH, libgit2 owner under root, --env not reaching the job command, a root-owned t3 base dir). Exit 1 on a miss.
# Usage: scripts/dev/t3-env/test.sh [path/to/start.sh]
set -u
f="${1:-$(dirname "$0")/start.sh}"
rc=0
fail() {
  echo "check: $1" >&2
  rc=1
}

bash -n "$f" || fail "start.sh does not parse"
grep -Eq '^[[:space:]]*sandy run' "$f" && fail "bare 'sandy run': systemd-run does not search the unit PATH"
grep -q '"\$SANDY_DIR/target/release/sandy" run' "$f" || fail "sandy is not called by absolute path"
grep -q -- '--setenv=SUDO_UID="\$(id -u)"' "$f" || fail "SUDO_UID is not set: libgit2 refuses the checkout as root"
grep -q -- '--env ' "$f" && fail "--env does not reach the job command: pass values as arguments"
grep -q 'guest.sh "\$NONCE"' "$f" || fail "the nonce is not passed to guest.sh as an argument"
grep -q -- '--credential external-actor' "$f" || fail "no --credential external-actor"
grep -q 'root 700' "$f" || fail "no trust-roots preflight: sandy as root refuses a user-owned directory"
g="$(dirname "$f")/guest.sh"
bash -n "$g" || fail "guest.sh does not parse"
grep -q 'install -d -o "\$owner" -g "\$owner" "\$base" "\$base/userdata"' "$g" || fail 'guest.sh does not create $base owned by the t3 user'
exit "$rc"
