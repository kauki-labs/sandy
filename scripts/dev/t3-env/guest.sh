#!/usr/bin/env bash
# Guest side of t3-sandy, run as the sandy job command: seed the harness config, start `t3 serve` as the
# t3 user, mint a one-time pairing code once it answers, and publish the code over plain http on
# 3774 at /<nonce> for the host to fetch. The guest has no ssh, no mesh and no console the host can
# read before the job ends, so this is the only channel. The nonce (T3_NONCE, from the wrapper) is the
# file name, so a request for any other path gets a 404. The job lives as long as `t3 serve`.
set -eu
home="${T3_HOME:-/var/lib/t3}"
owner="${T3_USER:-t3}"
base="$home/.t3"
port="${T3_PORT:-3773}"
codeport="${T3_CODE_PORT:-3774}"
# sandy's --env does not reach the job command (seen live: T3_NONCE unset), so the nonce is argument 1.
nonce="${1:-${T3_NONCE:-}}"
[ -n "$nonce" ] || {
  echo "guest.sh: no nonce: pass it as argument 1" >&2
  exit 2
}
bb="${T3_BUSYBOX:-/run/sandy/inputs/busybox}"
www="${T3_CODE_DIR:-/run/t3-code}"
case "$nonce" in "" | *[!0-9a-f]*)
  echo "guest.sh: T3_NONCE must be lowercase hex" >&2
  exit 2
  ;;
esac

# install -d gives the owner only to the leaf; a root-owned $base made t3 fail with EACCES on $base/worktrees.
install -d -o "$owner" -g "$owner" "$base" "$base/userdata"
[ -e "$home/.claude.json" ] || printf '{"hasCompletedOnboarding":true}\n' >"$home/.claude.json"
[ -e "$base/userdata/settings.json" ] || printf '{"linkedEnvironmentsEnabled":true}\n' >"$base/userdata/settings.json"
chown "$owner:$owner" "$home/.claude.json" "$base/userdata/settings.json"

as_t3() { runuser -u "$owner" -- env HOME="$home" GITHUB_TOKEN="${GITHUB_TOKEN:-}" GH_TOKEN="${GITHUB_TOKEN:-}" "$@"; }

as_t3 t3 serve --host 0.0.0.0 --port "$port" --base-dir "$base" &
server=$!
# Leave nothing behind when the script stops early; the job ends with the guest anyway.
trap 'kill $(jobs -p) 2>/dev/null || true' EXIT

ready=0
for _ in $(seq 180); do
  sandy-t3-ready "$port" && {
    ready=1
    break
  }
  kill -0 "$server" 2>/dev/null || {
    echo "guest.sh: t3 serve exited before it answered" >&2
    exit 1
  }
  "$bb" sleep 1
done
[ "$ready" = 1 ] || {
  echo "guest.sh: t3 serve did not answer in 180 s" >&2
  exit 1
}

# `t3 auth pairing create` prints "Token: <code>"; older builds only have `t3 pair`. Take the first
# plain token from the first command that prints one.
code=""
for cmd in "auth pairing create --ttl 5m --label sandy" "pair"; do
  # shellcheck disable=SC2086 # the words of $cmd are separate arguments on purpose
  out=$(as_t3 t3 $cmd --base-dir "$base" 2>&1) || continue
  cand=$(printf '%s\n' "$out" | sed -n 's/^Token: *//p' | head -n1)
  [ -n "$cand" ] || cand=$(printf '%s\n' "$out" | tail -n1)
  if printf '%s' "$cand" | grep -Eq '^[A-Za-z0-9_-]{6,128}$'; then
    code="$cand"
    break
  fi
done
[ -n "$code" ] || {
  echo "guest.sh: could not mint a pairing code" >&2
  exit 1
}

install -d -m 0755 "$www"
printf '%s\n' "$code" >"$www/$nonce"
"$bb" httpd -f -p "$codeport" -h "$www" &
httpd=$!
# The code lives five minutes; stop offering it then.
(
  "$bb" sleep 300
  rm -f "$www/$nonce"
  kill "$httpd" 2>/dev/null
) &

wait "$server"
