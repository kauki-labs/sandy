#!/usr/bin/env bash
# Starts a real sandyd and sandy-broker on this machine and drives the broker's
# environment endpoints with curl. It checks the wiring that T3 -> MCP -> broker -> sandyd
# depends on, not a VM: with no launch backend an environment stays `provisioning`.
#
# Usage: scripts/dev/broker-smoke.sh
#   SANDYD_BIN   path to sandyd       (default: target/debug/sandyd)
#   BROKER_BIN   path to sandy-broker (default: target/debug/sandy-broker)
#   BROKER_PORT  loopback port        (default: 18787)
#
# Build the binaries first: cargo build -p sandyd -p sandy-broker
set -euo pipefail

sandyd_bin=${SANDYD_BIN:-target/debug/sandyd}
broker_bin=${BROKER_BIN:-target/debug/sandy-broker}
port=${BROKER_PORT:-18787}
base="http://127.0.0.1:${port}"

for bin in "$sandyd_bin" "$broker_bin"; do
  [ -x "$bin" ] || {
    echo "broker-smoke: $bin is not executable; build it first" >&2
    exit 2
  }
done

sha256_hex() {
  if command -v sha256sum >/dev/null 2>&1; then
    printf %s "$1" | sha256sum | cut -d' ' -f1
  else
    printf %s "$1" | shasum -a 256 | cut -d' ' -f1
  fi
}

work=$(mktemp -d)
pids=()
cleanup() {
  for pid in "${pids[@]:-}"; do
    [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
  done
  rm -rf "$work"
}
trap cleanup EXIT

token=$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')
umask 077
printf '[{"id":"smoke","token_sha256":"%s","max_isolation_class":"untrusted","profiles":["dev"]}]' \
  "$(sha256_hex "$token")" >"$work/clients.json"

SANDY_SOCK="$work/sandyd.sock" SANDY_DB="$work/sandyd.db" "$sandyd_bin" >"$work/sandyd.log" 2>&1 &
pids+=($!)
for _ in $(seq 1 50); do
  [ -S "$work/sandyd.sock" ] && break
  sleep 0.1
done
[ -S "$work/sandyd.sock" ] || {
  echo "broker-smoke: sandyd did not create its socket" >&2
  cat "$work/sandyd.log" >&2
  exit 1
}

"$broker_bin" --control-socket "$work/sandyd.sock" --state-dir "$work/broker" \
  --clients-file "$work/clients.json" --bind "127.0.0.1:${port}" >"$work/broker.log" 2>&1 &
pids+=($!)
for _ in $(seq 1 50); do
  curl -s -o /dev/null "$base/v1/jobs" && break
  sleep 0.1
done

fail() {
  echo "broker-smoke: FAIL: $1" >&2
  echo "--- broker.log" >&2
  cat "$work/broker.log" >&2
  exit 1
}

call() { # method path [json-body] -> prints "<status> <body>"
  local method=$1 path=$2 body=${3:-}
  if [ -n "$body" ]; then
    curl -s -w ' %{http_code}' -X "$method" -H "Authorization: Bearer $token" \
      -H 'Content-Type: application/json' -d "$body" "$base$path"
  else
    curl -s -w ' %{http_code}' -X "$method" -H "Authorization: Bearer $token" "$base$path"
  fi
}

status_of() { echo "${1##* }"; }
field() { echo "$1" | sed -n "s/.*\"$2\":\"\([^\"]*\)\".*/\1/p"; }

anon=$(curl -s -o /dev/null -w '%{http_code}' "$base/v1/environments")
[ "$anon" = 401 ] || fail "an unauthenticated call gave $anon, not 401"

spec='{"request_id":"smoke-1","profile":"dev","lifetime":{"kind":"persistent"}}'
first=$(call POST /v1/environments "$spec")
[ "$(status_of "$first")" = 202 ] || fail "spawn gave: $first"
id=$(field "$first" environment_id)
[ -n "$id" ] || fail "spawn returned no environment_id: $first"

second=$(call POST /v1/environments "$spec")
[ "$(field "$second" environment_id)" = "$id" ] || fail "a retried spawn gave a different environment: $second"

got=$(call GET "/v1/environments/$id")
[ "$(field "$got" state)" = provisioning ] || fail "get did not show provisioning: $got"

deleted=$(call DELETE "/v1/environments/$id")
[ "$(field "$deleted" state)" = deleted ] || fail "delete did not end deleted: $deleted"

echo "broker-smoke: OK (environment $id spawned, retried idempotently, read back, deleted)"
