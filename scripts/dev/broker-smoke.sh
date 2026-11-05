#!/usr/bin/env bash
# Starts a real sandyd and sandy-broker on this machine and drives the broker's
# environment endpoints with curl. It checks the wiring that T3 -> MCP -> broker -> sandyd
# depends on, not a VM. By default there is no launch backend, so an environment stays
# `provisioning`. With BROKER_SMOKE_READY=1 sandyd runs the insecure process backend (no
# isolation) with a stand-in service, and the environment must reach
# `ready` with a connection URL that answers, then stop answering after delete.
#
# Usage: scripts/dev/broker-smoke.sh
#   SANDYD_BIN   path to sandyd       (default: target/debug/sandyd)
#   BROKER_BIN   path to sandy-broker (default: target/debug/sandy-broker)
#   BROKER_PORT  loopback port        (default: 18787)
#   BROKER_SMOKE_READY=1  also prove an environment reaches `ready` (needs python3)
#
# Build the binaries first: cargo build -p sandyd -p sandy-broker
set -euo pipefail

sandyd_bin=${SANDYD_BIN:-target/debug/sandyd}
broker_bin=${BROKER_BIN:-target/debug/sandy-broker}
port=${BROKER_PORT:-18787}
ready_mode=${BROKER_SMOKE_READY:-0}
if [ "$ready_mode" = 1 ] && ! command -v python3 >/dev/null 2>&1; then
  echo "broker-smoke: BROKER_SMOKE_READY=1 needs python3 for the stand-in service" >&2
  exit 2
fi
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
  wait 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

token=$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')
umask 077
# The token goes to curl through a header file, not argv, so `ps` never shows it.
printf 'Authorization: Bearer %s\n' "$token" >"$work/auth"
printf '[{"id":"smoke","token_sha256":"%s","max_isolation_class":"untrusted","profiles":["dev"]}]' \
  "$(sha256_hex "$token")" >"$work/clients.json"

backend_env=()
if [ "$ready_mode" = 1 ]; then
  backend_env=(
    SANDY_ENV_BACKEND=process-insecure
    "SANDY_ENV_PROCESS_COMMAND=python3 -m http.server {port} --bind 127.0.0.1"
    "SANDY_ENV_STATE_DIR=$work/environments"
  )
fi
env ${backend_env[@]+"${backend_env[@]}"} SANDY_SOCK="$work/sandyd.sock" SANDY_DB="$work/sandyd.db" \
  "$sandyd_bin" >"$work/sandyd.log" 2>&1 &
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

fail() {
  echo "broker-smoke: FAIL: $1" >&2
  echo "--- broker.log" >&2
  cat "$work/broker.log" >&2
  echo "--- sandyd.log" >&2
  cat "$work/sandyd.log" >&2
  for log in "$work"/environments/*/service.log; do
    [ -f "$log" ] || continue
    echo "--- $log" >&2
    cat "$log" >&2
  done
  exit 1
}

"$broker_bin" --control-socket "$work/sandyd.sock" --state-dir "$work/broker" \
  --clients-file "$work/clients.json" --bind "127.0.0.1:${port}" >"$work/broker.log" 2>&1 &
broker_pid=$!
pids+=("$broker_pid")
ready=0
for _ in $(seq 1 50); do
  kill -0 "$broker_pid" 2>/dev/null || fail "sandy-broker exited during startup"
  if curl -s -o /dev/null --max-time 2 "$base/v1/jobs"; then
    ready=1
    break
  fi
  sleep 0.1
done
[ "$ready" = 1 ] || fail "sandy-broker did not answer on $base"
# A process already on the port can answer the probe; a broker that lost the bind exits soon after.
sleep 0.3
kill -0 "$broker_pid" 2>/dev/null || fail "sandy-broker exited during startup"

call() { # method path [json-body] -> prints "<status> <body>"
  local method=$1 path=$2 body=${3:-}
  if [ -n "$body" ]; then
    curl -sS --max-time 10 -w ' %{http_code}' -X "$method" -H "@$work/auth" \
      -H 'Content-Type: application/json' -d "$body" "$base$path"
  else
    curl -sS --max-time 10 -w ' %{http_code}' -X "$method" -H "@$work/auth" "$base$path"
  fi
}

status_of() { echo "${1##* }"; }
field() { echo "$1" | sed -n "s/.*\"$2\":\"\([^\"]*\)\".*/\1/p"; }

anon=$(curl -sS --max-time 10 -o /dev/null -w '%{http_code}' "$base/v1/environments") || fail "unauthenticated probe failed"
[ "$anon" = 401 ] || fail "an unauthenticated call gave $anon, not 401"

spec='{"request_id":"smoke-1","profile":"dev","lifetime":{"kind":"persistent"}}'
first=$(call POST /v1/environments "$spec") || fail "spawn call failed"
[ "$(status_of "$first")" = 202 ] || fail "spawn gave: $first"
id=$(field "$first" environment_id)
[ -n "$id" ] || fail "spawn returned no environment_id: $first"

second=$(call POST /v1/environments "$spec") || fail "retried spawn call failed"
[ "$(status_of "$second")" = 202 ] && [ "$(field "$second" environment_id)" = "$id" ] || fail "a retried spawn gave a different environment: $second"

got=$(call GET "/v1/environments/$id") || fail "get call failed"
if [ "$ready_mode" = 1 ]; then
  for _ in $(seq 1 90); do
    case "$(field "$got" state)" in
    ready) break ;;
    failed | stopped | deleted) fail "the environment ended in state $(field "$got" state) before ready: $got" ;;
    esac
    [ "$(status_of "$got")" = 200 ] || fail "get gave: $got"
    sleep 1
    got=$(call GET "/v1/environments/$id") || fail "get call failed"
  done
  [ "$(field "$got" state)" = ready ] || fail "the environment did not reach ready: $got"
  url=$(field "$got" url)
  [ -n "$url" ] || fail "a ready environment has no connection url: $got"
  curl -s -o /dev/null --max-time 5 "$url" || fail "the connection url did not answer: $url"
else
  [ "$(field "$got" state)" = provisioning ] || fail "get did not show provisioning: $got"
fi

deleted=$(call DELETE "/v1/environments/$id") || fail "delete call failed"
[ "$(field "$deleted" state)" = deleted ] || fail "delete did not end deleted: $deleted"
if [ "$ready_mode" = 1 ]; then
  # The driver converges once a second, so the stop is not instant.
  stopped=0
  for _ in $(seq 1 15); do
    if ! curl -s -o /dev/null --max-time 2 "$url"; then
      stopped=1
      break
    fi
    sleep 1
  done
  [ "$stopped" = 1 ] || fail "the service still answers 15 s after delete: $url"
  echo "broker-smoke: OK ready (environment $id reached ready at $url, answered, deleted, stopped answering)"
else
  echo "broker-smoke: OK (environment $id spawned, retried idempotently, read back, deleted)"
fi
