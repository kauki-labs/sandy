#!/usr/bin/env bash
# Live gate for #609 (epic #597), tier-3, never counted green from a fake (INV-S9).
#
# Boots the T3 guest (nix/guest, topology qemu-t3) on a Linux KVM host in egress-proxy mode and shows that the
# harness binaries t3 launches (`claude`, `codex`) reach their provider through the guest's proxy relay
# (`HTTPS_PROXY=http://127.0.0.1:3128`), and that a host off the allow-list does not get through. The guest has no NIC,
# so a request that reaches the provider can only have gone through the proxy. The harnesses get a fake key: the
# provider's own 401 is the proof that the request arrived.
#
# Needs: a Linux host with KVM and /dev/vhost-vsock access, nix. No root, tap or nft, no real credential. Run from the
# repo root:
#
#   scripts/dev/live-harness-proxy.sh
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$repo_root"

if [ "$(uname -s)" != "Linux" ]; then
  echo "refusing: the harness proxy gate needs a Linux KVM host" >&2
  exit 2
fi
if [ ! -r /dev/vhost-vsock ] || [ ! -w /dev/vhost-vsock ]; then
  echo "refusing: /dev/vhost-vsock is not accessible to this user" >&2
  exit 2
fi

# Short, fixed base: a unix socket path holds at most 108 bytes (see live-vsock-bridge.sh).
work=$(mktemp -d /tmp/slb.XXXXXX)
chmod 0700 "$work"
mkdir -p "$work/home"
cleanup() {
  # qemu and virtiofsd are plain children of sandy; every one of them carries this run's private work dir.
  pkill -f -- "$work/" 2>/dev/null || true
  for _ in $(seq 20); do
    pgrep -f -- "$work/" >/dev/null 2>&1 || break
    sleep 0.5
  done
  pkill -9 -f -- "$work/" 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

cat >"$work/guest.sh" <<'GUEST'
set -u
claude=$(ls -d /nix/store/*-claude-code-*/bin/claude 2>/dev/null | head -1)
codex=$(ls -d /nix/store/*-codex-*/bin/codex 2>/dev/null | head -1)
mkdir -p /tmp/h/c /tmp/h/x
echo "SK> env: HTTPS_PROXY=${HTTPS_PROXY:-unset}"
# No NIC: the only way out is the proxy relay, which is what makes a provider reply a proof of the proxy.
echo "SK> netdevs: $(ls /sys/class/net | tr '\n' ' ')"
echo "SK> binaries: claude=${claude:+yes} codex=${codex:+yes}"
echo "SK> curl-allowed: $(timeout 30 curl -sS -o /dev/null -w '%{http_code}' https://api.anthropic.com/ 2>&1 | tail -c 200)"
echo "SK> curl-denied: $(timeout 30 curl -sS -o /dev/null -w '%{http_code}' https://example.org/ 2>&1 | tail -c 200)"
echo "SK> claude-allowed: $(cd /tmp && HOME=/tmp/h CLAUDE_CONFIG_DIR=/tmp/h/c ANTHROPIC_API_KEY=sk-ant-fake timeout 60 "$claude" -p hi 2>&1 | tail -c 300 | tr '\n' ' ')"
echo "SK> codex-allowed: $(cd /tmp && HOME=/tmp/h CODEX_HOME=/tmp/h/x OPENAI_API_KEY=sk-fake timeout 60 "$codex" exec --skip-git-repo-check hi 2>&1 | tail -c 300 | tr '\n' ' ')"
(cd /tmp && HOME=/tmp/h CLAUDE_CONFIG_DIR=/tmp/h/c ANTHROPIC_API_KEY=sk-ant-fake ANTHROPIC_BASE_URL=https://example.org timeout 60 "$claude" -p hi >/tmp/denied.log 2>&1)
denied_rc=$?
echo "SK> claude-denied: rc=$denied_rc $(tail -c 300 /tmp/denied.log | tr '\n' ' ')"
echo "SK> done: yes"
GUEST

echo "== building sandy and the egress proxy"
cargo build -q -p sandy-cli --bin sandy
cargo build -q -p sandy-egress-proxy

echo "== building the T3 guest"
nix build --no-link "$repo_root/nix/guest#packages.x86_64-linux.guest-runner-t3"

echo "== running the guest"
status=0
TMPDIR="$work" SANDY_HOME="$work/home" SANDY_EGRESS=proxy \
  SANDY_EGRESS_PROXY_BIN="$repo_root/target/debug/sandy-egress-proxy" \
  nix shell nixpkgs#qemu nixpkgs#virtiofsd -c \
  "$repo_root/target/debug/sandy" -o json run "$repo_root/nix/guest#topologies.x86_64-linux.qemu-t3" \
  --timeout 600 --allow api.anthropic.com:443 --allow api.openai.com:443 \
  --input "$work/guest.sh:guest.sh" -- bash /run/sandy/inputs/guest.sh \
  >"$work/result.json" 2>"$work/stderr.log" || status=$?
if [ ! -s "$work/result.json" ]; then
  echo "sandy produced no result (exit $status):" >&2
  tail -n 12 "$work/stderr.log" >&2
  exit 1
fi

python3 -I - "$work/result.json" <<'PY' || status=1
import json, re, sys
text = open(sys.argv[1], errors="replace").read()
result, _ = json.JSONDecoder().raw_decode(text[text.index("{"):])
tail = (result.get("logs") or {}).get("tail", "").replace("\r", "\n")
lines = {}
for line in tail.splitlines():
    m = re.search(r"SK> ([a-z-]+): ?(.*)", line)
    if m:
        lines[m.group(1)] = m.group(2)
for key, value in lines.items():
    print(f"{key}: {value}")
if result.get("status") != "succeeded":
    print("the guest run did not succeed:", result.get("status"), result.get("message"), file=sys.stderr)
    sys.exit(1)

failures = []
def check(ok, what):
    if not ok:
        failures.append(what)

expected = ["env", "netdevs", "binaries", "curl-allowed", "curl-denied", "claude-allowed", "codex-allowed", "claude-denied", "done"]
check(all(k in lines for k in expected), "the guest output is incomplete: " + ", ".join(k for k in expected if k not in lines))
check(lines.get("netdevs", "").split() == ["lo"], "the guest has a network device besides lo, so a provider reply proves nothing about the proxy")
check(lines.get("env") == "HTTPS_PROXY=http://127.0.0.1:3128", "the job env does not carry the proxy")
check(lines.get("binaries") == "claude=yes codex=yes", "claude or codex is missing from the image")
check(re.fullmatch(r"[1-5]\d\d", lines.get("curl-allowed", "")), "curl did not reach an allow-listed host")
check("response 403" in lines.get("curl-denied", ""), "a host off the allow-list was not refused with 403")
check("Invalid API key" in lines.get("claude-allowed", ""), "claude did not reach its provider through the proxy")
check(re.search(r"\b401 Unauthorized\b", lines.get("codex-allowed", "")) and "api.openai.com" in lines.get("codex-allowed", ""),
      "codex did not reach its provider through the proxy")
# The 403 itself is shown by curl-denied. claude must not succeed against a host off the allow-list: a clean exit or
# the provider's reply means the request got through.
denied = lines.get("claude-denied", "")
check(denied.startswith("rc=") and not denied.startswith("rc=0 ") and "Invalid API key" not in denied,
      "claude got a reply from a host off the allow-list")
for what in failures:
    print("FAIL:", what, file=sys.stderr)
sys.exit(1 if failures else 0)
PY

if [ "$status" -eq 0 ]; then
  echo "live-harness-proxy: OK"
fi
exit "$status"
