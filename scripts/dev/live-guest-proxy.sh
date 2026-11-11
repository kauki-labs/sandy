#!/usr/bin/env bash
# Live gate for #609 (epic #597), tier-3, never counted green from a fake (INV-S9).
#
# Boots the service guest (nix/guest, topology qemu-service on a Linux KVM host, vfkit-service on Apple silicon) in
# egress-proxy mode and shows that an HTTPS client in the guest reaches an allow-listed host through the guest's proxy
# relay (`HTTPS_PROXY=http://127.0.0.1:3128`), and that a host off the allow-list does not get through. The guest has
# no NIC, so a reply from an outside host can only have gone through the proxy.
#
# Needs: a Linux host with KVM and /dev/vhost-vsock access, or an Apple silicon macOS host with the aarch64-linux
# builder (`sandy doctor` names what is missing); nix. No root, tap or nft, no real credential. Run from the repo root:
#
#   scripts/dev/live-guest-proxy.sh
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$repo_root"

case "$(uname -s)" in
Linux)
  if [ ! -r /dev/vhost-vsock ] || [ ! -w /dev/vhost-vsock ]; then
    echo "refusing: /dev/vhost-vsock is not accessible to this user" >&2
    exit 2
  fi
  topology=topologies.x86_64-linux.qemu-service
  guest_runner=packages.x86_64-linux.guest-runner-service
  hypervisor_tools=(nixpkgs#qemu nixpkgs#virtiofsd)
  # sandy runs in its own session, so its qemu, virtiofsd and egress proxy share one process group.
  isolate=(setsid)
  ;;
Darwin)
  # The vfkit leg (KHE5): the same checks on an Apple silicon guest. vfkit needs no privileges.
  topology=topologies.aarch64-linux.vfkit-service
  guest_runner=packages.aarch64-darwin.guest-runner-vfkit-service
  hypervisor_tools=(nixpkgs#vfkit)
  # macOS has no setsid; the vfkit proxy listens on a socket under the run's work dir, which the path sweep finds.
  isolate=()
  ;;
*)
  echo "refusing: the guest proxy gate needs a Linux KVM host or an Apple silicon macOS host" >&2
  exit 2
  ;;
esac

# Short, fixed base: a unix socket path holds at most 108 bytes (see live-vsock-bridge.sh).
work=$(mktemp -d /tmp/slb.XXXXXX)
chmod 0700 "$work"
mkdir -p "$work/home"
sandy_pgid=""
cleanup() {
  # Linux: sandy runs in its own session, so its qemu, virtiofsd and egress proxy share one process group. The qemu
  # proxy's command line holds no work dir (it is given a vsock port and a peer cid), so only the group finds it.
  # macOS: there is no group; the path sweep below finds vfkit and the proxy, whose socket paths hold the work dir.
  if [ -n "$sandy_pgid" ]; then
    kill -- "-$sandy_pgid" 2>/dev/null || true
  fi
  # qemu and virtiofsd also carry this run's private work dir.
  pkill -f -- "$work/" 2>/dev/null || true
  for _ in $(seq 20); do
    pgrep -f -- "$work/" >/dev/null 2>&1 || break
    sleep 0.5
  done
  if [ -n "$sandy_pgid" ]; then
    kill -9 -- "-$sandy_pgid" 2>/dev/null || true
  fi
  pkill -9 -f -- "$work/" 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

cat >"$work/guest.sh" <<'GUEST'
set -u
echo "SK> env: HTTPS_PROXY=${HTTPS_PROXY:-unset}"
# No NIC: the only way out is the proxy relay, which is what makes a provider reply a proof of the proxy.
echo "SK> netdevs: $(ls /sys/class/net | tr '\n' ' ')"
echo "SK> curl-allowed: $(timeout 30 curl -sS -o /dev/null -w '%{http_code}' https://api.anthropic.com/ 2>&1 | tail -c 200)"
echo "SK> curl-allowed-2: $(timeout 30 curl -sS -o /dev/null -w '%{http_code}' https://api.openai.com/ 2>&1 | tail -c 200)"
echo "SK> curl-denied: $(timeout 30 curl -sS -o /dev/null -w '%{http_code}' https://example.org/ 2>&1 | tail -c 200)"
echo "SK> done: yes"
GUEST

echo "== building sandy and the egress proxy"
cargo build -q -p sandy-cli --bin sandy
cargo build -q -p sandy-egress-proxy

echo "== building the service guest"
nix build --no-link "$repo_root/nix/guest#$guest_runner"

echo "== running the guest"
status=0
TMPDIR="$work" SANDY_HOME="$work/home" SANDY_EGRESS=proxy \
  SANDY_EGRESS_PROXY_BIN="$repo_root/target/debug/sandy-egress-proxy" \
  ${isolate[@]+"${isolate[@]}"} nix shell "${hypervisor_tools[@]}" -c \
  "$repo_root/target/debug/sandy" -o json run "$repo_root/nix/guest#$topology" \
  --timeout 600 --allow api.anthropic.com:443 --allow api.openai.com:443 \
  --input "$work/guest.sh:guest.sh" -- bash /run/sandy/inputs/guest.sh \
  >"$work/result.json" 2>"$work/stderr.log" &
sandy_pgid=$!
wait "$sandy_pgid" || status=$?
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
    m = re.search(r"SK> ([a-z0-9-]+): ?(.*)", line)
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

expected = ["env", "netdevs", "curl-allowed", "curl-allowed-2", "curl-denied", "done"]
check(all(k in lines for k in expected), "the guest output is incomplete: " + ", ".join(k for k in expected if k not in lines))
check(lines.get("netdevs", "").split() == ["lo"], "the guest has a network device besides lo, so a provider reply proves nothing about the proxy")
check(lines.get("env") == "HTTPS_PROXY=http://127.0.0.1:3128", "the job env does not carry the proxy")
check(re.fullmatch(r"[1-5]\d\d", lines.get("curl-allowed", "")), "curl did not reach the first allow-listed host")
check(re.fullmatch(r"[1-5]\d\d", lines.get("curl-allowed-2", "")), "curl did not reach the second allow-listed host")
check("response 403" in lines.get("curl-denied", ""), "a host off the allow-list was not refused with 403")
for what in failures:
    print("FAIL:", what, file=sys.stderr)
sys.exit(1 if failures else 0)
PY

if [ "$status" -eq 0 ]; then
  echo "live-guest-proxy: OK"
fi
exit "$status"
