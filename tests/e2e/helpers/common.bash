# Shared setup for the sandy CLI end-to-end suite (bats).
#
# Black-box: every test drives the built `sandy` binary at the process boundary
# (argv, exit code, stdout, stderr), never the Rust library. This is the layer the
# in-crate `assert_cmd` tests don't reach: the real compiled CLI as an agent or a
# shell would invoke it.

# The worktree root, relative to this helper (tests/e2e/helpers/common.bash),
# so it resolves the same whichever subdir a .bats file loads it from.
_repo_root() { cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd; }

setup() {
  # The flake check passes SANDY_BIN; a dev-shell run falls back to the debug
  # build. A missing binary skips (with the build command) rather than failing,
  # so `bats` on a clean tree reports "skipped", not a false red.
  : "${SANDY_BIN:=$(_repo_root)/target/debug/sandy}"
  export SANDY_BIN
  if [ ! -x "$SANDY_BIN" ]; then
    skip "sandy binary not found at $SANDY_BIN (build: nix develop -c cargo build -p sandy-cli, or pass SANDY_BIN)"
  fi
  # Isolate all host state: the journal ($SANDY_HOME) and the credential trust
  # roots ($XDG_CONFIG_HOME/sandy). Tests never touch the real ~/.config/sandy.
  SANDY_HOME="$(mktemp -d)"
  export SANDY_HOME
  XDG_CONFIG_HOME="$(mktemp -d)"
  export XDG_CONFIG_HOME
}

teardown() {
  [ -n "${SANDY_HOME:-}" ] && rm -rf "$SANDY_HOME"
  [ -n "${XDG_CONFIG_HOME:-}" ] && rm -rf "$XDG_CONFIG_HOME"
}

# Thin wrapper so a test reads `run --separate-stderr sandy <args>`.
sandy() { "$SANDY_BIN" "$@"; }

# Skip unless a real boot is both requested and possible: SANDY_LIVE=1, a guest
# template to boot (SANDY_E2E_TEMPLATE, e.g. /path/to/guest#topologies.<sys>.<hv>),
# and the host's hypervisor on PATH (vfkit on macOS, qemu on Linux). Mirrors the
# Rust `require_live` gate (INV-S9): off-matrix is skipped, never counted green.
require_live() {
  [ "${SANDY_LIVE:-}" = "1" ] || skip "live boot: set SANDY_LIVE=1 (needs nixos + virtualization)"
  [ -n "${SANDY_E2E_TEMPLATE:-}" ] || skip "live boot: set SANDY_E2E_TEMPLATE to a bootable guest attr"
  local hv
  hv=$([ "$(uname)" = "Darwin" ] && echo vfkit || echo qemu)
  command -v "$hv" >/dev/null 2>&1 || skip "live boot: $hv not on PATH"
}
