#!/usr/bin/env bats
#
# The live boot surface: a real job booted through `sandy run` to a locked result
# envelope. Needs nixos + virtualization (a hypervisor and a buildable guest), so
# every test is gated by `require_live` and SKIPPED off-matrix (INV-S9) — it never
# runs in the plain sandbox and is not wired into CI. Run it on a capable host:
#
#   SANDY_LIVE=1 SANDY_E2E_TEMPLATE='/path/to/guest#topologies.<system>.<hv>' \
#     nix develop -c bats tests/e2e/live
#
# Envelope field names are the LOCKED snake_case schema from result.rs: status is
# "succeeded" | "failed" | "cancelled", with exit_code and result_schema_version.

bats_require_minimum_version 1.5.0

load ../helpers/common

@test "run boots a trivial job to a succeeded envelope (live)" {
  require_live
  run --separate-stderr sandy -o json run "$SANDY_E2E_TEMPLATE" -- true
  [ "$status" -eq 0 ]
  [ "$(printf '%s' "$output" | jq -r .status)" = "succeeded" ]
  [ "$(printf '%s' "$output" | jq -r .exit_code)" = "0" ]
  [ "$(printf '%s' "$output" | jq -r .result_schema_version)" = "1" ]
}

@test "a non-zero guest command yields a failed envelope, not a crash (live)" {
  require_live
  run --separate-stderr sandy -o json run "$SANDY_E2E_TEMPLATE" -- sh -c "exit 7"
  # The run completed; the guest's failure is reported in the envelope (band 1),
  # not as an infra fault, and is not retryable.
  [ "$(printf '%s' "$output" | jq -r .status)" = "failed" ]
  [ "$(printf '%s' "$output" | jq -r .retryable)" = "false" ]
}

@test "a booted job is recorded and listed afterwards (live)" {
  require_live
  sandy run "$SANDY_E2E_TEMPLATE" -- true >/dev/null 2>&1
  run --separate-stderr sandy -o json ls
  [ "$status" -eq 0 ]
  [ "$(printf '%s' "$output" | jq 'length')" -ge 1 ]
}
