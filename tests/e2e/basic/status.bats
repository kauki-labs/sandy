#!/usr/bin/env bats
#
# `status` talks to sandyd: with none running it is an infrastructure fault (exit 3), and the error stays plain text
# on stderr even under `-o json` (only successful output is JSON). An unknown job id is covered by
# crates/sandy-cli/tests/daemon_e2e.rs.

bats_require_minimum_version 1.5.0

load ../helpers/common

@test "status with no sandyd running exits 3 naming the socket" {
  run --separate-stderr sandy status some-job
  [ "$status" -eq 3 ]
  [[ "$stderr" == *"could not connect to sandyd at $SANDY_SOCK"* ]]
}

@test "an error stays plain text on stderr even under -o json" {
  run --separate-stderr sandy -o json status some-job
  [ "$status" -eq 3 ]
  [[ "$stderr" == *"could not connect to sandyd"* ]]
  [ -z "$output" ]
}
