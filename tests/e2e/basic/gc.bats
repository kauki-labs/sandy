#!/usr/bin/env bats
#
# `gc` talks to sandyd: with none running it is an infrastructure fault (exit 3), and `--keep-last` is a flag, not a
# positional count. The calls it makes are covered by crates/sandy-cli/tests/daemon_verbs.rs.

bats_require_minimum_version 1.5.0

load ../helpers/common

@test "gc with no sandyd running exits 3 naming the socket" {
  run --separate-stderr sandy gc
  [ "$status" -eq 3 ]
  [[ "$stderr" == *"could not connect to sandyd at $SANDY_SOCK"* ]]
}

@test "gc --keep-last N is accepted" {
  run --separate-stderr sandy gc --keep-last 3
  [ "$status" -eq 3 ]
}

@test "gc --keep-last takes a number" {
  run --separate-stderr sandy gc --keep-last many
  [ "$status" -eq 2 ]
  [[ "$stderr" == *"invalid value"* ]]
}
