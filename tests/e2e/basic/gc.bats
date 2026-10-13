#!/usr/bin/env bats
#
# `gc`: the empty-home no-op and the `--keep-last` flag (not a positional count).

bats_require_minimum_version 1.5.0

load ../helpers/common

@test "gc on an empty home evicts nothing and exits 0" {
  run --separate-stderr sandy gc
  [ "$status" -eq 0 ]
  [[ "$output" == *"evicted 0 record"* ]]
}

@test "gc --keep-last N is accepted" {
  run --separate-stderr sandy gc --keep-last 3
  [ "$status" -eq 0 ]
}
