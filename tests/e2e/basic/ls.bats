#!/usr/bin/env bats
#
# `ls`: the empty-home listing in plain and json, and the global `-o` placement.

bats_require_minimum_version 1.5.0

load ../helpers/common

@test "ls on an empty home exits 0 with no records" {
  run --separate-stderr sandy ls
  [ "$status" -eq 0 ]
  [ -z "$output" ]
}

@test "ls -o json on an empty home is an empty JSON array" {
  run --separate-stderr sandy -o json ls
  [ "$status" -eq 0 ]
  [ "$(printf '%s' "$output" | jq -c .)" = "[]" ]
}

@test "the -o flag is global and may follow the subcommand" {
  run --separate-stderr sandy ls -o json
  [ "$status" -eq 0 ]
  [ "$(printf '%s' "$output" | jq -c .)" = "[]" ]
}
