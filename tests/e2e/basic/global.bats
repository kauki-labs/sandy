#!/usr/bin/env bats
#
# Global parsing: help, unknown subcommand/flag, and the global `-o` format flag.

bats_require_minimum_version 1.5.0

load ../helpers/common

@test "--help prints usage and exits 0" {
  run --separate-stderr sandy --help
  [ "$status" -eq 0 ]
  [[ "$output" == *"Usage: sandy"* ]]
}

@test "an unrecognized subcommand is a usage error" {
  run --separate-stderr sandy no-such-command
  [ "$status" -eq 2 ]
  [[ "$stderr" == *"unrecognized subcommand"* ]]
}

@test "an unknown flag is a usage error" {
  run --separate-stderr sandy --no-such-flag
  [ "$status" -eq 2 ]
  [[ "$stderr" == *"unexpected argument"* ]]
}

@test "an unknown -o value is rejected with the allowed set" {
  run --separate-stderr sandy -o yaml ls
  [ "$status" -eq 2 ]
  [[ "$stderr" == *"invalid value 'yaml'"* ]]
  [[ "$stderr" == *"plain"* && "$stderr" == *"json"* ]]
}
