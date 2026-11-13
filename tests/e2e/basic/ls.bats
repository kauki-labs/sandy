#!/usr/bin/env bats
#
# `ls` talks to sandyd: with none running it is an infrastructure fault (exit 3), and the global `-o` may follow the
# subcommand. The listing itself is covered by crates/sandy-cli/tests/daemon_verbs.rs.

bats_require_minimum_version 1.5.0

load ../helpers/common

@test "ls with no sandyd running exits 3 naming the socket" {
  run --separate-stderr sandy ls
  [ "$status" -eq 3 ]
  [[ "$stderr" == *"could not connect to sandyd at $SANDY_SOCK"* ]]
  [ -z "$output" ]
}

@test "the -o flag is global and may follow the subcommand" {
  run --separate-stderr sandy ls -o json
  [ "$status" -eq 3 ]
  [[ "$stderr" == *"could not connect to sandyd"* ]]
}
