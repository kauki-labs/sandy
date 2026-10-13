#!/usr/bin/env bats
#
# `status`: a missing job id errors on stderr, and the error stays plain text
# even under `-o json` (only successful output is JSON).

bats_require_minimum_version 1.5.0

load ../helpers/common

@test "status on a missing job id errors on stderr" {
  run --separate-stderr sandy status no-such-job
  [ "$status" -eq 2 ]
  [[ "$stderr" == *"job record not found"* ]]
}

@test "an error stays plain text on stderr even under -o json" {
  run --separate-stderr sandy -o json status no-such-job
  [ "$status" -eq 2 ]
  [[ "$stderr" == *"job record not found"* ]]
  [ -z "$output" ]
}
