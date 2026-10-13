#!/usr/bin/env bats
#
# `run`, the non-live argument contract only: a template is required, a trailing
# command is not. The real boot lives in ../live/run.bats (gated).

bats_require_minimum_version 1.5.0

load ../helpers/common

@test "run requires a template" {
  run --separate-stderr sandy run
  [ "$status" -eq 2 ]
  [[ "$stderr" == *"TEMPLATE"* ]]
}
