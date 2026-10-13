#!/usr/bin/env bats
#
# `cred github verify`, the non-live paths: a capability is required, and a
# missing trust root fails against the isolated `$XDG_CONFIG_HOME`, never the
# real ~/.config. Registering a real App (browser/network) is out of scope here.

bats_require_minimum_version 1.5.0

load ../helpers/common

@test "cred github verify requires a capability" {
  run --separate-stderr sandy cred github verify some-name
  [ "$status" -eq 2 ]
  [[ "$stderr" == *"capability"* ]]
}

@test "cred github verify on a missing trust root errors (isolated config)" {
  run --separate-stderr sandy cred github verify no-such-root --capability read-code
  [ "$status" -eq 2 ]
  [[ "$stderr" == *"trust root"* ]]
  [[ "$stderr" == *"No such file"* ]]
  [[ "$stderr" == *"$XDG_CONFIG_HOME"* ]]
}
