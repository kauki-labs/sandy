# The sandy-agent overlay (#287, M2 spec #269 D3): the sandbox agent, for a
# sandbox-IMAGE NixOS deployment — the agent goes on top of the image inside
# the sandbox, not the host. Split out from the single sandy-executor overlay
# (operator ruling, #287 follow-up): sandy-agent and sandy-host-executor have
# different deployment targets, so one bundled overlay shipping both onto
# either target was the wrong shape.
#
# This is the SINGLE source for the agent build — `nix/guest/flake.nix`
# applies this overlay instead of maintaining its own separate
# `rustPlatform.buildRustPackage` copy of `sandy-agent`, so the guest image
# and a bare-host deployment never drift from two independent build
# definitions of the same binary.
final: prev: {
  sandy-agent = import ./lib.nix final prev "sandy-agent";
}
