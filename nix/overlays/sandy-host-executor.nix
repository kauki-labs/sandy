# The sandy-host-executor overlay (#287, M2 spec #269 D3): the host-side
# executor binary, for the HOST NixOS config (the remote host) — not the sandbox image.
# Split out from the single sandy-executor overlay (operator ruling, #287
# follow-up): sandy-agent and sandy-host-executor have different deployment
# targets, so one bundled overlay shipping both onto either target was the
# wrong shape.
#
# Does NOT include sandy-agent: the host nixosModule's `agentPackage` option
# CONSUMES the agent package (defaulted to `pkgs.sandy-agent`, for
# `SANDY_AGENT_PATH` injection) rather than defining it — a consumer applies
# both this overlay and `sandy-agent.nix` to get that default, or supplies
# its own `agentPackage` if it only wants this one.
final: prev: {
  sandy-host-executor = import ./lib.nix final prev "sandy-host-executor";
  # The packaged `$SANDY_GUEST_WRAPPER` source tree (#332, CodeRabbit finding
  # on PR #333) — a sibling package, not folded into `sandy-host-executor`
  # itself: it is data `nix` reads at dispatch time, never compiled into the
  # binary. See `nix/overlays/guest-wrapper-src.nix` for why it has to carry
  # more than just `nix/guest-wrapper` on its own.
  sandy-guest-wrapper = import ./guest-wrapper-src.nix final prev;
}
