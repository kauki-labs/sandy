# The sandy-host-executor overlay (#287, M2 spec #269 D3): the host-side
# executor binary, for the HOST NixOS config (ws01) — not the sandbox image.
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
}
