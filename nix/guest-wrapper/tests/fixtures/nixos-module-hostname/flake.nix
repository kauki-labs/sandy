{
  description = "sandy #325 test fixture: a nixosModule that sets networking.hostName itself (kind 2, mkForce collision)";

  outputs = { ... }: {
    # Picks the same option `commonModule` requires (`networking.hostName =
    # "sandy"`) to prove #325's `lib.mkForce` fix in `nix/lib/guest.nix`
    # resolves the collision rather than raising a conflicting-definitions
    # eval error.
    nixosModules.default = {
      networking.hostName = "totally-not-sandy";
    };
  };
}
