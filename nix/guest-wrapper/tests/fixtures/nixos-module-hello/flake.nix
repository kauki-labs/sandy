{
  description = "sandy #325 test fixture: a plain nixosModule, no sandy awareness at all (kind 2)";

  outputs = { ... }: {
    nixosModules.default =
      { pkgs, ... }:
      {
        environment.systemPackages = [ pkgs.hello ];
      };
  };
}
