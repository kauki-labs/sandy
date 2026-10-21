{
  description = "sandy #326 negative fixture: a devShell whose shellHook assumes the host, not the guest (kind 4)";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { nixpkgs, ... }:
    {
      # Pins down #326's acceptance bar: this hook's assumptions hold when
      # `nix develop` runs it on the host, and silently do NOT hold once
      # synthesized into the guest's login shell. `aarch64-darwin` is here
      # only so the host side is an observed `nix develop` run (`HOOK_OS=
      # Darwin`, `HOOK_HAS_USERS_DIR=yes`), not a predicted one — sandy's own
      # `--from-devshell` never reads it (it only ever looks at the GUEST's
      # system, `x86_64-linux`/`aarch64-linux`); `tests/live_flake_devshell.rs`
      # asserts the guest's actual divergent values (`Linux`/`no`).
      devShells = nixpkgs.lib.genAttrs [ "x86_64-linux" "aarch64-linux" "aarch64-darwin" ] (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          default = pkgs.mkShell {
            shellHook = ''
              echo "HOOK_OS=$(uname)"
              if [ -d /Users ]; then
                echo "HOOK_HAS_USERS_DIR=yes"
              else
                echo "HOOK_HAS_USERS_DIR=no"
              fi
            '';
          };
        }
      );
    };
}
