{
  description = "sandy #325 test fixture: a full, sandy-unaware nixosConfiguration (kind 3, extendModules)";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    {
      # Shaped like someone's real aarch64 board config (generic-extlinux
      # bootloader, a real root filesystem), not a stripped-down stub — the
      # point of kind 3 is proving `extendModules` against a config that
      # carries its own bootloader/filesystem/hostname assumptions, the same
      # ones #325's design note warns can collide with `commonModule`.
      # Targets aarch64-linux: the only guest arch this fixture's own vfkit
      # live leg can actually boot.
      nixosConfigurations.default = nixpkgs.lib.nixosSystem {
        system = "aarch64-linux";
        modules = [
          (
            { pkgs, ... }:
            {
              networking.hostName = "realhost";
              system.stateVersion = "24.11";
              boot.loader.grub.enable = false;
              boot.loader.generic-extlinux-compatible.enable = true;
              fileSystems."/" = {
                device = "/dev/disk/by-label/NIXOS_SD";
                fsType = "ext4";
              };
              environment.systemPackages = [ pkgs.hello ];
            }
          )
        ];
      };
    };
}
