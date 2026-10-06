{
  description = "sandy guest microVMs for live acceptance (#26/#27)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    microvm.url = "github:microvm-nix/microvm.nix";
    microvm.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs =
    {
      self,
      nixpkgs,
      microvm,
    }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};

      # A minimal microVM that speaks the sandy console protocol:
      # hostName "sandy" makes getty print the `sandy login:` banner that is the
      # pinned READY_MARKER; autologin drops to a root shell on ttyS0 that reads
      # the injected command frame. base64/coreutils/sh are in the system path so
      # the frame (`… | base64 -d | sh; printf 'exit=%d' "$?"`) runs.
      guest = nixpkgs.lib.nixosSystem {
        inherit system;
        modules = [
          microvm.nixosModules.microvm
          (
            { lib, ... }:
            {
              networking.hostName = "sandy";
              system.stateVersion = "24.11";

              microvm = {
                hypervisor = "qemu";
                vcpu = 2;
                mem = 512;
                graphics.enable = false;
                # Back the store as an on-disk erofs image (not the default
                # host-store virtiofs share): sandy's qemu backend attaches the
                # store as a read-only virtio-blk drive and refuses a virtiofs
                # store, so the guest must carry its own store image.
                storeOnDisk = true;
              };

              # Serial console on ttyS0 (sandy drives -serial/-nographic there).
              boot.kernelParams = [ "console=ttyS0" ];

              # Autologin root on every console so the injected frame lands in a
              # shell, not a password prompt.
              services.getty.autologinUser = "root";
              users.users.root.password = "";

              # Keep the guest tiny and fast to boot.
              documentation.enable = lib.mkForce false;
              boot.initrd.systemd.enable = lib.mkForce false;
            }
          )
        ];
      };
    in
    {
      # microvm.nix's own runner — used to prove the guest boots and speaks the
      # protocol before sandy's backend drives it.
      packages.${system}.guest-runner = guest.config.microvm.declaredRunner;

      # The built guest config, so the topology module can read kernel/initrd/
      # store off it (added next).
      nixosConfigurations.sandy-guest = guest;
    };
}
