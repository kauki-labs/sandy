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
      # `mkGuest`/`mkTopology` (plus the `commonModule` protocol wiring and the
      # agent overlay they bake in) are the shared guest-composition module
      # (#324): this nested flake's own `../../flake.nix` exposes the same
      # functions as `lib.mkGuest`/`lib.mkTopology` for a consuming flake, both
      # built from this one file so they can't drift apart. Imported directly
      # by relative path (not as a flake input): a `path:../..` input here
      # would pull the root flake's own nixpkgs/microvm pins into this nested
      # flake's lock, when each flake's pins are meant to stay independent.
      guestLib = import ../lib/guest.nix { inherit nixpkgs microvm; };
      inherit (guestLib) mkGuest mkTopology;

      # Guest networking for the #29 live egress gate. sandy's qemu backend adds
      # the NIC itself (`-netdev tap,ifname=$SANDY_TAP` + virtio-net with the fixed
      # `02:00:00:00:00:01` MAC) because it assembles its own qemu argv rather than
      # using microvm's declaredRunner — so the guest only needs to bring up and
      # DHCP whatever ethernet interface appears. `Type = "ether"` matches it
      # without depending on a predictable name; the host side of the tap runs the
      # DHCP server (the gate starts dnsmasq). The guest's own firewall is off: the
      # host enforces egress (guest-scoped nftables on the tap), and the
      # "bypass impossible" row flushes the guest's rules anyway.
      networkingModule =
        { pkgs, ... }:
        {
          networking.useNetworkd = true;
          systemd.network.enable = true;
          systemd.network.networks."10-ether" = {
            matchConfig.Type = "ether";
            networkConfig.DHCP = "yes";
          };
          networking.firewall.enable = false;
          # `nft` in the guest so the #29 "bypass impossible" row can really flush
          # the guest's own ruleset — otherwise that step is a silent no-op and the
          # assertion is vacuous.
          environment.systemPackages = [ pkgs.nftables ];
        };

      # GitHub credential consumption for a `sandy run --credential` job. The scoped
      # token is staged read-only at /run/sandy/secrets/GITHUB_TOKEN (sandy fixes
      # that name). Both consumers read the FILE at use-time, not the boot-time
      # `$GITHUB_TOKEN` env snapshot, so a mid-run refresh (#49) is picked up: the
      # env export happens once at login and can never update a running process.
      #   - git over HTTPS: a named credential helper on PATH returns the current
      #     token per operation as `x-access-token:<token>`, scoped to github.com so
      #     the token never travels to another remote.
      #   - the gh CLI: a PATH wrapper re-reads the file into GH_TOKEN and execs the
      #     real gh, so `gh api`/`gh pr` see the current token per call.
      # Both are shell-independent on purpose: a helper binary and a wrapper binary
      # are found by non-interactive shells, scripts, and anything that execs the
      # tool, which a shell alias is not.
      credentialModule =
        { pkgs, ... }:
        let
          tokenFile = "/run/sandy/secrets/GITHUB_TOKEN";
          # git invokes `git credential-sandy-gh <op>`; only `get` returns anything.
          gitHelper = pkgs.writeShellScriptBin "git-credential-sandy-gh" ''
            [ "$1" = get ] || exit 0
            [ -r ${tokenFile} ] || exit 0
            printf 'username=x-access-token\npassword=%s\n' "$(cat ${tokenFile})"
          '';
          # The only `gh` on PATH: refresh-safe GH_TOKEN, re-read each invocation,
          # then exec the real gh by store path.
          ghWrapper = pkgs.writeShellScriptBin "gh" ''
            if [ -r ${tokenFile} ]; then
              GH_TOKEN="$(cat ${tokenFile})"
              export GH_TOKEN
            fi
            exec ${pkgs.gh}/bin/gh "$@"
          '';
        in
        {
          programs.git = {
            enable = true;
            config.credential."https://github.com".helper = "sandy-gh";
          };
          environment.systemPackages = [
            gitHelper
            ghWrapper
          ];
        };

      # qemu guest for the Linux node (x86_64-linux/KVM), console ttyS0. Carries the
      # networking module so the #29 egress gate has guest egress to filter.
      qemuGuest = mkGuest {
        system = "x86_64-linux";
        hypervisor = "qemu";
        extraModules = [
          networkingModule
          credentialModule
        ];
      };

      # vfkit guest for an Apple-silicon host (aarch64-darwin host, aarch64-linux guest — vfkit
      # requires matching arch), console hvc0. The kernel/initrd/erofs build on
      # the aarch64-linux linux-builder; the runner assembles on darwin.
      vfkitGuest = mkGuest {
        system = "aarch64-linux";
        hypervisor = "vfkit";
        vmHostPackages = nixpkgs.legacyPackages.aarch64-darwin;
        extraModules = [ credentialModule ];
      };

    in
    {
      # microvm.nix's own runners — used to prove each guest boots and speaks the
      # protocol before sandy's backend drives it.
      packages.x86_64-linux.guest-runner = qemuGuest.config.microvm.declaredRunner;
      packages.aarch64-darwin.guest-runner-vfkit = vfkitGuest.config.microvm.declaredRunner;

      # The built guest configs (the topology attrs read kernel/initrd/store off
      # these).
      nixosConfigurations.sandy-guest-qemu = qemuGuest;
      nixosConfigurations.sandy-guest-vfkit = vfkitGuest;

      # The guest-side sandy-agent, per guest system (#238) — the same
      # `pkgs.sandy-agent` the guest config itself carries (via the overlay
      # applied in `mkGuest`), re-exposed here for direct `nix build`.
      packages.x86_64-linux.sandy-agent = qemuGuest.pkgs.sandy-agent;
      packages.aarch64-linux.sandy-agent = vfkitGuest.pkgs.sandy-agent;

      # sandy's `Topology` per guest: `nix eval --json <flake>#topologies.<sys>.<hv>`.
      topologies = {
        x86_64-linux.qemu = mkTopology qemuGuest;
        aarch64-linux.vfkit = mkTopology vfkitGuest;
      };
    };
}
