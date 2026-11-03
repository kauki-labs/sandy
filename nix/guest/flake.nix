{
  description = "sandy guest microVMs for live acceptance (#26/#27)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    microvm.url = "github:microvm-nix/microvm.nix";
    microvm.inputs.nixpkgs.follows = "nixpkgs";
    # The t3 server and its harnesses (#608) come from their own pin so the base guest (kernel, agent) does not
    # move with it. This is the root flake's nixpkgs revision, where t3code is 0.1.2, the version the owner
    # exercised. Older pins carry 0.0.44, which lacks `t3 pair --scope`.
    nixpkgs-t3.url = "github:NixOS/nixpkgs/31ecbaca1bdefa45dffc409f0250bd8039ea0010";
  };

  outputs =
    {
      self,
      nixpkgs,
      nixpkgs-t3,
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

      # Guest networking for the #29 live egress gate and the #602 `nic` profile (the vfkit guest carries it
      # too; there the NIC has no host egress boundary, #603). sandy's qemu backend adds
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
          # assertion is vacuous. `glibc.bin` for `getent`: NixOS doesn't put it on
          # PATH by default, and the #376 live gate needs it to prove the guest
          # really can't resolve a name through a host-local resolver.
          environment.systemPackages = [
            pkgs.nftables
            pkgs.glibc.bin
          ];
        };

      # The T3 server and the harness binaries it launches (#608). `t3 serve` is started by the service workload
      # kind (#589), never by the image; provider config dirs (`CLAUDE_CONFIG_DIR`, `CODEX_HOME`) come from the
      # identity profile (#592), so the image holds no key, token or config. t3's wrapper puts `claude` and `codex`
      # on its own PATH. `sandy-t3-ready` is the probe: it succeeds only once the server answers HTTP 200 on its
      # loopback port (it replies 503 while starting), so readiness never rests on console text.
      #
      # The closure is about 3.7 GB because nixpkgs builds t3code with electron (1.4 GB) and the codex binary is
      # 1 GB. The image is built once and shared read-only. A server-only build is a follow-up.
      t3Module =
        { pkgs, ... }:
        let
          t3pkgs = import nixpkgs-t3 {
            inherit (pkgs.stdenv.hostPlatform) system;
            config.allowUnfreePredicate = pkg: builtins.elem (nixpkgs-t3.lib.getName pkg) [ "claude-code" ];
          };
          t3 = t3pkgs.t3code.override {
            enableClaude = true;
            enableCodex = true;
          };
          ready = pkgs.writeShellScriptBin "sandy-t3-ready" ''
            exec ${pkgs.curl}/bin/curl --fail --silent --show-error --max-time 2 --output /dev/null \
              "http://127.0.0.1:''${1:-3773}/"
          '';
        in
        {
          environment.systemPackages = [
            t3
            ready
          ];
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

      # The same guests with the T3 server and harnesses (#608).
      qemuT3Guest = mkGuest {
        system = "x86_64-linux";
        hypervisor = "qemu";
        extraModules = [
          networkingModule
          credentialModule
          t3Module
        ];
      };

      vfkitT3Guest = mkGuest {
        system = "aarch64-linux";
        hypervisor = "vfkit";
        vmHostPackages = nixpkgs.legacyPackages.aarch64-darwin;
        extraModules = [
          networkingModule
          credentialModule
          t3Module
        ];
      };

      # vfkit guest for an Apple-silicon host (aarch64-darwin host, aarch64-linux guest — vfkit
      # requires matching arch), console hvc0. The kernel/initrd/erofs build on
      # the aarch64-linux linux-builder; the runner assembles on darwin.
      vfkitGuest = mkGuest {
        system = "aarch64-linux";
        hypervisor = "vfkit";
        vmHostPackages = nixpkgs.legacyPackages.aarch64-darwin;
        extraModules = [
          networkingModule
          credentialModule
        ];
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
      nixosConfigurations.sandy-guest-qemu-t3 = qemuT3Guest;
      nixosConfigurations.sandy-guest-vfkit-t3 = vfkitT3Guest;

      # The guest-side sandy-agent, per guest system (#238) — the same
      # `pkgs.sandy-agent` the guest config itself carries (via the overlay
      # applied in `mkGuest`), re-exposed here for direct `nix build`.
      packages.x86_64-linux.sandy-agent = qemuGuest.pkgs.sandy-agent;
      packages.aarch64-linux.sandy-agent = vfkitGuest.pkgs.sandy-agent;

      # Eval-only acceptance for the T3 guest image (#608): the image carries the t3 server at the version the
      # owner exercised, and a readiness probe. Nothing here builds the 3.7 GB closure.
      checks.x86_64-linux.t3-guest-packages =
        let
          pkgs = nixpkgs.legacyPackages.x86_64-linux;
          names = map (
            p: p.name
          ) self.nixosConfigurations.sandy-guest-qemu-t3.config.environment.systemPackages;
          wanted = [
            "t3code-0.1.2"
            "sandy-t3-ready"
          ];
          missing = builtins.filter (w: !(builtins.elem w names)) wanted;
        in
        assert missing == [ ] || throw "the t3 guest image lacks: ${builtins.toString missing}";
        pkgs.runCommand "t3-guest-packages" { } "touch $out";

      # sandy's `Topology` per guest: `nix eval --json <flake>#topologies.<sys>.<hv>`.
      topologies = {
        x86_64-linux.qemu = mkTopology qemuGuest;
        aarch64-linux.vfkit = mkTopology vfkitGuest;
        x86_64-linux.qemu-t3 = mkTopology qemuT3Guest;
        aarch64-linux.vfkit-t3 = mkTopology vfkitT3Guest;
      };
    };
}
