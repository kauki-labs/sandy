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
      # A minimal microVM that speaks the sandy console protocol:
      # hostName "sandy" makes getty print the `sandy login:` banner that is the
      # pinned READY_MARKER; autologin drops to a root shell on the serial console
      # that reads the injected command frame. coreutils (base64) and sh are in
      # the system path so the frame (`… | base64 -d | sh; printf 'exit=%d'`) runs.
      #
      # `hypervisor` selects the backend: qemu (Linux, console ttyS0) or
      # vfkit (macOS, console hvc0). `vmHostPackages` is the host (darwin) pkgs
      # the vfkit runner needs so its isDarwin check passes; null for qemu.
      commonModule =
        { lib, ... }:
        {
          networking.hostName = "sandy";
          system.stateVersion = "24.11";

          microvm = {
            vcpu = 2;
            mem = 512;
            graphics.enable = false;
            # Back the store as an on-disk erofs image (not the default
            # host-store virtiofs share): sandy's backends attach the store as a
            # read-only block device and refuse a virtiofs store.
            storeOnDisk = true;
          };

          # Autologin root on the serial console so the injected frame lands in a
          # shell, not a password prompt. microvm.nix points the guest console at
          # the hypervisor's serial device (ttyS0 for qemu, hvc0 for vfkit).
          services.getty.autologinUser = "root";
          users.users.root.password = "";

          # sandy stages each job secret as a read-only file named by its env-var
          # name under a virtiofs share tagged `sandy-secrets` (sandy's
          # SECRET_MOUNT_TAG). Mount it at /run/sandy/secrets; `nofail` so the
          # microvm declaredRunner boot-proof (which attaches no such share) still
          # boots. sandy's own backends always attach the share, so the device is
          # present and the mount completes before login.
          fileSystems."/run/sandy/secrets" = {
            device = "sandy-secrets";
            fsType = "virtiofs";
            options = [
              "ro"
              "nofail"
              "x-systemd.device-timeout=2s"
            ];
          };
          # sandy copies each `--input HOST:NAME` into a share tagged `sandy-inputs`
          # (sandy's INPUT_MOUNT_TAG) and mounts it read-only here, so the job reads
          # an input at /run/sandy/inputs/NAME. `nofail` so a run with no inputs (no
          # such share attached) still boots.
          fileSystems."/run/sandy/inputs" = {
            device = "sandy-inputs";
            fsType = "virtiofs";
            options = [
              "ro"
              "nofail"
              "x-systemd.device-timeout=2s"
            ];
          };
          # sandy shares a writable dir tagged `sandy-outputs` (OUTPUT_MOUNT_TAG)
          # and collects it to the host at teardown; the job writes under
          # /run/sandy/outputs/NAME. Writable (no `ro`); `nofail` so a run with no
          # outputs still boots.
          fileSystems."/run/sandy/outputs" = {
            device = "sandy-outputs";
            fsType = "virtiofs";
            options = [
              "nofail"
              "x-systemd.device-timeout=2s"
            ];
          };
          # The store is an erofs block device, so nothing else pulls in the
          # virtiofs driver; the secret share needs it. Load it in stage 2 (the
          # mount is not in the initrd).
          boot.kernelModules = [ "virtiofs" ];

          # The login shell exports each staged secret as its `$NAME`, then prints
          # the READY_MARKER once it is up and reading — so the injected command (a
          # child `sh` of this login shell) inherits the secrets, and sandy injects
          # into a shell actually reading input, not during the getty→login handoff
          # that flushes pending tty input (the vfkit autologin race). The child
          # `sh` is not a login shell, so it never re-prints the marker.
          programs.bash.loginShellInit = ''
            if [ -d /run/sandy/secrets ]; then
              for f in /run/sandy/secrets/*; do
                [ -f "$f" ] && export "''${f##*/}=$(cat "$f")"
              done
            fi
            printf 'SANDY-READY\n'
          '';

          # Keep the guest tiny and fast to boot.
          documentation.enable = lib.mkForce false;
          boot.initrd.systemd.enable = lib.mkForce false;
        };

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

      mkGuest =
        {
          system,
          hypervisor,
          vmHostPackages ? null,
          extraModules ? [ ],
        }:
        nixpkgs.lib.nixosSystem {
          inherit system;
          modules = [
            microvm.nixosModules.microvm
            commonModule
            (
              { lib, ... }:
              {
                microvm.hypervisor = hypervisor;
                # The vfkit runner is a darwin script driving a Linux guest, so it
                # needs the host (darwin) package set; qemu runs on the Linux host.
                microvm.vmHostPackages = lib.mkIf (vmHostPackages != null) vmHostPackages;
              }
            )
          ]
          ++ extraModules;
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

      # Emit sandy's `Topology` JSON from a built guest config: the kernel/initrd/
      # erofs-store paths, the full kernel cmdline (console device per hypervisor),
      # cpu/mem, extra virtiofs shares, and the hypervisor tag. sandy reads this
      # via `nix eval --json <flake>#topologies.<system>.<hypervisor>` (INV-TOPOLOGY).
      # Realise the paths first (build the guest/runner) so they exist at boot.
      mkTopology =
        cfg:
        let
          c = cfg.config;
          consoleDev = if c.microvm.hypervisor == "vfkit" then "hvc0" else "ttyS0";
        in
        {
          kernel = "${c.microvm.kernel}/${c.system.boot.loader.kernelFile}";
          initrd = "${c.microvm.initrdPath}";
          store.erofs_image = "${c.microvm.storeDisk}";
          kernel_cmdline = builtins.concatStringsSep " " (
            [
              "console=${consoleDev}"
              "reboot=t"
              "panic=-1"
            ]
            ++ c.microvm.kernelParams
          );
          cpu = c.microvm.vcpu;
          mem = c.microvm.mem;
          # Only extra virtiofs shares (the store is the erofs image above).
          shares = map (s: {
            inherit (s) tag;
            host = "${s.source}";
            guest = s.mountPoint;
          }) (builtins.filter (s: s.proto == "virtiofs") c.microvm.shares);
          hypervisor = c.microvm.hypervisor;
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

      # sandy's `Topology` per guest: `nix eval --json <flake>#topologies.<sys>.<hv>`.
      topologies = {
        x86_64-linux.qemu = mkTopology qemuGuest;
        aarch64-linux.vfkit = mkTopology vfkitGuest;
      };
    };
}
