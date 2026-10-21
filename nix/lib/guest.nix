# The reusable sandy guest-composition module (#324): `mkGuest`/`mkTopology`
# plus the sandy console-protocol wiring (`commonModule`) they bake in, as one
# definition shared by the root flake's `lib.mkGuest`/`lib.mkTopology` export
# and `nix/guest/flake.nix`'s own qemu/vfkit guests — not two copies that can
# drift. Takes `nixpkgs`/`microvm` as the flake inputs that build the guest, so
# each caller's own lockfile pins stay in force (the root flake and
# `nix/guest/flake.nix` pin both independently; this file commits to neither).
{ nixpkgs, microvm }:
let
  # The sandbox agent baked into the guest image (#238): the sandy-agent
  # overlay (#287, the overlay split) is the SINGLE source for this build
  # now, applied as a module below rather than this flake maintaining its
  # own separate `rustPlatform.buildRustPackage` copy — one definition,
  # not two that could drift. Imported directly by relative path (not as a
  # flake input): this file already sits in the same repo as the overlay.
  agentOverlay = import ../overlays/sandy-agent.nix;

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
    { lib, pkgs, ... }:
    {
      # #325: `lib.mkForce` on every option below that NixOS's module system
      # would otherwise raise a conflicting-definitions eval error on, once an
      # arbitrary third-party `nixosModule`/`nixosConfiguration` (kinds 2/3) can
      # also set it. `boot.kernelModules` is deliberately NOT forced: it is
      # `listOf`-typed, so plain assignments from multiple modules concatenate
      # instead of conflicting — forcing it would instead *discard* a target
      # module's own kernel modules, the opposite of what kind 2/3 composition
      # needs.
      networking.hostName = lib.mkForce "sandy";
      system.stateVersion = lib.mkForce "24.11";

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
      services.getty.autologinUser = lib.mkForce "root";
      users.users.root.password = lib.mkForce "";
      # The READY marker and secret export live in bash's login init only
      # (below); if a composed module/configuration sets a different root
      # shell (NixOS's own default is `mkDefault cfg.defaultUserShell`), that
      # hook never runs and the job hangs forever with no error anywhere.
      users.users.root.shell = lib.mkForce pkgs.bashInteractive;

      # sandy stages each job secret as a read-only file named by its env-var
      # name under a virtiofs share tagged `sandy-secrets` (sandy's
      # SECRET_MOUNT_TAG). Mount it at /run/sandy/secrets; `nofail` so the
      # microvm declaredRunner boot-proof (which attaches no such share) still
      # boots. sandy's own backends always attach the share, so the device is
      # present and the mount completes before login.
      fileSystems."/run/sandy/secrets" = lib.mkForce {
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
      fileSystems."/run/sandy/inputs" = lib.mkForce {
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
      fileSystems."/run/sandy/outputs" = lib.mkForce {
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
      # virtio vsock carries the agent link from the host (#238).
      boot.kernelModules = [
        "virtiofs"
        "vmw_vsock_virtio_transport"
      ];
      environment.systemPackages = [ pkgs.sandy-agent ];

      # The login shell exports each staged secret as its `$NAME`, then prints
      # the READY_MARKER once it is up and reading — so the injected command (a
      # child `sh` of this login shell) inherits the secrets, and sandy injects
      # into a shell actually reading input, not during the getty→login handoff
      # that flushes pending tty input (the vfkit autologin race). The child
      # `sh` is not a login shell, so it never re-prints the marker.
      #
      # Split via `mkMerge`/`mkOrder` (not one plain string) so the
      # guest-wrapper's #326 devshell synthesis can slot a devShell's
      # `shellHook` in between secrets/inputs and the marker, at `mkAfter`
      # (1500) — after this block (1000), before the marker (2000) — without
      # relying on module-import order, which `types.lines` merge does not
      # otherwise guarantee between two separate modules.
      programs.bash.loginShellInit = lib.mkMerge [
        (lib.mkOrder 1000 ''
          if [ -d /run/sandy/secrets ]; then
            for f in /run/sandy/secrets/*; do
              [ -f "$f" ] && export "''${f##*/}=$(cat "$f")"
            done
          fi
          # Arbitrary guest paths: sandy writes a tab-separated manifest
          # (sandy's INPUT_MANIFEST_NAME) listing each input that asked to appear
          # at an absolute path; symlink each one to its staged entry. Line 1 is
          # the version; columns are name, guest_path, source, hash (last two
          # reserved). Runs before the READY marker so the job sees the links.
          if [ -f /run/sandy/inputs/.sandy-inputs ]; then
            tail -n +2 /run/sandy/inputs/.sandy-inputs | while IFS="$(printf '\t')" read -r name path _; do
              [ -n "$name" ] && [ -n "$path" ] || continue
              mkdir -p "$(dirname "$path")"
              ln -sfn "/run/sandy/inputs/$name" "$path"
            done
          fi
        '')
        (lib.mkOrder 2000 "printf 'SANDY-READY\\n'")
      ];

      # Keep the guest tiny and fast to boot.
      documentation.enable = lib.mkForce false;
      boot.initrd.systemd.enable = lib.mkForce false;
    };
in
{
  # Exported alongside `mkGuest`/`mkTopology` (#325): the guest-wrapper flake's
  # kind-3 strategy (`nixosConfigurations.<name>.extendModules { ... }`, a
  # already-evaluated config rather than a fresh `mkGuest` call) needs the exact
  # same protocol module `mkGuest` bakes in above — reusing this binding, not a
  # second copy, is the whole point of `commonModule` being one definition.
  inherit commonModule;

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
        { nixpkgs.overlays = [ agentOverlay ]; }
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
      # The agent this image carries, at its in-guest store path (#238).
      agent_program = "${cfg.pkgs.sandy-agent}/bin/sandy-agent";
    };
}
