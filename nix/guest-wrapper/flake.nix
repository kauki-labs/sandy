{
  description = "sandy's internal wrapper flake for `sandy run --flake` (#325)";

  # Never evaluated directly: sandy drives it with `--override-input target
  # <ref>` so `target` is always the real flake a `sandy run --flake <ref>`
  # invocation named, never this flake's own locked default. `target.follows
  # = "nixpkgs"` just gives that default something resolvable to lock against
  # (an aliased input, no separate fetch) — its content is never read.
  #
  # `nixpkgs`/`microvm` are pinned to the exact revs `nix/guest/flake.lock`
  # already has, so a `sandy run --flake` build reuses that flake's already-
  # built kernel/initrd/sandy-agent store paths instead of rebuilding them
  # from a second, independently-resolved pin. Still two independent
  # lockfiles by the same convention as `nix/guest/flake.nix` vs. the root
  # flake (#324): nothing keeps them in sync beyond this initial match, and a
  # future `nix flake update` here is free to drift.
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/151fa4e8ddfdd8dd25d945ad94ed54a13de9f6e4";
    microvm = {
      url = "github:microvm-nix/microvm.nix/52860fa190bdecfe4a837de09b7f9e7babed4871";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    target.follows = "nixpkgs";
  };

  outputs =
    {
      nixpkgs,
      microvm,
      target,
      ...
    }:
    let
      inherit (nixpkgs) lib;

      # The reusable guest-composition module (#324): `mkGuest`/`mkTopology`
      # plus the `commonModule` protocol wiring they bake in, the same
      # definition `nix/guest/flake.nix` and the root flake's own
      # `lib.mkGuest`/`lib.mkTopology` export build from. Imported by
      # relative path, not as a flake input, for the same reason #324 gave:
      # this flake's own `nixpkgs`/`microvm` pins stay independent of
      # `nix/lib/guest.nix`'s caller-supplied ones.
      guestLib = import ../lib/guest.nix { inherit nixpkgs microvm; };
      inherit (guestLib) mkGuest mkTopology commonModule;

      # The sandbox agent overlay (#238/#287): imported directly, the same
      # standalone file `nix/guest/flake.nix` and `nix/lib/guest.nix` both
      # import, so the kind-3 composition below carries the identical agent
      # build `mkGuest` would have applied, not a second copy.
      agentOverlay = import ../overlays/sandy-agent.nix;

      # sandy's live hypervisor matrix (the same pairing `nix/guest/flake.nix`
      # exposes): qemu only on x86_64-linux, vfkit only on aarch64-linux
      # (vfkit requires a matching host/guest arch). Not a full 2x2 — the
      # other two pairs are not part of sandy's native-backend matrix, so
      # this flake never offers them either.
      matrix = {
        qemu = "x86_64-linux";
        vfkit = "aarch64-linux";
      };
      vmHostPackagesFor =
        hypervisor: if hypervisor == "vfkit" then nixpkgs.legacyPackages.aarch64-darwin else null;
      hypervisorModule =
        hypervisor:
        { lib, ... }:
        {
          microvm.hypervisor = hypervisor;
          microvm.vmHostPackages = lib.mkIf (vmHostPackagesFor hypervisor != null) (
            vmHostPackagesFor hypervisor
          );
        };

      # Reshapes a `hypervisor -> value` function into `matrix`'s shape keyed
      # `<system>.<hypervisor>` (the same nesting `topologies.<system>.
      # <hypervisor>` already uses, #324), so a `--flake` kind-2 attr path
      # reads exactly like a hand-written `topologies` one.
      bySystemAndHypervisor =
        f:
        lib.mapAttrs' (
          hypervisor: system: lib.nameValuePair system { ${hypervisor} = f hypervisor; }
        ) matrix;

      # One `mkGuest` call taking an already-built module value, shared by
      # kind 2 (below) and kind 4 (devshell, #326) so neither duplicates the
      # `mkGuest` invocation itself — the seam `mkGuest` already exposes to
      # `nix/guest/flake.nix`'s own `extraModules` callers.
      guestFromModuleValue =
        module: hypervisor:
        mkGuest {
          system = matrix.${hypervisor};
          inherit hypervisor;
          vmHostPackages = vmHostPackagesFor hypervisor;
          extraModules = [ module ];
        };

      # Kind 2 (nixos-module, #325): wrap one `target.nixosModules.<name>` as
      # one more `extraModules` entry. No new composition logic: an
      # externally-named module is just routed through the same seam.
      guestFromModule =
        moduleName: hypervisor: guestFromModuleValue target.nixosModules.${moduleName} hypervisor;

      # Kind 4 (devshell, #326, best-effort): synthesize a throwaway
      # nixosModule from `target.devShells.<system>.<name>` rather than
      # requiring the target to expose `nixosModules`/`nixosConfigurations`
      # itself — many real flakes only ship a devShell. Always opt-in
      # (`sandy run --flake … --from-devshell`), never auto-detected; the CLI
      # always prints a best-effort warning before using this path, since a
      # devShell was never designed as a NixOS module: its `shellHook`
      # assumes an interactive shell, the dev's own checkout as `cwd`, and
      # inherited host env (direnv, host-specific paths) — none of which
      # exist identically in the guest's login shell (#326's negative fixture
      # pins down what actually happens: silently different output, not a
      # crash).
      devShellModule =
        shellName: hypervisor:
        let
          shell = target.devShells.${matrix.${hypervisor}}.${shellName};
        in
        { lib, ... }:
        {
          # `buildInputs`/`nativeBuildInputs` both just mean "on PATH in the
          # booted guest" here — the host-side cross-compilation distinction
          # between the two has no equivalent meaning for a systemPackages
          # list, so both map the same way.
          environment.systemPackages = (shell.buildInputs or [ ]) ++ (shell.nativeBuildInputs or [ ]);
          # `mkAfter`: `nix/lib/guest.nix`'s `commonModule` pins its
          # secrets/inputs export at `mkOrder 1000` and the SANDY-READY
          # marker print at `mkOrder 2000` specifically so this hook (1500)
          # can slot between them — after secrets/inputs are ready, before
          # the marker — so the job's own command starts only once the hook
          # has run.
          programs.bash.loginShellInit = lib.mkAfter (shell.shellHook or "");
        };
      guestFromDevShell =
        shellName: hypervisor: guestFromModuleValue (devShellModule shellName hypervisor) hypervisor;

      # Every devShell name target exposes, across both guest systems — the
      # union, not just one system's, since `topologiesFromDevShell` must be
      # a real enumerable attrset for `nix eval`'s attribute-path access
      # (unlike `topologiesFromModule`, `target.devShells` is nested by
      # system first, so this can't just be `builtins.mapAttrs` over it
      # directly).
      devShellNames = lib.unique (
        lib.concatMap (system: builtins.attrNames (target.devShells.${system} or { })) (
          builtins.attrValues matrix
        )
      );

      # Kind 3 (nixos-configuration, #325): layer the same protocol wiring
      # onto an ALREADY-realized `nixosConfigurations.<name>` via
      # `extendModules` (a real `nixosSystem` method, nixpkgs'
      # `nixos/lib/eval-config.nix`), not a fresh `mkGuest` call — the
      # target's own modules (bootloader, filesystems, hardware) stay in
      # force; sandy only adds the console protocol + agent + hypervisor
      # selection on top. The riskiest of the three kinds (#325's design
      # note): a real host config's own assumptions can collide with
      # `commonModule`'s, surfaced as a module-system "conflicting
      # definition values" error rather than this flake silently picking a
      # side.
      #
      # `extendModules` keeps the target's own system fixed, so unlike kind 2
      # there is no system/hypervisor matrix to choose from — only whichever
      # hypervisor actually matches the configuration's own system is valid;
      # the other is a named `throw`, not a raw module-system stack trace.
      guestFromConfiguration =
        name: hypervisor:
        let
          cfg = target.nixosConfigurations.${name};
          required = matrix.${hypervisor};
          actual = cfg.pkgs.system;
        in
        if actual != required then
          throw "sandy: nixosConfigurations.${name} targets system ${actual}, but hypervisor ${hypervisor} needs a ${required} guest — pick a configuration that targets ${required}, or a hypervisor matching ${actual}"
        else
          cfg.extendModules {
            modules = [
              microvm.nixosModules.microvm
              { nixpkgs.overlays = [ agentOverlay ]; }
              commonModule
              (hypervisorModule hypervisor)
            ];
          };
    in
    {
      # `nix eval --json --override-input target <ref> <this>#topologiesFromModule.<attr>.<system>.<hypervisor>`
      topologiesFromModule = builtins.mapAttrs (
        moduleName: _:
        bySystemAndHypervisor (hypervisor: mkTopology (guestFromModule moduleName hypervisor))
      ) target.nixosModules;
      # `nix build --no-link --override-input target <ref> <this>#guestRunnersFromModule.<attr>.<system>.<hypervisor>`
      # realises the kernel/initrd/erofs store paths `topologiesFromModule`
      # only names — `mkTopology`'s doc comment (nix/lib/guest.nix) is explicit
      # that the caller must build these before boot.
      guestRunnersFromModule = builtins.mapAttrs (
        moduleName: _:
        bySystemAndHypervisor (
          hypervisor: (guestFromModule moduleName hypervisor).config.microvm.declaredRunner
        )
      ) target.nixosModules;

      # `nix eval --json --override-input target <ref> <this>#topologiesFromConfiguration.<attr>.<hypervisor>`
      topologiesFromConfiguration = builtins.mapAttrs (
        name: _:
        builtins.mapAttrs (hypervisor: _: mkTopology (guestFromConfiguration name hypervisor)) matrix
      ) target.nixosConfigurations;
      # Same realise-before-boot role as `guestRunnersFromModule`, for kind 3.
      guestRunnersFromConfiguration = builtins.mapAttrs (
        name: _:
        builtins.mapAttrs (
          hypervisor: _: (guestFromConfiguration name hypervisor).config.microvm.declaredRunner
        ) matrix
      ) target.nixosConfigurations;

      # `nix eval --json --override-input target <ref> <this>#topologiesFromDevShell.<name>.<system>.<hypervisor>`
      topologiesFromDevShell = builtins.listToAttrs (
        map (
          name:
          lib.nameValuePair name (
            bySystemAndHypervisor (hypervisor: mkTopology (guestFromDevShell name hypervisor))
          )
        ) devShellNames
      );
      # Same realise-before-boot role as `guestRunnersFromModule`, for kind 4.
      guestRunnersFromDevShell = builtins.listToAttrs (
        map (
          name:
          lib.nameValuePair name (
            bySystemAndHypervisor (
              hypervisor: (guestFromDevShell name hypervisor).config.microvm.declaredRunner
            )
          )
        ) devShellNames
      );
    };
}
