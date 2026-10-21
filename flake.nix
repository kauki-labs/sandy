{
  description = "sandy — Rust workspace";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-parts.url = "github:hercules-ci/flake-parts";
    rust-overlay.url = "github:oxalica/rust-overlay";
    crane.url = "github:ipetkov/crane";
    treefmt-nix.url = "github:numtide/treefmt-nix";
    flake-root.url = "github:srid/flake-root";
    pre-commit.url = "github:cachix/git-hooks.nix";
    # The guest-composition module (#324, `lib.mkGuest`/`lib.mkTopology`) needs
    # this to build the microVM; `nix/guest/flake.nix` pins its own copy
    # independently, so the two lockfiles can drift without either breaking.
    # `nix/lib/guest.nix` itself must stay compatible with whichever of the
    # two pins calls it — the `lib-guest-eval` check below evaluates it
    # against THIS flake's pin, and `nix/guest/flake.nix`'s own checks
    # exercise it against that nested flake's pin.
    microvm.url = "github:microvm-nix/microvm.nix";
    # Pinned for the `audit` check (CF-L-2): `cargo audit -d <path>` reads the
    # advisory TOML files directly, no git metadata needed, so the plain
    # tarball fetch is enough and the sandboxed build needs no network fetch
    # of its own.
    advisory-db = {
      url = "github:rustsec/advisory-db";
      flake = false;
    };

    flake-parts.inputs.nixpkgs-lib.follows = "nixpkgs";
    rust-overlay.inputs.nixpkgs.follows = "nixpkgs";
    treefmt-nix.inputs.nixpkgs.follows = "nixpkgs";
    pre-commit.inputs.nixpkgs.follows = "nixpkgs";
    microvm.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs =
    inputs@{ flake-parts, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      imports = [
        inputs.treefmt-nix.flakeModule
        inputs.flake-root.flakeModule
        inputs.pre-commit.flakeModule
      ];

      # Delivered standalone from perSystem (#287, D3): each overlay must work
      # in a consuming flake's own nixpkgs, and the module must be importable
      # without evaluating this flake's perSystem at all. Two overlays, not
      # one bundled default (#287 follow-up, operator ruling): sandy-agent
      # (a sandbox-image deployment) and sandy-host-executor (the ws01 host)
      # have different targets, so a consumer applies only the one(s) it
      # needs rather than always getting both.
      flake = {
        overlays = {
          sandy-agent = import ./nix/overlays/sandy-agent.nix;
          sandy-host-executor = import ./nix/overlays/sandy-host-executor.nix;
        };
        nixosModules.sandy-executor = import ./nix/modules/sandy-executor.nix;
        # The reusable guest-composition module (#324): `lib.mkGuest`/
        # `lib.mkTopology`, standalone same as the overlays above — a
        # consumer builds a `Topology` without evaluating this flake's
        # perSystem. `nix/guest/flake.nix` is this module's other caller
        # (its own qemu/vfkit guests), so the wiring has one definition.
        lib = import ./nix/lib/guest.nix {
          inherit (inputs) nixpkgs microvm;
        };
      };
      perSystem =
        {
          config,
          system,
          lib,
          ...
        }:
        let
          overlays = [
            (import inputs.rust-overlay)
            (import ./nix/overlays/sandy-agent.nix)
            (import ./nix/overlays/sandy-host-executor.nix)
          ];
          pkgs = import inputs.nixpkgs { inherit system overlays; };

          rustToolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
          craneLib = (inputs.crane.mkLib pkgs).overrideToolchain rustToolchain;

          # Dev-shell-only toolchain: the same pinned channel plus the
          # llvm-tools-preview component that cargo-llvm-cov needs to find
          # llvm-profdata/llvm-cov in the rustc sysroot. rust-toolchain.toml is
          # dependabot-managed and shared with CI, so it stays untouched; this
          # override adds the component for the shell alone. craneLib (the build)
          # keeps the unmodified toolchain.
          covToolchain = rustToolchain.override { extensions = [ "llvm-tools-preview" ]; };
          covCraneLib = (inputs.crane.mkLib pkgs).overrideToolchain covToolchain;

          # Code-quality tools absent from nixpkgs (see nix/quality.nix).
          qualityPackages = import ./nix/quality.nix { inherit pkgs lib; };

          # rustfmt.toml uses nightly-only options; format with a nightly rustfmt.
          nightlyRustfmt = pkgs.rust-bin.selectLatestNightlyWith (
            toolchain: toolchain.minimal.override { extensions = [ "rustfmt" ]; }
          );

          sandyPackages = import ./nix/packages/sandy.nix {
            inherit
              pkgs
              lib
              craneLib
              covCraneLib
              ;
            advisoryDb = inputs.advisory-db;
          };

          # CLI end-to-end suite (tests/e2e), non-live subset: drive the built
          # binary at the process boundary (argv, exit bands, `-o json` shape,
          # error paths). The live boot tests (tests/e2e/live) need a hypervisor
          # and skip off-matrix, so only the basic/ suite runs in the sandbox.
          testsE2eCli =
            pkgs.runCommand "sandy-tests-e2e-cli"
              {
                nativeBuildInputs = [
                  pkgs.bats
                  pkgs.jq
                ];
              }
              ''
                export SANDY_BIN=${sandyPackages.sandy}/bin/sandy
                cp -r ${./tests/e2e} e2e && chmod -R +w e2e
                bats e2e/basic/
                touch "$out"
              '';

          # The project-docs structure gate: the vendored validator
          # (scripts/validate_docs.py) checks the docs/ tree, frontmatter, ADR
          # sections, the decisions index (both directions), the AGENTS.md pointer,
          # and the mandatory mermaid blocks. Structure only, never content. Pure
          # Python stdlib, so it runs in the sandbox.
          projectDocs = pkgs.runCommand "sandy-project-docs" { nativeBuildInputs = [ pkgs.python3 ]; } ''
            cp -r ${./docs} docs
            cp ${./AGENTS.md} AGENTS.md
            python3 ${./scripts/validate_docs.py} .
            touch "$out"
          '';
        in
        {
          treefmt = {
            inherit (config.flake-root) projectRootFile;

            programs.rustfmt = {
              enable = true;
              package = nightlyRustfmt;
            };
            programs.nixfmt.enable = true;
            programs.taplo.enable = true;
            programs.shfmt.enable = true;
            programs.yamlfmt.enable = true;
            programs.prettier = {
              enable = true;
              includes = [
                "*.md"
                "*.json"
              ];
              excludes = [
                "*.yml"
                "*.yaml"
              ];
            };

            settings.global.excludes = [
              "LICENSE"
              "*.snap"
              "target/*"
              ".envrc"
              ".gitignore"
            ];
          };

          pre-commit.check.enable = true;
          pre-commit.settings.hooks = {
            treefmt = {
              enable = true;
              package = config.treefmt.build.wrapper;
            };
            check-executables-have-shebangs.enable = true;
            check-shebang-scripts-are-executable.enable = true;
            check-case-conflicts.enable = true;
            check-symlinks.enable = true;
            check-merge-conflicts.enable = true;
            check-added-large-files.enable = true;
            commitizen.enable = true;
            actionlint.enable = true;
            pinact = {
              enable = true;
              name = "pinact";
              description = "Check GitHub Action refs are SHA-pinned and resolvable";
              entry = "${pkgs.writeShellScript "pinact-check" ''
                token="''${GITHUB_TOKEN:-$(${pkgs.gh}/bin/gh auth token 2>/dev/null || true)}"
                if [ -z "$token" ]; then
                  echo "pinact: skipping — no GITHUB_TOKEN and gh not authenticated" >&2
                  exit 0
                fi
                export GITHUB_TOKEN="$token"
                exec ${pkgs.pinact}/bin/pinact run --check
              ''}";
              files = "^\\.github/workflows/.*\\.ya?ml$";
              language = "system";
              pass_filenames = false;
            };
            dependabot-validator = {
              enable = true;
              name = "Dependabot config validator";
              entry = "${pkgs.check-jsonschema}/bin/check-jsonschema --builtin-schema vendor.dependabot";
              files = "\\.github/dependabot\\.yml$";
              language = "system";
              pass_filenames = true;
            };
            project-docs = {
              enable = true;
              name = "project-docs structure";
              description = "Validate the docs/ tree, frontmatter, ADRs, the decisions index, and the AGENTS.md pointer";
              entry = "${pkgs.python3}/bin/python3 scripts/validate_docs.py .";
              files = "^(docs/.*|AGENTS\\.md|scripts/validate_docs\\.py)$";
              language = "system";
              pass_filenames = false;
            };
          };

          packages = sandyPackages // {
            default = sandyPackages.sandy;
            # The overlay's own packages (#287, D3), built via `pkgs` here so
            # `nix build .#sandy-host-executor`/`.#sandy-agent` exercises the
            # exact overlay a consumer applies, not a separate code path.
            # `sandy-guest-wrapper` (#332) is the packaged `SANDY_GUEST_WRAPPER`
            # source tree the host-executor NixOS module points at.
            inherit (pkgs) sandy-host-executor sandy-agent sandy-guest-wrapper;
          };

          checks = {
            inherit (sandyPackages)
              sandy
              clippy
              doc
              test
              shear
              audit
              coverage
              ;
            tests-e2e-cli = testsE2eCli;
            tests-daemon-e2e = sandyPackages.testsDaemonE2e;
            project-docs = projectDocs;
          }
          # nixosTest only evaluates on Linux (it builds a QEMU VM derivation
          # for the host system); harmless to omit it from the darwin check
          # set rather than fail evaluation there.
          // lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux {
            sandy-executor-vm = import ./nix/tests/sandy-executor-vm.nix { inherit pkgs; };
          }
          # Eval-only proof that the exported `lib.mkGuest`/`lib.mkTopology`
          # (#324) actually produce a complete `Topology` for BOTH hypervisor
          # legs, with no `extraModules` beyond what the module itself
          # carries — the same shape nix/guest/flake.nix's own qemuGuest/
          # vfkitGuest build on, proving the standalone export didn't drop
          # anything they silently relied on.
          #
          # CAUTION: `builtins.toJSON` alone is NOT eval-only here. The
          # resulting string still carries Nix's dependency "context" (each
          # embedded store path, e.g. the kernel/initrd/erofs image, is
          # recorded as a build input) — assigning that string to a real
          # derivation's environment forces Nix to REALIZE every one of
          # those paths before the derivation can build at all, which means
          # compiling a full guest system (confirmed the hard way: an
          # earlier version of this check pulled in 157 derivations,
          # including a complete x86_64-linux NixOS closure, kernel, initrd,
          # and erofs image, needing a real x86_64-linux builder — exactly
          # what this check exists to avoid).
          # `builtins.unsafeDiscardStringContext` strips that dependency
          # edge, keeping only the plain path string: Nix can always COMPUTE
          # a derivation's own output path from its inputs without building
          # it, so the check genuinely never compiles a guest artifact or
          # starts a hypervisor. Gated to one system (x86_64-linux): the
          # result doesn't depend on which system evaluates it, so running
          # it once is enough; `inputs.nixpkgs.legacyPackages.aarch64-darwin`
          # is itself an eval, not a build, so pulling it in from a Linux
          # runner for vfkit's `vmHostPackages` is fine here.
          // lib.optionalAttrs (system == "x86_64-linux") {
            lib-guest-eval =
              pkgs.runCommand "lib-guest-eval"
                {
                  qemuTopology = builtins.unsafeDiscardStringContext (
                    builtins.toJSON (
                      inputs.self.lib.mkTopology (
                        inputs.self.lib.mkGuest {
                          system = "x86_64-linux";
                          hypervisor = "qemu";
                        }
                      )
                    )
                  );
                  vfkitTopology = builtins.unsafeDiscardStringContext (
                    builtins.toJSON (
                      inputs.self.lib.mkTopology (
                        inputs.self.lib.mkGuest {
                          system = "aarch64-linux";
                          hypervisor = "vfkit";
                          vmHostPackages = inputs.nixpkgs.legacyPackages.aarch64-darwin;
                        }
                      )
                    )
                  );
                }
                ''
                  mkdir -p "$out"
                  printf '%s' "$qemuTopology" > "$out/qemu-topology.json"
                  printf '%s' "$vfkitTopology" > "$out/vfkit-topology.json"
                '';
          }
          # Eval-only proof that `nix/guest-wrapper/flake.nix` (#325, "never
          # evaluated directly" per its own description — sandy always drives
          # it with `--override-input target <ref>`) actually composes a real
          # target correctly, closing the same gap #324's PR #328 closed for
          # `lib.mkGuest`/`lib.mkTopology` themselves (`lib-guest-eval` above).
          # `--override-input` is a CLI-only mechanism, so these checks instead
          # call the wrapper's own `outputs` function directly with a fixture's
          # `outputs {}` standing in for `target` — the same "a flake.nix is
          # just an attrset" trick this file already uses for `nix/lib/guest.nix`.
          #
          # `guest-wrapper-module-eval` proves kind 2: the nixos-module-hostname
          # fixture's own `networking.hostName` collides with `commonModule`'s
          # forced `"sandy"` (#325's `lib.mkForce` fix target) and must still
          # evaluate clean.
          #
          # `guest-wrapper-configuration-eval` proves kind 3's hypervisor/system
          # matching discriminates correctly both ways: the fixture targets
          # aarch64-linux, so vfkit (the matching hypervisor) must succeed and
          # qemu (x86_64-linux required) must fail. `builtins.tryEval` reports
          # only success/failure, never the thrown message (confirmed: `nix
          # eval --expr 'builtins.tryEval (throw "x")'` returns `{ success =
          # false; value = false; }`, no trace of "x") — so the mismatch is
          # asserted by its outcome, not by pattern-matching
          # `guestFromConfiguration`'s thrown text.
          #
          # Same CAUTION as `lib-guest-eval`: `unsafeDiscardStringContext` on
          # the succeeding `toJSON`'d topologies keeps this eval-only, never
          # realizing the guest closure.
          // lib.optionalAttrs (system == "x86_64-linux") (
            let
              guestWrapperOutputsFor =
                target:
                (import ./nix/guest-wrapper/flake.nix).outputs {
                  inherit (inputs) nixpkgs microvm;
                  inherit target;
                };
              moduleFixture =
                (import ./nix/guest-wrapper/tests/fixtures/nixos-module-hostname/flake.nix).outputs
                  { };
              configFixture = (import ./nix/guest-wrapper/tests/fixtures/nixos-configuration/flake.nix).outputs {
                inherit (inputs) nixpkgs;
                self = null;
              };
              moduleTopology =
                (guestWrapperOutputsFor moduleFixture).topologiesFromModule.default.x86_64-linux.qemu;
              configMatching = (guestWrapperOutputsFor configFixture).topologiesFromConfiguration.default.vfkit;
              configMismatched = (guestWrapperOutputsFor configFixture).topologiesFromConfiguration.default.qemu;
            in
            {
              guest-wrapper-module-eval =
                pkgs.runCommand "guest-wrapper-module-eval"
                  { topology = builtins.unsafeDiscardStringContext (builtins.toJSON moduleTopology); }
                  ''
                    mkdir -p "$out"
                    printf '%s' "$topology" > "$out/topology.json"
                  '';
              guest-wrapper-configuration-eval =
                pkgs.runCommand "guest-wrapper-configuration-eval"
                  {
                    topology = builtins.unsafeDiscardStringContext (builtins.toJSON configMatching);
                    mismatchFails =
                      if (builtins.tryEval (builtins.deepSeq configMismatched configMismatched)).success then
                        "false"
                      else
                        "true";
                  }
                  ''
                    [ "$mismatchFails" = "true" ] || {
                      echo "expected topologiesFromConfiguration.default.qemu to fail (system mismatch), but it evaluated" >&2
                      exit 1
                    }
                    mkdir -p "$out"
                    printf '%s' "$topology" > "$out/topology.json"
                  '';
            }
          )
          # Eval-only proof that `services.sandy-executor.vm.enable` (ws01's
          # VM-capability hardening) is genuinely additive: OFF leaves the
          # unit byte-for-byte what it was before that option existed, ON
          # grants exactly the device/PATH/address-family set a real VM
          # dispatch needs. Never builds anything — only plain string/list
          # service-unit properties are forced, not `ExecStart` or any other
          # attribute that would pull in a package's store path (ws01 is
          # x86_64-linux only, so gated the same as the checks above). The
          # refusal path (vm.enable on, a probed fact like kvm_usable false)
          # is already exhaustively covered at the pure-function level by
          # `capability.rs`'s `vm_capability_requires_every_probed_fact` —
          # no redundant hermetic VM boot for the same logic here.
          // lib.optionalAttrs (system == "x86_64-linux") (
            let
              executorOverlays = [
                (import ./nix/overlays/sandy-agent.nix)
                (import ./nix/overlays/sandy-host-executor.nix)
              ];
              evalWith =
                extraConfig:
                (inputs.nixpkgs.lib.nixosSystem {
                  # Separate module-list entries, not a shallow `//` merge:
                  # both this base config and `extraConfig` set
                  # `services.sandy-executor.*`, and a shallow merge would
                  # drop the base's `enable`/`orchestrator`/`hostId` the
                  # instant `extraConfig` also touches `services`. The
                  # module system deep-merges across list entries by design.
                  modules = [
                    ./nix/modules/sandy-executor.nix
                    { nixpkgs.overlays = executorOverlays; }
                    {
                      services.sandy-executor = {
                        enable = true;
                        orchestrator = "127.0.0.1:1";
                        hostId = "eval-check";
                      };
                    }
                    extraConfig
                  ];
                  inherit system;
                }).config.systemd.services.sandy-executor;
              vmOff = evalWith { };
              vmOn = evalWith {
                services.sandy-executor.vm.enable = true;
              };
              # `.path` is a list of packages, not strings — names only, same
              # as `BindPaths`/`RestrictAddressFamilies` these compare
              # against plain string lists so the check stays build-free.
              pathNames = svc: map (p: p.pname or p.name) svc.path;
            in
            {
              sandy-executor-vm-opt-eval =
                pkgs.runCommand "sandy-executor-vm-opt-eval"
                  {
                    offBindPaths = builtins.toJSON vmOff.serviceConfig.BindPaths;
                    offRestrictAF = builtins.toJSON vmOff.serviceConfig.RestrictAddressFamilies;
                    offSuppGroups = builtins.toJSON vmOff.serviceConfig.SupplementaryGroups;
                    offDeviceAllow = builtins.toJSON (vmOff.serviceConfig.DeviceAllow or [ ]);
                    offPath = builtins.toJSON (pathNames vmOff);
                    onBindPaths = builtins.toJSON vmOn.serviceConfig.BindPaths;
                    onRestrictAF = builtins.toJSON vmOn.serviceConfig.RestrictAddressFamilies;
                    onSuppGroups = builtins.toJSON vmOn.serviceConfig.SupplementaryGroups;
                    onDeviceAllow = builtins.toJSON vmOn.serviceConfig.DeviceAllow;
                    onPath = builtins.toJSON (pathNames vmOn);
                  }
                  ''
                    [ "$offBindPaths" = "[]" ] || { echo "vm.enable=false must leave BindPaths empty, got: $offBindPaths" >&2; exit 1; }
                    [ "$offSuppGroups" = "[]" ] || { echo "vm.enable=false must leave SupplementaryGroups empty, got: $offSuppGroups" >&2; exit 1; }
                    [ "$offDeviceAllow" = "[]" ] || { echo "vm.enable=false must leave DeviceAllow empty, got: $offDeviceAllow" >&2; exit 1; }
                    case "$offRestrictAF" in
                      *AF_VSOCK*) echo "vm.enable=false must not add AF_VSOCK, got: $offRestrictAF" >&2; exit 1 ;;
                    esac
                    for pkg in qemu nix virtiofsd git; do
                      case "$offPath" in
                        *"\"$pkg\""*) echo "vm.enable=false must not put $pkg on PATH, got: $offPath" >&2; exit 1 ;;
                      esac
                    done
                    case "$onBindPaths" in
                      *"/dev/kvm"*"-/dev/vhost-vsock"*) ;;
                      *) echo "vm.enable=true must bind /dev/kvm and -/dev/vhost-vsock, got: $onBindPaths" >&2; exit 1 ;;
                    esac
                    [ "$onSuppGroups" = '["kvm"]' ] || { echo "vm.enable=true must add the kvm group, got: $onSuppGroups" >&2; exit 1; }
                    case "$onDeviceAllow" in
                      *"/dev/kvm rw"*"/dev/vhost-vsock rw"*) ;;
                      *) echo "vm.enable=true must allow /dev/kvm and /dev/vhost-vsock through the cgroup device policy (PrivateDevices implies DevicePolicy=closed), got: $onDeviceAllow" >&2; exit 1 ;;
                    esac
                    case "$onRestrictAF" in
                      *AF_VSOCK*) ;;
                      *) echo "vm.enable=true must add AF_VSOCK, got: $onRestrictAF" >&2; exit 1 ;;
                    esac
                    for pkg in qemu nix virtiofsd git; do
                      case "$onPath" in
                        *"\"$pkg\""*) ;;
                        *) echo "vm.enable=true must put $pkg on PATH, got: $onPath" >&2; exit 1 ;;
                      esac
                    done
                    mkdir -p "$out"
                    echo ok > "$out/result"
                  '';
            }
          );

          # Built with covCraneLib so the toolchain on PATH carries
          # llvm-tools-preview (for cargo-llvm-cov); the project itself still
          # builds against the unmodified craneLib toolchain.
          devShells.default = covCraneLib.devShell {
            inputsFrom = [ sandyPackages.sandy ];
            shellHook = config.pre-commit.installationScript;
            packages = [
              config.treefmt.build.wrapper
              nightlyRustfmt
              pkgs.cargo-audit
              pkgs.cargo-nextest
              pkgs.cargo-release
              pkgs.cargo-shear
              # Drives the automated release workflow (.github/workflows/release.yaml):
              # version-bump PRs, changelog, tag, GitHub release, crates.io publish.
              pkgs.release-plz
              pkgs.cargo-insta
              pkgs.gh
              # code-quality skill tools from nixpkgs
              pkgs.cargo-llvm-cov
              pkgs.cargo-mutants
              pkgs.cargo-machete
              pkgs.cargo-public-api
              pkgs.cargo-modules
              pkgs.jq
              # CLI end-to-end suite (tests/e2e): bats drives the built binary,
              # jq (above) asserts the `-o json` envelope shape.
              pkgs.bats
              # code-quality skill tools not in nixpkgs (nix/quality.nix)
              qualityPackages.cargo-crap
              qualityPackages.cargo-iceberg4rust
              qualityPackages.cargo-anatomy
              qualityPackages.rust-code-analysis-cli
              qualityPackages.jscpd
              # The overlay's own packages (#287, D3: dev-shell first), so an
              # operator can run `sandy-host-executor`/`sandy-agent` from the
              # shell before any NixOS module lands them as a service.
              pkgs.sandy-host-executor
              pkgs.sandy-agent
            ]
            # bwrap (the containment confinement layer this binary probes
            # for, #142) is Linux-only; the dev shell itself still has to
            # evaluate on macOS.
            ++ lib.optionals pkgs.stdenv.hostPlatform.isLinux [
              pkgs.bubblewrap
            ];
          };

          formatter = config.treefmt.build.wrapper;
        };
    };
}
