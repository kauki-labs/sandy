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

    flake-parts.inputs.nixpkgs-lib.follows = "nixpkgs";
    rust-overlay.inputs.nixpkgs.follows = "nixpkgs";
    treefmt-nix.inputs.nixpkgs.follows = "nixpkgs";
    pre-commit.inputs.nixpkgs.follows = "nixpkgs";
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

      # Delivered standalone from perSystem (#287, D3): the overlay must work
      # in a consuming flake's own nixpkgs, and the module must be importable
      # without evaluating this flake's perSystem at all.
      flake = {
        overlays.default = import ./nix/overlays/sandy-executor.nix;
        nixosModules.sandy-executor = import ./nix/modules/sandy-executor.nix;
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
            (import ./nix/overlays/sandy-executor.nix)
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
            # `nix build .#sandy-host-client`/`.#sandy-agent` exercises the
            # exact overlay a consumer applies, not a separate code path.
            inherit (pkgs) sandy-host-client sandy-agent;
          };

          checks = {
            inherit (sandyPackages)
              sandy
              clippy
              doc
              test
              shear
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
          };

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
              # operator can run `sandy-host-client`/`sandy-agent` from the
              # shell before any NixOS module lands them as a service.
              pkgs.sandy-host-client
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
