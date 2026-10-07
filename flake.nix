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
      perSystem =
        {
          config,
          system,
          lib,
          ...
        }:
        let
          overlays = [ (import inputs.rust-overlay) ];
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
            inherit pkgs lib craneLib;
          };
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
          };

          packages = sandyPackages // {
            default = sandyPackages.sandy;
          };

          checks = {
            inherit (sandyPackages)
              sandy
              clippy
              doc
              test
              ;
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
              pkgs.cargo-insta
              pkgs.gh
              # code-quality skill tools from nixpkgs
              pkgs.cargo-llvm-cov
              pkgs.cargo-mutants
              pkgs.cargo-machete
              pkgs.cargo-public-api
              pkgs.cargo-modules
              pkgs.jq
              # code-quality skill tools not in nixpkgs (nix/quality.nix)
              qualityPackages.cargo-crap
              qualityPackages.cargo-iceberg4rust
              qualityPackages.cargo-anatomy
              qualityPackages.rust-code-analysis-cli
              qualityPackages.jscpd
            ];
          };

          formatter = config.treefmt.build.wrapper;
        };
    };
}
