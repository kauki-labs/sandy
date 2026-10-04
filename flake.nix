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

    # The E1–E3 integration seam (Blocks 1–3, 5). nix-vm lives here; after an
    # E-block merges upstream, bump with `nix flake update nix-modules` so Block
    # 5's LauncherBackend builds against the new machine contract. Pinned via
    # flake.lock (origin/main at scaffold time = 69e5878); not wired into the
    # Rust build or devShell — the Rust blocks don't evaluate it.
    nix-modules.url = "github:Teebor-Choka/nix-modules";

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

          devShells.default = craneLib.devShell {
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
            ];
          };

          formatter = config.treefmt.build.wrapper;
        };
    };
}
