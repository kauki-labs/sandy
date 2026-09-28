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

          pre-commit.settings.hooks = {
            treefmt = {
              enable = true;
              package = config.treefmt.build.wrapper;
            };
            check-merge-conflicts.enable = true;
            check-added-large-files.enable = true;
            commitizen.enable = true;
            sync-copilot-instructions = {
              enable = true;
              name = "Sync .claude/ instructions to Copilot files";
              entry = "bash .github/scripts/sync-copilot-instructions.sh";
              files = "(\\.claude/INSTRUCTIONS\\.md|\\.claude/rust\\.md)";
              language = "system";
              pass_filenames = false;
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
              pkgs.cargo-shear
              pkgs.cargo-insta
              pkgs.gh
            ];
          };

          formatter = config.treefmt.build.wrapper;
        };
    };
}
