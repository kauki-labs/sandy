# Rust package definitions for the sandy workspace.
#
# Builds the workspace with crane and exposes the derivations the flake wires
# into `packages` and `checks`: the build itself, clippy, docs, and tests. Deps
# are compiled once (`cargoArtifacts`) and reused by every derivation.
{
  pkgs,
  lib,
  craneLib,
}:
let
  src = craneLib.cleanCargoSource ../..;

  commonArgs = {
    inherit src;
    strictDeps = true;

    # The workspace root is a virtual manifest with no `[package]`, so name and
    # version are set here rather than read from Cargo.toml.
    pname = "sandy";
    version = "0.1.0";

    buildInputs = lib.optionals pkgs.stdenv.hostPlatform.isDarwin [
      pkgs.libiconv
    ];
  };

  cargoArtifacts = craneLib.buildDepsOnly commonArgs;
in
{
  # Workspace build. Tests run in their own derivation below.
  sandy = craneLib.buildPackage (
    commonArgs
    // {
      inherit cargoArtifacts;
      doCheck = false;
    }
  );

  clippy = craneLib.cargoClippy (
    commonArgs
    // {
      inherit cargoArtifacts;
      cargoClippyExtraArgs = "--all-targets --all-features -- --deny warnings";
    }
  );

  doc = craneLib.cargoDoc (
    commonArgs
    // {
      inherit cargoArtifacts;
    }
  );

  test = craneLib.cargoNextest (
    commonArgs
    // {
      inherit cargoArtifacts;
      partitions = 1;
      partitionType = "count";
    }
  );
}
