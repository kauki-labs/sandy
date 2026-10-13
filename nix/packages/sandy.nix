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
  # cleanCargoSource keeps only Rust sources + manifests; the topology tests
  # `include_str!` JSON fixtures at compile time, so keep `.json` too (else the
  # crane clippy/test derivations fail to read them in the sandbox).
  src = lib.cleanSourceWith {
    src = ../..;
    filter = path: type: (lib.hasSuffix ".json" path) || (craneLib.filterCargoSources path type);
    name = "source";
  };

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

  # Dependency hygiene gate: fail the build on any declared-but-unused workspace
  # dependency. cargo-shear is a static manifest + source scan (no compile, no
  # network), so it runs in the crane sandbox and exits non-zero on a finding.
  # AGENTS.md already prescribes `cargo shear --fix` in the dev loop; this makes
  # the same check a CI gate so an unused dep can't land. Reuses the shared
  # cargoArtifacts dep layer that clippy/test already build.
  shear = craneLib.mkCargoDerivation (
    commonArgs
    // {
      inherit cargoArtifacts;
      pnameSuffix = "-shear";
      buildPhaseCargoCommand = "cargo shear";
      nativeBuildInputs = [ pkgs.cargo-shear ];
    }
  );
}
