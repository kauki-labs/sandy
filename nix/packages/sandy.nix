# Rust package definitions for the sandy workspace.
#
# Builds the workspace with crane and exposes the derivations the flake wires
# into `packages` and `checks`: the build itself, clippy, docs, and tests. Deps
# are compiled once (`cargoArtifacts`) and reused by every derivation.
{
  pkgs,
  lib,
  craneLib,
  # A crane lib on the same pinned channel plus `llvm-tools-preview`, which
  # `cargo llvm-cov` needs to find `llvm-profdata`/`llvm-cov` in the rustc sysroot.
  # Used only for the `coverage` derivation; every other build keeps `craneLib`.
  covCraneLib,
}:
let
  # cleanCargoSource keeps only Rust sources + manifests; the topology tests
  # `include_str!` JSON fixtures at compile time, so keep `.json` too, and
  # sandy-proto's build.rs compiles `.proto` files at build time, so keep those
  # too (else the crane clippy/test derivations fail to read them in the sandbox).
  src = lib.cleanSourceWith {
    src = ../..;
    filter =
      path: type:
      (lib.hasSuffix ".json" path)
      || (lib.hasSuffix ".proto" path)
      || (craneLib.filterCargoSources path type);
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

  # Line coverage over the CI-runnable suite (tier-1/2), via `cargo llvm-cov
  # nextest`. Built with the coverage toolchain (llvm-tools-preview) and its own
  # instrumented dep layer. Only the default features are measured: the `live`
  # feature's tier-3 tests need a hypervisor + network and never run in CI, so
  # measuring them would understate real coverage. Writes an `lcov.info` the CI
  # job uploads; the per-crate summary prints in the build log.
  #
  # `daemon_e2e` (sandy-cli's end-to-end daemon suite) is excluded here too
  # (#233): it shells out to a nested `cargo build -p sandyd` mid-test to
  # locate a sibling crate's binary, which cannot complete inside this
  # derivation's hermetic, offline nix sandbox (giving the sandbox build/network
  # access to make it work would defeat crane's reproducibility, the wrong
  # direction). This temporarily drops `daemon_e2e` to dev-shell/local-only
  # coverage until #233's proper fix lands: nix builds `sandyd` as its own
  # derivation and passes its path in, the same `SANDY_BIN`-env-var pattern
  # `testsE2eCli` (flake.nix) already uses for `sandy`'s own binary, so the test
  # reads a pre-built path instead of invoking cargo itself.
  coverage = covCraneLib.cargoLlvmCov (
    commonArgs
    // {
      cargoArtifacts = covCraneLib.buildDepsOnly commonArgs;
      # `cargo llvm-cov nextest` matches the `test` check's runner, so add nextest.
      nativeBuildInputs = [ pkgs.cargo-nextest ];
      cargoLlvmCovCommand = "nextest";
      # cargo-llvm-cov writes the report during the build phase, before crane's
      # install creates $out, so `--output-path $out/lcov.info` hits a missing
      # dir. Create it first.
      preBuild = "mkdir -p \"$out\"";
      cargoLlvmCovExtraArgs = "--workspace --lcov --output-path $out/lcov.info -E 'not binary(daemon_e2e)'";
    }
  );
}
