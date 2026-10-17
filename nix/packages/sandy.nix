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
rec {
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
  # `daemon_e2e` (sandy-cli's end-to-end daemon suite, #212/#227) stays
  # excluded here (#233): it drives a SEPARATE `sandyd` process over a real
  # Unix socket, so attributing its coverage would need the instrumented
  # (`covCraneLib`) `sandyd` binary wired in too, not just a binary to spawn —
  # more than this check needs to solve. Its hermetic *correctness* (not
  # coverage) is `testsDaemonE2e` below.
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

  # Hermetic e2e check for `daemon_e2e` (#233): the real `sandyd` binary is
  # already built as part of the whole-workspace `sandy` package above (crane
  # installs every `[[bin]]` target it builds); this check just points
  # `daemon_e2e` at it via `$SANDYD_BIN` instead of letting the test shell out
  # to a nested `cargo build -p sandyd` mid-run, which cannot complete inside
  # a hermetic, offline nix sandbox (no target-dir lock to share, no network).
  # `daemon_e2e.rs`'s `sandyd_bin()` reads `$SANDYD_BIN` first, falling back to
  # the nested build only when it's unset (the dev-shell case). `test`/
  # `coverage` above still carry the un-filtered Rust test suite minus this one
  # file, so this is additive, not a replacement for them.
  testsDaemonE2e = craneLib.cargoNextest (
    commonArgs
    // {
      inherit cargoArtifacts;
      pnameSuffix = "-daemon-e2e";
      cargoNextestExtraArgs = "-p sandy-cli --test daemon_e2e";
      SANDYD_BIN = "${sandy}/bin/sandyd";
    }
  );
}
