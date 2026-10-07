# Code-quality tools that aren't in nixpkgs, packaged for the dev shell so
# `nix develop` provides every binary the code-quality skill's discovery step
# looks for. Each tool here is NOT available from nixpkgs as of this writing:
#
#   - cargo-crap, cargo-iceberg4rust, cargo-anatomy: not packaged in nixpkgs;
#     built straight from their crates.io releases.
#   - rust-code-analysis-cli: the crates.io release predates the score-export
#     flags the skill relies on, so it's pinned to a recent upstream main commit.
#   - jscpd: the npm `jscpd` package is only a launcher for a prebuilt native
#     binary; v5 is a Rust CLI, so it's built from the tagged source instead.
#
# Hashes were resolved by first building with `pkgs.lib.fakeHash` and pinning
# the value the build error reported. The nixpkgs-provided tools
# (cargo-llvm-cov, cargo-mutants, cargo-machete, cargo-public-api,
# cargo-modules, jq) are wired directly in flake.nix instead.
{
  pkgs,
  lib ? pkgs.lib,
}:
let
  inherit (pkgs) rustPlatform fetchCrate fetchFromGitHub;

  # A cargo subcommand published to crates.io and built from that release.
  cargoCrate =
    {
      pname,
      version,
      hash,
      cargoHash,
    }:
    rustPlatform.buildRustPackage {
      inherit pname version cargoHash;
      src = fetchCrate { inherit pname version hash; };
      # These are developer tools, not libraries; skip their test suites (some
      # expect a full cargo project fixture or network) to keep the shell cheap.
      doCheck = false;
    };
in
{
  # filerisk metric.
  cargo-iceberg4rust = cargoCrate {
    pname = "cargo-iceberg4rust";
    version = "0.3.0";
    hash = "sha256-1T5L6qNRT5pczwPRcLw/38mc13s5P/W8VKbuP1IwETM=";
    cargoHash = "sha256-ksZYzvbfoAkKL0TUx2YU+GZg5q3iX5Nm712xyzfC5wU=";
  };

  # crap metric (paired with nixpkgs cargo-llvm-cov).
  cargo-crap = cargoCrate {
    pname = "cargo-crap";
    version = "0.6.1";
    hash = "sha256-d+QtkPN6lHsPjTTbpfuYy0a85zUHtNjYJKkbICM+sfk=";
    cargoHash = "sha256-R0bp0MJZECyRAC0Mugh4kf1q1l35KcCelh3qUfR9iBU=";
  };

  # iad (instability/abstractness) metric.
  cargo-anatomy = cargoCrate {
    pname = "cargo-anatomy";
    version = "0.7.7";
    hash = "sha256-g/QH1QVYW06sM8RvixAMpJw4kRi8qVGu//s2SOAPziE=";
    cargoHash = "sha256-Cdm25jK/5xpMhpQdYtfwkBqyWMK94twX9iGjJGdOlSw=";
  };

  # cognitive / mi / halstead / loc / nom / hotspots metrics. Pinned to upstream
  # main: the crates.io release lacks the per-space score export these use.
  rust-code-analysis-cli = rustPlatform.buildRustPackage {
    pname = "rust-code-analysis-cli";
    version = "0-unstable-2026-01-20";
    src = fetchFromGitHub {
      owner = "mozilla";
      repo = "rust-code-analysis";
      rev = "37e5d83c056c8cbf827223d5814a93c5218df1a9";
      hash = "sha256-HxSs4EkOT3r/hVjafmVypVAgT3WpLc/WBbRJvm7yyLg=";
    };
    # Upstream .gitignores Cargo.lock, so it isn't in the fetched source. This
    # lockfile was generated once with `cargo generate-lockfile` at the pinned
    # rev (all deps are from crates.io, no git sources); regenerate it if the
    # rev bumps.
    cargoLock.lockFile = ./rust-code-analysis.Cargo.lock;
    postPatch = "ln -s ${./rust-code-analysis.Cargo.lock} Cargo.lock";
    # Workspace repo; build only the CLI binary crate.
    cargoBuildFlags = [
      "-p"
      "rust-code-analysis-cli"
    ];
    doCheck = false;
  };

  # duplication metric. jscpd v5 is a Rust CLI (the npm `jscpd` package is only a
  # launcher that dispatches to a prebuilt native binary); build it from source.
  # The cargo workspace lives in the repo's `rust/` subdir with a committed lock.
  jscpd = rustPlatform.buildRustPackage {
    pname = "jscpd";
    version = "5.4.0";
    src = fetchFromGitHub {
      owner = "kucherenko";
      repo = "jscpd";
      rev = "v5.4.0";
      hash = "sha256-j4f1jYpj3N7hnPxm1cq8nOvi7bBgohu6nm2y0gt4e6s=";
    };
    cargoRoot = "rust";
    buildAndTestSubdir = "rust";
    cargoHash = "sha256-wFmQjNspdmeWc9k1yhQbQ0xTyXlz92DaH+NZlJUJ7bA=";
    # Builds both `cpd` and `jscpd` bins; the discovery check wants `jscpd`.
    cargoBuildFlags = [
      "-p"
      "jscpd"
    ];
    doCheck = false;
  };
}
