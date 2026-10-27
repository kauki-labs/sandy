# Workaround for a currently-open nixpkgs regression (NixOS/nixpkgs#576588,
# opened 2026-10-20): cargo-llvm-cov's own build-time test suite fails on
# current nixpkgs-unstable (merge_failure_mode_all and others — a
# raw-profile-format mismatch internal to the tool's own tests, not to
# anything this repo builds). No upstream fix has merged yet. Skipping the
# package's own tests (doCheck) doesn't touch the binary we actually run —
# `cargo llvm-cov` itself works fine; only its build-time self-test fails.
# Revisit (drop this overlay) once nixpkgs#576588 closes.
final: prev: {
  cargo-llvm-cov = prev.cargo-llvm-cov.overrideAttrs (_old: {
    doCheck = false;
  });
}
