# Shared build helper for the sandy-agent and sandy-host-executor overlays
# (#287, the overlay split). One binary crate's build, by its exact package
# name, against the workspace's own `Cargo.lock` — `rustPlatform.buildRustPackage`,
# not this repo's own crane/rust-overlay toolchain, since an overlay has to
# work standalone in a consuming flake's nixpkgs, which has no reason to
# already carry crane or a pinned rust-overlay channel.
final: prev: pname:
let
  repo = ../..;
  src = prev.lib.fileset.toSource {
    root = repo;
    fileset = prev.lib.fileset.unions [
      (repo + "/Cargo.toml")
      (repo + "/Cargo.lock")
      (repo + "/crates")
      (repo + "/impls")
    ];
  };
in
prev.rustPlatform.buildRustPackage {
  inherit pname src;
  version = "0.1.1";
  cargoLock.lockFile = repo + "/Cargo.lock";
  cargoBuildFlags = [
    "-p"
    pname
  ];
  doCheck = false;
  meta.mainProgram = pname;
}
