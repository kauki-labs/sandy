# The sandy-executor overlay (#287, M2 spec #269 D3: "our infra ships as a nix
# overlay on a user-specified base, dev-shell first"). Adds `sandy-host-client`
# and `sandy-agent` as plain packages to whatever nixpkgs a consumer applies
# this overlay to — including a base with no rust-overlay/crane of its own.
#
# Built the same way nix/guest/flake.nix already builds sandy-agent for the
# microVM guest (plain `rustPlatform.buildRustPackage` against the workspace's
# own `Cargo.lock`), not this repo's own crane/rust-overlay toolchain: an
# overlay has to work standalone in a consuming flake's nixpkgs, which has no
# reason to already carry crane or a pinned rust-overlay channel.
final: prev:
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

  # One binary crate's build, by its exact package name (`sandy-host-client`,
  # `sandy-agent`) — no tests, no dev-only extras, just the binary this
  # overlay exists to deliver.
  mkSandyBin =
    pname:
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
    };
in
{
  sandy-host-client = mkSandyBin "sandy-host-client";
  sandy-agent = mkSandyBin "sandy-agent";
}
