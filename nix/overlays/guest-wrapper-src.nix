# Packages the files `SANDY_GUEST_WRAPPER` points a deployed host-executor at
# (#332, CodeRabbit finding on PR #333): `nix/guest-wrapper/flake.nix` imports
# `../lib/guest.nix` and `../overlays/sandy-agent.nix` by plain relative path,
# and `nix/overlays/lib.nix` (that second import) in turn sources
# `Cargo.toml`/`Cargo.lock`/`crates`/`impls` from two levels further up. A
# crane-built `sandy-host-executor` binary carries none of this, so shipping
# `nix/guest-wrapper` on its own once installed would leave those imports
# unreachable — confirmed empirically against a real packaged (non-git) copy:
# `access to absolute path '…/lib/guest.nix' is forbidden in pure evaluation
# mode`. This copies the exact relative layout those imports need, nothing
# more; `guest_wrapper_root` (`sandy-guest-template`) is the Rust-side half of
# this contract — it builds every installable as `{root}?dir=nix/guest-wrapper`
# against whichever root `$SANDY_GUEST_WRAPPER` names, this package or the dev
# tree's own `.git` root alike.
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
      (repo + "/nix/lib")
      (repo + "/nix/overlays")
      (repo + "/nix/guest-wrapper")
    ];
  };
in
# A real derivation (`cp -r`, not the bare `lib.fileset.toSource` value
# directly) so this is buildable as an ordinary flake package
# (`nix build .#sandy-guest-wrapper`) and not just usable by string
# interpolation — both `nix build` and `"${final.sandy-guest-wrapper}"` (the
# NixOS module's `SANDY_GUEST_WRAPPER` wiring) need a real store path either
# way; `toSource`'s own result already is one, this just names it properly.
prev.runCommand "sandy-guest-wrapper" { } ''
  cp -r ${src} "$out"
''
