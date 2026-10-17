#!/usr/bin/env python3
"""Enforce the release-model invariant: every binary crate's MAJOR version
matches sandy-lib's major.

Releases are per-binary (see release-plz.toml), but a binary's major must track
the library's major so a user reading "sandy-cli 2.x" knows it is built on
"sandy 2.x". This runs in CI (.github/workflows/pr.yaml) so the invariant is
machine-enforced, not a convention that silently rots.

Resolves `version.workspace = true` to the workspace version, so it is correct
both while crates share one version and after they are split to per-crate
versions.
"""

import pathlib
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parents[2]
ANCHOR = "sandy-lib"
BINARIES = ["sandy-cli", "sandyd", "sandy-agent"]


def load(path: pathlib.Path) -> dict:
    with open(path, "rb") as f:
        return tomllib.load(f)


def main() -> int:
    ws_version = (
        load(ROOT / "Cargo.toml").get("workspace", {}).get("package", {}).get("version")
    )

    versions: dict[str, str] = {}
    for cargo in sorted(
        [*ROOT.glob("crates/*/Cargo.toml"), *ROOT.glob("impls/*/Cargo.toml")]
    ):
        pkg = load(cargo).get("package")
        if not pkg:
            continue
        version = pkg.get("version")
        if isinstance(version, dict) and version.get("workspace"):
            version = ws_version
        if version is not None:
            versions[pkg["name"]] = version

    if ANCHOR not in versions:
        print(f"FAIL: anchor crate {ANCHOR} not found in the workspace")
        return 1
    anchor_major = versions[ANCHOR].split(".")[0]

    rc = 0
    for name in BINARIES:
        if name not in versions:
            print(f"FAIL: binary crate {name} not found in the workspace")
            rc = 1
            continue
        major = versions[name].split(".")[0]
        if major != anchor_major:
            print(
                f"FAIL: {name} {versions[name]} (major {major}) "
                f"!= {ANCHOR} major {anchor_major}"
            )
            rc = 1
        else:
            print(f"ok: {name} {versions[name]} (major {major}) == {ANCHOR} major {anchor_major}")

    print(f"\nanchor: {ANCHOR} = {versions[ANCHOR]}")
    if rc:
        print("\nA binary's major must equal sandy-lib's major. Bump them together.")
    return rc


if __name__ == "__main__":
    sys.exit(main())
