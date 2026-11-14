#!/usr/bin/env python3
"""Stub: renders empty generated files (red phase of the test-first commit)."""

import sys
from pathlib import Path


def main(argv: list[str]) -> int:
    args = [a for a in argv if not a.startswith("--")]
    out = Path(args[0] if args else ".") / "docs" / "generated"
    out.mkdir(parents=True, exist_ok=True)
    if "--check" not in argv:
        (out / "architecture.md").write_text("")
        (out / "index.html").write_text("")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
