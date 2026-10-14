#!/usr/bin/env python3
"""Validate a project's docs/ tree against the project-docs contract.

Single source of truth for every rule here is references/contract.md. This script
enforces the mechanical half of that contract; it never judges content quality.
Standard library only (no pyyaml): the frontmatter is flat `key: value` pairs plus
occasional `[a, b]` lists, parsed inline.

A "project" is any coherent unit of work: a code repo, a subproject, or a non-code
effort. The validator treats a project as a directory holding a docs/ tree.

Usage:
    validate_docs.py <project-path>           validate one project
    validate_docs.py --all <root-path>        validate every project found under root
    validate_docs.py <project-path> --json    machine-readable findings

Exit code 0 only when every checked project passes; nonzero if any finding is raised.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path

# --- contract constants (references/contract.md) -----------------------------

# Only active decisions get a file; discarded ones become footnotes (contract.md).
ADR_STATUSES = frozenset({"proposed", "accepted"})
UPDATED_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
KEBAB_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
MERMAID_RE = re.compile(r"(?m)^[ \t]*`{3,}[ \t]*mermaid\b")
LINK_RE = re.compile(r"\[[^\]]*\]\(([^)]+)\)")

# ADR body must contain these three labels, in this order.
ADR_REQUIRED_LABELS = ("Context", "Decision", "Consequences")
# A label written as a bold lead (**Label.**) or a heading (## Label); the set is
# fixed, so compile each form once.
ADR_LABEL_PATTERNS = {
    label: (
        re.compile(r"\*\*\s*" + re.escape(label) + r"\b"),
        re.compile(r"(?m)^#{1,6}\s+" + re.escape(label) + r"\b"),
    )
    for label in ADR_REQUIRED_LABELS
}
# Footnotes carry discarded/denied alternatives; every reference needs a definition.
FOOTNOTE_DEF_RE = re.compile(r"(?m)^\[\^([^\]]+)\]:")
FOOTNOTE_REF_RE = re.compile(r"\[\^([^\]]+)\](?!:)")

# The project-name key is `project`; `repo` is a deprecated alias still accepted.
NAME_KEYS = ("project", "repo")


@dataclass(frozen=True)
class DocSpec:
    """One doc kind the contract defines, as data the checks iterate over so the
    frontmatter, kind, and diagram rules all come from one table (contract.md)."""

    relpath: str  # path under docs/
    kind: str  # expected frontmatter `kind`
    requires_mermaid: bool


# Each required key is a name, or a tuple of interchangeable aliases.
FM_KEYS: tuple[object, ...] = ("title", "kind", NAME_KEYS, "updated")
SINGLETON_DOCS = (
    DocSpec("overview.md", "overview", True),
    DocSpec("spec.md", "spec", True),
    DocSpec("decisions/README.md", "decisions-index", False),
)
# ADRs have no `kind`; they carry `status` and never require a diagram.
ADR_REQUIRED_KEYS: tuple[object, ...] = ("title", "status", NAME_KEYS, "updated")


@dataclass
class Finding:
    project: str
    file: str | None
    rule: str
    message: str
    severity: str = "error"


# --- small helpers -----------------------------------------------------------


def _present(value: object) -> bool:
    """A frontmatter value counts as present unless it is absent or an empty/blank
    string (a non-string scalar, e.g. a list, counts as present)."""
    return value is not None and (not isinstance(value, str) or bool(value.strip()))


def _nonempty_str(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _key_satisfied(fm: dict[str, object], key: object) -> bool:
    aliases = key if isinstance(key, tuple) else (key,)
    return any(_present(fm.get(k)) for k in aliases)


# --- frontmatter parsing -----------------------------------------------------


def split_frontmatter(text: str) -> tuple[dict[str, object] | None, str]:
    """Return (frontmatter_dict, body). frontmatter_dict is None when the file
    does not open with a `---` ... `---` block. Body is the text after it."""
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return None, text
    for i in range(1, len(lines)):
        if lines[i].strip() == "---":
            fm = _parse_flat_yaml(lines[1:i])
            body = "\n".join(lines[i + 1 :])
            return fm, body
    # Opened a block but never closed it: treat as missing frontmatter.
    return None, text


def _parse_flat_yaml(lines: list[str]) -> dict[str, object]:
    out: dict[str, object] = {}
    for raw in lines:
        line = raw.rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        out[key.strip()] = _parse_scalar(value.strip())
    return out


def _parse_scalar(value: str) -> object:
    if value.startswith("[") and value.endswith("]"):
        inner = value[1:-1].strip()
        if not inner:
            return []
        return [_unquote(v.strip()) for v in inner.split(",")]
    return _unquote(value)


def _unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def _name_value(fm: dict[str, object]) -> str | None:
    """The project name from frontmatter: `project`, falling back to the `repo`
    alias. Returns None when neither is a non-empty string."""
    for key in NAME_KEYS:
        val = fm.get(key)
        if _nonempty_str(val):
            return val.strip()  # type: ignore[union-attr]
    return None


# --- per-project validation --------------------------------------------------


def validate_project(project_path: Path, project_label: str | None = None) -> list[Finding]:
    project = project_label or project_path.name or str(project_path)
    findings: list[Finding] = []
    docs = project_path / "docs"

    if not docs.is_dir():
        return [Finding(project, None, "undocumented", "no docs/ directory", "warning")]

    overview = docs / "overview.md"
    decisions = docs / "decisions"
    index = decisions / "README.md"

    # --- tree --------------------------------------------------------------
    if not overview.is_file():
        findings.append(Finding(project, "docs/overview.md", "missing-overview",
                                "docs/overview.md is required but missing"))
    if not index.is_file():
        findings.append(Finding(project, "docs/decisions/README.md", "missing-decisions-index",
                                "docs/decisions/README.md is required but missing"))

    adr_files = sorted(
        p for p in decisions.glob("*.md") if p.name != "README.md"
    ) if decisions.is_dir() else []
    if not adr_files:
        findings.append(Finding(project, "docs/decisions/", "missing-adr",
                                "docs/decisions needs at least one ADR besides README.md"))

    # --- frontmatter (contract-defined docs only; extras are ignored) ------
    # (path, kind|None for ADR, required_keys). Driven by the doc-kind table above.
    present_specs = [s for s in SINGLETON_DOCS if (docs / s.relpath).is_file()]
    checked: list[tuple[Path, str | None, tuple[object, ...]]] = [
        (docs / s.relpath, s.kind, FM_KEYS) for s in present_specs
    ]
    checked += [(adr, None, ADR_REQUIRED_KEYS) for adr in adr_files]

    texts: dict[Path, str] = {}  # each doc read once, reused below
    bodies: dict[Path, str] = {}  # body after frontmatter, reused for ADR checks
    name_values: dict[str, str] = {}  # relpath -> project value, for divergence
    for path, kind, required in checked:
        rel = path.relative_to(project_path).as_posix()
        text = path.read_text(encoding="utf-8")
        texts[path] = text
        fm, body = split_frontmatter(text)
        bodies[path] = body
        if fm is None:
            findings.append(Finding(project, rel, "frontmatter-missing",
                                    "missing YAML frontmatter block (--- ... ---)"))
            continue

        for key in required:
            if not _key_satisfied(fm, key):
                name = key[0] if isinstance(key, tuple) else key
                alias = f" (or its {key[1]!r} alias)" if isinstance(key, tuple) else ""
                findings.append(Finding(project, rel, "frontmatter-key",
                                        f"missing or empty required frontmatter key: {name}{alias}"))

        if kind is not None:
            actual = fm.get("kind")
            if actual is not None and actual != kind:
                findings.append(Finding(project, rel, "frontmatter-kind",
                                        f"kind is {actual!r}, expected {kind!r}"))
        else:
            status = fm.get("status")
            if _nonempty_str(status) and status not in ADR_STATUSES:
                findings.append(Finding(project, rel, "frontmatter-status",
                                        f"status {status!r} not one of {sorted(ADR_STATUSES)}"))

        updated = fm.get("updated")
        if _nonempty_str(updated) and not UPDATED_RE.match(updated):  # type: ignore[arg-type]
            findings.append(Finding(project, rel, "frontmatter-updated",
                                    f"updated {updated!r} is not an ISO date YYYY-MM-DD"))

        name_val = _name_value(fm)
        if name_val is not None:
            name_values[rel] = name_val

    # --- project value must be identical across all docs -------------------
    findings.extend(_check_name_divergence(project, name_values))

    # --- ADR filename + sections -------------------------------------------
    for adr in adr_files:
        rel = adr.relative_to(project_path).as_posix()
        if not KEBAB_RE.match(adr.stem):
            findings.append(Finding(project, rel, "adr-filename",
                                    f"ADR filename {adr.stem!r} is not kebab-case "
                                    r"(^[a-z0-9]+(-[a-z0-9]+)*$)"))
        findings.extend(_check_adr_sections(project, rel, bodies[adr]))

    # --- decisions index, both directions ----------------------------------
    if index.is_file():
        findings.extend(_check_index(project, project_path, texts[index], decisions, adr_files))

    # --- AGENTS.md pointer -------------------------------------------------
    findings.extend(_check_agents(project, project_path))

    # --- diagrams (per the doc-kind table) ---------------------------------
    for spec in present_specs:
        if spec.requires_mermaid and not MERMAID_RE.search(texts[docs / spec.relpath]):
            findings.append(Finding(project, f"docs/{spec.relpath}", "diagram",
                                    f"{spec.relpath} has no ```mermaid block"))

    return findings


def _check_name_divergence(project: str, name_values: dict[str, str]) -> list[Finding]:
    if len(set(name_values.values())) <= 1:
        return []
    majority = Counter(name_values.values()).most_common(1)[0][0]
    return [
        Finding(project, rel, "project-divergence",
                f"project is {val!r}, differs from {majority!r} used by the other docs")
        for rel, val in sorted(name_values.items())
        if val != majority
    ]


def _check_adr_sections(project: str, rel: str, body: str) -> list[Finding]:
    out = []
    positions: list[tuple[str, int]] = []
    for label in ADR_REQUIRED_LABELS:
        pos = _label_pos(body, label)
        if pos is None:
            out.append(Finding(project, rel, "adr-section",
                               f"ADR body missing {label!r} section "
                               f"(as **{label}.** or ## {label})"))
        else:
            positions.append((label, pos))

    # Order: only checkable when all labels are present.
    if len(positions) == len(ADR_REQUIRED_LABELS):
        ordered = [lbl for lbl, _ in sorted(positions, key=lambda lp: lp[1])]
        if ordered != list(ADR_REQUIRED_LABELS):
            out.append(Finding(project, rel, "adr-section-order",
                               f"ADR sections are {ordered}, expected "
                               f"{list(ADR_REQUIRED_LABELS)} in order"))

    out.extend(_check_footnotes(project, rel, body))
    return out


def _label_pos(body: str, label: str) -> int | None:
    """Start offset of a section label written as a bold lead (**Label.**) or a
    heading (## Label), or None if absent."""
    bold, heading = ADR_LABEL_PATTERNS[label]
    m = bold.search(body) or heading.search(body)
    return m.start() if m else None


def _check_footnotes(project: str, rel: str, body: str) -> list[Finding]:
    """Discarded/denied alternatives live in footnotes, so every `[^id]` used
    must have a `[^id]:` definition (an undefined footnote renders as raw text)."""
    defined = set(FOOTNOTE_DEF_RE.findall(body))
    referenced = set(FOOTNOTE_REF_RE.findall(body))
    return [
        Finding(project, rel, "adr-footnote",
                f"footnote [^{fid}] is referenced but never defined")
        for fid in sorted(referenced - defined)
    ]


def _check_index(project: str, project_path: Path, index_text: str, decisions: Path,
                 adr_files: list[Path]) -> list[Finding]:
    out = []
    linked = _index_links_in_dir(index_text)

    # Reverse: every in-dir link resolves to a real file.
    for target in sorted(linked):
        if not (decisions / target).is_file():
            out.append(Finding(project, "docs/decisions/README.md", "index-drift",
                               f"index links {target!r} but no such file exists"))

    # Forward: every ADR is linked from the index.
    for adr in adr_files:
        if adr.name not in linked:
            rel = adr.relative_to(project_path).as_posix()
            out.append(Finding(project, rel, "index-drift",
                               f"{adr.name} is not linked from decisions/README.md"))
    return out


def _index_links_in_dir(text: str) -> set[str]:
    """Link targets that point at a *.md file in the same directory (bare name
    or ./name), with any anchor stripped. Links to other dirs are skipped."""
    out: set[str] = set()
    for target in LINK_RE.findall(text):
        t = target.split("#", 1)[0].strip()
        if t.startswith("./"):
            t = t[2:]
        if not t.endswith(".md") or "/" in t:
            continue
        out.add(t)
    return out


def _check_agents(project: str, project_path: Path) -> list[Finding]:
    agents = project_path / "AGENTS.md"
    if not agents.is_file():
        return [Finding(project, "AGENTS.md", "agents-md",
                        "root AGENTS.md is required but missing")]
    text = agents.read_text(encoding="utf-8")
    return [
        Finding(project, "AGENTS.md", "agents-md", f"AGENTS.md does not mention {needle!r}")
        for needle in ("docs/overview.md", "docs/decisions")
        if needle not in text
    ]


# --- project discovery -------------------------------------------------------


def find_projects(root: Path) -> list[Path]:
    """Every dir under root that holds a docs/ dir OR a .git entry. A detected
    project is not descended into, so docs/decisions and nested workdirs are not
    mistaken for separate projects."""
    projects: list[Path] = []
    skip = {"node_modules", ".direnv", "target", "result", "__pycache__"}
    for dirpath, dirnames, _ in os.walk(root):
        d = Path(dirpath)
        if (d / "docs").is_dir() or (d / ".git").exists():
            projects.append(d)
            dirnames[:] = []  # prune: do not descend into a detected project
            continue
        dirnames[:] = [n for n in dirnames if n not in skip and not n.startswith(".")]
    return sorted(projects)


# --- CLI ---------------------------------------------------------------------


def _format_line(f: Finding) -> str:
    where = f"{f.project}/{f.file}" if f.file else f.project
    return f"{where}: {f.message}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate project docs against the contract.")
    parser.add_argument("path", help="project path, or root path with --all")
    parser.add_argument("--all", action="store_true",
                        help="treat path as a root and validate every project under it")
    parser.add_argument("--json", action="store_true", help="machine-readable findings")
    args = parser.parse_args(argv)

    root = Path(args.path)
    if not root.exists():
        print(f"error: path does not exist: {root}", file=sys.stderr)
        return 2

    projects = find_projects(root) if args.all else [root]

    all_findings: list[Finding] = []
    per_project: list[tuple[str, int]] = []
    for project_path in projects:
        if args.all and project_path != root:
            label = project_path.relative_to(root).as_posix()
        else:
            label = project_path.name or str(project_path)
        findings = validate_project(project_path, project_label=label)
        all_findings.extend(findings)
        per_project.append((label, len(findings)))

    if args.json:
        print(json.dumps([asdict(f) for f in all_findings], indent=2))
    else:
        for f in all_findings:
            print(_format_line(f))
        if args.all:
            print("", file=sys.stderr)
            for label, n in per_project:
                status = "PASS" if n == 0 else f"FAIL ({n})"
                print(f"{status:<10} {label}", file=sys.stderr)
        if not all_findings:
            print("ok: all checks passed", file=sys.stderr)

    return 0 if not all_findings else 1


if __name__ == "__main__":
    sys.exit(main())
