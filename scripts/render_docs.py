#!/usr/bin/env python3
"""Render the mermaid diagrams in a project's docs/ tree into two generated files.

Writes docs/generated/architecture.md (GitHub renders the mermaid in the file view
and in the PR diff) and docs/generated/index.html (one self-contained page). Both
come from the mermaid blocks in docs/**/*.md. Standard library only, deterministic
(no clock, no absolute paths, stable order, LF newlines), so the output can be
committed and checked for drift.

Design note, for the later port into the project-docs skill. Committing generated
files has a known cost: every PR that touches a docs/**/*.md also changes
docs/generated/*, so two such PRs conflict on the generated files even when their
source edits do not. The conflict is mechanical: rebase, rerun this script, commit.
Alternatives to weigh when porting:
  1. Do not commit; publish index.html from CI (GitHub Pages or an artifact). No
     conflicts, but the PR diff shows no rendered diagrams and the file view needs CI.
  2. Do not generate at all: GitHub already renders mermaid in the source docs.
     Loses the single page and the cross-file table of contents.
  3. Commit, but resolve conflicts with a .gitattributes merge driver that reruns
     this script. Removes the manual step; needs per-clone driver setup.
  4. A bot commits the regenerated files to the PR branch. No local step, but it
     pushes to author branches and needs write permission in CI.

Usage:
    render_docs.py [<project>]           write docs/generated/{architecture.md,index.html}
    render_docs.py --check [<project>]   exit 1 when a committed file differs from a fresh render

Exit codes: 0 ok, 1 drift (--check), 2 input error (unterminated mermaid fence, no docs/).
"""

from __future__ import annotations

import argparse
import html
import re
import sys
from dataclasses import dataclass
from pathlib import Path

GENERATED_DIR = "generated"
MD_NAME = "architecture.md"
HTML_NAME = "index.html"
# The SRI hash below belongs to exactly this version: update both together
# (curl the file, then `openssl dgst -sha384 -binary | openssl base64 -A`).
MERMAID_SRC = "https://cdn.jsdelivr.net/npm/mermaid@11.4.1/dist/mermaid.min.js"
MERMAID_SRI = "sha384-rbtjAdnIQE/aQJGEgXrVUlMibdfTSa4PQju4HDhN3sR2PmaKFzhEafuePsl9H/9I"
PARAGRAPH_MAX = 400
REGEN_HINT = "python3 scripts/render_docs.py"

# Rendered first, in this order; the rest follow alphabetically; decisions/ comes last.
FIXED_ORDER = (
    "overview.md",
    "architecture/overview.md",
    "architecture/components.md",
    "architecture/spec.md",
)

FENCE_OPEN_RE = re.compile(r"^(\s*)(`{3,}|~{3,})\s*(.*?)\s*$")
HEADING_RE = re.compile(r"^ {0,3}(#{1,6})\s+(.*?)\s*$")
HEADING_CLOSE_RE = re.compile(r"\s+#+$")
SENTENCE_END_RE = re.compile(r"[.!?](?=\s)")
BLOCK_START_RE = re.compile(r"^(\||[-*+]\s|\d+[.)]\s|>|<)")
LINK_RE = re.compile(r"!?\[([^\]]*)\]\([^)]*\)")
CODE_SPLIT_RE = re.compile(r"(`[^`]*`)")
SETEXT_RE = re.compile(r"^ {0,3}(=+|-+)[ \t]*$")
LIST_ITEM_RE = re.compile(r"^\s*([-*+]|\d+[.)])\s")
UNDERSCORE_EMPH_RE = re.compile(r"(?<!\w)(_{1,3})(?=\S)(.+?)(?<=\S)\1(?!\w)")
TAG_RE = re.compile(r"<[^>]+>")
NON_ANCHOR_RE = re.compile(r"[^\w\- ]")
CODE_SPAN_RE = re.compile(r"`([^`]+)`")


class RenderError(Exception):
    """Bad input; the CLI prints it to stderr and exits 2."""


@dataclass(frozen=True)
class Diagram:
    title: str
    anchor: str | None  # anchor of the heading in its source file; None without a heading
    paragraph: str
    body: str


@dataclass(frozen=True)
class SourceDoc:
    rel: str  # posix path under docs/
    diagrams: tuple[Diagram, ...]


def slug(text: str) -> str:
    """GitHub heading anchor: lowercase, drop punctuation except hyphens, spaces to hyphens."""
    text = UNDERSCORE_EMPH_RE.sub(r"\2", TAG_RE.sub("", LINK_RE.sub(r"\1", text)))
    return NON_ANCHOR_RE.sub("", text.lower()).replace(" ", "-")


def strip_links(text: str) -> str:
    """Links (and images) become their text; inline code spans stay verbatim.

    Relative link targets would point nowhere from docs/generated/, and a link in
    a title would nest inside the table-of-contents link.
    """
    return "".join(
        part if i % 2 else LINK_RE.sub(r"\1", part) for i, part in enumerate(CODE_SPLIT_RE.split(text))
    )


class Anchors:
    """Hands out anchors the way GitHub does: repeats get -1, -2, ... suffixes."""

    def __init__(self) -> None:
        self._seen: dict[str, int] = {}

    def add(self, text: str) -> str:
        base = slug(text)
        n = self._seen.get(base, 0)
        self._seen[base] = n + 1
        return base if n == 0 else f"{base}-{n}"


def trim_paragraph(text: str, limit: int = PARAGRAPH_MAX) -> str:
    """Cut to at most `limit` chars, on the last sentence end; else on a word."""
    if len(text) <= limit:
        return text
    ends = [m.end() for m in SENTENCE_END_RE.finditer(text[: limit + 1]) if m.end() <= limit]
    if ends:
        return text[: ends[-1]].rstrip()
    return text[:limit].rsplit(" ", 1)[0].rstrip() + "..."


def parse_doc(rel: str, text: str) -> SourceDoc:
    """Find the mermaid blocks of one file, with their heading and first paragraph.

    Fences follow CommonMark: a fence closes only on the same character, at least as
    long as the opener, so a mermaid fence inside a longer or different fence is text.
    An opener may be indented at most 3 spaces (a tab counts as 4), except inside a
    list item, where deeper indentation is the item's content. Headings are ATX
    (`## x`) or setext (text over `===` or `---`); a `---` after a blank line is a rule.
    """
    lines = text.split("\n")
    start = 0
    if lines and lines[0].strip() == "---":
        for i in range(1, len(lines)):
            if lines[i].strip() == "---":
                start = i + 1
                break

    kinds = ["text"] * len(lines)  # text | fence | heading
    headings: list[tuple[int, int, str]] = []  # (first line, last line, text)
    blocks: list[tuple[int, str]] = []  # (open line, dedented body)
    fence: tuple[str, int, int, str] | None = None  # char, length, indent, info word
    open_at = 0
    in_list = False
    for i in range(start, len(lines)):
        line = lines[i]
        if fence is None:
            if line.strip():
                if LIST_ITEM_RE.match(line):
                    in_list = True
                elif line[0] not in " \t":
                    in_list = False
            m = FENCE_OPEN_RE.match(line)
            if (
                m
                and not (m.group(2)[0] == "`" and "`" in m.group(3))
                and (in_list or len(m.group(1).expandtabs(4)) <= 3)
            ):
                info = m.group(3).split(None, 1)[0].lower() if m.group(3) else ""
                fence = (m.group(2)[0], len(m.group(2)), len(m.group(1)), info)
                open_at = i
                kinds[i] = "fence"
                continue
            h = HEADING_RE.match(line)
            if h:
                kinds[i] = "heading"
                headings.append((i, i, HEADING_CLOSE_RE.sub("", h.group(2)).strip()))
                continue
            if SETEXT_RE.match(line) and i > start and kinds[i - 1] == "text" and lines[i - 1].strip():
                first = i - 1
                while first - 1 >= start and kinds[first - 1] == "text" and lines[first - 1].strip():
                    first -= 1
                if not BLOCK_START_RE.match(lines[first].strip()):
                    for j in range(first, i + 1):
                        kinds[j] = "heading"
                    headings.append((first, i, " ".join(x.strip() for x in lines[first:i])))
            continue
        kinds[i] = "fence"
        char, length, indent, info = fence
        if re.match(rf"^\s*{re.escape(char)}{{{length},}}\s*$", line):
            if info == "mermaid":
                body = "\n".join(_dedent(b, indent) for b in lines[open_at + 1 : i])
                blocks.append((open_at, body))
            fence = None
    if fence is not None and fence[3] == "mermaid":
        raise RenderError(f"docs/{rel}:{open_at + 1}: unterminated mermaid fence")

    anchors = Anchors()
    heading_anchor = {first: anchors.add(t) for first, _last, t in headings}
    diagrams = []
    for open_line, body in blocks:
        prior = [h for h in headings if h[0] < open_line]
        if prior:
            first, last, title = prior[-1]
            diagrams.append(
                Diagram(strip_links(title), heading_anchor[first], _first_paragraph(lines, kinds, last), body)
            )
        else:
            diagrams.append(Diagram("Untitled diagram", None, "", body))
    return SourceDoc(rel, tuple(diagrams))


def _dedent(line: str, indent: int) -> str:
    strip = min(indent, len(line) - len(line.lstrip()))
    return line[strip:]


def _first_paragraph(lines: list[str], kinds: list[str], heading_line: int) -> str:
    """First plain paragraph of the section under a heading, trimmed; "" if none.

    Tables, lists, quotes, indented code and raw HTML are not prose and are skipped whole.
    """
    i = heading_line + 1
    while i < len(lines) and kinds[i] != "heading":
        if kinds[i] == "text" and lines[i].strip():
            start_line = lines[i]
            run = []
            while i < len(lines) and kinds[i] == "text" and lines[i].strip():
                run.append(lines[i].strip())
                i += 1
            indented_code = start_line.expandtabs(4).startswith("    ")
            if not indented_code and not BLOCK_START_RE.match(run[0]):
                return trim_paragraph(strip_links(" ".join(run)))
            continue
        i += 1
    return ""


def doc_order(rels: list[str]) -> list[str]:
    fixed = [r for r in FIXED_ORDER if r in rels]
    rest = sorted(r for r in rels if r not in FIXED_ORDER)
    return fixed + [r for r in rest if not r.startswith("decisions/")] + [
        r for r in rest if r.startswith("decisions/")
    ]


def read_text(path: Path, label: str) -> str:
    """UTF-8 (a BOM is dropped) with LF newlines; bad bytes are an input error."""
    try:
        return path.read_bytes().decode("utf-8-sig").replace("\r\n", "\n")
    except UnicodeDecodeError as err:
        raise RenderError(f"{label}: not valid UTF-8 ({err.reason} at byte {err.start})") from err


def collect(project: Path) -> list[SourceDoc]:
    docs = project / "docs"
    if not docs.is_dir():
        raise RenderError("no docs/ directory")
    rels = []
    for path in docs.rglob("*.md"):
        rel = path.relative_to(docs).as_posix()
        if path.is_file() and rel.split("/", 1)[0] != GENERATED_DIR:
            rels.append(rel)
    out = []
    for rel in doc_order(rels):
        text = read_text(docs / rel, f"docs/{rel}")
        doc = parse_doc(rel, text)
        if doc.diagrams:
            out.append(doc)
    return out


def project_name(project: Path) -> str:
    """`project:` from docs/overview.md frontmatter; else the directory name."""
    overview = project / "docs" / "overview.md"
    if overview.is_file():
        lines = read_text(overview, "docs/overview.md").split("\n")
        if lines and lines[0].strip() == "---":
            for line in lines[1:]:
                if line.strip() == "---":
                    break
                key, _, value = line.partition(":")
                if key.strip() in ("project", "repo") and value.strip():
                    return value.strip().strip("\"'")
    return project.resolve().name


def render_markdown(name: str, docs: list[SourceDoc]) -> str:
    anchors = Anchors()
    anchors.add(f"{name} architecture")
    anchors.add("Contents")
    toc: list[str] = []
    body: list[str] = []
    for doc in docs:
        path = f"docs/{doc.rel}"
        toc.append(f"- [{path}](#{anchors.add(path)})")
        body.append(f"## {path}\n")
        for d in doc.diagrams:
            label = d.title.replace("[", "\\[").replace("]", "\\]")
            toc.append(f"  - [{label}](#{anchors.add(d.title)})")
            body.append(f"### {d.title}\n")
            if d.paragraph:
                body.append(f"{d.paragraph}\n")
            body.append(f"```mermaid\n{d.body}\n```\n")
            frag = f"#{d.anchor}" if d.anchor else ""
            body.append(f"Source: [{path}{frag}](../{doc.rel}{frag})\n")
    parts = [
        f"# {name} architecture\n",
        f"> Generated by `scripts/render_docs.py`, do not edit. After changing any markdown file under docs/, run `{REGEN_HINT}` and commit `docs/generated/`.\n",
        "## Contents\n",
        "\n".join(toc) + "\n" if toc else "No mermaid diagrams found under docs/.\n",
        *body,
    ]
    return "\n".join(parts).rstrip("\n") + "\n"


CSS = """\
:root {
  --bg: #ffffff;
  --fg: #1f2328;
  --muted: #59636e;
  --border: #d1d9e0;
  --card: #f6f8fa;
  --link: #0969da;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0d1117;
    --fg: #e6edf3;
    --muted: #9198a1;
    --border: #3d444d;
    --card: #151b23;
    --link: #4493f8;
  }
}
* { box-sizing: border-box; }
html { color-scheme: light dark; }
body {
  margin: 0;
  padding: 0 16px;
  background: var(--bg);
  color: var(--fg);
  font: 16px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif;
  overflow-wrap: anywhere;
}
main { max-width: 960px; margin: 0 auto; padding: 24px 0 48px; }
a { color: var(--link); }
h1, h2, h3 { line-height: 1.25; }
h2 { margin-top: 2.5rem; padding-bottom: 0.3rem; border-bottom: 1px solid var(--border); }
nav.toc { background: var(--card); border: 1px solid var(--border); border-radius: 6px; padding: 8px 16px; }
nav.toc ul { margin: 4px 0; padding-left: 20px; }
.notice, .source { color: var(--muted); font-size: 0.9rem; }
section.diagram { margin: 1.5rem 0; }
.diagram-box { overflow-x: auto; background: var(--card); border: 1px solid var(--border); border-radius: 6px; padding: 12px; }
pre.mermaid { margin: 0; text-align: center; }
details { margin-top: 8px; }
details pre { overflow-x: auto; background: var(--card); border: 1px solid var(--border); border-radius: 6px; padding: 12px; }
"""

INIT_JS = """\
if (window.mermaid) {
  var dark = window.matchMedia('(prefers-color-scheme: dark)').matches;
  mermaid.initialize({startOnLoad:true, securityLevel:'strict', theme: dark ? 'dark' : 'default'});
}
"""


def _esc(text: str) -> str:
    """HTML-escape docs text; backtick spans become <code> (safe: escaped first)."""
    return CODE_SPAN_RE.sub(r"<code>\1</code>", html.escape(text))


def render_html(name: str, docs: list[SourceDoc]) -> str:
    toc: list[str] = []
    body: list[str] = []
    n = 0
    for f, doc in enumerate(docs, 1):
        path = f"docs/{doc.rel}"
        toc.append(f'<li><a href="#file-{f}">{html.escape(path)}</a>\n<ul>')
        body.append(f'<h2 id="file-{f}">{html.escape(path)}</h2>')
        for d in doc.diagrams:
            n += 1
            frag = f"#{d.anchor}" if d.anchor else ""
            href = html.escape(f"../{doc.rel}{frag}", quote=True)
            toc.append(f'<li><a href="#diagram-{n}">{_esc(d.title)}</a></li>')
            body.append(f'<section class="diagram" id="diagram-{n}">')
            body.append(f"<h3>{_esc(d.title)}</h3>")
            if d.paragraph:
                body.append(f"<p>{_esc(d.paragraph)}</p>")
            body.append(f'<div class="diagram-box"><pre class="mermaid">{html.escape(d.body)}</pre></div>')
            body.append(f"<details>\n<summary>Mermaid source</summary>\n<pre><code>{html.escape(d.body)}</code></pre>\n</details>")
            body.append(f'<p class="source">Source: <a href="{href}">{html.escape(path + frag)}</a></p>')
            body.append("</section>")
        toc.append("</ul>\n</li>")
    title = html.escape(f"{name} architecture")
    nav = "\n".join(toc) if toc else "<li>No mermaid diagrams found under docs/.</li>"
    page = f"""\
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
{CSS}</style>
</head>
<body>
<main>
<h1>{title}</h1>
<p class="notice">Generated by <code>scripts/render_docs.py</code>, do not edit. After changing any markdown file under docs/, run <code>{REGEN_HINT}</code> and commit <code>docs/generated/</code>.</p>
<nav class="toc">
<ul>
{nav}
</ul>
</nav>
{chr(10).join(body)}
</main>
<script src="{MERMAID_SRC}" integrity="{MERMAID_SRI}" crossorigin="anonymous"></script>
<script>
{INIT_JS}</script>
</body>
</html>
"""
    return page


def render_all(project: Path) -> dict[str, str]:
    docs = collect(project)
    name = project_name(project)
    return {MD_NAME: render_markdown(name, docs), HTML_NAME: render_html(name, docs)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Render docs mermaid blocks to docs/generated/.")
    parser.add_argument("project", nargs="?", default=".", help="project path (default: .)")
    parser.add_argument("--check", action="store_true", help="exit 1 if the committed files are out of date")
    args = parser.parse_args(argv)
    project = Path(args.project)
    try:
        outputs = render_all(project)
    except RenderError as err:
        print(f"error: {err}", file=sys.stderr)
        return 2

    out_dir = project / "docs" / GENERATED_DIR
    if args.check:
        stale = [
            name
            for name, text in outputs.items()
            if not (out_dir / name).is_file() or (out_dir / name).read_bytes() != text.encode("utf-8")
        ]
        for name in stale:
            print(f"docs/{GENERATED_DIR}/{name} is out of date")
        if stale:
            print(f"Run `{REGEN_HINT}` and commit docs/{GENERATED_DIR}/.", file=sys.stderr)
            return 1
        return 0

    out_dir.mkdir(parents=True, exist_ok=True)
    for name, text in outputs.items():
        (out_dir / name).write_bytes(text.encode("utf-8"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
