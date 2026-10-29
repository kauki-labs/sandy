#!/usr/bin/env python3
"""Enforce the charter's peer-verdict gate (#528, charter #462 Gates).

A PR may merge only if a comment pins its full head SHA in a first line like
`Peer verdict (sandy-9e): APPROVE, pinned to <sha>` and no later verdict on that
SHA says CHANGES. A new push changes the head SHA, so it voids the verdict. If the
diff changes text under an `Owner decisions` heading, a comment whose first line is
`Owner sign-off: APPROVE, pinned to <sha>` is also required.

Only comments from a trusted commenter count: the repo is public, so any stranger
could otherwise post a verdict. Trusted means the shared agent account (by login) or
an OWNER, MEMBER or COLLABORATOR association. The login is needed because the Actions
token sees a private org member as CONTRIBUTOR or NONE, so the association alone
rejected the real account (found by the evidence run on #530). All sessions share one GitHub account, so
the author says nothing about WHO wrote it. This check guards against forgetting the
gate. It cannot prove who gave a verdict, or that a session did not write its own.
The reviewer name is optional (a verdict without one passes); when present it is
checked against the charter's list for an APPROVE. A CHANGES verdict counts whatever
name it carries, but like any verdict it must come from a trusted commenter.

The owner guard reads ATX headings (`## Owner decisions`) only. A bold line or a
setext heading is not recognised.

Exempt from the verdict (not from the owner guard): PRs authored by a bot (the
release PR is authored by github-actions[bot]). The title is the author's to choose,
so it is never an exemption.

CLI: check_peer_verdict.py --pr pr.json --comments comments.json --diff diff.patch
pr.json is {number, head_sha, author}; comments.json is a list of
{body, created_at, updated_at, author_association, author}. The diff should carry wide context (`git diff -U100000`) so the
nearest heading is always visible. Exit 0 passes, 1 fails with the reason on stdout.
"""

import argparse
import json
import re
import sys

REVIEWER = re.compile(r"^(sandy-[a-z0-9]+|sandbox PoC)$")
TRUSTED = {"OWNER", "MEMBER", "COLLABORATOR"}
# The one account all agent sessions post as (see the module docstring).
TRUSTED_LOGINS = {"Teebor-Choka"}
PINNED = r"[,.]?\s+pinned to\s+[`*]*(?P<sha>[0-9a-f]{40})\b"
VERDICT = re.compile(
    r"^\**Peer verdict(?:\s*\((?P<name>[^)]+)\))?\s*:\s*(?P<kind>APPROVE|CHANGES)" + PINNED,
    re.IGNORECASE,
)
OWNER_SIGN_OFF = re.compile(r"^\**Owner sign-off\s*:\s*APPROVE" + PINNED, re.IGNORECASE)
OWNER_HEADING = re.compile(r"^owner decisions\b", re.IGNORECASE)
HEADING = re.compile(r"^(#{1,6})\s+(.*?)\s*$")
FENCE = re.compile(r"^(```|~~~)")


def first_line(body: str) -> str:
    for line in body.splitlines():
        if line.strip():
            return line.strip()
    return ""


def is_trusted(comment: dict) -> bool:
    return comment.get("author") in TRUSTED_LOGINS or comment.get("author_association") in TRUSTED


def trusted(comments: list) -> list:
    return [c for c in comments if is_trusted(c)]


def ignored_note(comments: list) -> str:
    """Say how many comments were ignored as untrusted, so a failure is diagnosable."""
    ignored = [c for c in comments if not is_trusted(c)]
    if not ignored:
        return ""
    seen = sorted({c.get("author_association") or "none" for c in ignored})
    return f" ({len(ignored)} untrusted comment(s) ignored, associations seen: {', '.join(seen)})"


def changes_owner_decisions(diff: str) -> bool:
    """True if a +/- line sits inside an `Owner decisions` section of the diff.

    The section runs from its heading to the next heading of the same or a higher
    level, so `###` subsections stay inside it. Lines in fenced code are ignored, so a
    `# comment` in a code block is not read as a heading.
    """
    owner_level = 0  # 0: not inside an owner section
    in_hunk = False
    fenced = False
    for line in diff.splitlines():
        if line.startswith("diff --git "):
            in_hunk, fenced, owner_level = False, False, 0
        elif line.startswith("@@"):
            in_hunk = True
        elif in_hunk and line[:1] in (" ", "+", "-"):
            text = line[1:]
            if FENCE.match(text):
                fenced = not fenced
            elif not fenced:
                match = HEADING.match(text)
                if match:
                    level = len(match.group(1))
                    if OWNER_HEADING.match(match.group(2)):
                        owner_level = level
                    elif owner_level and level <= owner_level:
                        owner_level = 0
            if line[0] in "+-" and owner_level:
                return True
    return False


def verdict_problem(pr: dict, comments: list) -> str:
    """Empty string if the head SHA has a standing APPROVE, else the reason."""
    head = pr["head_sha"].lower()
    pinned = []
    bad_name = None
    for c in sorted(trusted(comments), key=lambda c: c.get("updated_at") or c["created_at"]):
        m = VERDICT.match(first_line(c["body"]))
        if not m or m.group("sha").lower() != head:
            continue
        kind = m.group("kind").upper()
        name = (m.group("name") or "").strip()
        if kind == "APPROVE" and name and not REVIEWER.match(name):
            bad_name = name
            continue
        pinned.append(kind)
    if pinned:
        return "" if pinned[-1] == "APPROVE" else f"the latest peer verdict on {head} is CHANGES"
    if bad_name:
        return f"the verdict names reviewer '{bad_name}', not a sandy-* session or sandbox PoC"
    return f"no peer verdict pinned to the full head SHA {head}{ignored_note(comments)}"


def evaluate(pr: dict, comments: list, diff: str):
    """Return (ok, reason). `reason` is empty on success."""
    problems = []
    if not pr["author"].endswith("[bot]"):
        problem = verdict_problem(pr, comments)
        if problem:
            problems.append(problem)
    if changes_owner_decisions(diff):
        head = pr["head_sha"].lower()
        signed = any(
            (m := OWNER_SIGN_OFF.match(first_line(c["body"]))) and m.group("sha").lower() == head
            for c in trusted(comments)
        )
        if not signed:
            problems.append(
                f"the diff changes an Owner decisions section: needs an 'Owner sign-off: APPROVE, pinned to {head}' comment"
            )
    return (not problems, "; ".join(problems))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--pr", required=True)
    parser.add_argument("--comments", required=True)
    parser.add_argument("--diff", required=True)
    args = parser.parse_args()
    with open(args.pr) as f:
        pr = json.load(f)
    with open(args.comments) as f:
        comments = json.load(f)
    with open(args.diff) as f:
        diff = f.read()
    ok, reason = evaluate(pr, comments, diff)
    print("peer verdict: ok" if ok else f"peer verdict: FAIL - {reason}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
