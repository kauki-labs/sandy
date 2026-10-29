"""Tests for check_peer_verdict (#528). Run: python3 -m unittest scripts/ci/test_check_peer_verdict.py"""

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import check_peer_verdict as cpv  # noqa: E402

HEAD = "81306d037df9e3e7c102b646ac09b3aee08d78ba"
OLD = "4f2fd8adea84f8031be62c1eba34b69cf6638213"


def pr(author="Teebor-Choka", title="test(sandyd): a change", head=HEAD):
    return {"number": 517, "head_sha": head, "author": author, "title": title}


def comment(body, at="2026-10-29T14:58:23Z", assoc="MEMBER", updated=None):
    return {
        "body": body,
        "created_at": at,
        "updated_at": updated or at,
        "author_association": assoc,
    }


def sign_off(sha=HEAD, word="APPROVE"):
    return f"Owner sign-off: {word}, pinned to {sha}"


def verdict(sha=HEAD, kind="APPROVE", name=None):
    who = f" ({name})" if name else ""
    return f"Peer verdict{who}: {kind}, pinned to {sha}.\n\nBody."


def diff_with(heading, changed_line="+changed"):
    return (
        "diff --git a/docs/x.md b/docs/x.md\n"
        "--- a/docs/x.md\n+++ b/docs/x.md\n@@ -1,6 +1,6 @@\n"
        " # Title\n"
        f" ## {heading}\n"
        f"{changed_line}\n"
        " ## Next\n"
    )


class PeerVerdict(unittest.TestCase):
    def test_a_verdict_pinned_to_the_head_sha_passes(self):
        ok, why = cpv.evaluate(pr(), [comment(verdict())], "")
        self.assertTrue(ok, why)

    def test_the_reviewer_name_in_the_bold_form_passes(self):
        body = f"**Peer verdict (sandy-f4): APPROVE, pinned to `{HEAD}`.**\n\nBody."
        ok, why = cpv.evaluate(pr(), [comment(body)], "")
        self.assertTrue(ok, why)

    def test_a_verdict_on_an_older_sha_fails(self):
        ok, why = cpv.evaluate(pr(), [comment(verdict(sha=OLD))], "")
        self.assertFalse(ok)
        self.assertIn(HEAD, why)

    def test_no_verdict_fails(self):
        ok, why = cpv.evaluate(pr(), [comment("looks fine to me")], "")
        self.assertFalse(ok)
        self.assertIn("no peer verdict", why)

    def test_a_changes_verdict_fails(self):
        ok, _ = cpv.evaluate(pr(), [comment(verdict(kind="CHANGES"))], "")
        self.assertFalse(ok)

    def test_a_later_changes_verdict_overrides_an_earlier_approve(self):
        comments = [
            comment(verdict(), at="2026-10-29T14:00:00Z"),
            comment(verdict(kind="CHANGES"), at="2026-10-29T15:00:00Z"),
        ]
        ok, _ = cpv.evaluate(pr(), comments, "")
        self.assertFalse(ok)

    def test_a_later_approve_overrides_an_earlier_changes(self):
        comments = [
            comment(verdict(kind="CHANGES"), at="2026-10-29T14:00:00Z"),
            comment(verdict(), at="2026-10-29T15:00:00Z"),
        ]
        ok, why = cpv.evaluate(pr(), comments, "")
        self.assertTrue(ok, why)

    def test_a_reviewer_name_outside_the_charter_list_fails(self):
        ok, why = cpv.evaluate(pr(), [comment(verdict(name="zelus-a8"))], "")
        self.assertFalse(ok)
        self.assertIn("zelus-a8", why)

    def test_sandbox_poc_is_an_allowed_reviewer(self):
        ok, why = cpv.evaluate(pr(), [comment(verdict(name="sandbox PoC"))], "")
        self.assertTrue(ok, why)

    def test_a_short_sha_does_not_pin_the_head(self):
        ok, _ = cpv.evaluate(pr(), [comment(verdict(sha=HEAD[:7]))], "")
        self.assertFalse(ok)

    def test_a_bot_authored_pr_is_exempt(self):
        for author in ("dependabot[bot]", "github-actions[bot]", "renovate[bot]"):
            ok, why = cpv.evaluate(pr(author=author), [], "")
            self.assertTrue(ok, f"{author}: {why}")

    def test_a_release_title_from_a_human_author_is_not_exempt(self):
        ok, _ = cpv.evaluate(pr(title="chore: release anything"), [], "")
        self.assertFalse(ok)

    def test_a_verdict_from_a_stranger_does_not_count(self):
        for assoc in ("NONE", "CONTRIBUTOR", "FIRST_TIMER"):
            ok, _ = cpv.evaluate(pr(), [comment(verdict(), assoc=assoc)], "")
            self.assertFalse(ok, assoc)

    def test_a_collaborator_verdict_counts(self):
        ok, why = cpv.evaluate(pr(), [comment(verdict(), assoc="COLLABORATOR")], "")
        self.assertTrue(ok, why)

    def test_a_changes_verdict_with_an_unlisted_name_still_blocks(self):
        comments = [
            comment(verdict(), at="2026-10-29T14:00:00Z"),
            comment(verdict(kind="CHANGES", name="zelus-a8"), at="2026-10-29T15:00:00Z"),
        ]
        ok, _ = cpv.evaluate(pr(), comments, "")
        self.assertFalse(ok)

    def test_a_stranger_changes_verdict_does_not_block(self):
        comments = [
            comment(verdict(), at="2026-10-29T14:00:00Z"),
            comment(verdict(kind="CHANGES"), at="2026-10-29T15:00:00Z", assoc="NONE"),
        ]
        ok, why = cpv.evaluate(pr(), comments, "")
        self.assertTrue(ok, why)

    def test_an_edit_to_changes_orders_by_the_update_time(self):
        comments = [
            comment(verdict(kind="CHANGES"), at="2026-10-29T14:00:00Z", updated="2026-10-29T16:00:00Z"),
            comment(verdict(), at="2026-10-29T15:00:00Z"),
        ]
        ok, _ = cpv.evaluate(pr(), comments, "")
        self.assertFalse(ok)

    def test_a_sha_only_on_a_later_line_does_not_pin(self):
        ok, _ = cpv.evaluate(pr(), [comment(f"Peer verdict: APPROVE\n\npinned to {HEAD}")], "")
        self.assertFalse(ok)

    def test_a_conditional_approve_does_not_count(self):
        body = f"Peer verdict: APPROVE once {HEAD} is fixed"
        ok, _ = cpv.evaluate(pr(), [comment(body)], "")
        self.assertFalse(ok)

    def test_a_quoted_verdict_does_not_count(self):
        ok, _ = cpv.evaluate(pr(), [comment("> " + verdict())], "")
        self.assertFalse(ok)

    def test_a_change_under_owner_decisions_needs_an_owner_sign_off(self):
        ok, why = cpv.evaluate(pr(), [comment(verdict())], diff_with("Owner decisions"))
        self.assertFalse(ok)
        self.assertIn("Owner sign-off", why)

    def test_an_owner_sign_off_pinned_to_the_head_clears_the_owner_guard(self):
        comments = [comment(verdict()), comment(sign_off())]
        ok, why = cpv.evaluate(pr(), comments, diff_with("Owner decisions"))
        self.assertTrue(ok, why)

    def test_an_owner_sign_off_on_an_older_sha_does_not_clear_it(self):
        comments = [comment(verdict()), comment(sign_off(sha=OLD))]
        ok, _ = cpv.evaluate(pr(), comments, diff_with("Owner decisions"))
        self.assertFalse(ok)

    def test_an_owner_sign_off_that_denies_does_not_clear_it(self):
        comments = [comment(verdict()), comment(f"Owner sign-off: DENIED, was {HEAD}")]
        ok, _ = cpv.evaluate(pr(), comments, diff_with("Owner decisions"))
        self.assertFalse(ok)

    def test_an_owner_sign_off_from_a_stranger_does_not_clear_it(self):
        comments = [comment(verdict()), comment(sign_off(), assoc="NONE")]
        ok, _ = cpv.evaluate(pr(), comments, diff_with("Owner decisions"))
        self.assertFalse(ok)

    def test_a_change_in_a_subsection_of_owner_decisions_counts(self):
        diff = (
            "diff --git a/d.md b/d.md\n--- a/d.md\n+++ b/d.md\n@@ -1,6 +1,6 @@\n"
            " ## Owner decisions\n"
            " ### Decision 1\n"
            "+changed\n"
            " ## Next\n"
        )
        ok, _ = cpv.evaluate(pr(), [comment(verdict())], diff)
        self.assertFalse(ok)

    def test_a_hash_line_in_a_fenced_block_is_not_a_heading(self):
        diff = (
            "diff --git a/d.md b/d.md\n--- a/d.md\n+++ b/d.md\n@@ -1,8 +1,8 @@\n"
            " ## Owner decisions\n"
            " ```\n"
            " # a shell comment\n"
            " ```\n"
            "+changed\n"
        )
        ok, _ = cpv.evaluate(pr(), [comment(verdict())], diff)
        self.assertFalse(ok)

    def test_a_second_file_resets_the_owner_section(self):
        diff = (
            "diff --git a/a.md b/a.md\n--- a/a.md\n+++ b/a.md\n@@ -1,2 +1,2 @@\n"
            " ## Owner decisions\n"
            " text\n"
            "diff --git a/b.md b/b.md\n--- a/b.md\n+++ b/b.md\n@@ -1,2 +1,2 @@\n"
            "+changed with no heading above it\n"
        )
        ok, why = cpv.evaluate(pr(), [comment(verdict())], diff)
        self.assertTrue(ok, why)

    def test_a_change_after_the_next_same_level_heading_is_outside(self):
        diff = diff_with("Owner decisions", " unchanged").replace(
            " ## Next\n", " ## Next\n+changed\n"
        )
        ok, why = cpv.evaluate(pr(), [comment(verdict())], diff)
        self.assertTrue(ok, why)

    def test_a_change_outside_owner_decisions_needs_no_sign_off(self):
        ok, why = cpv.evaluate(pr(), [comment(verdict())], diff_with("Context"))
        self.assertTrue(ok, why)

    def test_a_removed_line_under_owner_decisions_counts(self):
        ok, _ = cpv.evaluate(
            pr(), [comment(verdict())], diff_with("Owner decisions", "-removed")
        )
        self.assertFalse(ok)

    def test_a_context_only_hunk_under_owner_decisions_is_not_a_change(self):
        ok, why = cpv.evaluate(
            pr(), [comment(verdict())], diff_with("Owner decisions", " unchanged")
        )
        self.assertTrue(ok, why)

    def test_the_owner_guard_applies_to_an_exempt_pr_too(self):
        ok, _ = cpv.evaluate(
            pr(author="github-actions[bot]"), [], diff_with("Owner decisions")
        )
        self.assertFalse(ok)


if __name__ == "__main__":
    unittest.main()
