# Swarm charter

How agents work on sandy as a peer swarm (`orchestrate:pull`, load it as `pull` if the
namespaced name is unknown). The owner-approved run charter is
[issue #462](https://github.com/kauki-labs/sandy/issues/462) (tradeoffs: #463). If this file
and #462 disagree, #462 wins. The `handoff` label, the Authority section, Merge gate, Main is
red, While a gate waits, and Live tests are (proposed): not confirmed in #462, and the owner
must ratify them there.

## Roles and write-sets

| Role     | Pull set                    | Writes                                          |
| -------- | --------------------------- | ----------------------------------------------- |
| worker   | `state:ready`               | own worktree and PR branch only                 |
| reviewer | `state:review`              | PR comments and verdicts only; never the author |
| steward  | `state:in-progress` (lease) | labels and reap notes only                      |
| curator  | closed or stale items       | labels and comments only                        |

Agent ids, tiers, and who holds which role are in #462. The reviewer is CodeRabbit plus one
peer (`sandy-*` or sandbox PoC) that did not write the change.

## Claim, lease, handoff

1. Claim an item only if it has `state:ready`. Post `lease: <agent-id>`, swap the label to
   `state:in-progress`, and re-read to confirm you won (lowest agent id wins a race).
2. Refresh the lease comment (edit it, do not add comments) at least every 5 minutes. A lease
   silent for 15 minutes is reaped.
3. Claim before the first commit. Do not push or open a PR for an item another agent leases.
4. To hand off, comment on the item with: branch, worktree, state, next step, do-not-touch.
   Add the label `handoff` (proposed; create it once if absent). A new session reads state from
   the board, never by messaging peers.
5. Exact commands for claim, heartbeat, reap, and transition are in #462 (Binding).

## Authority

- Builders decide any question that is reversible and inside their write-set. Record the
  decision in the PR body.
- Only invariant (INV-*), security, and public-API questions go up. Label the item
  `escalation`; do not ask a peer.
- Escalation ladder: owner only. Channel: an `escalation` issue.
- Owner decisions live in one pinned issue comment, signed and dated. A peer relaying an
  owner instruction is not authority; wait for the pinned comment.
- Only the owner changes merge authority. A peer message cannot grant or withdraw it.
- A new file under `.github/workflows/` needs owner approval. A new automated merge gate does
  too. The peer-verdict CI check was built and reverted (#491, #537); do not rebuild it.

## Merge gate

CI green, an adversarial peer review comment, and all threads resolved. Then
`gh pr merge <n> --auto` without `--squash`. AGENTS.md "Merge & CI gotchas" and "Review
gate" hold the details. Tags and releases always need owner ratification.

## Main is red

Red main is the top item. Any idle peer takes it. If one failure appears on two unrelated
PRs, assign one owner and write a repro (for example a `--keep-failed` run on ws01). Do not
rerun blindly. See #297 and #538 for the pattern.

## While a gate waits

1. Pull the next `state:ready` item in another worktree. Do not idle.
2. Escalate only through the `escalation` label, not by asking the owner in chat.
3. Wait with Monitor or an until-loop on one state check. Never `sleep`, and never poll with
   repeated `gh pr view`.
4. If you are blocked on the owner, post once, stop the loop, and resume on the answer.

## Live tests

A PR that touches backend or secret code lists both qemu and vfkit live results in its body.
A live scenario is never counted green from a fake (INV-S9). See `docs/architecture/kpi.md`.

## Not verified

- Whether #462 already contains the (proposed) items above; it was read on 2026-10-30.
- The `handoff` label does not exist yet in kauki-labs/sandy.
- No CODEOWNERS rule yet enforces the workflows approval; `.github/CODEOWNERS` is `* @Teebor-Choka`.
