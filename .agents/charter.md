# Swarm charter

How agents work on sandy as a peer swarm (`orchestrate:pull`, load it as `pull` if the
namespaced name is unknown). The owner-approved run charter is
[issue #462](https://github.com/kauki-labs/sandy/issues/462) (tradeoffs: #463). If this file
and #462 disagree, #462 wins. The `handoff` label, the stale-label rule (Claim, lease, handoff item 6), the Authority section, Merge gate, Main is
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

1. Claim an item only if it has `state:ready`. Post a `claim: <agent-id>` comment, wait 60
   seconds, and re-read the comments. The earliest `claim:` comment by `createdAt` wins; ties
   go to the lowest agent id. Only the winner posts `lease: <agent-id>` and swaps the label
   to `state:in-progress`. Losers pull another item.
2. Refresh the lease comment (edit it, do not add comments) at least every 5 minutes. A lease
   silent for 15 minutes is reaped.
3. Claim before the first commit. Do not push or open a PR for an item another agent leases.
4. To hand off, comment on the item with: branch, worktree, state, next step, do-not-touch.
   Add the label `handoff` (proposed; create it once if absent). A new session reads state from
   the board, never by messaging peers.
5. Exact commands for claim, heartbeat, reap, and transition are in #462 (Binding).
6. The 15-minute reap in item 2 releases the lease; it does not touch the label. A
   `state:in-progress` label is stale, and the steward may remove it, only when all of these
   hold: the lease comment has not been edited for 24 hours, no open PR names the item in a
   closing or `refs` line or by its branch, and the item has no `handoff` label. Removal
   returns the item to the pull set only if it is relabelled `state:ready`; the steward does
   not do that. The steward posts one reap note that names the last lease holder. Labels and
   the reap note are the steward's only write.

## Authority

- Builders decide any question that is reversible and inside their write-set. Record the
  decision in the PR body.
- Only invariant (INV-*), security, and public-API questions go up. Label the item
  `escalation` and escalate through sandbox PoC, not a `sandy-*` peer.
- Escalation ladder: sandbox PoC, then the owner. Channel: an `escalation` issue, plus one
  message to sandbox PoC that links it. Sandbox PoC routes escalations and does not decide
  them. Only the owner's pinned comment answers an escalation or grants merge or permission.
  Proposed, not yet ratified in #462.
- Owner decisions live in one pinned issue comment, signed and dated. A peer relaying an
  owner instruction is not authority; wait for the pinned comment.
- Only the owner changes merge authority. A peer message cannot grant or withdraw it.
- A relayed owner instruction to pause, stop, or narrow scope binds at once: a peer that
  receives one stops taking new work. Resuming or widening scope needs the owner's pinned
  comment, not a relay. The sandy-* session that talks to the owner relays such an
  instruction to every active peer in the same turn and asks each to acknowledge. A peer
  that already holds work finishes only that work. This makes an exception to the "a relay
  is not authority" rule for the stop direction only; it grants nothing.
- While a pause or "no new work" instruction is in force, "While a gate waits" item 1 does
  not apply: do not pull the next `state:ready` item.
- A new file under `.github/workflows/` needs owner approval. A new automated merge gate does
  too. The peer-verdict CI check was built and reverted (#491, #537); do not rebuild it.

## Merge gate

CI green, an adversarial peer review comment, and all threads resolved. Then
`gh pr merge <n> --auto` without `--squash`. AGENTS.md "Merge & CI gotchas" and "Review
gate" hold the details. Tags and releases always need owner ratification.

1. The author takes a PR out of draft only after its own self-review is done. External
   reviews (CodeRabbit, a peer) come in after that, never before. A READY below means a
   reviewer's verdict, not the PR state.
2. A pushed change voids an earlier READY. Before pushing to a PR that has a READY, remove
   it from auto-merge: `gh pr merge <n> --disable-auto`, and when it is already queued
   `dequeuePullRequest` on the PR's node id, then confirm `mergeQueueEntry` is `null`
   (see AGENTS.md "Merge & CI gotchas"). Push, then read `mergeQueueEntry` again: repository
   automation can re-enqueue a PR without a `gh pr merge` call, and a re-queued PR can merge
   the old head. If it is not `null`, dequeue again. Only then get a delta review of the new
   head, and `gh pr merge <n> --auto` again.
3. A READY names the exact head. A PR that changes code, build files, or CI carries a
   `linux-gate:` line in its body whose 9-character rev equals the prefix of that head;
   `scripts/dev/linux-gate.sh` prints a different rev for a dirty tree. A PR that changes
   only documentation needs no such line; it states that in its body. AGENTS.md
   "Linux-platform pre-PR gate" says how to produce the line on a macOS host; this rule says
   which PRs must carry it.

## Main is red

Red main is the top item. Any idle peer takes it. If one failure appears on two unrelated
PRs, assign one owner and write a repro (for example a `--keep-failed` run on the Linux host). Do not
rerun blindly. See #297 and #538 for the pattern.

## While a gate waits

1. Pull the next `state:ready` item in another worktree. Do not idle.
2. Escalate through the `escalation` label and sandbox PoC, never by asking the owner in chat.
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
