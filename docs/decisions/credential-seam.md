---
title: "Decisions: credential seam (CredentialProvider)"
status: accepted
project: sandy
updated: 2026-10-25
---

# Decisions: credential seam (`CredentialProvider`)

Minting a short-lived, least-privilege forge token for a job, delivering it
in-guest, refreshing it mid-run, and revoking it at teardown. Subsystem spec:
[`../architecture/spec.md#4-credential-seam-credentialprovider`](../architecture/spec.md#4-credential-seam-credentialprovider).

## 1. Mint → stage → revoke bracket, fail-closed

**Status:** accepted. **Upholds:** INV-7.

**Context.** A job that needs a forge token must never run without one when one
was requested, and a token must never outlive the job.

**Decision.** `run_job_with_credential` mints **before** boot; a mint failure
returns an infra fault with **no boot**. The lease is revoked on every path (ok,
error, kill).

**Consequences.** A credentialed run is all-or-nothing: either the token exists
and is delivered, or the run fails closed as infra (retryable), never a degraded
run with a missing token. Proven live by K10.

**Set aside.** Best-effort mint (boot anyway, hope the token shows up): rejected,
it would turn a credential outage into a silent task failure.

## 2. Trust root, not a shared server

**Status:** accepted. **Upholds:** INV-1 for the trust root, which never
leaves the controller. The per-job installation token is a stated interim
exception to INV-1 (it reaches the guest's environment); see the residual
risk below.

**Context.** Handing every job a long-lived shared token is a broad blast radius;
a central token-minting service is another thing to run and secure.

**Decision.** The provider is a GitHub App whose private key stays on the
controller (`sandy cred github register/import/verify/deregister`). Each job mints
an **installation token** scoped to its repos/capabilities. The minted token is a
secret, delivered over the secret channel.

**Consequences.** Each job gets a narrow, short-lived token; the trust root never
leaves the controller. The provider is a seam (`CredentialProvider`), so GitLab
or another forge is a new adapter.

**Residual risk, interim.** The installation token is staged on the secret
share and the guest login shell exports it as `$GITHUB_TOKEN`, so a hostile job
can read and exfiltrate it (see
[`spec.md`'s attacker model](../architecture/spec.md#attacker-model)). A copied
token stays usable only until the controller revokes it: at the next refresh,
which supersedes and revokes the stale token (decision 3), or at job teardown
at the latest, which revokes the live token on every path (decision 1) —
whichever comes first, not the token's full native TTL. The token's narrow
scope bounds the damage further, but egress has to allow the forge for git to
work at all, so the token leaving with the job is not prevented today. The
exit is an in-flight token swap at the #360 mediation
proxy, tracked in #372: the proxy terminates TLS and inserts the token on the
wire as the request leaves, so the token never has to sit in the guest. #360's
v1 deliberately leaves TLS termination out, so the swap waits on #372. The
owner ruled that the swap is a separate injector component, not the proxy; see
[`credential-injector.md`](credential-injector.md) (proposed, #707). If #372
is dropped, this residual risk becomes a permanent, accepted one.

## 3. Mid-run refresh

**Status:** accepted.

**Context.** A job can outlive an installation token's TTL, and `git credential
fill` must keep serving a valid token without the job seeing it on argv or console.

**Decision.** A refresh thread with a large margin and short tick re-mints and
rewrites the live secret file; the guest's `git credential fill` serves the fresh
token.

**Consequences.** A long job keeps working across token expiry; the value is never
exposed on argv/console. Proven live by K11 (`live_refresh.rs`), which refuses on
default margins rather than skip-greening (INV-S9).

## 4. Trust material is written only into a private trust-roots dir

**Status:** accepted. **Upholds:** INV-1.

**Context.** The GitHub App private key and the trust-root configs live in
`$XDG_CONFIG_HOME/sandy/trust-roots` (or `~/.config/...`). The key was written with
`truncate`, which kept an existing file's mode and followed a symlink at its path.
The config was written through a fixed `<path>.tmp` that also followed a symlink.
The dir itself was created at the umask's mode and never checked (#194).

**Decision.** Both go through `sandy::write_trust_secret`, which uses
`sandy_fsutil::OwnedDir`: the dir is created `0700` if missing, and an existing
one must be this user's and not group- or world-writable. Each file is written
`0600` from creation, with `O_EXCL | O_NOFOLLOW`, under a unique temp name, then
renamed into place. An unsafe existing dir is refused, not repaired. The error
says another user may have changed the key or config, asks for a check, and then
names `chmod 700`.

**Consequences.** Reads of the App key and trust-root configs (#200) open the
dir first and check it on that handle: a dir that others can write to, or another
user owns, is refused with the same tamper message before any file in it is
opened, with no backwards compatibility (operator ruling). The file is then opened
relative to the checked dir, without following a symlink at the leaf, and checked
on its own handle: it must be a regular file owned by the current user, or it is
refused, since another user must have put it there, and writable by no one else,
or it is refused, since it may have been changed in place. An existing install
whose trust-roots dir is group-writable (for example, registered under umask
`0002`, so `0775`) is refused on every read, register, import, and deregister
(which loads the config first) until the user verifies the files and runs
`chmod 700`, so its credentialed runs stop until then. Deregister's shred never
follows a symlink at the key path. That is a deliberate break. The reader follows
a symlinked trust-roots dir and checks the dir it resolves to; the writers refuse
one. Register checks the dir before capture, so the refusal
never leaves a forge App behind whose key it could not save. The trust-root name is
checked to be a single file name before anything is created.

**Set aside.** Tightening the dir to `0700` and continuing: if the dir was writable
by others, the key or config in it may already have been swapped, and continuing
would trust it silently.

## 5. Trust-root protection today is perms-only, not encryption-at-rest

**Status:** accepted.

**Context.** Decision 4's `0700` dir / `0600` files with `O_NOFOLLOW` (`open_trust_dir`,
`open_trust_file`, `crates/sandy/src/cred.rs`) keep other local users and symlink
tricks out, but the App private key and trust-root configs still sit on disk as
plaintext readable by the controller's own user.

**Decision.** That is the floor enforced today, and no more: encrypted-at-rest
storage for the trust-roots dir (disk encryption, a secrets manager, a sealed
box) is the operator's deployment responsibility, not something sandy enforces
in code.

**Consequences.** A controller host with unencrypted disk and an attacker who
gains the controller user's own account (not just another local user) can read
the trust material directly; perms-only protection does not defend against
that. Operators who need that guarantee supply it at the deployment layer.

## 6. `gc` reclaims a leaked `cred-*`/`verify-*` staging dir by mtime, heartbeated while live

**Status:** accepted.

**Context.** `sandy run --credential` and the trust-root verify probe stage a
token into a fresh, randomly named private dir under the sandy staging base
(`cred-<hex>` / `verify-<hex>`, #174's `private_staging_dir`). A drop guard
removes it on normal exit or panic, but SIGKILL or a crash before the guard
runs leaves it behind, still holding a token valid for up to its mint TTL
(#195).

**Decision.** `sandy gc` sweeps `cred-*`/`verify-*` dirs under the staging base
whose mtime is at least `MAX_TTL_SECS` old
(`sandy_fsutil::sweep_stale_staging_dirs`). Age is read from the dir's own
mtime rather than a separately tracked start time, so the same mechanism that
ages a leaked dir out also has to not age out a live one. That requirement is
not automatic: the mid-run refresh thread only rewrites `cred_dir`'s file when
`should_refresh` actually fires, and a provider's native token TTL (GitHub
~1h) can exceed `MAX_TTL_SECS` (3000s) between refreshes, so a job quiet that
long would otherwise look abandoned. The refresh loop therefore heartbeats
`cred_dir`'s mtime every tick, independent of whether a refresh fires; a
`kill -9`'d process stops ticking, so a genuinely leaked dir still ages out
and gets swept. `safe_heartbeat_tick` refuses a `SANDY_REFRESH_TICK_SECS` at
or above `MAX_TTL_SECS - CALL_DEADLINE` and falls back to the 60s default,
leaving margin for one stalled adapter call between heartbeats, not just
bounding the tick in isolation (the Consequences below has the full
accounting and the one residual this doesn't close). The sweep is
best-effort within `gc`: a staging base that cannot be validated or listed is
logged and skipped, and a single entry that can't be read, stat'ed, or
removed is skipped and retried on a later `gc`, neither ever blocking `gc`'s
primary job-record eviction.

The heartbeat alone isn't enough: `refresh_loop` touches `cred_dir`'s mtime
and then calls `refresh_once` synchronously, so a stalled `GithubAdapter`
call would block the next heartbeat for as long as the call hangs. Every
GitHub API call this adapter makes (mint, refresh, revoke, uninstall, the
permissions read) runs under one wall-clock deadline,
`CALL_DEADLINE = MAX_TTL_SECS / 2` (`with_call_deadline`), covering the whole
call including whatever retries octocrab makes internally, not a per-attempt
figure that needs multiplying out by a retry count. If octocrab's own
retries don't finish inside that one deadline, the call just fails, the same
outcome as any other failed mint/refresh/revoke. A single deadline around
the whole call also means a connection that keeps resetting a per-read
timeout by trickling bytes still can't outlast it, wherever in the
connect/read/retry sequence the stall happens.

**Consequences.** `refresh_once` makes two sequential adapter calls on its
live path, `refresh` then `revoke` of the superseded token (and on its
stage-failure path, `refresh` then `revoke_orphan`, still two), so the
relevant safety margin is not one `CALL_DEADLINE` but the gap between
`cred_dir` mtime touches across the whole `refresh_once` call. That margin
rests on a side effect, not just the heartbeat: staging the refreshed token
creates and renames a temp file inside `cred_dir` between the `refresh` and
`revoke` calls, which touches the dir's own mtime the same way the heartbeat
does, resetting the gap. So the worst case per loop iteration is
`CALL_DEADLINE + tick`, not `2 * CALL_DEADLINE`: whichever of `refresh` or
`revoke` stalls to the deadline, the stage write already reset the clock
before or after it. At the 60s default tick that is about 1560s, safely
under `MAX_TTL_SECS`. Of the two residuals specific to this two-call margin,
one is now closed (`safe_heartbeat_tick` caps against it) and one remains
open, tracked separately; the last two bullets below are separate residuals
of their own, not part of this margin:

- **Closed.** `safe_heartbeat_tick` used to cap the tick to below
  `MAX_TTL_SECS` alone (up to 2999s), not to something that keeps
  `CALL_DEADLINE + tick` under `MAX_TTL_SECS`; a `SANDY_REFRESH_TICK_SECS`
  configured near that ceiling could push the worst case to about 4500s,
  over the sweep threshold. `CALL_DEADLINE` is now exported through the
  facade (`sandy::CALL_DEADLINE`) so `safe_heartbeat_tick` (in `sandy-cli`)
  caps against `MAX_TTL_SECS - CALL_DEADLINE` instead, keeping
  `CALL_DEADLINE + tick` under the sweep threshold for any accepted tick.
- **Open, tracked as [#364](https://github.com/kauki-labs/sandy/issues/364).**
  The stage write's own create step can itself fail before touching
  `cred_dir` (drawing a temp name, or the temp file's own `O_CREAT|O_EXCL`
  write, on `ENOSPC`/`EDQUOT`/`EMFILE`). On that narrow path, `refresh_once`
  goes `refresh` then `revoke_orphan` with no stage touch in between, so
  both calls' worst cases compound: `2 * CALL_DEADLINE + tick`, about 3060s
  at the default tick, just over the sweep threshold. It needs both a
  stage-create failure and two full-length stalls at once. Closing it means
  restructuring `refresh_once`'s stage-failure path to touch `cred_dir`'s
  mtime before calling `revoke_orphan`, a bigger change than this decision's
  timeout sizing; deferred to the linked issue.
- Retrying a non-idempotent `POST /access_tokens` was already possible under
  octocrab's default retry policy before this change; nothing here
  introduces it. If GitHub completes the mint but the response is lost to a
  retry, or `CALL_DEADLINE` cuts a request off after GitHub already
  processed it, that token is unrecorded by `self.mints`, so neither the
  retry's own eventual success nor a later `revoke_orphan` call can revoke
  the earlier one; it lives out its native ~1h expiry instead of the shorter
  TTL the seam otherwise enforces.
- Once the job's run finishes, the refresh thread stops on the next loop
  check of the stop signal, not mid-call. An in-flight `refresh_once` delays
  that check, and the explicit teardown revoke, by up to the same windows
  above. Harmless: the job has already finished by then, so a `gc` sweep
  racing the job's own teardown cleanup only removes the same files
  slightly early.

A `verify-*` dir (the trust-root verify probe) gets no heartbeat, but the
permissions-read call happens before the probe dir even exists, so it never
counts against the dir's lifetime. On the probe's success path, `mint` (at
most `CALL_DEADLINE`) is followed by the same stage touch, then `revoke` (at
most `CALL_DEADLINE`), so the dir is at most about `CALL_DEADLINE` old when
verify removes it, well under `MAX_TTL_SECS`. On the stage-failure branch it
can reach `2 * CALL_DEADLINE` (`MAX_TTL_SECS`), but no token is staged in
the dir by then, so a sweep there is harmless, and verify's own best-effort
`remove_dir_all` cleans it up regardless.

**Set aside.** Tracking each staging dir's mint time in a side file (instead
of reading mtime) was considered and rejected: it adds a second piece of
state that could drift from the dir's actual contents, where mtime is already
authoritative and free.

## 7. The terminal journal write waits for final redaction, instead of amending

**Status:** accepted. **Upholds:** INV-6, M-6.

**Context.** `run_job`'s terminal journal write (step 6, INV-6) happens right
after its own console redaction pass, which only ever sees the credential's
initial token — `run_job_with_credential` only learns about a mid-run refresh
after its refresh thread joins. The original fix for that (`amend_terminal_envelope`)
re-redacted the returned envelope and then overwrote the already-journaled
record in a second write. A crash between the first write and the amend left a
permanent terminal record where a refreshed token that leaked into the console
was never redacted (#322, found by CodeRabbit re-reviewing #320).

**Decision.** `run_job_with_credential` runs the shared core
(`run_job_core`) without writing a terminal record. After its refresh thread
joins, it re-redacts the console against every token the run ever had live
(`redact_with_refreshes`), folds in a revoke-failure warning if any, and only
then writes the terminal record — once. The non-credentialed `run_job` path is
unchanged: it still writes its terminal record immediately, since it never has
a refresh to wait for.

Both paths share that one write through `write_terminal_record`, which takes
the job flock and re-reads before writing (`JournalWriter::persist_if_still_running`):
a concurrent `kill`/`reconcile_job` can already have flipped the record to
`Cancelled`/`Crashed` under the same flock while this run was still boxing up
its own result (review finding on #415 — neither path held the job flock
around its own run, so a `kill` racing the final write could be silently
overwritten). The terminal write is skipped, not retried, when the record is
no longer `Running`: that other writer's result stands.

A failed terminal write (I/O error, not the race above) is folded into the
returned envelope's `warnings` (L-12) on both paths, not only logged: without
it, the caller sees an ordinary successful exit with no sign INV-6 wasn't met,
and a later `status`/`wait` then disagrees with the result this call already
returned. Teardown has already run by this point, so there is nothing left to
undo by failing the call outright instead.

**Consequences.** The credentialed path's terminal record and its token
redaction are one atomic write: a crash can observe either no terminal record
(before that write) or a fully-redacted one (after it), never a
partially-redacted one in between. `amend_terminal_envelope` is removed, along
with the two-write (write, then later lock + read + overwrite) sequence it
used. The shared `write_terminal_record` now does read the journal once before
its single write, under the job flock, but only to guard against a _different_
concurrent writer — never to merge into or amend a record of its own. Proven
by `credentialed_run_writes_the_terminal_record_once_after_refresh_redaction`
in `supervisor.rs`, which uses `CountingJournal` (a `JournalWriter` test
double) to record the write count and checks the persisted terminal record,
and by the existing `credentialed_run_redacts_the_token_from_the_console` /
`credential_revoke_failure_surfaces_as_a_warning_not_a_fault` integration
tests in `cli_jobs.rs`, which still pass unchanged.

**Set aside.** Keeping the amend and instead making it atomic under the job
flock (lock, read, merge, write) was considered and rejected: it still leaves
the same crash window between the first write and the lock being taken, just
narrower; removing the first write entirely closes the window rather than
shrinking it. This is a different flock use than the one added above: that
earlier rejection was about _this run's own_ two writes racing each other, not
about guarding the one remaining write against _another_ writer's result.

## 8. A profile names an identity; the registry holds names only (#592)

**Status:** accepted for slice 1 (the registry). Re-injection, renewal and revoke per environment are later slices.
**Upholds:** INV-1 for the registry and the request, which hold no secret value. The values that a `service_secrets` name
selects still reach the guest's environment, the interim exception that decision 2 states; the profile only narrows
which names get there.

An environment request names an identity profile and never carries a secret. The operator keeps a registry of
profiles. A profile holds the name of a registered trust root, the credential `Scope` (the repository allow-list and
the capabilities) and the secret names the service may read. It holds no value. The registry is JSON, an array of
named entries, so a duplicate name is detectable. The parse refuses an unknown key, a name that looks like a
credential, a repeated key and any malformed entry, and no error shows a key, a name or a value from the file or the caller.

`service_secrets` defaults to none. The T3 service runs as a non-root user and inherits the secret exports of the
root login shell (#632), so the profile says which names reach it and staging exports only those. The secret directory
stays root-only. An allowlist in the agent was set aside: it would drop the keys the harnesses need.

**Set aside:** reading the registry through `serde` derive, and a prefix list to decide which text is safe to show. A
derive error repeats the offending value, and the text reaches logs. A prefix list knows only some secret formats, so
no key or name is shown at all (review of #592). The same limit holds for the "looks like a credential" check on
names: it is best-effort, and the contract is names only. **Open:** one shared name rule for this registry and sandyd's request check (they match today, but are
two copies). Spec: `docs/design/credential-seam/identity-profiles.md`.
