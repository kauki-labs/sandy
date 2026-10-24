---
title: "Decisions: credential seam (CredentialProvider)"
status: accepted
project: sandy
updated: 2026-10-20
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

**Status:** accepted. **Upholds:** INV-1 (the minted token is a secret).

**Context.** Handing every job a long-lived shared token is a broad blast radius;
a central token-minting service is another thing to run and secure.

**Decision.** The provider is a GitHub App whose private key stays on the
controller (`sandy cred github register/import/verify/deregister`). Each job mints
an **installation token** scoped to its repos/capabilities. The minted token is a
secret, delivered over the secret channel.

**Consequences.** Each job gets a narrow, short-lived token; the trust root never
leaves the controller. The provider is a seam (`CredentialProvider`), so GitLab
or another forge is a new adapter.

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
~1h) can exceed `MAX_TTL_SECS` (3000s) between refreshes — a job quiet that
long would otherwise look abandoned. The refresh loop therefore heartbeats
`cred_dir`'s mtime every tick, independent of whether a refresh fires; a
`kill -9`'d process stops ticking, so a genuinely leaked dir still ages out
and gets swept. The sweep is best-effort within `gc`: a staging base that
cannot be validated or listed is logged and skipped, never blocking `gc`'s
primary job-record eviction.

**Consequences.** A `verify-*` dir (a short synchronous probe, no refresh
loop) gets no heartbeat and needs none — it is always removed well within
`MAX_TTL_SECS` on any non-crash path. Sweep safety for a live job depends only
on `SANDY_REFRESH_TICK_SECS` staying below `MAX_TTL_SECS` — the refresh margin
plays no part, since the heartbeat fires every tick regardless of whether a
refresh does. The 60s default tick satisfies that by a wide margin.

**Set aside.** Tracking each staging dir's mint time in a side file (instead
of reading mtime) was considered and rejected: it adds a second piece of
state that could drift from the dir's actual contents, where mtime is already
authoritative and free.
