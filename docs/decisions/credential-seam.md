---
title: "Decisions: credential seam (CredentialProvider)"
status: accepted
project: sandy
updated: 2026-10-14
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

**Consequences.** Reads of the App key and trust-root configs (#200) open the file and check it on the handle: it must be a regular file owned by the current user, or it is refused, since another user must have put it there. A dir that others can write to, or another user owns, logs the same tamper warning, but the read goes ahead; refusing those reads would break every credentialed run on an existing wide install, and is left to the operator. An
existing install whose trust-roots dir is group-writable (for example, registered
under umask `0002`, so `0775`) is refused on its next register or import until the
user verifies the files and runs `chmod 700`; deregister writes no trust material
and still works, and its shred never follows a symlink at the key path. That is a
deliberate, one-time break. Register checks the dir before capture, so the refusal
never leaves a forge App behind whose key it could not save. The trust-root name is
checked to be a single file name before anything is created.

**Set aside.** Tightening the dir to `0700` and continuing: if the dir was writable
by others, the key or config in it may already have been swapped, and continuing
would trust it silently.
