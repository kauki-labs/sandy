---
title: "Decisions: secret channel"
status: accepted
project: sandy
updated: 2026-10-14
---

# Decisions: secret channel

Delivering a named secret to the job as `$NAME` without it touching argv, env, or
the Nix store. Subsystem spec:
[`../architecture/spec.md#3-secret-channel`](../architecture/spec.md#3-secret-channel).

## 1. On-disk channel only

**Status:** accepted. **Upholds:** INV-1.

**Context.** A secret passed on argv or in the process env, or written into the
world-readable Nix store, leaks through `/proc`, the console, or the store path.

**Decision.** Each secret is staged to a `0600` file (atomic
temp→fsync→rename) in a `0700` dir shared read-only at `sandy-secrets`; the guest
login shell exports each file as its `$NAME`. A world- or group-readable source
is **rejected, not staged**, and `validate_no_secret_leak` rejects a secret whose
name is also set as a plain env var.

**Consequences.** The secret reaches the job only as a `$NAME` backed by a RO
file; it is never on argv, env, or the store. Proven live by K8/K9.

**Set aside.** argv/env delivery: rejected outright (the leak surface above).

## 2. Caller-owned dir for refresh

**Status:** accepted.

**Context.** A long job's credential must be refreshable mid-run (see the
credential seam), which means rewriting the live secret file while the guest runs.

**Decision.** `RunSpec.secret_dir` lets the caller stage into a dir it keeps
rewriting; because that dir is the live virtiofs share, a rewrite is seen
in-guest.

**Consequences.** The credential bracket can re-deliver a rotated token without a
reboot (feeds K10/K11); the secret channel owns the on-disk mechanics, the
credential seam owns the rotation policy.

## 3. One writer, owned private directories only

**Status:** accepted. **Upholds:** INV-1.

**Context.** Three secret writers had drifted apart (#174). The secret channel's
writer created a fixed `<NAME>.tmp` with the umask's mode, followed a symlink
planted there, and tightened to `0600` only after writing. The credential writer
accepted any directory. `sandy run --credential` staged the token into a
predictable, pre-creatable `/tmp/sandy-cred-<pid>` (#192).

**Decision.** Every secret staged for a job (credential tokens, secret-channel
secrets, fabric work-secrets) is written by `sandy_fsutil::OwnedDir::write_secret`:
the directory is opened once (`O_DIRECTORY | O_NOFOLLOW`) and must be this user's
and not group- or world-writable. The file is created `0600` with
`O_EXCL | O_NOFOLLOW` under a unique temporary name, synced, renamed into place,
and the directory is synced, all relative to that handle. The credential directory
is a fresh `0700`, randomly named directory under the validated staging base
(`private_staging_dir`); an existing entry at that name is refused.

**Consequences.** A staging directory that is group- or world-writable, or owned
by another user, is now refused where it was accepted before. That includes a
caller-supplied `RunSpec.secret_dir` (§2) created with a permissive umask (for
example `0002`): the caller must create it private. Every directory sandy creates
for secrets is `0700` and every secret `0600`, so its own flows are unaffected
under any umask: each create site sets the mode on the new entry itself, so even
a umask that clears the owner's bits (for example `0400`) cannot leave an
unopenable dir or an unreadable secret (#197, #204).

**Set aside.** Checking the file rather than the directory: another principal who
can write the directory can swap the file after any check on it.
