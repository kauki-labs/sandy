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
unopenable dir or an unreadable secret (#197, #204). On Linux, correcting a dir
the umask narrowed goes through `/proc/self/fd`; under a sane umask the new dir
is already `0700` and `/proc` is not needed.

**Set aside.** Checking the file rather than the directory: another principal who
can write the directory can swap the file after any check on it.

## 4. The t3 access credential stays in a `0600` file (#669)

The guest agent lifts the pairing token `t3 serve` prints at startup (`<url>#token=<token>`) out of the job
transcript and writes it to `t3-access.json` in the directory named by `SANDY_T3_ACCESS_DIR`, through the one
`0600` writer of section 3. Only the token is kept: a consumer builds the URL it hands out from the host-side
bridge, never from the guest's printed host. The directory is opened before the job starts, and the executor
drops a submitter's `SANDY_T3_ACCESS_DIR`.

The token is valid only for a window after the server starts, so the capture runs from the first transcript
byte, scans the first 1 MiB, and gives up after five minutes. It never reaches a log or a `Debug` print. The
agent redacts it from the job console and the archive, and the `pipe-pane` transcript file is `0600` and removed
when the job's tmux session is dropped.

On demand, a Control envelope `application/vnd.sandy.t3-access.request` on the orchestrator channel becomes a
`LinkFrame::AccessRequest`. Its payload is a nonce (1 to 64 of `A-Za-z0-9_-`): the channel drops an envelope whose
content it already holds, so a requester sends a fresh nonce every time, and the answer echoes it. The agent
answers with `AccessGranted { nonce, token }` or `AccessUnavailable { nonce, reason }`, also when the job has no
access directory or no token yet. The relay posts it as an `Output` envelope (`...t3-access.granted` or
`...unavailable`, payload `<nonce>\n<body>`). The token rides the link and that envelope only: `Debug` of the
frame and of `AccessAnswer` redacts it, the relay drops a token that is not 1 to 1 KiB of `A-Za-z0-9._~-`, and a
peer channel cannot post either answer type. The agent ends the answer task by signal, never by abort, so an
answer being written finishes whole.

Open: the live attach stream still shows the printed line to an attached viewer during the token's window.
Closing that needs t3 not to print the URL to its tty, which is an upstream change, or an owner decision to
accept the exposure for an attach that already carries the same authority. The seeded-token source and teardown
revocation are later slices of #669.
