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
