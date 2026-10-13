# Refresh re-delivery (#49) — design note

Increment to the credential-seam package. Closes the last gap in execution-bound
credential lifetime: a job that runs past the provider's token cap keeps a valid,
scoped token for its whole run, and the old token is revoked as soon as it rotates.

Tier: `note` (one plan, extends an already-built package). Read after
[`credential-seam-proposal.md`](credential-seam-proposal.md).

## Problem

GitHub installation tokens live ~1h, fixed by the provider (GitLab is day-granular).
`run_job_with_credential` mints at boot and revokes at teardown, so for jobs under
~1h the token's lifetime already equals the execution. A job that runs longer loses
its credential mid-run: the token expires, pushes/pulls start failing, and nothing
re-mints.

## What the code already gives us

- The guest mounts the host's `inst_dir` read-only at `/run/sandy/secrets` over a
  live virtiofs share (`crates/sandy-backend/src/qemu.rs:368`,
  `stage_secrets` → `inst_dir/<NAME>`). Rewriting `inst_dir/<NAME>` on the host
  updates the guest's file live — this is the re-stage channel, already present.
- `provider.refresh(&lease)` re-mints a fresh scoped token
  (`crates/sandy/src/cred_github.rs:235`; GitHub has no rotate, so refresh = re-mint
  - revoke-old).
- `should_refresh(now, expires_at, margin)` decides when to fire
  (`crates/sandy-cli/src/supervisor.rs:319`).

## What's missing — three seams

1. **Concurrency.** `VmBackend::run` blocks until the job exits. A refresh timer
   has to run on a second thread alongside it.
2. **A handle to the guest-visible file.** That file is `inst_dir/<NAME>`, where
   `inst_dir = temp_dir/sandy/<run_id>` is derived inside `run` from a `run_id` the
   backend generates and never exposes before it returns. The refresh timer has no
   way to name the file today.
3. **Consumption.** The guest login shell exports each secret as `$NAME` **once**,
   at boot. After a refresh rewrites the file, a job still holding `$GITHUB_TOKEN`
   from its environment sees the **stale** token. Refresh is only observable if the
   job reads `/run/sandy/secrets/<NAME>` at use-time.

Seam 3 is the hinge: it decides whether any of seams 1–2 are worth building.

## The fork

- **A — build mid-run re-delivery.** Job reads the token from the file at use-time
  (a git credential helper that `cat`s `/run/sandy/secrets/GITHUB_TOKEN`, or a
  re-read before each remote op). A refresh thread re-mints near expiry, rewrites
  the guest file, revokes the old token. Delivers true execution-bound credentials
  for long jobs. Cost: seams 1 + 2 + a documented consumption contract (long jobs
  read the file, not the env snapshot).
- **B — bound and refuse.** Keep `$NAME` env delivery. Cap a credentialed job's
  duration at the token lifetime; refuse or warn when a job would outlive its token.
  No concurrency, no file-handle seam. Honest and small, but long jobs can't use a
  credential at all.
- **C — defer.** Document the ~1h cap as a known limit; revisit when a real >1h
  credentialed job exists.

### If A — the file-handle sub-fork (seam 2)

1. **Caller owns the secret dir.** `run_job_with_credential` stages into a dir it
   owns; the backend shares that dir directly instead of copying into its own
   `inst_dir`. Clean handle, trivial refresh. Larger backend-API change — touches
   the `StagedArgs`/stage surface peer #68 just reworked.
2. **Predictable inst_dir.** Expose `run_id` pre-run (or predict the path); the
   refresh thread rewrites `temp_dir/sandy/<run_id>/<NAME>`. Small diff, but couples
   to a backend-internal layout and has a pre-boot race (the file must exist before
   the first rewrite).
3. **Backend refresh seam.** `run` takes a refresh channel/callback it drives.
   Cleanest ownership, most invasive to the `VmBackend` trait.

## Scope note

This is an edge-case feature: it only changes behaviour for jobs that run past the
provider token cap (~1h on GitHub). Worth building as the completion of the
execution-bound guarantee, but its value and its consumption contract both turn on
seam 3 — which is why that's settled before the mechanism.

## Acceptance (if A)

- A credentialed job scripted to run past a shortened refresh margin reads a token
  from `/run/sandy/secrets/<NAME>` that changes mid-run, and both values are valid
  against the provider at their respective times.
- The pre-refresh token is revoked within the margin of the rotation (assert the
  old token is rejected, not just that a new one works — a silent non-revoke must be
  observably distinguishable).
- No secret value reaches argv, env, the host log, or the captured console
  (`logs.tail`) across the refresh.
- Teardown still revokes the live token on every exit path.
