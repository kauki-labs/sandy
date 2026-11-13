---
title: "Decisions: journal"
status: accepted
project: sandy
updated: 2026-11-13
---

# Decisions: journal

**Superseded.** The Journal, `reconcile_job` and the owner liveness lock were deleted in #483
with the direct execution path (#221). sandyd's `JobStore` (sqlite) is the only job record.
The decisions below stay as the history of why the Journal was built; they describe code that
no longer exists, and their test pointers (`live_boot.rs`, `cli_jobs.rs`) name removed files.

Persisting durable job records and reconciling liveness without racing the owner.
Subsystem spec: [`../architecture/spec.md#7-journal-removed-in-483`](../architecture/spec.md#7-journal-removed-in-483).

## 1. Running before boot

**Status:** accepted. **Upholds:** INV-6.

**Context.** If the backend is launched before any record is written, a crash
between launch and the first write leaves an orphan VM with no journal trace.

**Decision.** The `Running` record is the **first** write, before the backend
runs; the terminal record always carries the envelope.

**Consequences.** An empty journal proves the backend was never reached (pairs
with the band-2 silent-run guard); every finished job has a terminal record with
its envelope.

**Credentialed path: the terminal write is deferred, not amended (#322).** The
non-credentialed `run_job` still writes the terminal record immediately after its
own console redaction. `run_job_with_credential` instead runs the shared core
(`run_job_core`) without writing a terminal record, joins its refresh thread, and
only writes the terminal record once the console has been re-redacted against
every token the run ever had live (`redact_with_refreshes`) and any
revoke-failure warning (L-12) has been folded in. Before this, `run_job` wrote a
terminal record redacted against only the initial token, and
`run_job_with_credential` amended it after the fact (`amend_terminal_envelope`,
now removed) — two separate writes, not one atomic one. A crash in the window
between them left a permanent record with a refreshed token unredacted, the
exact class of exposure M-6 exists to close. INV-6 still holds on every path: a
`Running` record precedes the backend run, and a terminal record always carries
the envelope — only the _order_ within the credentialed path changed, to put the
one terminal write after redaction is final.

## 2. Reconcile through the seam

**Status:** accepted. **Upholds:** INV-3.

**Context.** Reading running state straight from the registry races the owning
process and can misreport a crashed owner as alive.

**Decision.** `status`/`wait`/`kill` reach running state via
`reconcile_job` + `VmBackend::boxes` and the owner's liveness lock (decision 3),
never a direct registry read.

**Consequences.** A crashed owner is reconciled to a terminal state rather than
reported as running; liveness has one path, so the ops commands agree. Proven live
by K3 (`live_boot.rs::cli_lifecycle_over_a_real_job`).

**Set aside.** Direct registry reads for liveness: rejected, they race the owner.

## 3. The owner holds a liveness lock for the run; `kill` signals the owner (#699, #695)

**Status:** accepted. **Upholds:** INV-3, INV-6, INV-7.

**Context.** Decision 2 says liveness is the job flock, "held by a live owner". It was not: the lock was taken only
inside each write and dropped, and the `Running` record carries no box id, so `reconcile_job` could not tell a live run
in another process from a dead one. `sandy status` from a second process read a live run as `crashed` (#699). `sandy
kill` had the same blindness: it wrote `cancelled` and signalled nothing, because the VM backends' `kill` only edits an
in-memory registry (#695).

**Decision.**

- Each job has a second lockfile, `<job>.live`, apart from the short write lock `<job>.lock`. The owning `sandy run`
  takes it before the `Running` record is written and keeps it past the terminal write (`JobOutcome` carries it). The
  kernel drops it with its holder, so a held lock is a live owner even if the pid was reused. Readers probe it read-only
  with a shared lock, so two readers never make each other see a live owner. `reconcile_job` leaves a
  `running` record alone while it is held.
- `sandy kill` of a live owner (lock held) sends `SIGTERM` to the record's `writer_pid`, which `sandy run` answers by
  cancelling the run (#687: guest stopped, credential revoked, terminal record with its receipt). It then waits up to 60 s
  for the owner to finish and returns the record the **owner** wrote. It writes no `cancelled` record of its own for a live
  job: that record would carry no credential receipt and win the race against the owner's.
- Every refusal leaves the record `running` and fails: a kernel `EPERM` (the owner is another user's: the error names
  that and says to run `kill` as that user or root), a record naming pid 0 or 1 (never signalled), an owner still live
  after the budget (no `SIGKILL`: it would skip the revoke, #687). An owner that exits without a terminal record is
  settled by `reconcile_job` (`crashed`).
- `kill` of a dead owner is unchanged: the box is torn down through the backend and the record flips to `cancelled`.

**Consequences.** `sandy status` and `wait` no longer write a false `crashed` for a live run, so `ls` and `gc` no longer see one. A record written before
this change has no `.live` file, so its owner reads as dead, as before. `SIGKILL` of the owner still leaves a `running`
record and an orphaned VM until the next sweep (#666); `sandy kill` of such a job takes the dead-owner path.

**Set aside.** Holding the existing write lock for the run: the owner's own terminal write takes it, so it would deadlock,
and `kill` would block behind the whole run. Storing pid and start time in the record to check identity: a held lock
already proves the owner and cannot be fooled by a reused pid, and it needs no schema change.
