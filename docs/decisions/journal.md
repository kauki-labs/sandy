---
title: "Decisions: journal"
status: accepted
project: sandy
updated: 2026-10-25
---

# Decisions: journal

Persisting durable job records and reconciling liveness without racing the owner.
Subsystem spec: [`../architecture/spec.md#7-journal`](../architecture/spec.md#7-journal).

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

**Decision.** `ls`/`status`/`wait`/`kill`/`gc` reach running state via
`reconcile_job` + `VmBackend::boxes` **under the job flock**, never a direct
registry read.

**Consequences.** A crashed owner is reconciled to a terminal state rather than
reported as running; liveness has one path, so the ops commands agree. Proven live
by K3 (`live_boot.rs::cli_lifecycle_over_a_real_job`).

**Set aside.** Direct registry reads for liveness: rejected, they race the owner.
