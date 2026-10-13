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
