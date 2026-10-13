---
title: "Decisions: result envelope + classification"
status: accepted
project: sandy
updated: 2026-10-14
---

# Decisions: result envelope + classification

Turning a physical `Outcome` into the locked `ResultEnvelope` and a process exit
band that agree. Subsystem spec:
[`../architecture/spec.md#6-result-envelope--classification`](../architecture/spec.md#6-result-envelope--classification).

## 1. Locked envelope

**Status:** accepted. **Upholds:** INV-11.

**Context.** A caller (human or agent) must be able to trust `status`,
`retryable`, and `exit_code` without reconciling them itself, and a plan that
never booted must not look like a clean zero-exit run.

**Decision.** `status` / `retryable` / `exit_code` are authoritative and
cross-checked (INV-11): band 3 (infra) is the **only** retryable band; an invalid
plan is band 2 with **no journal record and no boot** (the silent-run guard).

**Consequences.** The three fields can never disagree; a pre-boot rejection is
observably distinct from a booted run that exited 0. Proven by the `classify_outcome`
band tests and, live, by every KPI asserting the envelope.

## 2. Outputs populated

**Status:** accepted.

**Context.** A caller needs to know what the run actually produced, independent of
where on the host it was collected.

**Decision.** After a successful run the supervisor lists each declared output's
collected files as `OutputRef`s (`<name>/<rel>` named, `<rel>` catch-all),
independent of the host dest. Receipts/provenance remain placeholders.

**Consequences.** `envelope.outputs` is a stable manifest of produced files (K6);
provenance is a known gap, not an implied guarantee.

## 3. Two renderings in lock-step

**Status:** accepted.

**Context.** A human wants a readable summary; an agent wants the full structured
envelope, and the two must not drift.

**Decision.** `-o plain` (default, human, lists outputs) and `-o json` (the full
serialized envelope) both flow through the `format_*` helpers.

**Consequences.** The two renderings stay in lock-step; adding a field surfaces in
both. `plain` is the default so interactive use is readable without a flag.
