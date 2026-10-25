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
independent of the host dest. `Provenance.template_store_path` remains a
placeholder.

**Consequences.** `envelope.outputs` is a stable manifest of produced files (K6);
`Provenance` is a known gap, not an implied guarantee — distinct from the audit
receipt (decision 5 below), which does not reuse `Provenance`.

## 3. Two renderings in lock-step

**Status:** accepted.

**Context.** A human wants a readable summary; an agent wants the full structured
envelope, and the two must not drift.

**Decision.** `-o plain` (default, human, lists outputs) and `-o json` (the full
serialized envelope) both flow through the `format_*` helpers.

**Consequences.** The two renderings stay in lock-step; adding a field surfaces in
both. `plain` is the default so interactive use is readable without a flag.

## 4. Non-fatal faults surface as `warnings`, not silently

**Status:** accepted. **Upholds:** INV-11.

**Context.** Some failures (e.g. a credential revoke failing at teardown, L-12)
must not fail an otherwise-successful run, but swallowing them into a log line
only means an API/JSON caller never sees them.

**Decision.** `ResultEnvelope` gains `warnings: Vec<String>` (schema bumped to
`2`, `#[serde(default)]` so a `1` journal record still deserializes). A non-fatal
fault is named there — never the secret value — in addition to its
`tracing::warn!`.

**Consequences.** The locked key set grows by one key, a deliberate version
bump (not a quiet addition): `envelope_wire_keys_are_snake_case` is updated on
purpose. `warnings` is empty on every ordinary run.

## 5. Envelope receipts v1 (#361)

**Status:** accepted. **Upholds:** INV-1.

**Context.** `ResultEnvelope.receipts`/`.provenance` were placeholders
(`kpi.md`'s "Not yet a KPI"): nothing specified what audit lineage a receipt
should carry, or how to keep a hostile guest's own claims (`docs/architecture/
spec.md`'s attacker model, #357) from being taken as host fact. The input was
the Agent Compute Engine deep dive's audit-lineage requirement (#356):
tracing every outbound action back through agent and user to the resource it
touched.

**Decision.** `ResultEnvelope` gains `receipt: Option<Receipt>` (schema bumped
to `3`, `#[serde(default)]` so a `2` record still deserializes). Named
`Receipt` for the wire shape the issue specifies — a different type from the
pre-existing side-effect `Receipt` on `receipts` (e.g. a GitHub PR a job
opened); the two are unrelated and neither replaces the other. The new type
splits fields by who observed them:

- `host_observed` (the guest cannot influence these): `who` (a verified
  submitter cap's `scope.peer` with `authenticated: true`, or the local uid
  with `authenticated: false`); `what` (job id, template ref, and `Option`s
  for a resolved store path and a manifest digest); `where` (the backend kind
  plus `Option`s for a dispatching executor's identity); `credential`
  (provider, `Scope`, lifecycle timestamps, revoke outcome — never the
  token); `egress` (enforced/unenforced plus reason, the allow-list actually
  applied, and a reserved empty `attempts`); `timing` (boot start, job start,
  teardown).
- `guest_reported` (a hostile guest can shape these): exit code, output names
  and sizes.

A field with no source today is `None`, never a fabricated placeholder
(`template_store_path: String::new()` was the defect this issue names): no run
path yet resolves a template to a store path or builds a manifest digest for a
direct `sandy run`, and no run path yet derives `who` from a verified
submitter cap or reports a job-start timestamp distinct from boot. sandyd's
dispatch core does not persist a receipt — or any envelope — for a dispatched
job at all yet, so `who.authenticated` is `false` on every run this version
ships (#413 tracks the wiring, not faked by hand-building a `Cap` in a
test that calls itself "sandyd-path"). `egress`'s enforcement reads the same
`EgressOutcome` that already drives `run_job`'s enforce/revert bracket — not a
second copy of the logic, and the same signal #358's warning surfaces.

**Alternative set aside.** Retyping the pre-existing `receipts: Vec<Receipt>`
field to carry this shape instead of adding a new field: every `2` record on
disk already has `"receipts": []` (an array), and an object can't deserialize
into that shape — the schema-bump precedent (decision 4) exists precisely to
avoid breaking old records, so a retype was never on the table once that
precedent is honored.

**Consequences.** The locked key set grows by one key (`receipt`), schema `3`.
Digests (#373), signing (#374), and filling `egress.attempts` from the #360
proxy (#375) are explicitly out of this version.
