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

## 6. Sign receipts relayed from remote executors (#374)

**Status:** accepted (design only — no relay path exists to sign yet; see
Consequences). **Upholds:** INV-1.

**Context.** Decision 5's `host_observed`/`guest_reported` split assumes the
guest is the only hostile party (#357's attacker model): fields a hostile
_guest_ can shape are already named and isolated. It says nothing about a
hostile _relay path_ — once a receipt crosses from a remote executor back to
`sandyd` and into its store, nothing stops it being altered in transit or
after storage. #374's own framing names exactly that gap: "for local runs the
host supervisor writes the envelope and the guest can't touch it... signing
only matters once receipts are relayed between machines and have to stay
verifiable after the fact [to] an auditor [who checks] a receipt later
without trusting sandyd's database." Decision 12 (`sandyd.md`) already
accepts that an executor's identity is its mesh IP, with no attestation; this
decision does not change that — it is a different problem (receipt
integrity, not registration authenticity) with a different answer.

**Decision.**

- **Key: a per-executor Ed25519 keypair, not the WireGuard identity.**
  `ExecutorAllowlist` (`crates/sandyd/src/host_registry.rs`, today a bare
  `HashSet<IpAddr>`) grows a verifying key alongside each allowed peer IP —
  the same trust anchor decision 12 already uses for registration, extended
  rather than duplicated. Reusing the mesh WireGuard key is set aside below.
  Ed25519 over an HMAC (decision in `impls/fabric-local/src/capauth.rs`) is
  deliberate: HMAC is symmetric, so whoever can _verify_ a receipt can also
  _forge_ one — exactly what #374 rules out for a third-party auditor who
  must verify without being handed sandyd's own secret.
- **Format: a detached Ed25519 signature over the receipt's canonical
  bytes**, encoded the same way `capauth.rs`'s `canonical_scope_bytes` already
  does for `CapScope` (length-prefixed, field-order-fixed, so no two fields'
  concatenation can collide with a different split between them) — a second,
  independent implementation of the same scheme, not a shared helper, since
  `AuditReceipt` and `CapScope` have no fields in common and forcing one
  through the other's shape would obscure both. The signed bytes cover the
  **whole** `AuditReceipt` — `host_observed` AND `guest_reported` — not just
  `host_observed`. The split in decision 5 is about which party's _claims_
  to trust, not about which bytes get tamper-evidence: the executor
  physically relayed both blocks, so both should be verifiably exactly what
  it sent, even though `guest_reported`'s contents remain a guest's
  unverified claim once you look inside them. This decision names the
  scheme (length-prefixed, field-order-fixed) but not the field-by-field
  byte mapping for `AuditReceipt`'s own shape (nested structs, `Option`s,
  enums like `EgressEnforcement`, timestamps, vectors like `attempts` and
  `outputs`, free text) — CodeRabbit on this PR. That mapping is the
  implementation issue's job, explicitly: every nested field, `Option`, and
  collection needs one fixed encoding before two independent
  implementations (executor-side signing, sandyd-side verification) can be
  guaranteed to produce or check the same bytes.
- **sandyd countersigns.** Once `sandyd` verifies the executor's signature
  and accepts the receipt, it signs `(executor_signature, the receipt's own
canonical bytes, job_id, the verified submitter's identity from decision
12's `ExecutorAllowlist` check)` with its own orchestrator key. This closes
  the gap the executor's signature alone leaves open: an auditor who trusts
  only the executor's signature still has to trust that `sandyd` stored,
  rather than substituted, the bytes it verified. The countersignature is an
  attestation of custody ("sandyd received exactly this, from this verified
  peer, for this job"), independent of and layered over the executor's own
  attestation of origin ("I produced exactly this"). Either layer's failure
  is independently detectable.
- **Replay is closed by binding, not a nonce.** The signed canonical bytes
  include `job_id` and the dispatching executor's identity (mirroring
  `AuditReceipt.host_observed.location`), so a signature cannot be lifted
  from one job's receipt and attached to another's. `sandyd`'s ingestion
  additionally refuses a receipt for a `job_id` it has no matching dispatch
  record for, and treats a job's receipt as write-once: a second,
  differently-signed receipt for an already-recorded `job_id` is rejected,
  not silently overwritten. Neither check exists today (CodeRabbit on this
  PR): `HostRegistry` tracks which host a job was _placed_ on, live, for
  routing — it is not a durable record of past dispatches, and nothing
  persists an accepted receipt yet. Whichever store ends up owning
  dispatched-job state (`JobStore`/`JobRegistry`, or a new table) must
  persist both the dispatch-to-executor mapping and the write-once
  accepted-receipt marker before these checks are implementable; this is
  new persistent state the implementation issue adds, not enforcement
  `sandyd` already has lying around.

**Adversarial pass.**

- _A compromised executor forges a receipt for a `job_id` never dispatched to
  it._ Signing does not defend against this directly, and the design does
  not pretend to: decision 6's (`sandyd.md`) per-job agent-link
  authentication (the run-id + token prefix) already scopes a dispatched
  job's relay channel to that one job, so an executor holding a valid key
  cannot use it to originate traffic for a `job_id` `sandyd` never
  dispatched to that peer — that boundary is transport-level, not
  cryptographic. What signing adds on top: `sandyd`'s own ingestion check
  (above) that a signed receipt's `job_id` matches an actual dispatch to
  that signing identity, so even a replayed-and-resigned attempt (not just a
  raw replay) is refused. This ingestion check applies to every
  receipt-submission path, including any future relay channel beyond the
  agent-link — it must not come to depend on agent-link authentication
  specifically, which is a property of today's one transport, not of the
  check itself. This does NOT cover a job that genuinely _was_
  dispatched to that executor and never ran — see below.
- _A compromised executor lies about `host_observed` fields it genuinely
  controls_ (fake timing, a fake backend kind). Out of scope for this
  decision, and stated as such: a compromised _executor_ is a stronger
  attacker than the compromised _guest_ decision 5's split defends against,
  and decision 12 already accepts "mesh IP is identity, no attestation" as
  the limit of what registration alone can prove. Signing makes the lie
  non-repudiable (the executor cannot later deny having asserted it) and
  tamper-evident (no one downstream can alter it without invalidating the
  signature) — it does not make the assertion true. This matches #374's own
  framing: the goal is "stays verifiable after the fact," not "cannot lie."
- _Replaying another run's receipt._ Closed by the job_id-binding + write-once
  rule above: a captured, validly-signed receipt for job A cannot be
  resubmitted as job B's receipt (the signed bytes name A). An exact
  resubmission of job A's own already-accepted receipt (bit-identical
  signature and bytes, e.g. a retried network send) is accepted
  idempotently — a no-op that stores nothing new — rather than rejected: it
  carries no new claim to distrust. A _different_ signed receipt for a
  `job_id` that already has one is rejected (CodeRabbit on this PR narrows
  this from the stronger, inaccurate claim that every second submission is
  blocked): write-once means one accepted receipt per job, not one
  submission attempt per job.
- _A job that was dispatched but never actually run._ CodeRabbit on this PR:
  the defenses above only bind a receipt to a `job_id` `sandyd` genuinely
  dispatched to that executor — they do not prove the executor ran it. A
  compromised executor that received a real `Dispatch` for job A can skip
  running it entirely and sign a receipt for job A anyway; the dispatch-match
  check in the bullet above accepts that receipt, because by its own
  definition job A _was_ dispatched there. This decision's "forges a receipt
  for a job it never ran" framing is narrower than it reads: it rules out a
  receipt for a `job_id` never dispatched to that peer, not a receipt for a
  dispatched job the executor never actually executed. Signing makes that
  claim non-repudiable and tamper-evident; it does not make it true, and
  nothing in this design supplies independent execution evidence (e.g. a
  liveness/progress signal from the running job itself) that `sandyd` could
  check the claim against. Left as a stated limit, not closed: an auditor
  reading a signed receipt should know it attests "the executor claimed
  this," not "sandyd independently confirmed this ran."

**Alternative set aside.** Deriving the receipt-signing key from the
executor's WireGuard identity (decision 12) instead of provisioning a second
keypair. Set aside: WireGuard's X25519 keys are for key exchange, not
signing, and converting one into an Ed25519 signing key is a non-standard,
easy-to-get-subtly-wrong construction for no real provisioning savings — an
operator already has to get a value onto each allow-listed host (the IP) and
onto `sandyd` (the allowlist entry); adding a public key to that same
one-time step costs little next to a conversion that would need its own
security review.

**Consequences.** This decision answers #374's open questions; it does not
implement them. #413 confirms that `sandyd`'s dispatch core does not persist
a `ResultEnvelope` for a dispatched job at all yet (no relay path exists to
sign), so implementation is blocked on that landing first — tracked
separately, not reopened here. `ExecutorAllowlist`'s wire/config shape
changes (an `IpAddr` set becomes an `IpAddr -> VerifyingKey` map); key
provisioning (how an operator generates and installs a keypair) is left to
the implementation issue, not decided here. `ed25519-dalek` becomes a new
dependency of whichever crate ends up owning the signing/verification
(`sandy-executor-proto` or a new seam) once implemented.
