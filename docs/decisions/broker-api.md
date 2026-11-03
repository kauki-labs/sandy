---
title: "Decisions: broker API tier"
status: proposed
project: sandy
updated: 2026-11-03
---

# Decisions: broker API tier

The HTTP tier in front of sandyd (`sandy-broker`, #591). `sandyd.md` decision 7 puts every
non-CLI client behind it, and decision 25 makes `sandy-mcp` its first caller. The wire
contract is [`../api/broker.openapi.yaml`](../api/broker.openapi.yaml). This record covers the
job-endpoint slice. Environment endpoints wait for #587.

All decisions here are **proposed**. Items marked _owner_ touch security or the public API
and need ratification on #591.

## 1. A separate process that speaks the control RPC over UDS

**Context.** `sandyd.md` decision 24: one sandyd per submitter user, and UDS peers must share
the daemon's uid. A broker that serves HTTP clients is a UDS peer of sandyd.

**Decision.**

- `sandy-broker` is its own binary and crate. It depends on `sandy-control-proto` for the
  frame codec and never on `sandyd`. It runs as the daemon's user and opens one UDS
  connection per request.
- The HTTP server is `hyper` 1 with hand-routed paths. The lockfile already holds it through
  `reqwest`. No web framework is added.

**Consequence.** sandyd sees one submitter, the broker's uid. Per-client identity does not
cross the UDS, so **every per-client check (list, get, cancel) happens in the broker**.
Receipts' `who` (#413) records the broker, not the HTTP client, until #566 settles
multi-tenancy.

**Alternative set aside.** A listener inside sandyd: it would put HTTP parsing, client
auth, and the token store inside the process that holds submitter caps.

## 2. Client identity: a static token file, loopback only (_owner_)

**Decision.**

- The broker reads a clients file (0600, refused otherwise): per client an `id`, the
  SHA-256 of its bearer token, a `max_isolation_class`, and `roots` (see 4). It never stores
  or logs a token.
- A request without a valid `Authorization: Bearer` gets `unauthenticated`. Tokens compare in
  constant time.
- The broker binds loopback only. A non-loopback address is refused at startup, because
  this slice has no TLS. Remote callers and mTLS (`sandyd.md` decision 20) are a follow-up.

**Alternative set aside.** Deciding mTLS client auth here: a security-model choice that
belongs to the owner, and `sandy-mcp` accepts only loopback `http` today.

## 3. Job ownership and the attach token stay in the broker

**Decision.**

- `Submit` returns the attach token. The broker stores `job_id -> (client id, token)` in a
  0600 file written with `sandy-fsutil`. It survives a broker restart. No response body, error,
  or log line carries the token.
- `get`, `cancel` and list act only on the caller's own jobs. A job of another client and an
  unknown job both return `not_found`, so a caller cannot probe ids (`sandyd.md` decision 23).
  Cancel presents the stored token to sandyd.
- A job with no stored token (a restart that lost the file) is uncancellable through the API,
  as in decision 23. The operator path `sandyd cancel` still works.

## 4. Host paths in a submit body fail closed (_owner_)

**Context.** `SubmitJob.inputs[].host`, `outputs[].dest` and `secrets[].host_path` name host
paths that sandyd reads or writes as its user. Over HTTP that lets any client make the daemon
touch any path of that user: a confused deputy.

**Decision.** The broker refuses a path outside the client's configured `roots` (canonical
path, symlinks resolved, `..` refused). A client with no `roots` may not send inputs,
outputs, or secrets. A request for an isolation class above the client's
`max_isolation_class` is `forbidden`. The default class is `untrusted` (#596).

**Consequence.** The contract is unchanged on the wire. These are new refusals, so `sandy-mcp`
tests keep passing.

## 5. Deferred in this slice

- `attach` returns the typed error `unsupported`. The control RPC's data plane is a UDS stream.
  An HTTP bridge is its own design and aligns with #513 (NDJSON).
- Environment endpoints return `unsupported` until #587 lands.
- Rate limiting, quotas, and the audit trail are #596.
- `SubmitJob` has no `request_id`. Job idempotency is a contract change and is not made here.

## Consequences

- Every broker refusal is typed (`unauthenticated`, `forbidden`, `not_found`, `unsupported`),
  so `sandy-mcp` passes them through unchanged.
- A broker restart keeps job ownership, so the owner can still cancel.
- A caller on another machine cannot reach the broker until the TLS follow-up lands.
- sandyd cannot tell two HTTP clients apart. The broker is the only per-client boundary.

## Acceptance

Tier-2 tests run the broker against an in-process sandyd. See
[`../architecture/kpi.md`](../architecture/kpi.md) for the live rows.
