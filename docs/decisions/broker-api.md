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
job and environment endpoints (sections 1 to 6). Attach and link are deferred (section 5).

All decisions here are **proposed**. Items marked _owner_ touch security or the public API
and need ratification on #591.

## 1. A separate process that speaks the control RPC over UDS

**Context.** `sandyd.md` decision 24: one sandyd per submitter user, and UDS peers must share
the daemon's uid. A broker that serves HTTP clients is a UDS peer of sandyd.

**Decision.**

- `sandy-broker` is its own binary and crate. It depends on `sandy-control-proto` for the
  frame codec and never on `sandyd`. It runs as the daemon's user and opens one UDS
  connection per control RPC, each with a 30 s deadline. Submit, list and get make one RPC.
  Cancel makes one. A submit makes a second RPC only when the owner-table save fails and the
  job is cancelled.
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
- One broker per state directory: the broker holds an exclusive lock on `owners.lock` for as
  long as any handler holds the table, so a second instance cannot clobber it.
- **Residual: a crash, or a reply timeout, between sandyd accepting `Submit` and the table write**
  leaves a job with no owner. On a timeout the broker never learns the job id, so it cannot
  cancel it. `SubmitRequest` has no correlation key and `ListResponse` carries no token,
  so a restarted broker can neither link nor cancel it. Closing it needs a control-RPC
  change (a client-chosen key echoed durably, and a recoverable cancel authority). The
  operator path `sandyd cancel` still works. Tracked in #621.

## 4. Host paths in a submit body fail closed (_owner_)

**Context.** `SubmitJob.inputs[].host`, `outputs[].dest` and `secrets[].host_path` name host
paths that sandyd reads or writes as its user. Over HTTP that lets any client make the daemon
touch any path of that user: a confused deputy.

**Decision.** The broker refuses a path outside the client's configured `roots`: it must be
absolute, contain no `..`, and reach its target through no symlink below the root (a dangling
link and a link that stays inside the root are refused too). A client with no `roots` may not
send inputs, outputs, or secrets. A request for an isolation class above the client's
`max_isolation_class` is `forbidden`. `required_isolation_class` has no default: a missing
field is `invalid_request`, as in the contract.

The broker also refuses a clients list with a duplicate id, a duplicate token hash, an empty
id, or a hash that is not 64 lowercase hex digits. It caps open connections, times out slow
request headers, and runs each request on its own task, so a client that hangs up mid-submit
cannot leave a job without an owner.

**Consequence.** The contract is unchanged on the wire. These are new refusals, so `sandy-mcp`
tests keep passing.

**Residual risk (_owner_).** The check is a point in time. A client that can write inside its
root can swap a directory for a symlink after the check, and sandyd then follows it as its
own user (`crates/sandy/src/stage/inputs.rs` and `outputs.rs` open by path). Only an fd-based
open in sandyd closes this. Until then, `roots` must be directories that the HTTP client
cannot write to concurrently with a submit, or the client must be trusted with the daemon
user's files. Tracked in a follow-up issue.

## 5. Deferred in this slice

- `attach` returns the typed error `unsupported`. The control RPC's data plane is a UDS stream.
  An HTTP bridge is its own design and aligns with #513 (NDJSON).
- `link` returns `unsupported` until T3 offers an external link interface (#585 open point 1).
- Rate limiting, quotas, and the audit trail are #596.
- `SubmitJob` has no `request_id`. Job idempotency is a contract change and is not made here.

## 6. Environment endpoints map onto sandyd's typed environment RPC (#587 A2)

**Decision.**

- Spawn, get, list, stop, resume, cancel and delete each make one control RPC with the typed
  messages. The broker never forwards client JSON bytes: sandyd compares the create spec
  byte for byte, so the broker builds the message.
- sandyd keys idempotency over all callers. The broker sends `idempotency_key` as a 16-digit
  hash of the client id, a dot, and the client's `request_id` (at most 111 characters of
  letters, digits, `-`, `_`, `.`). Two clients never collide, and one cannot learn another's
  environment through a repeated key.
- The owner table records the environment and the request id per client. Another client's
  environment, and an unknown one, both give `not_found` on every route, and list shows only
  the caller's.
- Per-client quota: `max_environments` in the clients file (default 4) counts the client's
  non-terminal environments. A replay of a request id the client already used skips the check.
  Creates run one at a time, so the check and the create cannot race.
- sandyd's `EnvironmentError` codes map to fixed messages: `NOT_FOUND` 404 `not_found`,
  `REQUEST_ID_CONFLICT` 409, `QUOTA_EXCEEDED` 429, `UNSUPPORTED_FOR_LIFETIME` 409,
  `INVALID_STATE` 409 and `INVALID_ARGUMENT` 400 as `invalid_request`. sandyd's own text is
  not relayed.
- A create whose owner save fails answers `unavailable`. The client's retry replays the create,
  gets the same environment, and records it, so no orphan outlives a retry.
- A client may hold `max_environments` non-terminal environments (default 4) and may ever
  create `max_environment_records` (default 64). sandyd keeps a deleted row for replay and
  counts it against its own cap, so without the second limit one client could create and
  delete until sandyd's table is full for everyone. The real fix is sandyd pruning deleted
  rows and paging its list reply (#633).
- A create that sandyd answers with an environment another client already owns is refused
  (`TakenOver`), and two clients whose ids share a 16-digit hash prefix are refused at startup.
- `failure.reason` is logged and not relayed: it is sandyd's text and may name a path or a
  credential once the launch driver writes it. `failure.step` is relayed.
- An owner file in the earlier job-only shape fails the load.
- `steps` is provisional: sandyd sends none until the launch driver (#587 slice C), and each
  name maps to status `pending` until slice C pins the format.

**Residual.** A create whose reply times out and is never retried leaves an environment with
no owner, which the broker cannot list. sandyd's own row cap and the profile checks still apply
to it. Closing it is the correlation work in #621.

## Consequences

- Every broker refusal is typed (`unauthenticated`, `forbidden`, `not_found`,
  `invalid_request`, `request_id_conflict`, `quota_exceeded`, `unsupported_for_lifetime`,
  `unsupported`, `unavailable`), so `sandy-mcp` passes them through unchanged. sandyd's own
  refusal text is never relayed: a `ControlError` becomes `unavailable`, an `EnvironmentError`
  code gets a fixed message.
- A broker restart keeps job ownership, so the owner can still cancel.
- The owner table is rewritten whole on each submit and each environment create, and never pruned. Pruning waits for #596.
- A caller on another machine cannot reach the broker until the TLS follow-up lands.
- sandyd cannot tell two HTTP clients apart. The broker is the only per-client boundary.

## Acceptance

Tier-2 tests run the broker against an in-process sandyd. See
[`../architecture/kpi.md`](../architecture/kpi.md) for the live rows.
