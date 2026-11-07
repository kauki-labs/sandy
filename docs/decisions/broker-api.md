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

**Residual risk (_owner_).** The check is a point in time. sandyd now opens the leaf of each input, output and
secret path without following a link and works below it through that handle (guest-shares decision 14, #618), and no
longer copies a link inside an input tree by value. That does not stop a hostile client: the client picks the path
depth, so it can submit `root/a/leaf` and swap `root/a`, which is above the leaf and still followed. Closing that
needs the client's root to reach sandyd, a public-API change tracked on #618 and #607. Until then, `roots` must be
directories that the HTTP client cannot write to concurrently with a submit, or the client must be trusted with the
daemon user's files.

## 5. Deferred in this slice

- `attach` is no longer deferred: decision 7 bridges it (#616).
- Output retention across a broker restart, and in sandyd, is not built: decision 8 keeps output in broker memory only.
- `link` returns `unsupported` until T3 offers an external link interface (#585 open point 1).
- Rate limiting, quotas, and the audit trail are #596.
- `SubmitJob` has no `request_id`. Job idempotency is a contract change and is not made here.

## 6. Environment endpoints map onto sandyd's typed environment RPC (#587 A2)

**Decision.**

- Spawn, get, stop, resume, cancel and delete each make one control RPC with the typed
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
  non-terminal environments. A replay of a request id the client already used skips the check only while sandyd still
  holds that environment: the broker asks sandyd (`GetEnvironment`), and if retention has
  collected it (`NOT_FOUND`) the replay would create a new environment, so both checks run.
  The sweep can also collect the row between that lookup and the create. When a replay
  that skipped the checks gets back an id other than the recorded one, the broker runs both
  checks then; over quota, it deletes the new environment, does not record it, and answers
  `quota_exceeded`. A replay that returns the recorded id, even a deleted one inside the
  window, is never checked.
  Creates of one client run one at a time, so the check and the create cannot race, and one
  client cannot hold up another.
- sandyd's `EnvironmentError` codes map to fixed messages: `NOT_FOUND` 404 `not_found`,
  `REQUEST_ID_CONFLICT` 409, `QUOTA_EXCEEDED` 429, `UNSUPPORTED_FOR_LIFETIME` 409,
  `INVALID_STATE` 409 and `INVALID_ARGUMENT` 400 as `invalid_request`. sandyd's own text is
  not relayed.
- A create whose owner save fails answers `unavailable`. The client's retry replays the create,
  gets the same environment, and records it, so no orphan outlives a retry.
- A client may hold `max_environments` non-terminal environments (default 4) and may ever
  create `max_environment_records` (default 64). sandyd keeps a deleted row for replay, so without
  the second limit one client could create and delete many rows. sandyd now collects deleted rows
  after a retention window and counts only rows that are not deleted against its cap (#633,
  sandyd decision 27), so the record cap is a per-client bound, not the only defence.
- List and the quota check read sandyd's list page by page (500 rows a page, following
  `next_page_token`) and filter to the caller's rows. The broker reads at most 10000 rows for one
  request; a daemon holding more answers `unavailable` and logs it, never a truncated list or
  quota count. The broker's own list is not paged: a client sees only its own rows, which
  `max_environment_records` bounds.
- A create that sandyd answers with an environment another client already owns is refused
  (`TakenOver`), and two clients whose ids share a 16-digit hash prefix are refused at startup.
- `failure.reason` is neither relayed nor logged by the broker: it is sandyd's text and may name
  a path or a credential once the launch driver writes it, and sandyd's store holds it for the
  operator. `failure.step` is relayed only if it is a plain name (at most 64 characters of
  letters, digits, `-`, `_`, `.`), else as `unknown`.
- `connection.url` is relayed only while the state is `ready`. A stopped, failed or deleted
  environment has no reachable service, and a URL sandyd still holds for it could outlive the
  delete.
- A client may name only the profiles in its `profiles` list (`forbidden` otherwise). An empty
  list allows none. sandyd owns whether a profile exists (#592); the broker owns who may use it.
- `ttl_secs` is bounded by sandyd (1 to 604800). Any client may still ask for a `persistent`
  lifetime: a per-client lifetime policy is an owner decision (#607).
- An owner file in the earlier job-only shape fails the load.
- `steps` is provisional: sandyd sends none until the launch driver (#587 slice C), and each
  name maps to status `pending` until slice C pins the format.

**Residual.** A create whose reply times out and is never retried leaves an environment with
no owner, which the broker cannot list. sandyd's own row cap and the profile checks still apply
to it. Closing it is the correlation work in #621. A create whose owner save fails answers
`unavailable`; a retry that arrives when the client is at its quota gets `quota_exceeded`
and does not replay, because the broker has no record of the request. The broker does not
record the request before the create: a refused request that was then corrected would skip the
quota check, and a client could exceed the quota by one environment per distinct key.

## 7. Attach is a ticket plus a bearer-gated NDJSON stream (#616)

**Decision.**

- `POST /v1/jobs/{id}/attach` (bearer) mints a random 256-bit single-use ticket for the caller's
  own live job and answers `{"stream_url": "/v1/jobs/{id}/stream/{ticket}", "expires_in_s": 30}`.
  `stream_url` is a relative path: the client resolves it against the API URL it already uses.
  A foreign or unknown job is `not_found`; a finished job is `unavailable`. This call does no
  attach RPC and no join.
- Tickets live in broker memory only, never on disk, and expire after 30 seconds. A client holds
  at most 4 tickets plus open streams, and the broker at most 32. Over a cap answers
  `quota_exceeded` (429). No new public error code.
- `GET /v1/jobs/{id}/stream/{ticket}` needs the bearer too, so a leaked URL alone gives
  nothing. An unknown, expired, malformed, other-client or other-job ticket gives one identical
  `not_found`; a mismatched presenter does not spend the ticket. A valid ticket is removed
  before anything else, so it works once.
- The broker then makes the attach RPC with the stored attach token, connects to sandyd's attach
  socket and sends `Join` with the cap. `Refused`, a timeout (10 s) or any fault gives a fixed
  `unavailable`; sandyd's text is not relayed.
- The response is `200`, `application/x-ndjson`, `Cache-Control: no-store`, chunked. Each
  delivered stdout or stderr chunk is `{"type":"output","data":"<base64>"}` (bytes opaque,
  streams merged). The last line is `{"type":"exit","reason":...}` with `closed`,
  `job_terminal:<JOB_STATUS_*>`, `job_terminal_truncated:<JOB_STATUS_*>` or a fixed `fault:` text (`fault:data plane error`, `fault:status unavailable` after 5 failed status polls in a row). The shape follows the CLI's
  `daemon attach -o json` (#513) minus its `attached` line, which carries the cap.
- The token and the cap never appear in a response, header, URL or log line (a test scans the
  captured logs). The broker never logs the stream URL or a ticket.
- The stream is read-only. The broker never writes to the data-plane connection and never
  closes its write half: a client EOF makes sandyd's relay leave. Archive frames are dropped.
- sandyd replays the channel from sequence 0 on every join. A second stream for the same job
  sees the output again. Accepted.
- The broker polls job status about once a second, the first poll one period after the join (the
  replay is already flowing). On a terminal status it keeps forwarding until the data plane has
  been quiet for 500 ms, then sends `exit` `job_terminal:<STATUS>`. If frames still arrive 30
  seconds after the job ended, it sends `job_terminal_truncated:<STATUS>`: the output is
  incomplete and the client can open a new stream to replay it. An unknown job status reads as
  `JOB_STATUS_FAILED`, as the status route does.
- Every write to the client waits at most 30 seconds. A client that stops reading loses its
  stream and frees its slot; the data-plane buffer is two frames. If the HTTP client goes away,
  the broker drops the data-plane connection at once, even while a status call is outstanding,
  and sends nothing. The job is untouched.
- The stream's producer task has its own cap: the handler slot is free once the response head
  is out, so the ticket and stream caps above bound the producers.

**Side effect.** An open broker stream is an attach to sandyd. On a remote host that keeps the
job attached and lifts the unlimited-while-attached policy (#340, `sandyd.md` decision 14) for as
long as the stream is open, up to the client's four. Closing the stream restores it.

## 8. Output is read by offset from a broker-held buffer (#643)

**Context.** sandyd keeps no job output. Output reaches the broker only on the attach socket, and
attach ends when the job does. A polling client (the `job_output` MCP tool) needs one request per
call (`sandy-mcp`, `sandyd.md` decision 25) and needs output after exit. The owner chose a broker
route over giving `sandy-mcp` a stream reader.

**Decision.**

- When the broker accepts a submit it starts one collector task for that job. The collector
  makes the attach RPC and joins the attach socket like a stream does (decision 7), polls job
  status once a second, and after a terminal status drains until the plane is quiet for 500 ms
  (30 s at most). It appends each stdout or stderr chunk to the job's buffer.
- The collector attaches with `collector: true` and the attach token (`sandyd.md` decision 32).
  sandyd mints a read-only cap under its own peer name for it. That cap is a membership of its
  own: a submitter attach mints the shared `operator` membership with one cursor, and a
  collector on it would take messages from a client's stream. A collector join is not counted
  as an attach and sends no `AttachStateChanged`.
- Buffer bounds: 1 MiB per job, the oldest bytes dropped. The 16 MiB total is split evenly over
  the configured clients. A client over its share loses its own oldest finished job first, then
  its growing job drops its oldest bytes. One client's output never evicts another's. Offsets stay
  absolute across drops.
- `GET /v1/jobs/{id}/output?offset=N&limit=M` (bearer) answers `data` (base64), `offset`,
  `next_offset`, `dropped`, `done`, and, when done, `state` and `fault`. `limit` defaults to
  64 KiB and clamps to 1..256 KiB. Another client's job and an unknown job give one identical
  `not_found`. An offset past the end, a repeated or unknown query key, or a non-integer value
  gives `invalid_request`.
- A finished job's buffer is readable for 15 minutes after collection ends
  (`SANDY_BROKER_OUTPUT_RETENTION_SECS`, whole seconds, at most 7 days; a larger value stops
  the broker at start), then `not_found`. Expired buffers are swept on the next submit or read.
  After the job ends the collector keeps draining until the data plane is quiet for 500 ms, and
  for 30 s at most, so `done` can lag the exit by that long.
- Dropping the broker aborts every collector task, which closes their attach connections.
- A collector that cannot attach (five tries), loses the data plane, or loses the status path
  ends the buffer with a fixed `fault` text. Output may be missing; the route says so instead of
  reporting a clean `done`.
- Nothing is written to disk. A broker restart loses every buffer, and the route answers
  `not_found` for jobs submitted before it. The OpenAPI text says this.

**MCP.** `sandy-mcp` has no output tool. Raw job output returned through a tool would bypass the
secret guard (O8). Owner decision, still open.

**Set aside.** Persisting output to disk, and retention in sandyd. Both are separate work.

## Consequences

- Every broker refusal is typed (`unauthenticated`, `forbidden`, `not_found`,
  `invalid_request`, `request_id_conflict`, `quota_exceeded`, `unsupported_for_lifetime`,
  `unsupported`, `unavailable`), so `sandy-mcp` passes them through unchanged. sandyd's own
  refusal text is never relayed: a `ControlError` becomes `unavailable`, an `EnvironmentError`
  code gets a fixed message.
- A broker restart keeps job ownership, so the owner can still cancel. It loses retained output (decision 8).
- The owner table is rewritten whole on each submit and each environment create, and never pruned. Pruning waits for #596.
- A caller on another machine cannot reach the broker until the TLS follow-up lands.
- sandyd cannot tell two HTTP clients apart. The broker is the only per-client boundary.

## Acceptance

Tier-2 tests run the broker against an in-process sandyd. See
[`../architecture/kpi.md`](../architecture/kpi.md) for the live rows.
