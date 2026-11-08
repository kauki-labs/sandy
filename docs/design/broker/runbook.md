# Broker runbook: run sandyd, the broker and sandy-mcp together

Status: the wiring below is proven by `scripts/dev/broker-smoke.sh` against the real
binaries. An environment stays `provisioning` until a launch backend makes it `ready`: the
opt-in process backend does that today (see "Run an environment end to end"), the VM backend
is #587 slice C. Design: [`../../decisions/broker-api.md`](../../decisions/broker-api.md).
Contract: [`../../api/broker.openapi.yaml`](../../api/broker.openapi.yaml).

## What runs

```text
T3 / an agent --stdio--> sandy-mcp --HTTP, bearer--> sandy-broker --UDS, control RPC--> sandyd
```

`sandy-mcp` holds no state. `sandy-broker` authenticates the caller, owns per-client
ownership and quotas, and keeps each job's attach token. `sandyd` runs as the same user as the
broker and stores jobs and environments.

## Steps

1. Build: `cargo build -p sandyd -p sandy-broker -p sandy-mcp`.
2. Make a token and its hash. The broker stores only the hash.

   ```bash
   token=$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')
   printf %s "$token" | shasum -a 256 | cut -d' ' -f1   # sha256sum on Linux
   (umask 077; mkdir -p ~/.config/sandy; printf %s "$token" > ~/.config/sandy/broker.token)
   ```

3. Write the clients file. The broker refuses to start if any group or other
   permission bit is set (use mode 0600). Field names are not checked: a misspelt `profiles`
   is ignored and every spawn gets `forbidden`.

   ```json
   [
     {
       "id": "t3",
       "token_sha256": "<the 64 lowercase hex digits above>",
       "max_isolation_class": "untrusted",
       "profiles": ["dev"],
       "max_environments": 4,
       "max_environment_records": 64,
       "roots": []
     }
   ]
   ```

   | Field                     | Meaning                                                    | Default      |
   | ------------------------- | ---------------------------------------------------------- | ------------ |
   | `id`                      | The client's name. Owns its jobs and environments.         | required     |
   | `token_sha256`            | SHA-256 of the bearer token, lowercase hex.                | required     |
   | `max_isolation_class`     | `untrusted` or `trusted`. A higher request is `forbidden`. | required     |
   | `profiles`                | Profile names a spawn may use.                             | none allowed |
   | `max_environments`        | Non-terminal environments at once.                         | 4            |
   | `max_environment_records` | Environments ever created, deleted ones included.          | 64           |
   | `roots`                   | Directories a job's inputs, outputs and secrets may name.  | none allowed |

4. Start sandyd: `SANDY_SOCK=/path/sandyd.sock SANDY_DB=/path/sandyd.db sandyd`. Without
   the variables it uses a `0700` directory it creates under the OS temp base.
   sandyd appends an audit line for each environment create, stop, cancel and delete to
   `/path/sandyd.db.audit.jsonl` (or `SANDY_AUDIT_LOG`), mode `0600`. It does not start if it cannot open
   that file, and it refuses an environment operation it cannot audit. No rotation yet.
5. Start the broker:

   ```bash
   sandy-broker --control-socket /path/sandyd.sock --state-dir /path/broker-state \
     --clients-file /path/clients.json --bind 127.0.0.1:8787
   ```

   The bind address must be loopback. There is no TLS yet. Run one broker per state
   directory.

6. Point `sandy-mcp` at it:

   ```bash
   sandy-mcp --api-url http://127.0.0.1:8787 --credential-file ~/.config/sandy/broker.token
   ```

7. Check the wiring without a client: `scripts/dev/broker-smoke.sh` starts its own sandyd
   and broker in a temp directory, spawns an environment, retries it, reads it back and
   deletes it. `BROKER_SMOKE_READY=1` adds the process backend and checks the full path.

## Run an environment end to end

`SANDY_ENV_BACKEND=process-insecure` makes sandyd run each environment's service as a host
process. It has no isolation. While it is on, sandyd refuses an environment create from a client
whose `max_isolation_class` is not `trusted` (`forbidden`, #641): give the `t3` client
`"max_isolation_class": "trusted"` and use it on a dev machine only. Upgrade sandyd and the broker together: a broker that does not send the class gets every create refused. Lowering a client does not stop its stopped environments from resuming; delete them to revoke. Set the
variables on sandyd (names and meanings in `crates/sandyd/src/environment_backend.rs`):

```bash
SANDY_ENV_BACKEND=process-insecure \
SANDY_ENV_PROCESS_COMMAND='t3 serve --port {port} --base-dir {base_dir}' \
SANDY_ENV_STATE_DIR=/path/environments \
SANDY_SOCK=/path/sandyd.sock SANDY_DB=/path/sandyd.db sandyd
```

A spawn then moves `provisioning` to `ready`, and `GET /v1/environments/{id}` shows `connection.url`. Delete
stops the process on the driver's next tick (about a second).
`BROKER_SMOKE_READY=1 scripts/dev/broker-smoke.sh` runs this with a stand-in HTTP service
(it needs `python3`).

## What does not work yet

- Without `SANDY_ENV_BACKEND` a spawn stays `provisioning` and `connection` is absent. The
  isolated VM backend is #587 slice C.
- `link` returns `unsupported` until T3 offers an external link interface.
- No TLS or remote callers. mTLS client auth is an owner decision (#607).
- A create whose reply times out and is never retried leaves an environment with no owner
  (#621). sandyd collects deleted rows after `SANDY_ENV_RETENTION_SECS` (default one day) (#633).

- Upgrade sandyd and the broker together. A broker that predates paging ignores
  `next_page_token`, sees only the first 100 rows and undercounts quota. Set
  `SANDY_MAX_ENVIRONMENTS` at or below 10000: the broker's scan ceiling counts rows before
  its ownership filter, and `Failed` rows count toward the cap (a client can hold up to
  `max_environment_records` of them).

## When a call fails

| Response                                  | Cause                                                                                                                                                                                                                    |
| ----------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 401 `unauthenticated`                     | No bearer token, or its hash is not in the clients file.                                                                                                                                                                 |
| 400 `invalid_request`                     | The body is malformed or has unknown fields, `ttl_secs` does not fit the lifetime kind, or sandyd refused the fields.                                                                                                    |
| 403 `forbidden`                           | The profile is not in `profiles`, a host path is outside `roots`, the isolation class is above `max_isolation_class`, or an environment create came from a client below `trusted` while sandyd runs the process backend. |
| 404 `not_found`                           | The id does not exist, or belongs to another client. The two look the same.                                                                                                                                              |
| 409 `request_id_conflict`                 | The same `request_id` was used with a different payload.                                                                                                                                                                 |
| 409 `unsupported_for_lifetime`            | The action does not apply to this environment's lifetime or state.                                                                                                                                                       |
| 429 `quota_exceeded`                      | At `max_environments` or `max_environment_records`.                                                                                                                                                                      |
| 503 `unavailable`                         | sandyd is unreachable, refused, took over 30 s, or 64 requests are already in flight. Check the socket path.                                                                                                             |
| broker exits: "state directory is in use" | Another broker holds the state directory's `owners.lock`.                                                                                                                                                                |
| broker exits: "invalid clients"           | An empty or duplicate id, a duplicate token hash, or a hash that is not 64 lowercase hex digits.                                                                                                                         |
