# Broker runbook: run sandyd, the broker and sandy-mcp together

Status: the wiring below is proven by `scripts/dev/broker-smoke.sh` against the real
binaries. An environment stays `provisioning` until a launch backend makes it `ready`
(#587 slice C). Design: [`../../decisions/broker-api.md`](../../decisions/broker-api.md).
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
   deletes it.

## What does not work yet

- No environment becomes `ready` until a launch backend exists (#587 slice C). Today a
  spawn stays `provisioning` and `connection` is absent.
- `link` returns `unsupported` until T3 offers an external link interface.
- No TLS or remote callers. mTLS client auth is an owner decision (#607).
- A create whose reply times out and is never retried leaves an environment with no owner
  (#621). sandyd keeps deleted rows forever (#633).

## When a call fails

| Response                                  | Cause                                                                                                                    |
| ----------------------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| 401 `unauthenticated`                     | No bearer token, or its hash is not in the clients file.                                                                 |
| 400 `invalid_request`                     | The body is malformed or has unknown fields, `ttl_secs` does not fit the lifetime kind, or sandyd refused the fields.    |
| 403 `forbidden`                           | The profile is not in `profiles`, a host path is outside `roots`, or the isolation class is above `max_isolation_class`. |
| 404 `not_found`                           | The id does not exist, or belongs to another client. The two look the same.                                              |
| 409 `request_id_conflict`                 | The same `request_id` was used with a different payload.                                                                 |
| 409 `unsupported_for_lifetime`            | The action does not apply to this environment's lifetime or state.                                                       |
| 429 `quota_exceeded`                      | At `max_environments` or `max_environment_records`.                                                                      |
| 503 `unavailable`                         | sandyd is unreachable, refused, took over 30 s, or 64 requests are already in flight. Check the socket path.             |
| broker exits: "state directory is in use" | Another broker holds the state directory's `owners.lock`.                                                                |
| broker exits: "invalid clients"           | An empty or duplicate id, a duplicate token hash, or a hash that is not 64 lowercase hex digits.                         |
