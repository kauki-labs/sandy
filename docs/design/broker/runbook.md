# Broker runbook: run sandyd, the broker and sandy-mcp together

Status: the wiring below is proven by `scripts/dev/broker-smoke.sh` against the real
binaries. An environment stays `provisioning` until a launch backend makes it `ready`: the
opt-in process backend does that today (see "Run an environment end to end"), the VM backend
is #587 slice C. Design: [`../../decisions/broker-api.md`](../../decisions/broker-api.md).
Contract: [`../../api/broker.openapi.yaml`](../../api/broker.openapi.yaml).

## What runs

```text
An agent --stdio--> sandy-mcp --HTTP, bearer--> sandy-broker --UDS, control RPC--> sandyd
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
       "id": "example",
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

4. Start sandyd: `SANDY_SOCK=/path/sandyd.sock SANDYD_BROKER_SOCK=/path/broker.sock SANDY_DB=/path/sandyd.db sandyd`.
   Without the variables it uses a `0700` directory it creates under the OS temp base. `SANDYD_BROKER_SOCK` is the
   broker's own socket: `sandyd` accepts the client id the broker puts in each submission only there, so a job's receipt
   names the API client (`who.identity` is `broker:<client id>`). It must be an absolute path in the same directory as
   `SANDY_SOCK` (the attach socket is a sibling of both), and `sandyd` refuses to start otherwise, naming both paths.
   sandyd appends an audit line for each environment create, stop, cancel and delete to
   `/path/sandyd.db.audit.jsonl` (or `SANDY_AUDIT_LOG`), mode `0600`. It does not start if it cannot open
   that file, and it refuses an environment operation it cannot audit. No rotation yet.
5. Start the broker:

   ```bash
   sandy-broker --control-socket /path/broker.sock --state-dir /path/broker-state \
     --clients-file /path/clients.json --bind 127.0.0.1:8787
   ```

   In bearer mode the bind address must be loopback. For other machines use mutual TLS (below). Run one
   broker per state directory.

   Point `--control-socket` at the broker socket, not the main one. The broker puts a client id in every
   submission, and `sandyd` refuses a client id on the main socket, so a broker on the main socket cannot submit
   (its jobs answer `unavailable`). A client id the broker's clients file holds must be 1 to 128 bytes with no
   control character, or the broker does not start.

6. Point `sandy-mcp` at it:

   ```bash
   sandy-mcp --api-url http://127.0.0.1:8787 --credential-file ~/.config/sandy/broker.token
   ```

7. Check the wiring without a client: `scripts/dev/broker-smoke.sh` starts its own sandyd
   and broker in a temp directory, spawns an environment, retries it, reads it back and
   deletes it. `BROKER_SMOKE_READY=1` adds the process backend and checks the full path.

## Remote callers over mutual TLS (#887)

A broker is in one mode. The steps above are bearer mode: plaintext, loopback only. For callers on other machines, start
the broker with `--tls-identity-dir`: it then serves mutual TLS only, on any address, and ignores bearer tokens.

1. Make each caller a certificate. The broker pins a certificate by the SHA-256 of its DER bytes. The mesh's generator
   makes a suitable self-signed one: `sandy mesh key generate <dir>` writes `<dir>/identity.cert.der` and
   `<dir>/identity.key.der` and prints the fingerprint (the same one you pin).
2. Put the fingerprint in the clients file instead of `token_sha256` (a client has one or the other, never both, and the
   broker refuses to start otherwise):

   ```json
   {
     "id": "remote-a",
     "certs": [{ "sha256": "<64 hex digits>", "not_after": 1798761600 }],
     "max_isolation_class": "untrusted",
     "profiles": ["dev"],
     "roots": []
   }
   ```

   `not_after` is optional (unix seconds). A pin already past it when the broker starts is refused at the handshake. The
   handshake list is fixed at start, so a pin that expires later still completes the handshake. Each request re-checks
   `not_after` and answers `401 unauthenticated` once it has passed, on a new connection and on a long one alike. If the
   system clock cannot be read, the broker refuses every pin, with or without a `not_after`: it does not start in mTLS
   mode, and a running broker answers every certificate request `401`. Time-based checks cannot be trusted on a broken
   clock, so the broker never guesses. The certificate's own validity period is not checked. To rotate, list the old and
   the new pin together, restart, move the caller to the new certificate, then remove the old pin and restart. A fingerprint belongs to one
   client: listing it twice is refused.

3. Start the broker: `sandy-broker --control-socket /path/broker.sock --state-dir /path/broker-state --clients-file
/path/clients.json --bind 0.0.0.0:8443 --tls-identity-dir /path/broker-tls`. It creates the identity on first use and
   prints `broker mTLS fingerprint: <64 hex digits>` on stdout: a caller pins that value. The broker creates the identity
   directory `0700`. It refuses to start if that directory is a symlink or is owned or writable by another user, or if
   `identity.key.der` is a symlink, is owned by another user, or is readable by group or world. If you made the
   directory yourself, give it `0700` and the key `0600`, owned by the broker's user.
4. A caller connects with its certificate and key and pins the broker's fingerprint. Every caller needs a certificate,
   including a loopback one: `sandy-mcp` has no TLS client, so it keeps using a bearer broker on loopback.

To revoke a caller, remove its pin and restart the broker. The clients file is read once, so there is no reload, and a
restart ends every connection, attach stream and output collection in flight. A handshake that fails (a certificate that
is not pinned, a timeout, plaintext on the TLS port) gets no HTTP answer; the broker logs `handshake refused` (set
`RUST_LOG=warn` to see it: the default filter shows errors only) with the kind (`tls` or `handshake_timeout`) and the
peer address, never a certificate. A scanner can fill that log, so rotate it. Unauthenticated peers can hold up to 128
connection slots for the handshake timeout (10 s), so firewall the port to the callers' addresses.

### Upgrading an existing broker identity directory

An earlier mTLS broker created `--tls-identity-dir` with the process umask, so under umask 002 it is mode 0775 and its key 0644. The broker now refuses to start on such a directory, and the error names the path and the command:

1. Run `chmod 700 <identity dir>`.
2. Run `chmod 600 <identity dir>/identity.key.der`.
3. Start the broker. The fingerprint does not change, so no caller re-pins.

If the error says the key is a symlink, replace it with a regular file holding the key. If it says another user owns the
directory or the key, `chown` it to the broker's user. Removing both identity files mints a new identity, and every caller
must then pin the new fingerprint.

## Run an environment end to end

`SANDY_ENV_BACKEND=process-insecure` makes sandyd run each environment's service as a host
process. It has no isolation. While it is on, sandyd refuses an environment create from a client
whose `max_isolation_class` is not `trusted` (`forbidden`, #641): give the `example` client
`"max_isolation_class": "trusted"` and use it on a dev machine only. Upgrade sandyd and the broker together: a broker that does not send the class gets every create refused. Lowering a client does not stop its stopped environments from resuming; delete them to revoke. Set the
variables on sandyd (names and meanings in `crates/sandyd/src/environment_backend.rs`):

```bash
SANDY_ENV_BACKEND=process-insecure \
SANDY_ENV_PROCESS_COMMAND='example-service serve --port {port} --base-dir {base_dir}' \
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
- `link` returns `unsupported` until a service offers an external link interface.
- Remote callers need mTLS (above): no CA, no hot reload, revocation by restart. Bearer stays loopback only.
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
