# JobManifest parity with `sandy run`

Status: draft, owner decisions recorded below. Decision 2's mechanism and the streamed-transfer
size cap, both originally left open, are now decided (below); the implementation design and
rationale for how they're built live in `sandyd.md` §22 (#482), not here. It is the
gating work for #221 (migrate the direct-execution CLI onto sandyd), which the issue itself
calls "not yet scoped".

## Context

`sandy run` builds a `RunSpec` from its flags (`crates/sandy-cli/src/plan.rs`, `JobPlan`). A
job that goes through sandyd carries far less. Today there are two manifest shapes, and
neither matches `run`:

- `JobManifest` (`crates/sandy-orchestrator/src/lib.rs`): `entrypoint.command` and
  `requested_caps`. Submit also carries the isolation class (#381, #442).
- The executor's own decode of `Dispatch.manifest` (`crates/sandy-host-executor/src/dispatch.rs`):
  an argv for the process backend, or `flake`, `kind`, `attr`, `command`, `history_lines` for
  the VM backend.

`handle_dispatch` then fills the rest of `RunSpec` with fixed values: no inputs, outputs,
secrets, env, cpu or mem; `timeout_secs` is the constant `STAGE1_TIMEOUT_SECS`; the only grant
is `agent`.

## Parity matrix

| `run` flag                          | `RunSpec` field                                                                        | In `JobManifest` today            | Local dispatch                                                                                                                                                                                          | Remote dispatch                                                                                                        |
| ----------------------------------- | -------------------------------------------------------------------------------------- | --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| `TEMPLATE`, `--flake/--attr/--kind` | `template`                                                                             | no (VM decode only)               | pass the name                                                                                                                                                                                           | resolve on the host (done for VM, #332)                                                                                |
| `-- CMD`                            | `command`                                                                              | yes                               | done                                                                                                                                                                                                    | done                                                                                                                   |
| `--env`                             | `env`                                                                                  | no                                | copy                                                                                                                                                                                                    | copy                                                                                                                   |
| `--cpu`, `--mem`, `--timeout`       | `cpu`, `mem`, `timeout_secs`                                                           | no                                | copy, bound by host policy                                                                                                                                                                              | copy, bound by host policy                                                                                             |
| `--input HOST:NAME`                 | `inputs`                                                                               | no                                | the picked host-executor reads a submitter path (#496, `sandyd.md` §21: only a host that declared `shares_submitter_filesystem`)                                                                        | streamed over a per-job dial-back data link (#482, `sandyd.md` §22), capped at `MAX_OUTPUT_BYTES`/`MAX_OUTPUT_ENTRIES` |
| `--out [NAME:]DEST`                 | `outputs`                                                                              | no                                | the picked host-executor writes a submitter path (same #496 gate)                                                                                                                                       | streamed back over the same data link (#482, `sandyd.md` §22), sandyd re-validates every path before writing it        |
| `--secret NAME=@PATH`               | `secrets`, `grants`                                                                    | no                                | stage from the submitter's file (same #496 gate)                                                                                                                                                        | refused with a named error (decision 4) — unchanged by #482                                                            |
| `--allow HOST:PORT`                 | `JobPlan.allow`, outside `RunSpec` (reaches it as `RunSpec.egress` only in proxy mode) | no                                | apply and revert through the existing egress boundary (nftables, or the proxy, #403); a local apply failure refuses the run (band 3, before boot), and the policy is reverted on both success and error | refuse with a named error until the host applies and reverts the policy (#408)                                         |
| `--credential`, `--cred-capability` | credential bracket                                                                     | no (`SubmitRequest` fields, #481) | the daemon mints, stages a `GITHUB_TOKEN` file for the picked host-executor (same #496 gate), and revokes on every terminal path (`sandyd.md` §34); no mid-run refresh yet                              | refused with a named error until the encrypted mesh transport exists (#495)                                            |

## Decisions (proposed)

- **P1 — Split by locality.** Reach parity for local dispatch first. Every field that is a
  plain value (env, cpu, mem, timeout, template, command) is also correct for remote
  dispatch, so those ship once for both. Fields that name a submitter-side path (inputs,
  outputs, secrets) stay local-only until a transfer mechanism exists. A remote Submit that
  carries one is refused with a named error, never dropped.
- **P2 — The manifest names data, never submitter paths on a remote host.** A path in the
  manifest is read by whoever executes it. A path that is valid on the submitter's machine
  is wrong or hostile on another host.
- **P3 — One manifest type.** `JobManifest` grows the fields. The executor's two ad-hoc
  decodes become views of it, so the two shapes stop drifting. Deferred as its own decision
  (`docs/decisions/sandyd.md` §19): #480 lands the plain-value fields by growing `argv/v1`/
  `flake/v1` in place instead, since collapsing to one wire tag needs an explicit `SandboxKind`
  field to replace what the encoding tag signals today (decision 18).
- **P4 — Bounds are the host's, requests are the submitter's.** cpu, mem and timeout are
  requests, clamped by the executing host's policy. `STAGE1_TIMEOUT_SECS` becomes the
  default and the ceiling, not a constant.

## Specification

1. **Valid inputs.** Each field has the `run` flag's own validation (same parser as
   `plan.rs`). An unknown manifest encoding or an unknown field is refused. An empty `command`
   follows `run` ("boot the template's default").
2. **Expected output.** For the same supported flags, a job run through sandyd produces the same
   `RunSpec` as the direct path, and the same result envelope (INV-11) except the job id
   scheme.
3. **Failure definition.** A path field on a remote host whose picked placement declares
   neither `transfer` nor `shares_submitter_filesystem` (`secrets` specifically needs
   `shares_submitter_filesystem`, #482) is a refusal at Submit with the field named. No backend
   starts and no journal record is written. No field is silently ignored.
4. **Performance and scale.** Remote input/output transfer (#482) is capped at
   `MAX_OUTPUT_BYTES`/`MAX_OUTPUT_ENTRIES` per direction (`sandyd.md` §22), enforced at Submit
   and again while streaming.
5. **Dependency behaviour.** The executor re-validates every field it acts on, as it already
   does for the isolation class (defense in depth).

## Acceptance tests

- For each flag in the matrix, a table-driven test builds a `RunSpec` from `RunArgs` and from
  the equivalent `JobManifest`, and compares an explicit projection of the manifest-derived
  fields (`RunSpec` has no `PartialEq`). Runtime fields (`control`, `outcome_file`,
  `secret_dir`) are not part of this projection; they are tested separately.
- A manifest with a path field submitted for a remote host whose placement declares neither
  `transfer` nor `shares_submitter_filesystem` is refused with the field named
  (`secrets` specifically needs `shares_submitter_filesystem`, #482).
- The inverse: `inputs`/`outputs` submitted for remote dispatch onto a host that DOES declare
  `transfer` (or `shares_submitter_filesystem`) is accepted, not refused (#482).
- A manifest with an unknown field is refused, not accepted with the field dropped.
- A `timeout_secs` above the host ceiling is clamped, and the clamp is visible in the status.
- A `--secret` value never appears on the host side: not in the manifest bytes, the Dispatch
  frame, a log line, host argv, the host's own environment, or the Nix store. Inside the guest
  it's exposed deliberately, through a dedicated read-only share: staged under a `0700` base as a
  `0600` file, with `SANDY_SECRETS_DIR` naming the staged directory's path to the job (never the
  bytes). Separate tests cover the dedicated share, rejecting a source with the wrong
  permissions, the share being read-only, and staging removed at teardown. The remote Submit
  refusal is a separate test.
- The executor acts on every `RunSpec` field it receives. A tier-2 test over `FakeBackend`
  asserts that `env`, `timeout_secs`, `cpu`, `mem`, and `outputs` each reach the backend. A
  tier-3 `live` test asserts the guest-visible effect. A fake never counts as live evidence.
  `RunSpec.env` is a known gap today (`dispatch.rs` does not plumb it into the guest), so this
  test starts red.

## Out of scope

- The `service` field (#589): a declared long-running service with a health probe is specified in
  `docs/decisions/run-plane.md` §5, not here.
- Moving the CLI verbs (`ls`, `wait`, `kill`, `gc`) and unifying job ids. Those are the later
  steps of #221 and depend on this work.
- The egress proxy itself (#401 to #408). This spec only needs a field to carry the policy.

## Owner decisions

The owner answered the four questions of the first draft.

1. **Local first.** P1 stands: plain-value fields ship for local and remote dispatch; path
   fields ship for local dispatch only.
2. **Remote inputs and outputs stream over a per-job dial-back link, not the shared control
   connection** — reopened from the original draft's "control connection" wording (owner
   decision, 2026-10-29; the mechanism rationale is recorded in `sandyd.md` §22, #482, not
   repeated here). The size cap matches the existing local collect caps exactly:
   `MAX_OUTPUT_BYTES` (4 GiB) and `MAX_OUTPUT_ENTRIES` (100,000), applied to BOTH inputs and
   outputs for remote transfer (owner decision, 2026-10-29) — local inputs stay uncapped,
   unaffected; this cap is specific to the remote path. It is not part of the local-first
   step.
3. **The credential is minted on the daemon, before boot, fail-closed.** The trust root stays
   on the orchestrator host. Mint failure refuses the Submit; no backend starts without a
   token. The scoped, short-lived token crosses the mesh to the executor over a transport that
   encrypts traffic (TLS, QUIC, or an equivalent over vsock), as `sandyd.md` §2 requires for a
   bearer credential. Mesh authentication alone does not protect it in transit. A long-running
   job gets the token refreshed before expiry; the token is revoked on the job's terminal state
   (success, failure, or cancellation), and any credential staged for it is cleaned up at
   teardown. Tier-2 `FakeProvider` tests cover mint success, mint failure, cancellation or kill
   mid-run, refresh, and a revoke failure.
4. **A secret never crosses the mesh.** A remote Submit that carries `--secret` is refused
   with a named error. INV-1 stays simple: secret bytes stay on the submitter's machine.

The size cap for streamed inputs and outputs, originally left open here, is now decided —
see decision 2 above.

## Self-test: what could pass every test above and still be wrong?

A field that the daemon accepts and the executor drops without a trace. The matrix requires a
named refusal for each unsupported field. The table test defines its parity-field projection as
an explicit list, plus an allowlist of plumbing-only fields (`control`, `outcome_file`,
`secret_dir`) that are deliberately excluded, and asserts every projected field has a matrix
row. It still destructures `RunSpec` exhaustively, so a new field with no classification in
either list fails to compile instead of becoming a silent gap.
