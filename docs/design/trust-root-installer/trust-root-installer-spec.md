# Trust-root installer (sandy app register): spec

Design amendments (grounded deviations from the proposal) go here and supersede it. None yet.

The verify probe lives in the `Provisioner` trait (one method per kind), so Block 1 owns the
pipeline's "verify before success" rule and Blocks 2/3 own their kind's actual probe. That keeps
the scope-rendering next to the mint it must match (the hinge).

## Block index

| #   | Block                                                                       | Runs on | Depends on | Satisfies                         |
| --- | --------------------------------------------------------------------------- | ------- | ---------- | --------------------------------- |
| 0   | Preconditions + trust-root config schema                                    | host    | -          | REQ-1, REQ-5                      |
| 1   | Target model + `Provisioner` trait + installer pipeline + `FakeProvisioner` | host    | 0          | REQ-2, REQ-5, REQ-6, REQ-7, REQ-8 |
| 2   | GitHub provisioner (manifest flow)                                          | host    | 1          | REQ-3, REQ-7                      |
| 3   | GitLab provisioner (guided paste-back)                                      | host    | 1          | REQ-4, REQ-7                      |

## Block 0: Preconditions + trust-root config schema

**Purpose.** Define the on-disk trust-root record the credential-seam adapter reads, and the
load/save helpers that enforce its permissions. This is the contract the whole feature produces.

**Architecture.** A serde `TrustRoot` struct, kind-tagged (`github` / `gitlab`), serialized as
TOML under the sandy config dir (`$XDG_CONFIG_HOME/sandy/trust-roots/{name}.toml`, fallback
`~/.config/...`). Secret bytes live in a sibling `0600` file referenced by path
(`private_key_path` / `token_path`), never inline. `save` writes record + secret file `0600`;
`load` refuses a secret file that is group/world-readable.

**Interfaces.** Input: fields supplied by the pipeline (Block 1). Output: a `TrustRoot` record
and secret file the credential-seam adapter loads unmodified (Block 0/3/4 contract). Config
surface: config-dir path (env override), file mode (`0600`).

**Satisfies:** REQ-1, REQ-5.

Verification (positive) tests:

| Test                      | Setup / Inject                           | Expected result                                                                                  |
| ------------------------- | ---------------------------------------- | ------------------------------------------------------------------------------------------------ |
| github record round-trips | `save` a github `TrustRoot`, then `load` | fields equal; secret file mode is `0600`.                                                        |
| adapter-shaped output     | `load` a github record                   | yields exactly the fields credential-seam Block 3 names (`app_id`, key path, `installation_id`). |

Adversarial (negative) tests:

| Test                          | Setup / Inject                        | Expected result                                                                       |
| ----------------------------- | ------------------------------------- | ------------------------------------------------------------------------------------- |
| world-readable secret refused | secret file chmod `0644`, then `load` | named `PermError`; load does NOT silently proceed (assert it returns no usable root). |
| missing secret file           | record present, secret file deleted   | named error; no empty or partial `TrustRoot` returned.                                |

## Block 1: Target model + `Provisioner` trait + installer pipeline + `FakeProvisioner`

**Purpose.** The shared register flow and the seam each kind plugs into, plus the pre-run
disclosure that makes the no-backdoor property auditable.

**Architecture.** `Target { kind, base_url }` (base_url defaults to the public host). A
`Provisioner` trait: `plan(target, caps) -> RegistrationPlan` (URL to open + step text + the
manifest/scopes to show), `capture(plan) -> CapturedSecret`, `verify(trust_root, caps) -> ()`.
Pipeline: resolve target → print the disclosure (every host contacted = the target forge only;
capture is local; write is `0600`; no key ships) → `plan` → hand-hold (open URL via `webbrowser`,
print concise steps) → `capture` → `TrustRoot` via Block 0 → `verify` → report. `FakeProvisioner`
(tier-2, no network) gives deterministic `capture`/`verify` for the pipeline's own tests.

**Interfaces.** Input: CLI args (`--kind`, `--base-url`, `--name`, the requested capabilities,
the target repo/project). Output: a written `TrustRoot` + a success/failure result. Config
surface: the capability set requested; nothing persistent beyond Block 0.

**Satisfies:** REQ-2, REQ-5, REQ-6, REQ-7, REQ-8.

Verification (positive) tests:

| Test                        | Setup / Inject                          | Expected result                                                                  |
| --------------------------- | --------------------------------------- | -------------------------------------------------------------------------------- |
| register over the fake      | `FakeProvisioner`, valid capture+verify | a `0600` trust root is written and success is reported only after verify passes. |
| second provisioner plugs in | add a stub `Provisioner`                | pipeline and CLI compile unchanged (REQ-2).                                      |

Adversarial (negative) tests:

| Test                        | Setup / Inject                                                | Expected result                                                                                                         |
| --------------------------- | ------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| verify fails → no success   | `FakeProvisioner.verify` returns an error                     | `register` exits non-zero with a named error and leaves no usable trust root; success is NOT printed.                   |
| no non-forge host contacted | run under a network allow-list permitting only the forge host | the whole flow completes (or the only possible failure is a blocked non-forge call, which never occurs); asserts REQ-6. |

## Block 2: GitHub provisioner (manifest flow)

**Purpose.** A live `Provisioner` for github.com and GitHub Enterprise Server.

**Architecture.** Build a manifest from the requested caps (`contents`/`pull_requests` rendered
from `Capability`, `metadata:read`, `hook_attributes.active:false`, `public:false`). Start a
`127.0.0.1` listener on a random high port carrying a single-use `state` nonce; open
`<base>/settings/apps/new` (user) or `<base>/organizations/<org>/settings/apps/new` (org) with an
auto-submit form POSTing the manifest. Catch `?code=&state=`, verify the nonce, `POST
<api-base>/app-manifests/{code}/conversions`, capture `id` + `pem`, write the `pem` `0600`. Then
hand-hold **Install**, and capture `installation_id` via `GET <api-base>/app/installations` (App
JWT) or the install settings URL. `verify`: mint a 1-repo installation token for the requested
caps, confirm it works, confirm the App's actual permissions do not exceed the request, then
`DELETE /installation/token`.

**Interfaces.** Input: `Target{github, base_url}`, caps, owner (user | org). Output:
`TrustRoot{app_id, private_key_path, installation_id}`. Config surface: owner kind (selects the
new-app path), the repo set to install on.

**Satisfies:** REQ-3, REQ-7.

Verification (positive) tests:

| Test               | Setup / Inject                                  | Expected result                                                                  |
| ------------------ | ----------------------------------------------- | -------------------------------------------------------------------------------- |
| github.com capture | register against a throwaway repo on github.com | `pem` captured with zero manual paste; verify mints a token scoped to that repo. |
| GHES base URL      | `--base-url <ghes-host>`                        | new-app form and conversions call route to that host, not github.com.            |

Adversarial (negative) tests:

| Test                         | Setup / Inject                                         | Expected result                                                                                   |
| ---------------------------- | ------------------------------------------------------ | ------------------------------------------------------------------------------------------------- |
| widened permissions detected | user edits the manifest form to add a permission       | verify re-reads the App's actual permissions and fails; the over-grant is observable, not silent. |
| reused/expired code          | call conversions with a spent or >1 h `code`           | named error; no partial trust root written.                                                       |
| foreign-process redirect     | hit the localhost redirect with a wrong/absent `state` | rejected; the handshake does not complete for another process.                                    |

## Block 3: GitLab provisioner (guided paste-back)

**Purpose.** A live `Provisioner` for gitlab.com and self-managed GitLab.

**Architecture.** Render the needed scopes from caps (`read_repository` / `write_repository`,
`api` where required) and the least role; open the group/project access-token (or service-account)
settings deep-link at `<base>` with concise step text (which scopes to tick, which role, what
expiry). Prompt a **no-echo** paste of the created token, write it `0600`, capture the
project/group id. `verify`: a scoped probe (a `read_repository`-level call, a guarded
`write_repository` dry-run where requested) that confirms the token works and that its scopes
match the request (reject an over-broad personal token).

**Interfaces.** Input: `Target{gitlab, base_url}`, caps, project/group id, `account_kind`.
Output: `TrustRoot{token_path, project_or_group_id, account_kind}`. Config surface:
`account_kind` (`group-token` | `project-token` | `service-account`), token expiry.

**Satisfies:** REQ-4, REQ-7.

Verification (positive) tests:

| Test                  | Setup / Inject                                     | Expected result                                       |
| --------------------- | -------------------------------------------------- | ----------------------------------------------------- |
| gitlab.com paste-back | register with a pasted project token on gitlab.com | token stored `0600`; verify reads the project.        |
| self-managed base URL | `--base-url <self-managed-host>`                   | the deep-link and verify call route to that instance. |

Adversarial (negative) tests:

| Test                       | Setup / Inject                                       | Expected result                                                                                                      |
| -------------------------- | ---------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| over-broad token rejected  | paste a broad personal PAT instead of the scoped one | verify detects scopes beyond the request and refuses (assert refusal, not silent accept).                            |
| service account on Free/CE | request `service-account` on a Free/CE instance      | named "unsupported tier" error that names the group/project-token fallback (REQ-8: don't require a missing feature). |

## Escalation appendix

Never hand-build the HTTP listener or JWT signing.

| Tool                       | License        | Adds                                        | Cost               | Reach for it when                                                                                               |
| -------------------------- | -------------- | ------------------------------------------- | ------------------ | --------------------------------------------------------------------------------------------------------------- |
| `tiny_http`                | Apache-2.0/MIT | the single-use `127.0.0.1` redirect catcher | a tiny HTTP dep    | Block 2 needs to catch the manifest `?code=`.                                                                   |
| `webbrowser`               | MIT/Apache-2.0 | cross-platform "open this URL"              | trivial            | any kind opens a pre-filled page.                                                                               |
| `octocrab`                 | MIT/Apache-2.0 | GitHub App JWT + mint/revoke + REST         | a larger dep       | Block 2 verify — **only if** the credential-seam GitHub adapter also uses it (keep one client).                 |
| `jsonwebtoken` + `reqwest` | MIT            | RS256 App JWT + raw REST                    | you wire the calls | the raw path if `octocrab` is too heavy; the conversions call needs no auth, so `reqwest` alone covers capture. |
| `gitlab` crate             | MIT            | GitLab REST                                 | a dep              | Block 3 verify read.                                                                                            |

## Acceptance criteria

End to end, for each kind: `sandy app register` on a throwaway target writes a `0600` trust root
that a credential-seam adapter loads unmodified and mints a correctly scoped lease; `register`
reports success only after the verify probe passes and asserts the scope is not broader than
requested; the command contacts only the target forge host; and no shared secret ships in the
binary.

**Hinge measurement (OPEN):** the installer's verify-probe scope rendering must be identical to
the credential-seam adapter's mint rendering. If they drift, "verified" lies. This stays open
until credential-seam Blocks 3/4 exist and the two share one renderer; it is the single
equivalence the whole guarantee turns on.
