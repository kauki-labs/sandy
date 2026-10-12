# Trust-root installer (sandy cred github register): proposal

## 1. Purpose and non-goals

Give anyone running sandy a one-command way to stand up the forge trust root the credential
seam consumes (credential-seam Block 0), for a chosen target (github.com, GitHub Enterprise
Server, gitlab.com, self-managed GitLab): pre-fill the registration, hand-hold the few manual
clicks with concise explanations, and capture the resulting credential locally at `0600`. The
credential is generated into the installer's own hands, unique per installer, with no shared
secret and no author-controlled server in the path.

Explicitly NOT:

- **Not the credential adapter or job-time minting** (credential-seam Blocks 1/3/4). This
  writes the config those read; it never mints a job token.
- **Not a hosted "install our App" button.** A shared App means the author holds the one key
  that mints for every installation, the backdoor this feature exists to remove.
- **Not the install-repo-scope IaC.** That is operator-specific tofu in `kauki-labs/infra`
  (`tf/cloud/02-github/`), for the author's own orgs, not shipped to installers.

## 2. Where this plugs in today

On sandy `origin/main`:

- The credential-seam work package (`../credential-seam/`) defines the consumer: a
  `CredentialProvider` seam over an abstract `Scope { targets, capabilities }` (`Capability` =
  `ReadCode`/`WriteCode`/`ReadPr`/`WritePr`), a GitHub adapter (App JWT → installation token,
  Block 3) and a GitLab adapter (service PAT → project/group token, Block 4). Its **Block 0,
  "Preconditions (trust roots)"**, names the config surface the adapters read (which provider,
  trust-root location, target scope) but establishes it **by hand** ("configure a GitHub App
  key path"). This feature automates Block 0.
- `crates/sandy/src/cred.rs` holds the GitHub-shaped, mint-only seam; the live adapter is
  walled on trust-root setup. The installer removes that wall for any installer, not just the
  author.
- `crates/sandy-cli/` is the `sandy` binary (`doctor`, `run`/`ls`/`status`/`wait`/`kill`/`gc`);
  `app register` is a new verb there.
- Operator precedent: `kauki-labs/infra` registers the author's own Apps declaratively
  (manifests + tofu install scope), and sandy's own `docs/github-app.md` is the manual version
  of this flow. The installer generalizes that bootstrap into a command.

## 3. Requirements (fixed constraints)

- REQ-1: When the user runs `sandy cred github register` for a target, the system SHALL write a
  trust-root config the credential-seam adapter consumes (the Block 0 contract), needing no
  further hand configuration. (MUST)
- REQ-2: The system SHALL support a `github` and a `gitlab` kind, each on its public host or a
  self-hosted base URL, through one pipeline with per-kind adapters. (MUST)
- REQ-3: For a `github` target, the system SHALL pre-fill the App registration via the GitHub
  App Manifest flow and capture the private key automatically from the manifest conversion.
  (MUST)
- REQ-4: For a `gitlab` target, where no manifest flow exists, the system SHALL deep-link the
  pre-scoped access-token / service-account creation, explain each step, and capture the
  user-created token. (MUST)
- REQ-5: The captured credential SHALL be written `0600` on the controller and SHALL NOT be
  echoed to logs, argv, env, or any guest share. (MUST — inherits credential-seam REQ-5)
- REQ-6: The credential SHALL be generated into the installer's own hands (GitHub: a
  GitHub→localhost redirect; GitLab: the user's browser), unique per installer; the system
  SHALL ship no shared secret and SHALL contact no author-controlled network endpoint during
  registration. (MUST — the no-backdoor guarantee)
- REQ-7: After capture, the system SHALL verify the credential mints or reads a correctly
  scoped probe lease and matches the expected scope before reporting success, and SHALL fail
  with a named error otherwise. (MUST)
- REQ-8: The system SHALL NOT require a provider capability that does not exist (e.g. a GitLab
  manifest flow) and SHALL NOT report success when the verify probe fails. (MUST NOT)
- REQ-9: When the user deregisters a trust root, the system SHALL revoke the credential at the
  forge **before** destroying the local secret, then shred the local key and record; and where
  the forge offers no API to delete the App registration itself, the system SHALL report that
  residue and name the manual deletion step. (MUST)

## 4. Design

Two candidates, on the axis "where provider knowledge lives."

**Candidate A, per-target commands** (`register github`, `register gitlab`, each hard-coding
its UI). Rejected: it duplicates the identical capture/store/verify pipeline across 2 kinds ×
(public, self-hosted) and forces the CLI to branch per target; the only genuinely per-target
step is how the registration is initiated.

**Candidate B, one pipeline + `Provisioner` adapters (chosen).** Mirrors the credential-seam's
own one-seam-plus-adapters shape, so the two stay consistent. Read in order:

1. Because credential-seam Block 0 already fixes the config the adapters read, the installer's
   sole output is that config. It is a **front-end to Block 0**, not a new subsystem;
   everything below follows from holding that output contract fixed.
2. Because GitHub offers a manifest handshake that returns the private key to a caller-chosen
   redirect and GitLab offers none, the two kinds cannot share a capture mechanism → a
   `Provisioner` trait per kind behind a shared pipeline (resolve target → provision → capture
   → write `0600` → verify).
3. Because the key must reach only the installer (REQ-6), GitHub's redirect is
   `http://127.0.0.1:<port>` and the conversion is called from the user's machine; GitLab's
   token is created in the user's own browser and pasted back. No author host sits in either
   path, so no-backdoor is **structural, not a promise**.
4. Because self-hosted differs from public only by host, a target is `{ kind, base_url }` and
   adapters render host-relative URLs → GHES and self-managed GitLab are the same adapter with
   a base URL, not new code.
5. Because capturing a secret is indistinguishable from capturing a wrong or over-broad one,
   the pipeline ends in a **verify probe** that mints or reads at the exact expected scope and
   asserts both "works" and "not broader" (REQ-7) → success is proven, not assumed.
6. Because the guarantee still rests on trusting sandy's binary, before acting the installer
   prints what it will and will not do (captures locally, writes `0600`, ships no key, talks to
   no author host) and shows the manifest before submit → the trust is auditable at run time.

**Considered and set aside:** a hosted "install our App" button. Fairly: it is the smoothest
UX, one click, no Create step. Rejected because the author would then hold the single key that
mints for every installation, exactly the backdoor REQ-6 forbids; no amount of key hygiene
removes the capability.

## 5. Data model / history

One trust-root config record per registered target, written by the installer and read by the
adapter. Concrete surface (TOML, under the sandy config dir, `0600`):

- common: `name`, `kind` (`github`|`gitlab`), `base_url` (default the public host), `target`
  (repo full-name set, or project/group id).
- github: `app_id`, `private_key_path` (a `0600` `.pem`), `installation_id`.
- gitlab: `token_path` (`0600`), `project_or_group_id`, `account_kind`
  (`group-token`|`project-token`|`service-account`).

No history or versioning; re-running `register` for a `name` rewrites the record after an
explicit confirm. Secret bytes live only in the referenced `0600` side file, never inline in
the record.

## 6. Technology & licensing

| Technology                                  | Role                                                | License        | Status                                                                                       |
| ------------------------------------------- | --------------------------------------------------- | -------------- | -------------------------------------------------------------------------------------------- |
| GitHub App Manifest flow                    | pre-fill + secret-returning handshake (GitHub kind) | GitHub feature | adopt (REQ-3)                                                                                |
| GitLab access-tokens / service-accounts API | scoped trust root (GitLab kind)                     | GitLab feature | adopt (REQ-4)                                                                                |
| `tiny_http`                                 | single-use `127.0.0.1` redirect catcher             | Apache-2.0/MIT | candidate (escalation; don't hand-build)                                                     |
| `webbrowser`                                | open the pre-filled URL cross-platform              | MIT/Apache-2.0 | candidate                                                                                    |
| `jsonwebtoken` + `reqwest`                  | App JWT for installation-id lookup + verify         | MIT            | candidate (raw path)                                                                         |
| `octocrab`                                  | GitHub REST/JWT, verify mint                        | MIT/Apache-2.0 | candidate — adopt only if the credential-seam GitHub adapter does too (keep them one client) |
| `gitlab` crate                              | GitLab REST, verify read                            | MIT            | candidate                                                                                    |

## 7. Risks & technical debt

- GitLab paste-back briefly exposes the token to the terminal / clipboard. Mitigated: read via
  a no-echo prompt, never logged; document the clipboard caveat. (risk)
- GitLab service accounts are Premium/Ultimate only; Free/CE installers fall back to a group or
  project access token, narrower provenance, same capability. (constraint)
- The manifest flow needs a one-hour window and a free localhost port; a blocked port or a slow
  user fails the handshake. Mitigated by a clear timeout and a resumable re-run. (risk)
- The verify probe must render scope **identically** to the real adapter's mint, or "verified"
  lies. This is a coordination seam with credential-seam Blocks 3/4; share the renderer rather
  than copy it. (debt, and the hinge below)
- The shared config schema couples this feature to credential-seam Block 0; if that surface
  changes, both move together. (debt)

## 8. Open items and follow-up

- Sizing / validation the pilot must produce: the exact verify probe per kind (GitHub: mint +
  immediately revoke a 1-repo token; GitLab: a `read_repository` call), confirmed against the
  real adapters once credential-seam Blocks 3/4 land.
- GitHub client choice (`octocrab` vs raw) is inherited-open from credential-seam Block 2/3;
  the conversion call needs no auth, so it does not block this feature.
- Out of scope, committed later: non-interactive / CI registration (a different trust model, it
  needs a pre-seeded secret); batch multi-target registration; a GitLab OAuth-app path if ever
  needed.

## 9. Rollout

1. Agree the shared config schema with credential-seam Block 0 (gate: both sides name the same
   fields).
2. Ship the pipeline + `FakeProvisioner` (tier-2, no network) → gate: register + verify green
   over the fake, and a network allow-list shows no non-forge host contacted.
3. GitHub provisioner → gate: a real github.com registration produces a working, correctly
   scoped token on a throwaway repo.
4. GitLab provisioner → gate: a real gitlab.com registration produces a working project token.
5. Self-hosted base-URL pass (GHES + self-managed GitLab) → gate: one self-hosted run each, or
   documented as untested when no instance is available.
6. Deregister → gate: a registered trust root is revoked at the forge and shredded locally, after
   which a mint attempt fails and the forge shows the installation gone (GitHub) or the token
   revoked (GitLab).

## 10. Validation pass (self-adversarial)

What the chosen direction opened up:

- A verify probe that mints then revokes could leave a live token if revoke fails → the probe
  asserts the token is **rejected** after revoke and fails register otherwise; no success on a
  dangling credential.
- A pre-filled manifest can be edited between display and submit (user widens permissions) →
  verify re-reads the created App's actual permissions and fails if they exceed the requested
  ceiling, so a widened grant is observable, not silent.
- GitLab paste-back invites pasting the wrong token (a broad personal PAT) → verify asserts the
  token's scopes match the request and rejects an over-broad token.
- "No author host" could be violated by a stray telemetry call → the pre-run disclosure lists
  every host the command contacts (the target forge only), and a tier-2 network allow-list
  makes a violation a test failure.
- The localhost redirect catcher is an open port another local process could hit → bind
  `127.0.0.1` on a random high port, carry a single-use nonce in `state`, and shut the listener
  down the moment the code arrives.
- Deregister could shred the local key first and then be unable to revoke the live install (the
  GitHub revoke needs the pem to sign its JWT) → fixed by ordering: revoke at the forge before
  the local shred (REQ-9). And since no API deletes the App registration, deregister ends by
  naming the manual deletion rather than silently leaving a powerless-but-present App shell.

## 11. Unresolved questions

- The exact config file location and format (proposed TOML under the sandy config dir): confirm
  against how the credential-seam adapter wants to load it. Decider: credential-seam Block 0
  owner.
- GitLab's default floor, a group access token or a project access token. Decider: the pilot,
  from real job scopes.

## Sources

1. Registering a GitHub App from a manifest — GitHub Docs: https://docs.github.com/en/apps/sharing-github-apps/registering-a-github-app-from-a-manifest (accessed 2026-10-11)
2. Create a GitHub App from a manifest (`POST /app-manifests/{code}/conversions`) — GitHub REST API: https://docs.github.com/en/rest/apps/apps#create-a-github-app-from-a-manifest (accessed 2026-10-11)
3. Group access tokens API — GitLab Docs: https://docs.gitlab.com/api/group_access_tokens (accessed 2026-10-11)
4. Group service accounts API — GitLab Docs: https://docs.gitlab.com/api/group_service_accounts (accessed 2026-10-11)
5. GitLab token overview and scopes — GitLab Docs: https://docs.gitlab.com/security/tokens/ (accessed 2026-10-11)
6. sandy credential-seam work package: `../credential-seam/` (repo path)
7. Delete an installation for the authenticated app (`DELETE /app/installations/{installation_id}`) — GitHub REST API: https://docs.github.com/en/rest/apps/apps#delete-an-installation-for-the-authenticated-app (accessed 2026-10-12)
