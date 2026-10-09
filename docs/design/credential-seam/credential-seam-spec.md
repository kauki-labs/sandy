# Provider-agnostic credential seam: spec

Design amendments (grounded deviations from the proposal) go here and supersede it.

- None yet. The proposal's §4 chain is the design of record.

## Block index

| #   | Block                                                                       | Runs on      | Depends on | Satisfies           |
| --- | --------------------------------------------------------------------------- | ------------ | ---------- | ------------------- |
| 0   | Preconditions (trust roots, FakeProvider, #50 status)                       | host         | -          | REQ-1, REQ-5        |
| 1   | Generic `CredentialProvider` seam + abstract `Scope`                        | tier-2       | 0          | REQ-1, REQ-2, REQ-7 |
| 2   | Lifecycle bracket in `run_job` (mint/revoke/refresh, revoke-to-enforce-TTL) | tier-2       | 1          | REQ-3, REQ-4, REQ-5 |
| 3   | GitHub adapter (App JWT → installation token)                               | host, walled | 1          | REQ-1               |
| 4   | GitLab adapter (service PAT → project/group token)                          | host, walled | 1          | REQ-1               |
| 5   | Credential transport seam (local stage; network deferred)                   | tier-2       | 2          | REQ-6               |
| 6   | Proxy tier for per-PR/MR confinement (optional)                             | host, walled | 1          | REQ-7               |

Refresh re-delivery inside Block 2 blocks on `#50` (external); until it lands, Block 2 ships
host-side refresh with a provider-cap limit on job length.

## Block 0: Preconditions

**Purpose.** Establish the trust roots and the test double so the rest is buildable and tier-2
testable without a live forge.
**Architecture.** A GitHub App (private key + App ID + installation id) and/or a GitLab service
account (PAT with Maintainer on the project / Owner on the group) are operator-provided and held by
the controller. A `FakeProvider` implements `CredentialProvider` in-memory for tier-2. `#50` (guest
re-stage) is tracked as the refresh-re-delivery blocker.
**Interfaces.** Input: operator secrets (App key / service PAT) on the controller. Output: a
configured provider handle. Config surface: which provider, trust-root location, target scope.
**Satisfies:** REQ-1, REQ-5.

Verification (positive) tests:

| Test                           | Setup / Inject                  | Expected result                                                                      |
| ------------------------------ | ------------------------------- | ------------------------------------------------------------------------------------ |
| Fake provider mints            | `FakeProvider::returning(tok)`  | `mint` returns a `Lease` whose `secret_ref` resolves to `tok`.                       |
| Trust root stays on controller | configure a GitHub App key path | the key path is read only by the controller process; never added to any guest share. |

Adversarial (negative) tests:

| Test               | Setup / Inject                 | Expected result                                                                                              |
| ------------------ | ------------------------------ | ------------------------------------------------------------------------------------------------------------ |
| Missing trust root | no App key / no PAT configured | `mint` fails with a named `CredError`, mapped to the exit-3 retryable band; the job does not run token-less. |

## Block 1: Generic `CredentialProvider` seam + abstract `Scope`

**Purpose.** Replace the GitHub-shaped `InstallationTokenMinter` / `TokenScope` with a
provider-agnostic contract and scope.
**Architecture.** `trait CredentialProvider { fn mint(&self, scope: &Scope, ttl_hint: Duration)
-> Result<Lease, CredError>; fn revoke(&self, handle: &CredentialHandle) -> Result<(), CredError>;
fn refresh(&self, handle: &CredentialHandle) -> Result<Lease, CredError>; }`. `Scope { targets:
Vec<Target>, capabilities: Vec<Capability> }`; `Capability` is `ReadCode|WriteCode|ReadPr|WritePr|…`.
`Lease { secret_ref, expires_at, handle }`; `handle` carries the provider-side id for revoke/rotate
and no bytes. `FakeProvider` records `(scope, ttl_hint)` calls. The existing `mint_token` clamp/stage
logic moves behind the trait unchanged (INV-1 preserved).
**Interfaces.** Input: `Scope`, `ttl_hint`. Output: `Lease`. Config surface: capability→provider
mapping table (per adapter, D-mapping in the decision log).
**Satisfies:** REQ-1, REQ-2, REQ-7.

Verification (positive) tests:

| Test                             | Setup / Inject                                    | Expected result                                                              |
| -------------------------------- | ------------------------------------------------- | ---------------------------------------------------------------------------- |
| Scope round-trips                | `Scope{targets:[repo], caps:[WriteCode,WritePr]}` | `FakeProvider` records exactly that scope; no provider branch in the caller. |
| Lease carries no bytes           | mint over the fake                                | `format!("{lease:?}")` contains neither the token nor any trust-root byte.   |
| Second adapter, no caller change | add a stub adapter                                | caller code and `run_job` compile unchanged (REQ-2).                         |

Adversarial (negative) tests:

| Test                    | Setup / Inject                  | Expected result                                                                                                                                    |
| ----------------------- | ------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Scope` has no PR field | attempt to express "only PR #7" | the type cannot represent it; the compile-time surface has no PR/MR field (REQ-7 / D3).                                                            |
| Over-broad capability   | map `WritePr`                   | the capability renders to the least permission/role that works and no more; asserted against a fixed expected rendering, not the adapter's output. |

## Block 2: Lifecycle bracket in `run_job`

**Purpose.** Bind credential validity to the sandbox execution and enforce the TTL by revocation.
**Architecture.** `run_job` gains a credential lease bracket beside the egress lease: `mint` at
boot, `revoke` at teardown on every path (success, failure, fault), a refresh timer that re-mints/
rotates before `expires_at` and re-delivers. The cosmetic `MAX_TTL_SECS` clamp becomes real:
schedule `revoke` at `min(ttl_hint, provider_cap)` rather than trusting the token's own expiry.
**Interfaces.** Input: a `CredentialProvider`, a `Scope`, the sandbox lifecycle. Output: a live
`Lease` staged for the guest; a revoked handle at teardown. Config surface: `ttl_hint`, refresh
margin.
**Satisfies:** REQ-3, REQ-4, REQ-5.

Verification (positive) tests:

| Test                   | Setup / Inject                        | Expected result                                                                               |
| ---------------------- | ------------------------------------- | --------------------------------------------------------------------------------------------- |
| Revoke at teardown     | run a job to completion over the fake | `revoke(handle)` is called exactly once at teardown.                                          |
| Revoke on failure path | backend `run` errors                  | `revoke` still called; a dangling un-revoked lease never remains.                             |
| Refresh before expiry  | `ttl_hint` < job length, fake clock   | a new lease is minted before `expires_at`; the old handle is revoked after the new is staged. |

Adversarial (negative) tests:

| Test                            | Setup / Inject                    | Expected result                                                                                                                                                                     |
| ------------------------------- | --------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Clamp is enforced, not cosmetic | `ttl_hint` below the provider cap | a `revoke` is scheduled at `ttl_hint`; the credential is invalid after it even though the native token would still be valid (assert the bad "still valid" behaviour does NOT hold). |
| Two live tokens during refresh  | force a refresh                   | at no point are both old and new tokens simultaneously valid after the new is confirmed; the old is revoked.                                                                        |
| Mint fails mid-bracket          | provider `mint` errors at boot    | fail-closed: the job does not boot token-less; a named retryable fault, not a silent run.                                                                                           |

## Block 3: GitHub adapter

**Purpose.** A live `CredentialProvider` for GitHub App installation tokens.
**Architecture.** Sign an RS256 JWT (App ID, ≤10 min exp) from the App private key → `POST
/app/installations/{id}/access_tokens` with `repository_ids` + `permissions` rendered from `Scope`
→ `Lease`. `revoke` = `DELETE /installation/token`. `refresh` = re-mint (no GitHub rotate API).
**Interfaces.** Input: App key/ID/installation id, `Scope`. Output: `Lease` (installation token).
Config surface: capability→permission map; the single installation/repo set.
**Satisfies:** REQ-1 (GitHub). Host-gated, walled on the App registration (INV-S9: never green from
the fake).

Verification (positive) tests:

| Test        | Setup / Inject                                       | Expected result                                                                                                                  |
| ----------- | ---------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| Scoped mint | `Scope{targets:[one repo], caps:[ReadCode,WritePr]}` | token works on that repo for those permissions; token request body carries only `repository_ids:[one]` + the mapped permissions. |
| Revoke      | mint then `revoke`                                   | `DELETE /installation/token` returns 204; the token is thereafter rejected.                                                      |

Adversarial (negative) tests:

| Test                              | Setup / Inject                       | Expected result                                                       |
| --------------------------------- | ------------------------------------ | --------------------------------------------------------------------- |
| Cannot exceed installation grants | request a permission the App lacks   | mint is refused by GitHub / pre-checked; no over-grant leaks (REQ-1). |
| Out-of-scope repo blocked         | use the token on a repo not in scope | request denied; asserts the token is not broader than requested.      |

## Block 4: GitLab adapter

**Purpose.** A live `CredentialProvider` for GitLab project/group access tokens.
**Architecture.** `POST /projects/:id/access_tokens` (or group) with `scopes` + `access_level`
rendered from `Scope`, authenticated by the service-account PAT → `Lease`. `revoke` = `DELETE
…/access_tokens/:id`. `refresh` = `POST …/access_tokens/:id/rotate`.
**Interfaces.** Input: service PAT, project/group id, `Scope`. Output: `Lease`. Config surface:
capability→(scopes+role) map; project vs group preference (prefer project).
**Satisfies:** REQ-1 (GitLab). Host-gated, walled on the service account.

Verification (positive) tests:

| Test             | Setup / Inject                                   | Expected result                                                                                |
| ---------------- | ------------------------------------------------ | ---------------------------------------------------------------------------------------------- |
| Scoped mint      | `Scope{targets:[one project], caps:[WriteCode]}` | project token works on that project with the least role; scopes carry only `write_repository`. |
| Rotate = refresh | mint then `rotate`                               | a new token returns; the previous is immediately revoked (GitLab rotate semantics).            |

Adversarial (negative) tests:

| Test                  | Setup / Inject           | Expected result                                                                                                     |
| --------------------- | ------------------------ | ------------------------------------------------------------------------------------------------------------------- |
| No group blast radius | `Scope` with one project | a project token is minted, never a group token; assert the target is project-scoped.                                |
| Role not escalated    | map `WriteCode`          | `access_level` is the lowest that works (Developer, not Maintainer/Owner); asserted against the expected rendering. |

## Block 5: Credential transport seam

**Purpose.** Separate how a lease reaches the guest from who mints it.
**Architecture.** `trait CredentialTransport { fn deliver(&self, lease: &Lease) -> Result<SecretRef>; }`.
The local transport stages into the existing `0600` → RO virtiofs share (today's path). The network
transport (mTLS push controller→agent) is declared but deferred to the `#36` epic; the trust root
never transits either.
**Interfaces.** Input: `Lease`. Output: a `SecretRef` the guest can read. Config surface: transport
choice (local | network).
**Satisfies:** REQ-6.

Verification (positive) tests:

| Test           | Setup / Inject       | Expected result                                                   |
| -------------- | -------------------- | ----------------------------------------------------------------- |
| Local delivery | deliver a fake lease | staged `0600` under `0700`, shared RO; wiped at teardown (INV-1). |

Adversarial (negative) tests:

| Test                      | Setup / Inject               | Expected result                                                                                        |
| ------------------------- | ---------------------------- | ------------------------------------------------------------------------------------------------------ |
| Trust root never transits | inspect what `deliver` moves | only the scoped lease bytes move; the App key / service PAT is never in the delivered payload (REQ-5). |

## Block 6: Proxy tier (optional, per-PR/MR confinement)

**Purpose.** The only path to sub-repo confinement, kept optional and off the default.
**Architecture.** An authenticating proxy holds the repo/project lease and filters the guest's
git/API traffic to one PR/MR/branch; the guest gets a proxy credential, not the forge token. It
implements `CredentialProvider`, so callers are unchanged.
**Interfaces.** Input: a wrapped `CredentialProvider`, a PR/MR selector. Output: a proxy `Lease`.
Config surface: the allowed PR/MR/branch, the upstream forge.
**Satisfies:** REQ-7 (the proxy path).

Verification (positive) tests:

| Test               | Setup / Inject               | Expected result                      |
| ------------------ | ---------------------------- | ------------------------------------ |
| Confined to one PR | guest acts on the allowed PR | request passes through to the forge. |

Adversarial (negative) tests:

| Test                             | Setup / Inject                                | Expected result                                                                                                 |
| -------------------------------- | --------------------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| Other PR blocked                 | guest targets a different PR in the same repo | the proxy rejects it, though the underlying token would allow it (proves confinement is real, not the token's). |
| Guest never sees the forge token | inspect the guest credential                  | it is the proxy credential, not the installation/project token (REQ-5).                                         |

## Escalation appendix

Never hand-build a pipeline. Off-the-shelf options, each matched to a different shortfall:

| Tool                                     | License        | Adds                                            | Cost             | Reach for it when                               |
| ---------------------------------------- | -------------- | ----------------------------------------------- | ---------------- | ----------------------------------------------- |
| octocrab                                 | MIT            | GitHub App JWT → installation token, typed REST | a dependency     | Block 3, to avoid hand-rolling JWT+REST.        |
| jsonwebtoken                             | MIT            | RS256 App JWT signing                           | small            | Block 3, if using raw REST instead of octocrab. |
| gitlab (rust crate) or raw `reqwest`     | MIT            | GitLab token API calls                          | a dependency     | Block 4.                                        |
| rustls / tokio-rustls                    | MIT/Apache-2.0 | mTLS for the network transport                  | moderate         | Block 5 network path, under #36.                |
| oauth2-proxy / a filtering reverse proxy | MIT            | an authenticating proxy front end               | a service to run | Block 6, before writing a bespoke proxy.        |

## Acceptance criteria

- Provider-agnostic `run_job` lease lifecycle is green over `FakeProvider`: mint at boot, revoke at
  teardown on every path, refresh before expiry, with no provider branch in `run_job` (Blocks 1, 2).
- The TTL clamp is enforced by revocation, not cosmetic: a credential is invalid after `ttl_hint`
  even though the native token would still be valid (Block 2 adversarial).
- The trust root never reaches the guest; only a scoped, short-lived lease does (Blocks 2, 5
  adversarial).
- Each live adapter mints a correctly-scoped token, revokes it, and refreshes it, host-gated and
  walled on its trust root, counted green only from a real run (INV-S9), never from the fake
  (Blocks 3, 4).
- Hinge measurement reserved for the pilot: the refresh margin under real GitHub 1 h tokens that
  never leaves a dead-token window (Block 2, open item).
- Per-PR/MR confinement, if the pilot needs it, is demonstrated through the proxy with the
  underlying token proven broader than the guest's reach (Block 6).
