# Provider-agnostic credential seam: proposal

## 1. Purpose and non-goals

Give a sandbox job short-lived, least-privilege git/forge access through one provider-agnostic
seam, so GitHub and GitLab (and later others) plug in as adapters behind a single `mint` /
`revoke` / `refresh` contract, and the credential's validity is bound to the sandbox's execution
rather than a fixed clock.

This is explicitly NOT:

- A per-pull-request credential. Neither provider can mint one (§3, §4); PR/MR confinement, if
  required, is a proxy tier, not a token feature.
- The GitHub App registration or a GitLab service account. Those are the operator-provided trust
  roots the seam consumes; standing them up is out of scope here.
- The agent control plane (`#36`). This seam assumes the agent model's transit constraint but does
  not design the scheduler, registration, or mTLS layer itself.

## 2. Where this plugs in today

On `origin/main`:

- `crates/sandy/src/cred.rs` has a GitHub-shaped, mint-only seam: `InstallationTokenMinter` (trait
  with one `mint(scope, ttl_secs)` method), `FakeMinter`, `mint_token` (clamps `ttl_secs` to
  `MAX_TTL_SECS = 3000` and stages the result), and `TokenScope { repositories, permissions }`. No
  real minter, no `revoke`, no `refresh`. The live client is walled on the App registration.
- `crates/sandy-cli/src/supervisor.rs` wires it via `mint_run_token`.
- The secret channel it rides: `crates/sandy/src/stage/secrets.rs` `stage_secrets` writes each
  secret to a `0600` file under a `0700` per-run dir, shared into the guest as a read-only virtiofs
  share, wiped on every teardown path (INV-1: bytes never reach argv, env, or the Nix store).
- `run_job` stages secrets once at boot and reverts at exit; there is no mid-run update path.

## 3. Requirements (fixed constraints)

- REQ-1: When a job declares a credential scope, the seam SHALL mint a credential limited to that
  scope through a provider adapter, and SHALL NOT grant access beyond the installation's own grants.
  (MUST)
- REQ-2: The seam SHALL expose one provider-agnostic contract (`mint`, `revoke`, `refresh`) over an
  abstract scope, so a new forge is an adapter and no caller branches on the provider. (MUST)
- REQ-3: When the sandbox terminates (success, failure, or fault), the seam SHALL revoke the
  credential, and SHALL NOT rely on the token's native expiry as the upper bound on its validity.
  (MUST)
- REQ-4: While a job runs longer than the provider's maximum token lifetime, the seam SHALL refresh
  the credential (re-mint or rotate) and re-deliver it, so the job never holds an expired token
  mid-run. (MUST)
- REQ-5: The minting trust root (App private key / service-account PAT) SHALL remain on the
  controller/host and SHALL NOT be delivered into the guest; the guest SHALL receive only a scoped,
  short-lived credential, never the power to mint. (MUST)
- REQ-6: When the credential is delivered to an executing agent over a network (the agent model,
  `#36`), it SHALL transit an authenticated, encrypted channel and SHALL carry the shortest workable
  lifetime. (MUST)
- REQ-7: The seam SHALL NOT require a provider feature that does not exist; single-PR/MR confinement
  SHALL be provided, if at all, by an external filtering proxy, not by the token. (MUST NOT)

## 4. Design

Two structurally distinct candidates, differing on where provider knowledge lives.

**Candidate A, per-provider minters.** Keep one trait per forge (`GitHubMinter`, `GitLabMinter`),
each with its own `mint`/`revoke`/`refresh`, and let `run_job` pick. Rejected: the lifecycle
(mint-at-boot, revoke-at-teardown, refresh-timer, transport) is identical across providers, so this
duplicates it per forge and forces `run_job` to branch on the provider. The scope types diverge
(`repositories+permissions` vs `projects+scopes+role`) with no common surface, so a job spec
becomes provider-specific. It fails REQ-2.

**Candidate B, one seam + adapters (chosen).** A single `CredentialProvider` trait owns the
contract; provider adapters translate an abstract scope and hold the provider-specific trust root
and API calls. The lifecycle lives once, above the adapters. Presented as a chain:

1. REQ-1/REQ-2 need one contract over an abstract scope. Because the two providers' native floors
   differ only in spelling, `repositories × permissions` (GitHub) and `projects × (scopes + role)`
   (GitLab), the abstract `Scope { targets: Vec<Target>, capabilities: Vec<Capability> }` maps onto
   both: an adapter renders `Target` as a repo or a project and `Capability` (e.g. `ReadCode`,
   `WriteCode`, `ReadPr`, `WritePr`) into GitHub permissions or GitLab scopes+role.
2. Because neither provider exposes a sub-repository selector (§Sources 1, 2), `Scope` deliberately
   has no PR/MR field (REQ-7). PR-confinement, where needed, is a wrapping provider: an
   authenticating proxy holds the repo/project credential and filters the guest's traffic to one
   PR/branch, handing the guest only a proxy credential. It implements the same `CredentialProvider`
   trait, so callers are unchanged.
3. Because both providers' native TTL is too coarse to be the execution bound, GitHub is a fixed 1 h
   with no custom-expiry parameter, GitLab's `expires_at` is day-granularity (§Sources 1, 2), the
   token's TTL is NOT the lifetime mechanism. The seam binds validity by bracketing the sandbox:
   `mint` at boot, `revoke` at teardown (REQ-3), with the native TTL only a backstop if the
   controller dies first. This is the exact bracket shape `run_job` already uses for the egress
   boundary (apply at boot, revert at teardown), so the credential lease is a sibling of the egress
   lease in the supervisor.
4. Because a job may outlive the token's hard cap (only GitHub's 1 h bites), the seam refreshes
   (REQ-4): GitHub re-mints (no refresh API), GitLab rotates (`POST .../rotate`). `refresh` returns
   a new lease the supervisor re-delivers. Refresh re-delivery into a running guest is the dependency
   on `#50` (mid-run re-stage channel); until `#50` lands, refresh is host-side only and jobs are
   capped at the provider lifetime.
5. Because the agent model ships the credential controller→agent (REQ-5/REQ-6), delivery is a
   separate `CredentialTransport` seam: today a local stage into the virtiofs secret share; under the
   agent model, an mTLS push to the agent, which stages it locally for its guest. The minting trust
   root never crosses either boundary, only the minted, scoped, short-lived lease does.

**Considered and set aside:** folding transport into the provider adapter (so a GitHub adapter knows
how to reach the agent). Rejected: transport is orthogonal to the forge, every provider would
re-implement it, and the local-vs-network choice is set by `#36`, not by the forge.

## 5. Data model / history

- `Scope { targets: Vec<Target>, capabilities: Vec<Capability> }`, provider-neutral; adapters render it.
- `Lease { secret_ref: SecretRef, expires_at: Instant, handle: CredentialHandle }`. The `handle`
  carries the provider-side id needed to revoke/rotate; the bytes ride the existing `SecretRef`
  channel, so `Lease` is loggable without leaking (mirrors `StagedSecret`).
- No persistent store: a lease lives for one sandbox execution and is revoked at teardown. The only
  durable secret is the trust root (App key / service PAT), held by the controller, never minted.

## 6. Technology & licensing

| Technology                            | Role                                    | License        | Status                     |
| ------------------------------------- | --------------------------------------- | -------------- | -------------------------- |
| GitHub App installation token API     | GitHub adapter mint/revoke              | GitHub ToS     | Walled on App registration |
| GitLab project/group access token API | GitLab adapter mint/revoke/rotate       | GitLab ToS     | Walled on service account  |
| octocrab (or raw REST + JWT)          | GitHub App JWT → installation token     | MIT            | Not yet chosen             |
| JWT (RS256) signing                   | GitHub App auth                         | lib-dependent  | Not yet chosen             |
| mTLS transport (rustls)               | agent-model credential delivery (REQ-6) | MIT/Apache-2.0 | Deferred to #36 epic       |

## 7. Risks & technical debt

- Refresh correctness: a mis-timed refresh (re-mint after expiry, or re-stage the guest can't re-read)
  leaves a job with a dead token mid-run. Mitigate with a refresh margin well under the cap and the
  `#50` round-trip test; until `#50`, cap long jobs rather than ship a half-refresh.
- The `MAX_TTL_SECS` clamp is currently cosmetic: GitHub ignores the requested TTL and always issues
  ~1 h. The clamp only becomes real when paired with revoke-at-`ttl_secs`. Debt carried from `#25`;
  this seam fixes it in Block 2.
- Proxy tier is a bespoke network component, the highest-risk build; keep it optional and off the
  default path, and prefer an off-the-shelf authenticating proxy (escalation appendix in the spec).
- Agent-model transit widens INV-1 beyond the host. Until `#36`'s mTLS layer exists, the network
  adapter is not built; the local transport is the only shipped one.

## 8. Open items and follow-up

- Sizing/validation the pilot must produce: the refresh margin (seconds before expiry to re-mint)
  that holds under real GitHub 1 h tokens; whether GitLab day-granularity expiry needs any backstop
  beyond revoke.
- Out of scope but committed later, gated at the `#36` epic: the mTLS network transport; the agent's
  local stage of a pushed lease.
- Blocked on `#50`: mid-run re-stage for refresh re-delivery into the guest.

## 9. Rollout

1. Seam + adapters behind `FakeProvider` (tier-2, no live forge). Gate: provider-agnostic `run_job`
   lease lifecycle green over the fake; `revoke` and `refresh` exercised.
2. GitHub adapter live. Gate: real installation token minted, scoped, revoked; host-gated, walled on
   the App (tracked, not counted green from the fake, INV-S9).
3. GitLab adapter live. Gate: real project token minted, scoped, rotated, revoked; host-gated, walled
   on the service account.
4. Refresh re-delivery, after `#50`. Gate: a job past the cap keeps a live token across a refresh.
5. Proxy tier (optional). Gate: a guest confined to one PR/MR through the proxy; off the default path.
6. Network transport, under `#36`. Gate: lease delivered controller→agent over mTLS; trust root never
   transits.

## 10. Validation pass (self-adversarial)

What this design opens up:

- A generic `Capability` set risks a lossy mapping, e.g. GitLab's role model has no clean GitHub
  equivalent, so an under- or over-grant could hide in the adapter. Fix: each adapter ships an
  adversarial test asserting a capability renders to the least role/permission that works and no
  more (spec Block 1 adversarial table), and the mapping table is in the decision log, not inferred.
- Revoke-at-teardown is best-effort; a controller crash skips it. Fix: the native TTL is the backstop
  (REQ-3 keeps it as a bound, just not the primary), and `revoke` is idempotent so a later sweep can
  re-revoke by handle.
- Refresh introduces a window where two tokens are valid (old not yet revoked, new minted). Fix:
  rotate/revoke the old immediately after the new is staged and confirmed readable; assert single
  live token in the refresh test.
- The proxy tier could become the default and mask that the token itself is over-scoped. Fix: the
  proxy is explicitly optional and additive; the token is always minted least-privilege first, proxy
  or not (REQ-1 holds independently).

## 11. Unresolved questions

- Does the pilot need the proxy tier at all, or is repo/project + least-capability + short life
  sufficient for sandy's jobs? Decider: the user, once real job scopes are known.
- GitHub client: octocrab vs raw REST+JWT. Decider: the Block 2 implementer, on dependency weight.

## Sources

1. GitHub App installation access tokens: scope is `repositories`/`repository_ids` × `permissions`,
   fixed 1 h expiry with no custom-TTL parameter, revoke via `DELETE /installation/token`, no refresh
   API. https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app
   and https://docs.github.com/en/rest/apps/installations (accessed 2026-10-08).
2. GitLab project/group access tokens: scope is `scopes` × `access_level`, `expires_at` is
   day-granularity (max ~365, admin-tunable), revoke via `DELETE …/access_tokens/:id`, rotate via
   `POST …/access_tokens/:id/rotate`. https://docs.gitlab.com/api/project_access_tokens/ and
   https://docs.gitlab.com/security/tokens/access_token_scopes/ (accessed 2026-10-08).
3. GitLab `CI_JOB_TOKEN` is execution-bound but obtainable only inside a GitLab CI job.
   https://docs.gitlab.com/ci/jobs/ci_job_token/ (accessed 2026-10-08).
4. GitHub `GITHUB_TOKEN` and OIDC are Actions-only, unavailable to a non-Actions runner.
   https://docs.github.com/en/actions/concepts/security/github_token (accessed 2026-10-08).
5. sandy repo, `crates/sandy/src/cred.rs`, `crates/sandy/src/stage/secrets.rs`,
   `crates/sandy-cli/src/supervisor.rs` (origin/main, read 2026-10-08).
