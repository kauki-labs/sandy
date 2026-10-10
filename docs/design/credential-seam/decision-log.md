# Decision log: Provider-agnostic credential seam

The anti-re-litigation record. Each decision uses MADR fields (see `references/methodology.md`).

## Verified facts

| Fact                                                                                                                                 | How verified                                                                       | Consequence                                                                                                         |
| ------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| GitHub installation tokens scope only by `repositories` × `permissions`; no PR/branch/path selector.                                 | docs.github.com generating-an-installation-access-token (2026-10-08).              | No per-PR token; `Scope` carries no PR field (D3).                                                                  |
| GitHub installation token TTL is a fixed 1 h; the create endpoint takes no expiry parameter.                                         | docs.github.com rest/apps/installations (2026-10-08).                              | TTL cannot be the execution bound; revoke-at-teardown is (D4). The `MAX_TTL_SECS` clamp is cosmetic without revoke. |
| GitHub has no refresh/rotate API for installation tokens; you re-mint.                                                               | docs.github.com (2026-10-08).                                                      | `refresh` on the GitHub adapter re-mints (D5).                                                                      |
| GitLab project/group tokens scope by `scopes` × `access_level`; no MR selector.                                                      | docs.gitlab.com access_token_scopes (2026-10-08).                                  | No per-MR token; same `Scope` floor as GitHub (D3).                                                                 |
| GitLab `expires_at` is day-granularity (max ~365, admin-tunable); it has a `rotate` endpoint.                                        | docs.gitlab.com project_access_tokens (2026-10-08).                                | Day TTL cannot bound a short job; revoke/rotate does (D4, D5).                                                      |
| Neither provider's execution-bound token (`GITHUB_TOKEN`, `CI_JOB_TOKEN`) is obtainable outside its CI.                              | docs.github.com github_token; docs.gitlab.com ci_job_token (2026-10-08).           | sandy must mint its own via App / service-account trust root (D2).                                                  |
| Current `cred.rs` is GitHub-shaped, mint-only: `InstallationTokenMinter`, `TokenScope{repositories,permissions}`, no revoke/refresh. | Read `crates/sandy/src/cred.rs` (origin/main, 2026-10-08).                         | The seam is a generalization + lifecycle addition, not a rewrite (D1).                                              |
| `run_job` stages secrets once at boot, reverts at exit; no mid-run update path.                                                      | Read `crates/sandy-cli/src/supervisor.rs`, `crates/sandy/src/stage/` (2026-10-08). | Refresh re-delivery blocks on `#50` (D5).                                                                           |
| `#36` decided: team/shared service → agent model; tokens transit controller→agent.                                                   | Issue #36 decision comment (2026-10-09).                                           | Transport is a first-class seam; INV-1 widens (D6).                                                                 |

## Decisions

### D1: One `CredentialProvider` trait + provider adapters, not per-provider minters

- **Status:** Accepted
- **Why:** The lifecycle (mint-at-boot, revoke-at-teardown, refresh, transport) is identical across
  forges; per-provider traits duplicate it and force `run_job` to branch on the provider.
- **Grounding:** Proposal §4 Candidate A vs B; current `InstallationTokenMinter` is already a seam,
  so this widens it rather than replacing it.
- **Confirmation:** `run_job` compiles and its lease-lifecycle tests pass over a `FakeProvider` with
  no provider-specific branch; a second adapter is added without touching `run_job`.

### D2: The minting trust root stays on the controller/host; only a minted lease reaches the guest

- **Status:** Accepted
- **Why:** A guest that could mint defeats least-privilege entirely (it could mint any scope). REQ-5.
- **Grounding:** Both providers mint from a long-lived secret (App private key / service PAT) that
  must not be shared; proposal §4 step 5.
- **Confirmation:** Adversarial test: the guest's secret share never contains the App key / service
  PAT, only the scoped lease; grep of the staged dir for the trust-root bytes fails.

### D3: `Scope` has no PR/MR field; per-PR confinement is an optional proxy tier

- **Status:** Accepted
- **Why:** Neither provider can scope a token below repo/project; encoding a PR field would imply a
  guarantee the token cannot keep. REQ-7.
- **Grounding:** Verified facts rows 1 and 4.
- **Confirmation:** The proxy implements the same `CredentialProvider` trait; the PR-confinement test
  runs through the proxy, and the non-proxy path asserts repo/project + least-capability only.

### D4: Lifetime is bound by a mint→revoke bracket around the sandbox, not by the token TTL

- **Status:** Accepted
- **Why:** Both providers' native TTL is too coarse (GitHub 1 h fixed, GitLab day); the token must
  not outlive the job, and the job may be far shorter. REQ-3.
- **Grounding:** Verified facts rows 2 and 5; the bracket mirrors the egress lease in `run_job`.
- **Confirmation:** Test: on sandbox teardown (success, failure, fault) the adapter's `revoke` is
  called; the token is invalid afterward. The native TTL remains only as a crash backstop.

### D5: `refresh` is provider-specific (GitHub re-mint, GitLab rotate); re-delivery blocks on #50

- **Status:** Accepted
- **Why:** GitHub has no rotate API; GitLab does. A job past the cap must not hold a dead token.
  REQ-4.
- **Grounding:** Verified facts rows 3 and 5; `#50` owns the mid-run re-stage channel.
- **Confirmation:** Test (after #50): a job running past the provider cap keeps a readable token
  across a refresh, with exactly one live token at a time.

### D6: Transport is a separate seam from the provider adapter

- **Status:** Accepted
- **Why:** Local-stage vs network-push is set by `#36`, not by the forge; folding it into the adapter
  makes every forge re-implement it. REQ-6.
- **Grounding:** `#36` decision (agent model); proposal §4 "Considered and set aside".
- **Confirmation:** The GitHub and GitLab adapters contain no transport code; swapping the local
  transport for the mTLS one changes no adapter.

## Considered and set aside

Do not re-propose without new information.

| Option                                                          | Why set aside                                                                                            |
| --------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| Per-provider minter traits (Candidate A)                        | Duplicates the lifecycle per forge; forces provider branches in `run_job`; no common scope surface (D1). |
| Encode a per-PR/MR field in `Scope`                             | No provider can honor it; would imply a guarantee the token cannot keep (D3).                            |
| Use the token's `expires_at`/TTL as the execution bound         | Too coarse on both providers; leaves a token valid long after the job or expiring mid-job (D4).          |
| Transport inside the provider adapter                           | Orthogonal to the forge; set by `#36`; duplicated per adapter (D6).                                      |
| Ship the trust root (App key / PAT) into the guest to self-mint | Destroys least-privilege; a compromised guest mints anything (D2).                                       |

## Open items

| Item                                            | Concrete close condition                                                                         |
| ----------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| Refresh margin under real GitHub 1 h tokens     | A live test measures the seconds-before-expiry re-mint that never leaves a dead-token window.    |
| Proxy tier needed for the pilot?                | User confirms whether sandy's real jobs need sub-repo confinement; if not, proxy stays deferred. |
| GitHub client choice (octocrab vs raw REST+JWT) | Block 2 implementer picks on dependency weight; recorded here when chosen.                       |
| `#50` guest consumption + re-stage              | `#50` closed; refresh re-delivery test green.                                                    |
