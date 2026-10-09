# Provider-agnostic credential seam (credential-seam): START HERE

A design for giving a sandbox job short-lived, least-privilege git/forge access through one
provider-agnostic seam. GitHub and GitLab plug in as adapters behind a single `mint` / `revoke` /
`refresh` contract, and the credential's validity is bound to the sandbox's execution by a
mint-at-boot / revoke-at-teardown bracket rather than the token's own clock. It is additive to the
`#25` cred module (which it generalizes) and the existing secret channel (`stage_secrets`, INV-1).
It is NOT the GitHub App / GitLab service-account setup (operator-provided trust roots), NOT the
agent control plane (`#36`), and NOT a per-PR token (no provider offers one; that is an optional
proxy tier).

## Read in this order

1. `credential-seam-proposal.md`: what and why, the two-candidate design, the self-adversarial pass.
2. `decision-log.md`: the verified facts and every load-bearing decision (D1–D6).
3. `credential-seam-spec.md`: how, as seven test-gated blocks with positive and adversarial tests.

Small tier: `research-notes.md` and `development-graph.md` are not written. The grounding lives in
the proposal (§2 current state, §Sources) and the decision log's verified-facts table; the build
order is the spec's block index (0→1→2, 1→3, 1→4, 2→5, 1→6). Promote to the full tier and run the
graph-engine skill if this is fanned out to an agent fleet.

## Status

Structurally complete, NOT finalized. Open items to close before build:

- The refresh margin under real GitHub 1 h tokens (a pilot measurement; decision log open items).
- Whether the pilot needs the proxy tier at all (the hinge below).
- GitHub client choice: octocrab vs raw REST+JWT (Block 2/3 implementer).
- `#50` (guest-side secret consumption + mid-run re-stage) must close before refresh re-delivery.

## The one decision the whole thing hinges on

Is repo/project + least-capability + revoke-on-exit sufficient for sandy's jobs, or is per-PR/MR
confinement required? It is open. Neither provider can scope a token below repo/project, so per-PR
confinement means building the proxy tier (spec Block 6); without that need, Blocks 0–5 are the whole
seam. The user decides once real job scopes are known. Everything else (the generic contract, the
lifecycle bracket, both adapters) is settled and does not wait on this.

## Environments

- Pilot (live, host-gated): a Linux/KVM host and an aarch64-darwin host, each with a registered
  GitHub App and/or GitLab service account. Live adapter runs are counted green only here (INV-S9),
  never from the fake.
- Load-sim: none. This seam has no load dimension; refresh timing is the only timed behaviour and is
  measured in the pilot.
- Non-pilot (tier-2, no forge): `FakeProvider` + a fake clock cover the seam, the lifecycle bracket,
  and the revoke/refresh logic without a live forge or trust root.

## Repos referenced

- `/Users/teebor/Fun/kauki.xyz/products/sandy` (this repo). Follow `AGENTS.md`: edition-2024 Rust,
  `nix develop -c cargo ...`, `nix fmt` + `nix flake check -L` before a PR, Conventional Commits,
  branch `<nick>/<type>/<component>/<desc>`, never push to `main`.
- Tracking issues: `#49` (this seam's tracker), `#50` (guest-consumption blocker), `#36` (agent-model
  epic that sets the network-transport constraint), `#25` (the merged GitHub-shaped predecessor).
