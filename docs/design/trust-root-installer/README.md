# Trust-root installer (sandy app register) (trust-root-installer): START HERE

`sandy app register` provisions the per-installer forge trust root the credential seam consumes
(credential-seam Block 0), for a chosen target (github.com, GitHub Enterprise Server, gitlab.com,
self-managed GitLab): it pre-fills the registration, hand-holds the few manual clicks, and
captures the credential locally at `0600`. The credential is generated into the installer's own
hands, unique per installer, with no shared secret and no author server in the path. It is
additive to the [credential seam](../credential-seam/) (it writes the config those adapters
read). It is NOT the adapter or job-time minting, NOT a hosted "install our App" button (that
would give the author a backdoor), and NOT the author's own install-scope IaC in
`kauki-labs/infra`.

This is a `small`-tier package: README + proposal + decision-log + spec. The `full`-tier docs
(`research-notes.md`, `development-graph.md`, methodology/invariants, per-node briefs) are
intentionally omitted, the grounding lives in the proposal §2/§Sources and the decision log's
verified-facts table, and the four spec blocks are small enough to build without a graph.

## Read in this order

1. `trust-root-installer-proposal.md`: what and why (purpose, requirements, the design chain, the self-adversarial pass).
2. `decision-log.md`: the verified facts and every load-bearing decision (D1–D6).
3. `trust-root-installer-spec.md`: how, as four test-gated blocks with positive and adversarial tests.

## Status

Structurally complete, NOT finalized. Open items to close before build:

- The config file schema vs credential-seam Block 0 (a shared Rust type or written agreement).
- The exact verify probe per kind, matched to the real adapter mint once credential-seam Blocks 3/4 land (the hinge).
- GitLab's default floor: group vs project access token (decided from real pilot job scopes).

## The one decision the whole thing hinges on

Whether the installer's **verify-probe scope rendering is identical to the credential-seam
adapter's mint rendering**. If they drift, a "verified" credential can still be wrong or
over-broad, so the no-over-grant guarantee rests on this one equivalence. It is **open** until
credential-seam Blocks 3/4 exist and the two share a single renderer.

## Environments

- Pilot (live, host-gated): a throwaway github.com repo and a throwaway gitlab.com project; optionally a GHES and a self-managed GitLab instance when available.
- Load-sim: none, this feature has no load dimension.
- Non-pilot (tier-2, no forge): `FakeProvisioner` + a network allow-list cover the pipeline, verify-before-success, and the CSRF/foreign-process guard without a live forge or any real trust root.

## Repos referenced

- `/Users/teebor/Fun/kauki.xyz/products/sandy` (this repo). Follow `AGENTS.md`: edition-2024 Rust, `nix develop -c cargo ...`, `nix fmt` + `nix flake check -L` before a PR, Conventional Commits, branch `kauki/<type>/<component>/<desc>`, never push to `main`.
- `../credential-seam/`: the consumer this feeds (REQ-1, REQ-5 in its proposal §3; config surface in its spec Blocks 0/3/4).
- `kauki-labs/infra` → `tf/cloud/02-github/`: the author's own operator setup (manifests + tofu install scope). Referenced only; not shipped to installers.
