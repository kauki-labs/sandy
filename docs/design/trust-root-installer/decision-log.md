# Decision log: Trust-root installer (sandy app register)

The anti-re-litigation record. Each decision uses MADR fields (see `references/methodology.md`).

## Verified facts

| Fact                                                                                                                                                                                                   | How verified                                                                        | Consequence                                                                               |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| GitHub's manifest flow returns `id` + `pem` + `webhook_secret` from `POST /app-manifests/{code}/conversions`, no auth (the one-time code is the credential), within a 1 h window.                      | GitHub Docs (sources 1, 2); used manually in sandy `docs/github-app.md` this cycle. | GitHub capture can be fully automated into the installer's own hands (REQ-3, REQ-6).      |
| GitLab has no manifest/handshake that returns a secret. The trust root is a group/project access token or a service account; its secret shows once in the UI; API creation needs a pre-existing token. | GitLab Docs (sources 3, 4, 5).                                                      | GitLab register is guided paste-back, not auto-capture (REQ-4).                           |
| A GitHub App has one private key, held by the App owner, and it mints tokens for **every** installation; there is no per-installation key.                                                             | GitHub Apps model (prior-cycle grounding, GitHub Docs).                             | Per-installer unique key ⇒ per-installer App. A shared App ⇒ author backdoor (drives D2). |
| GHES and self-managed GitLab run the same flows at a different base host.                                                                                                                              | GitHub/GitLab docs (sources 1–5).                                                   | `target = { kind, base_url }`; no new adapter per host (D4).                              |
| credential-seam Block 0 already defines the trust-root config surface (provider, trust-root location, target scope); Blocks 3/4 name the per-kind fields.                                              | `../credential-seam/credential-seam-spec.md` Blocks 0/3/4.                          | The installer's output **is** that contract; it is a front-end to Block 0 (D1, D6).       |
| GitLab service accounts are Premium/Ultimate only.                                                                                                                                                     | GitLab Docs (source 4).                                                             | Free/CE installers fall back to a group or project access token (D3).                     |

## Decisions

### D1: One pipeline + per-kind `Provisioner` adapters

- **Status:** Accepted
- **Why:** The capture/store/verify pipeline is identical across kinds and hosts; only how
  registration is initiated differs. Mirrors the credential-seam's own one-seam-plus-adapters
  shape, so the two stay consistent.
- **Grounding:** proposal §4; `../credential-seam/` Candidate B.
- **Confirmation:** a stub `Provisioner` plugs in with no change to the pipeline or CLI (same
  compile-time test the credential-seam uses for REQ-2).

### D2: No shared/hosted App; each installer registers their own

- **Status:** Accepted
- **Why:** A shared App's single key mints for every installation, which is the backdoor REQ-6
  forbids. No key hygiene removes the capability.
- **Grounding:** GitHub Apps key model (verified fact).
- **Confirmation:** `register` makes no request to any non-forge host (tier-2 network allow-list
  test fails if it does).

### D3: GitHub = manifest-flow auto-capture; GitLab = guided paste-back

- **Status:** Accepted
- **Why:** GitLab has no secret-returning handshake, so paste-back is its floor; GitHub's
  handshake makes auto-capture possible and preferable.
- **Grounding:** sources 1–5 (verified facts).
- **Confirmation:** GitHub register captures the `pem` with zero manual paste; GitLab register
  reads the token via a no-echo prompt and verifies its scope.

### D4: `target = { kind, base_url }` with host-relative URLs

- **Status:** Accepted
- **Why:** Self-hosted differs from public only by host.
- **Grounding:** GitHub/GitLab docs (verified fact).
- **Confirmation:** a GHES / self-managed `base_url` routes the same adapter (unit test with a
  fake base URL).

### D5: The pipeline ends in a scope-asserting verify probe; success is never reported from capture alone

- **Status:** Accepted
- **Why:** A captured secret is indistinguishable from a wrong or over-broad one (REQ-7/REQ-8).
- **Grounding:** proposal §10 (validation pass).
- **Confirmation:** an over-broad or non-working credential fails `register` with a named error
  (adversarial test); after a mint+revoke probe the token is asserted rejected.

### D6: Config schema is TOML, `0600`, secret bytes in a referenced side file, shared with credential-seam Block 0

- **Status:** Proposed (pending Block 0 owner confirmation)
- **Why:** Keeps the secret out of the record, matches REQ-5, and keeps one contract between
  installer and adapter.
- **Grounding:** credential-seam Block 0 config surface.
- **Confirmation:** the credential-seam adapter loads a register-written config unmodified
  (integration test once Blocks 3/4 land).

## Considered and set aside

Do not re-propose without new information.

| Option                                    | Why set aside                                                                                                 |
| ----------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| Hosted "install our App" button           | The author then holds the one key that mints for every installation, exactly the backdoor REQ-6 forbids.      |
| Per-target bespoke commands               | Duplicates the identical pipeline; only initiation differs (D1).                                              |
| GitLab via an OAuth application           | Needs a client secret held somewhere and acts as the user (broader, not scoped); no gain over a scoped token. |
| Secret stored inline in the config record | Widens exposure; a `0600` side file is tighter and matches REQ-5 (D6).                                        |

## Open items

| Item                                                   | Concrete close condition                                                                     |
| ------------------------------------------------------ | -------------------------------------------------------------------------------------------- |
| Config file location/format vs credential-seam Block 0 | A written agreement or a shared Rust type in the repo both sides use.                        |
| Exact verify probe per kind                            | Matches the real adapter's mint rendering once credential-seam Blocks 3/4 exist (the hinge). |
| GitLab default floor (group vs project token)          | Decided from real pilot job scopes.                                                          |
