# GitHub App setup (credential-seam trust root)

sandy's GitHub adapter mints short-lived, least-privilege installation tokens for a
job through the [credential seam](design/credential-seam/) (REQ-1). The minting trust
root is a **GitHub App** whose private key stays on the controller/host and never
enters a guest (REQ-5); the guest only ever receives a scoped, short-lived token.

This is the operator setup for that App. The credential-seam design treats the trust
root as operator-provided and out of its own scope; this doc fills that gap. Install
scope and the canonical secret storage are IaC in the `kauki-labs/infra` repo
(`tf/cloud/02-github/`, see its `SANDY-APP.md`).

## Capabilities the App grants

The seam's abstract `Capability` maps onto GitHub App permissions. The App grant is
the **ceiling**; each minted token down-scopes within it (REQ-1).

| seam `Capability` | GitHub App permission       |
| ----------------- | --------------------------- |
| `ReadCode`        | Contents: Read-only         |
| `WriteCode`       | Contents: Read & write      |
| `ReadPr`          | Pull requests: Read-only    |
| `WritePr`         | Pull requests: Read & write |
| (always)          | Metadata: Read-only (auto)  |

Current pilot grant: **`WriteCode` + `WritePr`** → Contents R/W + Pull requests R/W.
Start minimal and widen only per a real job's need.

## Topology: one App per owner

`"Only on this account"` scopes an App to the single owner that created it, so
personal + org repos need **two Apps** (the same single-owner limit the infra repo
records for its fine-grained PAT).

| App name (global)         | Owner                     | Manifest (in `infra`)                   |
| ------------------------- | ------------------------- | --------------------------------------- |
| `sandy-runner`            | `Teebor-Choka` (personal) | `sandy-runner.personal.manifest.json`   |
| `sandy-runner-kauki-labs` | `kauki-labs` (org)        | `sandy-runner.kauki-labs.manifest.json` |

A third party installing a `public` App gains nothing over your repos: installations
are isolated, and only the private-key holder can mint tokens, scoped to that one
installation. That is why `public:false` (Only on this account) costs nothing here.

**Pilot hosts.** Each pilot host (Linux/KVM, aarch64-darwin) needs the App
credentials present controller-side (REQ-5). The App is shared; placing its key on
each host 0600 is the operator's job.

## Bootstrap — once per App

Two browser clicks are irreducible (GitHub has no API to originate an App or to
install one): **Create**, and **Install**. `gh` + `jq` do the rest. Set these in
either path:

- Contents → **Read & write**
- Pull requests → **Read & write**
- Metadata → Read-only (auto)
- everything else → **No access**
- Webhook → untick **Active**, leave URL blank
- Where can this App be installed → **Only on this account**

### Path A — manifest flow (captures the `.pem` via gh)

Uses the committed manifest as the source and returns the private key once, so there
is no manual key download.

```sh
# in the infra repo
python3 -m http.server 8080        # catches the redirect; keep running

jq '. + {redirect_url:"http://localhost:8080/"}' \
  tf/cloud/02-github/sandy-runner.personal.manifest.json > /tmp/manifest.json

# Open a one-field HTML form POSTing `manifest` (the JSON string) to:
#   personal: https://github.com/settings/apps/new
#   org:      https://github.com/organizations/kauki-labs/settings/apps/new
# In the browser, click "Create GitHub App"  <-- irreducible click.
# GitHub redirects to http://localhost:8080/?code=<CODE>  (copy <CODE>, ~1h TTL)

gh api --method POST /app-manifests/<CODE>/conversions > /tmp/app.json
jq -r '.id'  /tmp/app.json                              # App ID
jq -r '.pem' /tmp/app.json > /tmp/sandy-runner.pem      # -> controller 0600, then shred
```

### Path B — UI by hand

Settings → Developer settings → GitHub Apps → New GitHub App (on the org for the
kauki App). Fill the permission set above, Create, then **Generate a private key**
(downloads the `.pem`).

### Then, per App

1. **Install App** → **Only select repositories** → pick ≥1 (tofu reconciles the set
   afterwards, so an over/under pick here is fine).
2. Read the **installation id**:
   ```sh
   # as the App (JWT from the pem); lists installations + ids
   gh api /app/installations --jwt-from-pem /tmp/sandy-runner.pem --app-id <APP_ID> \
     --jq '.[] | {id, account: .account.login}'
   ```
   Fallback: the install settings URL (`.../settings/installations/<ID>`).

## Where the three values live

| Value           | Home                                                                                                                                                                        |
| --------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `.pem`          | Controller/host, **0600, never in a guest** (REQ-5). Canonical copy in infra KeePass `Infrastructure/Credentials/sandy-runner app private key [personal]` / `[kauki-labs]`. |
| App id          | Alongside the key (not secret).                                                                                                                                             |
| Installation id | infra `tf/cloud/secrets.yaml` → `TF_VAR_sandy_installation_id_{personal,kauki_labs}` (not secret).                                                                          |

How the adapter reads these at runtime (config keys, octocrab vs raw REST+JWT) is the
credential-seam Block 2/3 concern and is not fixed here.

## Install scope is code

infra `tf/cloud/02-github/sandy_runner_app.tf` manages which repos each installation
may touch via `github_app_installation_repositories`. Once the installation ids and
repo names are set:

```sh
# in the infra repo
nix run .#tf -- -C tf/cloud/02-github apply
nix run .#tf -- -C tf/cloud/02-github plan   # expect: No changes
```

## References

- Credential seam design: [`docs/design/credential-seam/`](design/credential-seam/)
  (REQ-1, REQ-5 in `credential-seam-proposal.md` §3).
- Infra IaC: `kauki-labs/infra` → `tf/cloud/02-github/` (`SANDY-APP.md`).
