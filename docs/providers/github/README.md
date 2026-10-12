# GitHub credential provider

sandy mints short-lived, least-privilege GitHub tokens for a job from a **trust
root**: a GitHub App whose private key stays on the controller and never enters a
guest. One shared App per org; each job mints an installation token scoped to the
repos and capabilities it needs, revoked at teardown.

Commands: `sandy cred github register | verify | import | deregister`, and
`sandy run --credential`.

## Register (once per org)

```sh
sandy cred github register sandy-runner \
  --org <org> \
  --capability write-code --capability write-pr \
  --repo <owner>/<repo>
```

Open the localhost URL it prints, then click **Create** and **Install**. Those two
clicks are the only manual step: GitHub has no API to create or install an App,
which is also why there's no author backdoor (the key is generated into your
browser, never a shared server). sandy captures the key + ids, writes
`~/.config/sandy/trust-roots/sandy-runner.{json,pem}` (`0600`), and **verifies by
default** (dry-run mint + a check that the install grants no less than requested).
`--skip-verify` is the explicit escape.

The App name is deterministic (`<name>-<org>`), and a duplicate check refuses a
second registration, one shared App per org. `--name-override` sets an exact name;
`--force` overrides the check.

## Reuse (everyone else on the team)

The App is shared, so members 2..N don't register, they import its key from the
secret store (e.g. KeePass):

```sh
sandy cred github import sandy-runner \
  --app-id <id> --installation-id <id> --pem <path-to-shared-key>
```

No browser, no second App. The `.pem` is the trust root: `0600`, never committed,
never in a guest. Every key holder can mint for all the App's installs; if you want
per-person isolation instead, each member can `register` their own App (the
deterministic name + duplicate check are built for the shared model, so pass
`--name-override`/`--force` for the per-person case).

## Use it in a job

```sh
sandy run <template> --credential sandy-runner --cred-capability read-code -- <cmd>
```

Mints a token scoped to the trust root's repos and the given capability, injects it
as `GITHUB_TOKEN`, and revokes it at teardown.

## Verify / remove

```sh
sandy cred github verify sandy-runner --capability write-code   # re-check: mint + ceiling + revoke
sandy cred github deregister sandy-runner                       # uninstall at the forge + shred the local key
```

`deregister` uninstalls the installation and shreds the local key/config. The App
_registration_ shell can't be deleted via API, so it points you to the GitHub UI to
remove it. If the key is already gone it can't sign the uninstall, so it does the
local teardown and points to the UI.

## Capabilities

`read-code` / `write-code` / `read-pr` / `write-pr` render to GitHub `contents` and
`pull_requests` permissions (`metadata:read` always included). The registered App's
grant is the ceiling; each minted token is scoped at or below it.

GitHub Enterprise Server: pass `--base-url https://<host>` to `register` / `import`.

## Regression check

A live, host-gated end-to-end test guards the flow (it needs a real registered
App, so it's off by default and never runs in CI):

```sh
SANDY_LIVE=1 cargo nextest run -p sandy-cli --features live --test cred_e2e
```

It runs `verify` against the configured trust root — build the adapter, read the
installation's grant, mint a scoped token, revoke it — and fails if register,
verify, or the adapter regressed. `SANDY_CRED_HANDLE` / `SANDY_CRED_CAPS` target a
different root. (`sandy run --credential` into a live guest is a separate run-path
gate, pending guest-side secret consumption.)
