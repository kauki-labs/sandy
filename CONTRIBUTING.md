# Contributing

Thanks for helping improve sandy. This is the short version; the canonical,
always-current build/test/style guide is [`AGENTS.md`](AGENTS.md) (read natively
by Claude Code and GitHub Copilot), and the design lives in
[`docs/architecture/`](docs/architecture/overview.md).

## Licensing of contributions (CLA)

Sandy is dual-licensed: [AGPL-3.0-only](LICENSE) for open-source use, and a
separate commercial license for use that cannot meet the AGPL's terms (see
[COMMERCIAL.md](COMMERCIAL.md)). For the project to offer that commercial license,
it must hold sufficient rights in every contribution. By submitting a
contribution (a pull request, patch, or any other work), you agree to the
following with the project's current maintainer, **Tibor Csóka** ("the
Maintainer"). This grant runs to the Maintainer and to any successor who
takes over maintainership of this project (by transfer, assignment, or
otherwise); it does not need to be re-granted on a change of maintainer:

- **Grant.** You grant the Maintainer a perpetual, worldwide, non-exclusive,
  royalty-free, irrevocable license to reproduce, prepare derivative works of,
  publicly display and perform, sublicense, and distribute your contribution and
  derivative works, **with the right to sublicense and relicense it under any
  license, including AGPL-3.0, other open-source licenses, and
  proprietary/commercial licenses.**
- **Patents.** You grant the Maintainer and recipients a perpetual, worldwide,
  non-exclusive, royalty-free, irrevocable patent license for any patent claims
  you can license that your contribution necessarily infringes, alone or combined
  with the project.
- **You keep ownership.** This is a license, not an assignment; you retain all
  right, title, and interest in your contribution and may use it however you wish.
- **Representations.** Each contribution is your original work, you are entitled
  to grant these licenses, and if your employer has rights to your work you have
  permission to contribute.

If you do not agree, do not submit a contribution.

> These terms are the project's current CLA and may be revised; a contribution is
> accepted under the version in effect when it is submitted.

## Setup

sandy builds with [Nix](https://nixos.org/download) (flakes enabled). The dev
shell pins the Rust toolchain and every tool the workflow uses:

```bash
nix develop                      # enter the dev shell
nix develop -c cargo nextest run # tests
nix fmt                          # format everything
nix flake check -L               # the full gate: build, clippy, docs, tests, formatting
```

`direnv allow` loads the shell and the pre-commit hooks automatically (see the
[README](README.md#direnv-optional)).

## Making a change

- Match the check to the change (full matrix in [`AGENTS.md`](AGENTS.md#workflow)):
  for Rust, `cargo check`, `clippy --all-targets`, and `nextest run -p <crate>`
  for the touched crate; before a PR, `nix fmt` then `nix flake check -L`.
- Drive new behaviour from a failing test (TDD); when fixing a bug, add the
  regression test first.
- Touching a live (tier-3) test path? Run clippy with `--all-features`, and run
  the live suite on a host with a hypervisor (see
  [`docs/architecture/kpi.md`](docs/architecture/kpi.md)).
- Keep the diff to what the change needs, and preserve the invariants the spec
  calls out (INV-1 secrets off the data plane, INV-7 fail-closed, and the rest in
  [`docs/architecture/spec.md`](docs/architecture/spec.md)).

## Commits and PRs

- Use a [Conventional Commits](https://www.conventionalcommits.org) title; CI
  validates it, and the allowed types are `fix`, `feat`, `build`, `chore`,
  `docs`, `refactor`, `perf`, `test`.
- One logical change per PR, with the tests that prove it.

## Releases

Releases are automated by [release-plz](https://release-plz.dev). A version bump
reaching `main` opens the release; you do not tag or publish by hand.
release-plz also keeps a prepared bump PR open with the changelog.

**Currently GitHub releases only** (`release-plz.toml`): each binary
(`sandy-cli`, `sandyd`, `sandy-agent`) gets its own version, tag, and GitHub
release. crates.io publishing is deferred — `publish = false` workspace-wide —
until the trusted-publishing bootstrap below is done.

**crates.io bootstrap (not yet done; `kauki-labs/sandy` maintainer-only),
needed before `publish` flips back to `true`:**

1. [Trusted publishing](https://crates.io/docs/trusted-publishing) can't
   perform a crate's _first_ publish — each publishable crate needs one
   manual `cargo publish` (with a real token), in dependency order, before it
   exists on crates.io at all.
2. Once published once, register this repo + the workflow **file**
   `.github/workflows/release.yaml` (crates.io binds to the filename, not its
   `name: Release` display label — entering `Release` fails the OIDC
   exchange) as a Trusted Publisher for that crate — the release job then
   mints a short-lived OIDC token per run, so there's no long-lived
   `CARGO_REGISTRY_TOKEN` in the repo.
3. Repeat for every publishable crate, then in `release-plz.toml`: flip
   `publish` back to `true`, **and** remove the three binaries'
   `git_only = true` lines — release-plz treats `publish = true` together
   with `git_only = true` as an error, so both have to change together.

This bootstrap is scoped to `kauki-labs/sandy`'s own crates.io namespace — not
something a fork inherits. If you want to contribute, open a PR here rather
than publishing your own crates under these names. If you're standing up your
own deployment or a derivative project under the license (see
[COMMERCIAL.md](COMMERCIAL.md) if the AGPL's terms don't fit your use), you'll
run this same bootstrap against your own crates.io namespace, likely under
different crate names since these ones are already taken.

## Conduct

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).
