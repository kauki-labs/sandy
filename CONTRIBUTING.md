# Contributing

Thanks for helping improve sandy. This is the short version; the canonical,
always-current build/test/style guide is [`AGENTS.md`](AGENTS.md) (read natively
by Claude Code and GitHub Copilot), and the design lives in
[`docs/architecture/`](docs/architecture/overview.md).

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
reaching `main` opens the release (tag, GitHub release, and a crates.io publish
of `sandy-box` / `sandy-backend` / `sandy-cli` in dependency order); you do not
tag or publish by hand. release-plz also keeps a prepared bump PR open with the
changelog.

Publishing uses crates.io [trusted publishing](https://crates.io/docs/trusted-publishing):
the release job mints a short-lived token from GitHub's OIDC identity, so there
is no long-lived `CARGO_REGISTRY_TOKEN` in the repo. Before the first publish,
register this repo and the `Release` workflow as a Trusted Publisher for each
crate on crates.io; until that is set up the publish step fails closed.

## Conduct

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).
