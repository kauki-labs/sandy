# sandy

A Rust workspace skeleton. Member crates live under `crates/*` and share
version, metadata, dependency versions, and lints through the root `Cargo.toml`.
The starter crate is [`sandy-core`](crates/sandy-core).

The tooling is modelled on [`hoprnet/hopr-api`](https://github.com/hoprnet/hopr-api),
but the Nix build is self-contained (crane directly, no external Nix library).

## Layout

```text
crates/sandy-core/   starter library crate
nix/packages/        crane build definitions (build, clippy, docs, tests)
flake.nix            dev shell, formatter, checks
AGENTS.md            canonical agent instructions (read natively by Claude Code and Copilot)
.github/             CI, CODEOWNERS, labeler, dependabot
```

Agent instructions live once in [`AGENTS.md`](AGENTS.md). Claude Code reads it
natively (there is no `CLAUDE.md`), and GitHub Copilot reads it as `AGENTS.md`,
so there is nothing to keep in sync.

## Getting started

Requires [Nix](https://nixos.org/download) with flakes enabled. The dev shell
pins the Rust toolchain and every tool the workflow uses.

```bash
nix develop                     # enter the dev shell
nix develop -c cargo nextest run
nix fmt                         # format everything
nix flake check -L              # build + clippy + docs + tests + formatting
```

### direnv (optional)

For automatic shell loading, create an `.envrc` with:

```bash
watch_file nix/*.nix
watch_file rust-toolchain.toml
use flake

PATH_add .cargo/bin
PATH_add target/debug/
```

then run `direnv allow`.

## Adding a crate

Create `crates/<name>/` with a `Cargo.toml` that inherits from the workspace:

```toml
[package]
name = "<name>"
version.workspace = true
edition.workspace = true
license.workspace = true

[lints]
workspace = true
```

The `crates/*` glob in the root `Cargo.toml` picks it up automatically.

## License

MIT — see [LICENSE](LICENSE).
