# sandy Development Guidelines

## Project Overview

sandy is a Rust workspace. Member crates live under `crates/*` and share version,
metadata, dependency versions, and lints through the root `Cargo.toml`
(`[workspace.package]`, `[workspace.dependencies]`, `[workspace.lints]`). The
starter crate is `sandy-core`.

## Build & Test (run these before committing)

```bash
nix fmt                 # Format everything (Rust via nightly rustfmt, Nix, TOML, YAML, MD)
nix flake check -L      # Build + clippy (deny warnings) + docs + tests
```

Faster inner-loop commands inside the dev shell:

```bash
nix develop -c cargo check                    # Type-check the workspace
nix develop -c cargo clippy --all-targets     # Lint
nix develop -c cargo nextest run              # Tests
nix develop -c cargo shear --fix              # Prune unused dependencies
```

## Setup

1. Nix with flakes enabled (`experimental-features = nix-command flakes`).
2. `direnv allow` to load the dev shell and pre-commit hooks (needs an `.envrc`;
   see the README).

## Technology Stack

- **Rust**: edition 2024, workspace-shared deps and lints
- **Build**: Nix flake with crane (self-contained; no external Nix library)
- **Testing**: `cargo nextest`, `rstest` for parameterized cases, `insta` for snapshots
- **Formatting**: rustfmt (nightly), nixfmt, taplo, shfmt, yamlfmt, prettier — all via `nix fmt`

## Architecture

```text
crates/
  └─ sandy-core/   - starter library crate
```

Add a crate by dropping it under `crates/`; the workspace glob picks it up.

### Key patterns

- **Shared config**: crates inherit metadata and dep versions from the root with
  `version.workspace = true`, `thiserror.workspace = true`, and so on.
- **Shared lints**: `[lints] workspace = true` per crate applies the workspace
  lint table (`unsafe_code = forbid`, `missing_docs = warn`, clippy `all = warn`).
- **Deny warnings in CI**: clippy runs with `--deny warnings`, so documentation
  and lint gaps fail the build rather than piling up.

## Code Style

- `tracing::info!()`, not `info!()` — explicit prefix
- Errors: `thiserror` for typed errors; propagate with `?`, no `.unwrap()` in libraries
- Naming: `snake_case` functions/vars, `CamelCase` types/traits
- Document public items with `///`, including a rationale and an example where it helps
- Keep functions small; break logic into modules that can be reused

For language-specific rules see [rust.md](rust.md).

## Common mistakes to avoid

1. `.unwrap()` in library code → propagate with `?`
2. Missing `tracing::` prefix on log macros
3. Leaving compiler or clippy warnings → fix, or `#[allow(reason = "…")]` with a justification
4. Hardcoding config values instead of threading them through
