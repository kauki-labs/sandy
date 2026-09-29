# sandy — Agent Instructions

Single source of truth for every AI coding agent. Claude Code reads this file
natively (there is no `CLAUDE.md`), and GitHub Copilot reads it as `AGENTS.md`.
Everything an agent needs is here.

## Project overview

sandy is a Rust workspace. Member crates live under `crates/*` and share version,
metadata, dependency versions, and lints through the root `Cargo.toml`
(`[workspace.package]`, `[workspace.dependencies]`, `[workspace.lints]`). The
starter crate is `sandy-core`.

## Build & test (run before committing)

```bash
nix fmt                 # Format everything (Rust via nightly rustfmt, Nix, TOML, YAML, MD)
nix flake check -L      # Build + clippy (deny warnings) + docs + tests + formatting
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

## Workflow

1. Before modifying code, understand the surrounding context and existing patterns.
2. For multi-step features, plan before implementing.
3. After changes, run `nix develop -c cargo check` to verify.
4. When a cycle is finished, run `cargo shear --fix` followed by `cargo check` for
   dependency hygiene.
5. Format with `nix fmt`.
6. Run `nix develop -c cargo clippy --all-targets` and `nix develop -c cargo nextest run`.
7. Before opening a PR, run `nix flake check -L`.
8. Commit with a descriptive title using Conventional Commits notation.

## Architecture

```text
crates/
  └─ sandy-core/   - starter library crate
```

Add a crate by dropping it under `crates/`; the workspace glob picks it up.

- **Shared config**: crates inherit metadata and dep versions from the root with
  `version.workspace = true`, `thiserror.workspace = true`, and so on.
- **Shared lints**: `[lints] workspace = true` per crate applies the workspace
  lint table (`unsafe_code = forbid`, `missing_docs = warn`, clippy `all = warn`).
- **Deny warnings in CI**: clippy runs with `--deny warnings`, so documentation
  and lint gaps fail the build rather than piling up.

## Technology stack

- **Rust**: edition 2024, workspace-shared deps and lints
- **Build**: Nix flake with crane (self-contained; no external Nix library)
- **Testing**: `cargo nextest`, `rstest` for parameterized cases, `insta` for snapshots
- **Formatting**: rustfmt (nightly), nixfmt, taplo, shfmt, yamlfmt, prettier — all via `nix fmt`

## Code style

- `tracing::info!()`, not `info!()` — explicit prefix
- Errors: `thiserror` for typed errors; propagate with `?`, no `.unwrap()` in libraries
- Naming: `snake_case` functions/vars, `CamelCase` types/traits
- Document public items with `///`, including a rationale and an example where it helps
- Keep functions small; break logic into modules that can be reused

## Rust rules

- Prefer immutable structures.
- Use `Result` and `Option` for error handling and optional values.
- Follow Rust naming conventions: `snake_case` for variables and functions, `CamelCase` for types and traits.
- Leverage pattern matching.
- Write documentation comments with `///` for public items.
- Prefer async runtime-agnostic code; when not possible, use `tokio` runtime utilities.
- Default to native `async fn` in traits for static dispatch — this avoids unnecessary heap allocations.
- Reserve `async-trait` for dynamic dispatch, where you need `dyn Trait` object compatibility.
- For public traits, handle explicit `Send` bounds (via `trait-variant`, or by spelling out return types as
  `impl Future + Send`), since the compiler warns about implicit auto-trait assumptions.
- Prefix tracing macros with `tracing::` (e.g., `tracing::info!`).
- Use natural phrasing for test names; do not use the `test_` prefix.
- Tests containing `expect` or `unwrap` in the body should return `anyhow::Result<()>` with `.context()` on errors.
- After editing tests or code, rerun the closest package test suite to catch unintended failures.
- Use TDD to drive the design of new modules and features; when unsure, ask.
- Once a cycle is finished, run `cargo shear --fix` followed by `cargo check` for dependency hygiene and correctness.

## Common mistakes to avoid

1. `.unwrap()` in library code → propagate with `?`
2. Missing `tracing::` prefix on log macros
3. Leaving compiler or clippy warnings → fix, or `#[allow(reason = "…")]` with a justification
4. Hardcoding config values instead of threading them through
