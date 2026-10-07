# sandy — Agent Instructions

Single source of truth for every AI coding agent. Claude Code reads this file
natively (there is no `CLAUDE.md`), and GitHub Copilot reads it as `AGENTS.md`.
Everything an agent needs is here.

## Project overview

sandy is a Rust workspace that runs a job in an ephemeral NixOS microVM and
reports a locked result envelope. Member crates live under `crates/*` and share
version, metadata, dependency versions, and lints through the root `Cargo.toml`
(`[workspace.package]`, `[workspace.dependencies]`, `[workspace.lints]`):

- **`sandy`** — the deep library. Private implementation modules behind a curated
  `pub use` facade: the `VmBackend` seam + `FakeBackend`, the journal, reconcile,
  the result envelope (INV-11), console protocol, nix topology, egress, seed,
  secret staging, and gc.
- **`sandy-backend`** — the native `VmBackend` implementations: `QemuBackend`
  (Linux/KVM, serial on `ttyS0`) and `VfkitBackend` (macOS/Virtualization.framework,
  console on `hvc0`).
- **`sandy-cli`** — the `sandy` binary: `doctor` and `run`/`ls`/`status`/`wait`/
  `kill`/`gc` (text or `-o json`).

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

Before coding, understand the surrounding context and existing patterns; for multi-step
features, plan first. Match the check to the change rather than running the full gate every
time (the reasoning lives in the `rust-engineer` skill). Concrete commands:

| Change                             | Checks                                                                                                      |
| ---------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| Rust code                          | `nix develop -c cargo check`, `clippy --all-targets`, and `nextest run -p <crate>` for the touched crate    |
| Tests only                         | `nix develop -c cargo nextest run -p <crate>`                                                               |
| Docs, comments, `///`              | `nix fmt`; no tests unless a doctest changed                                                                |
| `Cargo.toml`, deps, or `flake.nix` | `cargo shear --fix`, then `nix develop -c cargo check`                                                      |
| Before opening a PR                | `nix fmt`, then `nix flake check -L` (full gate: build, clippy with deny-warnings, docs, tests, formatting) |

Commit with a Conventional Commits title.

## Architecture

```text
crates/
  ├─ sandy/          - deep library behind a curated facade (seam, journal, result, console, topology, …)
  ├─ sandy-backend/  - native VmBackend impls: QemuBackend (Linux) + VfkitBackend (macOS)
  └─ sandy-cli/      - the `sandy` binary (doctor, run/ls/status/wait/kill/gc)
nix/
  ├─ packages/       - crane build definitions
  └─ guest/          - bootable microVM guests + the Topology seam (own flake)
```

Add a crate by dropping it under `crates/`; the workspace glob picks it up.

- **Deep crate**: `sandy`'s module tree is private; the only public surface is
  the `pub use` facade in `lib.rs`. Reach a type through the facade, never into a
  module.
- **The run plane**: sandy owns the hypervisor launch natively through the
  `VmBackend` seam (qemu on Linux, vfkit on macOS). The VM shape comes from
  evaluating a guest flake attr into a typed `Topology` (`nix eval --json`); Nix
  still builds the artifacts. `FakeBackend` stands in for the sandbox tiers; a
  real boot is tier-3 (host), never counted green from a fake (INV-S9).
- **The guest** (`nix/guest/`, its own flake): a microVM named `sandy` (the
  `sandy login:` READY_MARKER) with an erofs store. `#packages.x86_64-linux.guest-runner`
  (qemu) and `#packages.aarch64-darwin.guest-runner-vfkit` build the runners;
  `#topologies.<system>.<hypervisor>` emit the `Topology` JSON sandy reads.
- **macOS needs a linux-builder**: vfkit requires a matching-arch guest, so an
  aarch64-darwin host builds its aarch64-linux guest on a remote `aarch64-linux`
  builder (nix-darwin's `nix.linux-builder`). `sandy doctor` refuses on macOS when
  nix or that builder is missing, naming the fix.
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

## Never

- **Bulk-update `Cargo.lock`.** It pulls unrelated upgrades into the diff. Use
  `cargo update --precise <crate>@<version>` for a targeted bump.
- **`.unwrap()` / `.expect()` in library code.** A panic becomes the caller's crash.
  Propagate with `?`; in tests return `anyhow::Result<()>` and add `.context()`.
- **Drop the `tracing::` prefix** on log macros — write `tracing::info!`, not `info!`.

## Common mistakes to avoid

1. Leaving compiler or clippy warnings → fix, or `#[allow(reason = "…")]` with a justification
2. Hardcoding config values instead of threading them through
