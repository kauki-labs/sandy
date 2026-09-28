# sandy — Claude Configuration

Read `.claude/INSTRUCTIONS.md` for full development guidelines, coding standards, and project conventions.

When working on Rust files, also read `.claude/rust.md` for language-specific rules.

Claude configuration and instructions live under `.claude/`.

## Workflow

1. Before modifying code, understand the surrounding context and existing patterns.
2. For multi-step features, plan before implementing.
3. After changes, run `nix develop -c cargo check` to verify.
4. For Rust changes, run `cargo shear --fix` followed by `cargo check` when a cycle is finished.
5. Run `nix fmt` to format.
6. Run `nix develop -c cargo clippy --all-targets` and `nix develop -c cargo nextest run` to verify everything builds and passes.
7. Before opening a PR, run `nix flake check -L`.
8. Commit with a descriptive title using Conventional Commits notation.

## Permissions

See `.claude/settings.json` for allowed commands.
