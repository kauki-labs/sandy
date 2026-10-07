# sandy

sandy runs a job in an ephemeral NixOS microVM and reports a locked result
envelope. It owns the hypervisor launch natively — qemu on Linux, vfkit on
macOS — behind one `VmBackend` seam.

The Nix build is self-contained (crane directly, no external Nix library); the
tooling is modelled on [`hoprnet/hopr-api`](https://github.com/hoprnet/hopr-api).

## Status

Early development, Phase A. The CLI (`doctor`, `run`/`ls`/`status`/`wait`/`kill`/
`gc`), the journal + result envelope, the native backends, and the guest microVMs
are in place; the guests boot and speak the console protocol on both legs (qemu on
x86_64 Linux, vfkit on an Apple-silicon host). Wiring the native spawn into a live
`sandy run`, plus the `live_boot`/`host_matrix` acceptance gates, is in progress
(#26/#27).

## Layout

```text
crates/sandy/          deep library behind a curated facade (seam, journal, result, console, topology)
crates/sandy-backend/  native VmBackend impls: QemuBackend (Linux) + VfkitBackend (macOS)
crates/sandy-cli/      the `sandy` binary
nix/packages/          crane build definitions (build, clippy, docs, tests)
nix/guest/             bootable microVM guests + the Topology seam (own flake)
flake.nix              dev shell, formatter, checks
AGENTS.md              canonical agent instructions (read natively by Claude Code and Copilot)
.github/               CI, CODEOWNERS, labeler, dependabot
```

## Architecture

sandy launches the guest itself through the `VmBackend` seam: `QemuBackend`
(Linux/KVM, serial on `ttyS0`) and `VfkitBackend` (macOS/Virtualization.framework,
console on `hvc0`). The VM's shape is read from a guest flake attr evaluated into a
typed `Topology` (`nix eval --json`); Nix still builds the kernel/initrd/store. The
console driver scans for the `sandy login:` banner, injects a base64-wrapped command
bracketed by per-run sentinels, captures the output, and parses the guest exit code
into the locked result envelope (INV-11).

The guests live in [`nix/guest/`](nix/guest) (their own flake). On macOS, vfkit
requires a matching-arch guest, so an Apple-silicon host builds its aarch64-linux
guest on a remote `aarch64-linux` builder — nix-darwin's
[`nix.linux-builder`](https://wiki.nixos.org/wiki/Nix-darwin). `sandy doctor`
refuses on macOS when nix or that builder is missing, and names the fix.

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
