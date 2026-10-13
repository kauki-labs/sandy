# sandy

[![PR](https://github.com/kauki-labs/sandy/actions/workflows/pr.yaml/badge.svg)](https://github.com/kauki-labs/sandy/actions/workflows/pr.yaml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust edition 2024](https://img.shields.io/badge/rust-edition%202024-orange.svg)](rust-toolchain.toml)

sandy runs a job in an ephemeral NixOS microVM and reports a locked result
envelope. It owns the hypervisor launch natively — qemu on Linux, vfkit on
macOS — behind one `VmBackend` seam, delivers inputs/outputs/secrets and a scoped
forge credential over virtio-fs shares, and enforces an egress allow-list around
the boot.

The Nix build is self-contained (crane directly, no external Nix library); the
tooling is modelled on [`hoprnet/hopr-api`](https://github.com/hoprnet/hopr-api).

## Status

A job boots a real microVM and runs end to end on both backends (qemu/KVM and
vfkit): `sandy run` mints and injects a scoped credential, mounts read-only inputs
and a read-only secret share, collects writable outputs to the host, and classifies
the outcome into the locked result envelope. Verified by host-gated live tests on
Linux/KVM and Apple-silicon hosts. The architecture is specified in
[`docs/architecture/`](docs/architecture/overview.md).

## Usage

```sh
sandy doctor                       # verify host prerequisites
sandy run <template> [flags] -- <cmd...>
```

`<template>` is a guest flake attr (e.g. `topologies.aarch64-linux.vfkit`). The
job command runs inside the guest; its exit code and the guest console come back in
the result envelope. Flags (repeatable where it makes sense):

| Flag                                       | Effect                                                                                                           |
| ------------------------------------------ | ---------------------------------------------------------------------------------------------------------------- |
| `--input HOST:NAME`                        | mount the host file/dir read-only at `/run/sandy/inputs/NAME` (write → `EROFS`)                                  |
| `--out DEST` / `--out NAME:DEST`           | collect everything under `/run/sandy/outputs` (or just `/run/sandy/outputs/NAME`) to the host `DEST` at teardown |
| `--secret NAME=@PATH`                      | inject the file's bytes as `$NAME` in-guest (never on argv/env)                                                  |
| `--credential <name>`                      | mint a scoped token from a `sandy cred github` trust root, inject it as `$GITHUB_TOKEN`, revoke at teardown      |
| `--allow HOST:PORT`                        | egress allow-list entry (enforced on Linux; macOS is unfiltered)                                                 |
| `--cpu N` / `--mem MiB` / `--timeout SECS` | resource knobs                                                                                                   |
| `-o plain` (default) / `-o json`           | human summary, or the full structured envelope for agents                                                        |

Credential trust roots are managed with
`sandy cred github register | import | verify | deregister` (see
[`docs/providers/github`](docs/providers/github/README.md)).

```sh
# read an input, write a collected output, with a scoped GitHub token
sandy run topologies.aarch64-linux.vfkit \
  --input ./data:data --out result:./out --credential sandy-runner \
  -- sh -c 'process /run/sandy/inputs/data > /run/sandy/outputs/result/report'
```

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
