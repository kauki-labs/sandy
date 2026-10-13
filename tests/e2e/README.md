# CLI end-to-end tests (bats)

Black-box tests that drive the built `sandy` binary at the process boundary:
argv parsing, exit bands (INV-11), the `-o json` envelope shape, and error paths.
This is the layer the in-crate `assert_cmd` tests don't reach, the real compiled
CLI as an agent or a shell invokes it. It complements, not replaces, the Rust
suites (see [`docs/architecture/spec.md`](../../docs/architecture/spec.md#testing-integration-vs-end-to-end)
for the integration-vs-end-to-end split).

## Layout

```
tests/e2e/
  basic/        non-live surface, one file per subcommand (global, ls, gc, status, run, cred)
  live/         real boots through `sandy run` (gated)
  helpers/      common.bash: binary resolution, state isolation, the require_live gate
```

- `basic/*.bats` — no hypervisor, no network, no `nix`. Runs anywhere the binary
  builds, including the Nix sandbox. One file per subcommand.
- `live/*.bats` — a real job booted through `sandy run`. Needs a hypervisor and a
  buildable guest, so every test is gated by `require_live` and **skipped**
  off-matrix (INV-S9: never counted green from a skip).
- `helpers/common.bash` — binary resolution, per-test `$SANDY_HOME` and
  `$XDG_CONFIG_HOME` isolation, and the `require_live` gate.

## Run it

Non-live subset (what CI could run), hermetically against the built binary:

```sh
nix build .#checks.x86_64-linux.tests-e2e-cli      # or aarch64-darwin
```

Everything, in the dev shell, against a debug build:

```sh
nix develop -c cargo build -p sandy-cli
nix develop -c bats tests/e2e/basic tests/e2e/live   # live tests skip without the env below
```

The live tier, on a host with virtualization:

```sh
SANDY_LIVE=1 SANDY_E2E_TEMPLATE='/path/to/guest#topologies.<system>.<hv>' \
  nix develop -c bats tests/e2e/live
```

`SANDY_BIN` overrides binary resolution (the flake check sets it to the built
package); otherwise the suite uses `target/debug/sandy`.
