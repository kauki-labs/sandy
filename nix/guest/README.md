# sandy guest microVMs

Bootable NixOS microVMs that speak sandy's console protocol, plus the `Topology`
seam sandy reads to launch them. Used to prove the native backends actually boot a
guest (tier-3 acceptance, #26/#27) — the sandbox tiers use `FakeBackend` instead.

This is its own flake (built on [microvm.nix](https://github.com/microvm-nix/microvm.nix)),
kept separate from the Rust workspace flake so the guest closures never enter the
crate build.

## The guests

One shared config, two hypervisor variants (microvm.nix drives both):

| Attr                                         | Host            | Guest         | Hypervisor | Console |
| -------------------------------------------- | --------------- | ------------- | ---------- | ------- |
| `packages.x86_64-linux.guest-runner`         | Linux/KVM       | x86_64-linux  | qemu       | `ttyS0` |
| `packages.aarch64-darwin.guest-runner-vfkit` | macOS (Apple M) | aarch64-linux | vfkit      | `hvc0`  |

Both: hostname `sandy` (so getty prints the `sandy login:` READY_MARKER),
autologin root on the serial console, and an **erofs store** on disk
(`microvm.storeOnDisk`) — sandy attaches the store as a read-only block device and
refuses a virtiofs store.

## Build and boot

```bash
# Linux node (qemu):
nix build .#guest-runner && result/bin/microvm-run

# macOS (vfkit) — builds the aarch64-linux guest on the linux-builder, runs on the Mac:
nix build .#packages.aarch64-darwin.guest-runner-vfkit && result/bin/microvm-run
```

On macOS the guest must match the host arch, so an Apple-silicon host builds its
aarch64-linux guest on a remote `aarch64-linux` builder (nix-darwin's
[`nix.linux-builder`](https://wiki.nixos.org/wiki/Nix-darwin), already registered in
`/etc/nix/machines`). `sandy doctor` refuses with a named fix when it is missing.

## The topology seam

sandy reads the VM shape from a flake attr evaluated to JSON (`nix eval --json`),
never re-deriving the hypervisor argv:

```bash
nix eval --json .#topologies.x86_64-linux.qemu    # or .aarch64-linux.vfkit
```

It emits the `sandy::Topology`: `kernel` (uncompressed `Image` for vfkit),
`initrd`, `store.erofs_image`, `kernel_cmdline` (with the per-hypervisor console),
`cpu`, `mem`, `shares`, `hypervisor`. Realise the paths first (build the guest) so
they exist when the backend boots.

## The console protocol

The guest side is a plain serial shell; sandy's state machine
(`crates/sandy/src/console`) drives it: scan for `sandy login:`, inject a
base64-wrapped command bracketed by unique per-run `<<SANDY-<uuid>-START/END>>`
sentinels, capture the bytes between them, parse the trailing `exit=<n>`.

Two constraints a live boot imposes (and the fixtures miss, because they hand-build
the stream):

- the guest serial is a tty with **echo** on, so the injected frame is echoed back
  — the sentinels are emitted from split `printf` literals so only the printf
  output carries a contiguous sentinel, never the echoed input;
- `exit=<n>` must sit on the first line **immediately after** END.

`protocol_probe.py` is the ground-truth reproducer: it drives sandy's exact
protocol against a built runner (`protocol_probe.py <runner>/bin/microvm-run "echo hi"`)
and reports the captured output and exit code. It is a spike artifact, not shipped
in the binary.
