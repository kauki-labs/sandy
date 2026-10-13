# Decisions: guest shares (`GuestShareTransport`)

Presenting host directories to the guest as virtio-fs mounts for inputs (RO),
outputs (RW), and the secret share (RO). Subsystem spec:
[`../architecture/spec.md#2-guest-shares-guestsharetransport`](../architecture/spec.md#2-guest-shares-guestsharetransport).

## 1. virtio-fs everywhere, one guest config

**Status:** accepted.

**Context.** Both backends must expose host dirs to the guest, and the guest
image should not need a per-backend mount config.

**Decision.** The guest statically mounts fixed tags (`sandy-inputs`,
`sandy-outputs`, `sandy-secrets`) with `nofail`, `fsType = "virtiofs"` on both
backends. qemu serves them with a `virtiofsd` daemon per share plus a
`vhost-user-fs-pci` device; vfkit serves virtio-fs natively.

**Consequences.** One guest config works on both hypervisors; the shares resolve
by fixed tag.

**Set aside.** 9p: the original bug was qemu emitting `-virtfs` (9p) while the
guest mounted `virtiofs`, so the tag never resolved. Fixed to virtiofs on the
qemu side; 9p is not used.

## 2. Read-only at the host boundary

**Status:** accepted. **Upholds:** INV-1.

**Context.** An input marked RO must stay unwritable even against a guest that
remounts its own root read-write.

**Decision.** On qemu, `--readonly` is passed to `virtiofsd`, so the host dir is
unwritable below the guest. On vfkit the guest mount's `ro` enforces it (its
virtio-fs device rejects a `,ro` arg). A write to an input fails `EROFS`.

**Consequences.** RO is enforced at the host boundary, not merely by guest
cooperation; proven live by K5 (`live_inputs.rs`).

## 3. Inputs copied, outputs collected

**Status:** accepted.

**Context.** A job needs its inputs present and its chosen outputs back on the
host, without a share handing the guest a path to escape through.

**Decision.** Inputs are copied under their name into the fixed-tag inputs share.
Outputs are a writable share collected to the host `DEST` at teardown and listed
in `envelope.outputs`. Collection **skips symlinks** and caps bytes/entries.

**Consequences.** A job dropping `out/x → /etc/shadow` neither leaks the target's
bytes nor plants a host-escaping link. Copying inputs is fine for typical sizes;
a no-copy / arbitrary-path variant is deferred (#82).

## 4. Fixed tags, not pooled

**Status:** accepted.

**Context.** An earlier model handed each run a pooled, dynamically-numbered tag
(`sandy<N>`), which forced dynamic mounting in the guest.

**Decision.** One fixed tag per channel, so the guest mounts statically.

**Consequences.** The guest image carries three static mounts; the pooled
dynamic-mount machinery is unnecessary and was removed.

**Set aside.** Pooled `sandy<N>` dynamic tags: dropped once fixed tags proved
sufficient for the one-job-per-VM model.
