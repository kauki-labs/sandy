---
title: "Decisions: guest shares (GuestShareTransport)"
status: accepted
project: sandy
updated: 2026-10-14
---

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

## 2. Read-only shares, enforced per platform

**Status:** accepted. **Upholds:** INV-1.

**Context.** An input or secret share marked RO should stay unwritable to the
guest, ideally even against a guest-root `mount -o remount,rw`.

**Decision.** On qemu, `--readonly` is passed to `virtiofsd`, so the host dir is
unwritable below the guest at the host boundary. On vfkit there is no host-side
option: its `virtio-fs` device takes only `sharedDir` and `mountTag` (verified
against vfkit v0.6.3), so RO is enforced only by the guest's `ro` mount, which a
guest-root remount can defeat. A write to a read-only input fails `EROFS` on both
in the cooperative case.

**Consequences.** RO enforcement is asymmetric: host-boundary on qemu,
guest-cooperative on vfkit. This is accepted rather than closed, because each share
is a single per-run, sandy-owned dir wiped at teardown — a guest that remounts rw
can corrupt only its own run's staging, never escape the share (virtio-fs confines
to `sharedDir`) or reach another run, and the VM is the trust boundary. K5
(`live_inputs.rs`) proves host-boundary RO on qemu and guest-mount RO on vfkit.

**Set aside (do not re-propose without new information).** Host-side RO on vfkit:
unavailable in the vfkit CLI as of v0.6.3 (its virtio-fs device has no read-only
option, though other vfkit devices do). Revisit if vfkit adds one.

## 3. virtiofsd runs `--sandbox=none`

**Status:** accepted.

**Context.** `virtiofsd` offers `--sandbox=namespace` (the default) and
`--sandbox=chroot` to confine the daemon itself, but both need privileges
(user-namespace setup or `CAP_SYS_CHROOT`) that sandy's unprivileged launch does
not hold.

**Decision.** The qemu transport launches each `virtiofsd` with `--sandbox=none`,
so the daemon has no namespace/chroot confinement of its own.

**Consequences.** The daemon's own sandbox is not a containment layer; the VM
boundary plus the fact that each daemon serves only one per-run, sandy-owned dir
(wiped at teardown) bound the blast radius. Dropping `--sandbox=none` for a
privileged mode would make the unprivileged launch fail, so it stays.

**Set aside.** A privileged `namespace`/`chroot` sandbox: rejected — it would
require sandy to run virtiofsd with elevated privileges, a larger attack surface
than the confinement it buys given the VM boundary.

## 4. Inputs copied, outputs collected

**Status:** accepted.

**Context.** A job needs its inputs present and its chosen outputs back on the
host, without a share handing the guest a path to escape through.

**Decision.** Inputs are copied under their name into the fixed-tag inputs share.
Outputs are a writable share collected to the host `DEST` at teardown and listed
in `envelope.outputs`. Collection **skips symlinks** and caps bytes/entries.

**Consequences.** A job dropping `out/x → /etc/shadow` neither leaks the target's
bytes nor plants a host-escaping link. Copying inputs is fine for typical sizes;
a no-copy / arbitrary-path variant is deferred (#82).

## 5. Fixed tags, not pooled

**Status:** accepted.

**Context.** An earlier model handed each run a pooled, dynamically-numbered tag
(`sandy<N>`), which forced dynamic mounting in the guest.

**Decision.** One fixed tag per channel, so the guest mounts statically.

**Consequences.** The guest image carries three static mounts; the pooled
dynamic-mount machinery is unnecessary and was removed.

**Set aside.** Pooled `sandy<N>` dynamic tags: dropped once fixed tags proved
sufficient for the one-job-per-VM model.
