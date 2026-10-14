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
bytes nor plants a host-escaping link. Copying inputs is fine for typical sizes.
Arbitrary guest paths landed on the retained copy (§6); a no-copy direct-share
variant is the local optimization in §7 (#82).

## 5. Fixed tags, not pooled

**Status:** accepted.

**Context.** An earlier model handed each run a pooled, dynamically-numbered tag
(`sandy<N>`), which forced dynamic mounting in the guest.

**Decision.** One fixed tag per channel, so the guest mounts statically.

**Consequences.** The guest image carries three static mounts; the pooled
dynamic-mount machinery is unnecessary and was removed.

**Set aside.** Pooled `sandy<N>` dynamic tags: dropped once fixed tags proved
sufficient for the one-job-per-VM model.

## 6. Arbitrary guest paths via a manifest

**Status:** accepted.

**Context.** A job often expects an input at a specific path (e.g. `/workspace`),
not only under `/run/sandy/inputs/<name>`. Forcing the fixed mount point makes the
caller rewrite the job or symlink by hand.

**Decision.** `--input HOST:/guest/path` surfaces an input at an absolute guest
path; `HOST:NAME` is unchanged. The host writes a tab-separated manifest
(`.sandy-inputs`: `name / guest_path / source / hash` per input) into the inputs
share, and a guest boot step symlinks each `guest_path` to the staged entry before
READY. The input is staged under an internal `in<index>` name.

**Consequences.** Placement is decoupled from the source: identical whether the
bytes came from a copy (today), a direct share (§7), or an object store later. The
manifest's `source`/`hash` columns are the forward slot for those. Proven by the
live test `an_input_appears_at_an_absolute_guest_path`.

## 7. No-copy direct share is a local-only, placement-aware optimization

**Status:** accepted (design); implementation deferred (#82, separate session).

**Context.** Copying a multi-GB input into staging is wasteful when the input
already lives on the machine that runs the job. A no-copy virtio-fs share of the
host dir avoids the copy, but only exists when the job runs on that host.

**Decision.** Direct-share is taken **only** when the job's target host is the
machine holding the input (placement-aware). Mechanism: the input gets its own
read-only `ShareSpec`/virtio-fs tag instead of a staging copy, and the manifest
records `source = "direct"`. The staging seam carries placement so it chooses
direct-share vs copy; when the orchestrator (#36) schedules elsewhere, it falls
back to copy/transport. In today's single-host world the target is always local,
so direct-share always applies.

**Consequences.** The "no-copy" win is local; it does not generalize to a fleet
(the input is not on the chosen host). A direct-shared read-only input stays RO at
the host boundary, same as a copied input (§2). Handoff for the implementer:
extend `source` to `direct`, add a per-input RO `ShareSpec`, gate on
`target == current machine`, keep the copy path as the fleet/remote fallback.
Acceptance: a large local input mounts without a staging copy and is read-only
in-guest; a non-local target falls back to copy.

**Set aside (do not re-propose without new information).** Unconditional (global)
direct-share: impossible once an orchestrator picks the host — the input is not
there, so the no-copy share cannot exist.

## 8. Content-addressed inputs (hashing)

**Status:** proposed.

**Context.** A fleet orchestrator (#36) wants to dedupe inputs and schedule a job
onto an agent that already has the input cached (cache-affinity), and the result
envelope wants input integrity/provenance (a placeholder today).

**Decision.** Inputs carry a content hash — the manifest's reserved `hash` column.
Empty today; the direction is to populate it so an input is addressed by content,
enabling dedup, a warm-cache scheduling hint, and integrity in the envelope.

**Consequences.** Hashing is the key that makes orchestrator-guided placement and
provenance tractable. Not wired yet; the slot exists so it lands without a manifest
format change.

**Set aside.** Mutable path/URL addressing: loses safe cache reuse and integrity.

## 9. Object stores are reached via tools, not a mount

**Status:** accepted.

**Context.** A native `--mount s3://` would make sandy an object-store client,
pushing cloud credentials and network into the guest and widening INV-1's surface.
Most of the time a job, or another sandbox, owns what it transports.

**Decision.** sandy does not mount object stores. A job reaches S3/object storage
from inside the guest via its own tools (`aws`, `rclone`, …) with a scoped
credential (the credential seam) and an egress allow. This reframes #67 from
"reintroduce `--mount` as an S3 mount" to this stance.

**Consequences.** The guest's object-store access is an explicit credential + egress
grant, auditable like the forge token, not a hidden sandy mount. #67 should be
closed or repurposed to record this.

**Set aside.** Native `--mount s3://`: rejected — credential + network surface in
the guest for no gain over a scoped tool grant.

## 10. Sandbox-to-sandbox data pipeline (direction)

**Status:** proposed.

**Context.** The common case is not "sandy owns the input" but "another sandbox
produced it": a job's output feeds another job's input. A content-addressed handoff
between sandboxes is the real shape behind the object-store question.

**Decision.** Capture this as a **future direction**, not a committed design: a
pipeline where sandbox outputs (content-hashed, §8) become other sandboxes' inputs,
placement-optimized by the orchestrator (#36) and the agent daemon (#65). Not built
in the input seam.

**Consequences.** Keeps the input model focused (copy + manifest + local
direct-share) while naming where it grows. It belongs with the agent-model epic
(#36/#65), not here.
