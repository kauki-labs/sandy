---
title: "Decisions: guest shares (GuestShareTransport)"
status: accepted
project: sandy
updated: 2026-10-15
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
variant was considered (§7) and withdrawn (#82).

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
bytes came from a copy (today), a direct share (§7, withdrawn), or an object store
later. The manifest's `source`/`hash` columns are the forward slot for those. Proven by the
live test `an_input_appears_at_an_absolute_guest_path`.

## 7. No-copy direct share is a local-only, placement-aware optimization

**Status:** withdrawn (2026-10-15; #82 closed not-planned).

**Withdrawn.** The spec check found direct-share incompatible with the current guest model, not
merely unscheduled. It would reverse two accepted decisions: §4 (inputs are copied by default)
and §5 (fixed static tags, which deliberately removed per-run/per-input dynamic mounting). A
per-input read-only `ShareSpec`/virtio-fs tag reintroduces exactly the dynamic mounting §5
retired, and flips §4's copy default, for a local-only win that does not generalize to a fleet.
The design below is kept as the record of what was considered.

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
there, so the no-copy share cannot exist. The no-copy local variant is set aside too:
re-propose only if the guest model stops depending on fixed static tags (§5 revisited), since
that dependency is what makes direct-share's per-input dynamic tags incompatible today.

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

**Consequences.** Keeps the input model focused (copy + manifest; direct-share
withdrawn, §7) while naming where it grows. It belongs with the agent-model epic
(#36/#65), not here.

## 11. The share seam generalizes to a `Presentation`; the process profile presents shares as `SANDY_*_DIR` env

**Status:** accepted. **Upholds:** INV-1.

**Context.** The fabric (#131 / #103) adds a non-VM executor — a process backend
with no virtio-fs. The `GuestShareTransport` seam was VM-shaped (launch daemons +
hypervisor argv), so a process profile could not present shares over it.

**Decision.** Generalize the seam, preserving the pure/IO split of decision #1
(the argv mapping stays a pure, tier-1-testable function): `plan(&[ShareSpec], mem)
-> Presentation` (PURE) + `activate(&[ShareSpec]) -> Result<Vec<Child>>` (IO).
`Presentation` is an enum — `Vm { args }` (the hypervisor argv) or `LocalDir { root,
placements }` — so the shared contract test covers all three transports uniformly.
`VirtiofsdTransport`/`VirtioFsTransport` relocate their argv/daemon bodies into
`plan`/`activate` unchanged. The process profile's `LocalDirTransport` maps each
staged `ShareSpec` to a placement and the backend exposes it to the job as
`SANDY_<TAG>_DIR` (e.g. `SANDY_INPUTS_DIR`); read-only shares (inputs, secrets) are
enforced **cooperatively** by `chmod a-w` on the staged files only (the dir stays
writable so teardown's `remove_dir_all` can wipe). Staging (`plan_shares`), output
collection, and the per-run wipe are shared with the VM backends.

**Consequences.** One seam, three impls, one contract. INV-1 holds: `SANDY_*_DIR`
carries the dir **path**, never the secret bytes (secrets stay 0600 files in the
secret dir, the env-pointer-not-value model of the Minter decision). The access
contract **diverges** by profile: a VM job reads fixed `/run/sandy/...` mount paths;
a process job reads `SANDY_*_DIR` env — a weak-isolation difference (the process
backend is not the real boundary; the VM is). The cooperative file-RO is defeatable
by a same-user job (it mirrors the vfkit RO asymmetry, §2), and a process that
escapes its group can leave a host orphan.

**Set aside (do not re-propose without new information).** Namespace-faithful
`/run/sandy/...` paths for the process profile (a mount-namespace bind-mount): it is
Linux-only, needs privilege/namespace machinery, and is deferred to **#135** (the
same cgroup/jail containment gate as full descendant reaping — the process backend
must not run real untrusted jobs until #135 lands). Folding host-side RO into a hard
boundary is likewise a #135 concern, not the cooperative MVP.

## 12. Host staging base validated before use (CWE-732)

**Status:** accepted. **Upholds:** INV-1.

**Context.** All three backends derived their per-run staging dirs from
`temp_dir().join("sandy")` with no check on it: a local attacker who pre-creates
a world-writable `/tmp/sandy`, or symlinks it, can redirect staged secrets/inputs
to a path they control (#138).

**Decision.** `ensure_sandy_staging_base` gates all three backends. It creates
the base `0700`, exclusive; if the base already exists it opens it by name with
`O_NOFOLLOW` (rejecting a symlink rather than following it) and fstats the
opened fd, rejecting anything not owned by the current uid or carrying a
group/world write bit. A bad base is **not repaired** — it fails closed with a
named error.

**Consequences.** Once the base passes validation it is `0700` and owned by the
current uid, so no other uid can create or replace entries under it afterward;
the per-run child dirs the backends join onto it (still plain path joins, not
their own `openat` traversal) inherit that guarantee. The base's _parent_
(`temp_dir()`) is also checked (#141): a world-writable parent without the sticky
bit is rejected via an `fstat` on the same `parent_fd`, since there an attacker
controlling the parent could swap the validated base out from under us. A sticky
`/tmp` (`01777`) or a per-user `$TMPDIR` (`0700`) passes. Uses `rustix` for the
`openat`/`mkdirat`/`fstat`/`getuid` calls, staying inside this crate's
`unsafe_code = "forbid"` lint.

**Set aside.** Repairing a bad base (chmod/chown back to safe): rejected — a
base an attacker got to first is not trustworthy even after a cosmetic fix, and
silent repair is exactly the kind of downgrade CWE-732 flags. Recursing further up
the tree than the immediate parent (grandparent and above): still out of scope —
the immediate-parent sticky check (#141, above) closes the attacker-writable-`TMPDIR`
gap, and walking the whole ancestry would recurse indefinitely for no gain on
sandy's supported configurations.
