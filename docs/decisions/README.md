---
title: sandy decision records
kind: decisions-index
project: sandy
updated: 2026-10-15
---

# Decision records

Why sandy is built the way it is, one file per subsystem category. Each record
is the full version of a decision the detailed spec states tersely inline:
context, the decision, its consequences, the alternative set aside (so it is not
re-proposed without new information), and the invariant it turns on.

For the terse per-subsystem view read
[`../architecture/spec.md`](../architecture/spec.md); for the pipeline and seams,
[`../architecture/overview.md`](../architecture/overview.md); for the live
acceptance matrix, [`../architecture/kpi.md`](../architecture/kpi.md).

| Category                                          | Covers                                     |
| ------------------------------------------------- | ------------------------------------------ |
| [run-plane](run-plane.md)                         | native hypervisor launch, console protocol |
| [process-containment](process-containment.md)     | non-VM executor cgroup reaping + the gate  |
| [guest-shares](guest-shares.md)                   | inputs/outputs/secrets as virtio-fs        |
| [secret-channel](secret-channel.md)               | `$NAME` delivery off argv/env/store        |
| [credential-seam](credential-seam.md)             | mint → stage → refresh → revoke            |
| [egress](egress.md)                               | guest-scoped allow-list around the boot    |
| [result-classification](result-classification.md) | locked envelope, exit bands, rendering     |
| [journal](journal.md)                             | durable records, reconcile                 |
| [agent-fabric](agent-fabric.md)                   | fabric seam contracts + test harness       |

Invariants referenced across these records: **INV-1** secrets never reach
argv/env/the store; **INV-3** liveness only through `VmBackend::boxes` + the job
flock; **INV-6** a `Running` record is written before boot; **INV-7** fail-closed;
**INV-11** `status` ⇔ `retryable` ⇔ exit band never disagree; **INV-S9** a live
scenario is never counted green from a fake.
