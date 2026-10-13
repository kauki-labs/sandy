---
title: sandy overview
kind: overview
project: sandy
updated: 2026-10-14
---

# sandy overview

sandy runs one job in an ephemeral NixOS microVM and returns a locked result envelope. It
owns the hypervisor launch natively (qemu on Linux, vfkit on macOS) behind one `VmBackend`
seam, delivers inputs/outputs/secrets and a scoped forge credential over virtio-fs shares,
enforces an egress allow-list around the boot, and classifies the outcome into a status + exit
band that never disagree.

```mermaid
flowchart LR
    cli["sandy-cli (parse flags)"] --> plan["JobPlan"]
    plan --> seam{"VmBackend seam"}
    seam -->|Linux| qemu["QemuBackend"]
    seam -->|macOS| vfkit["VfkitBackend"]
    qemu --> vm["NixOS microVM"]
    vfkit --> vm
    shares["inputs / outputs / secrets + scoped forge credential"] -. virtio-fs .-> vm
    egress["egress allow-list"] -. wraps boot .-> vm
    vm --> result["locked ResultEnvelope (status + exit band)"]
```

This file is a pointer; the detailed docs already live under `docs/`:

- Orientation, the run pipeline, and the four seams →
  [`architecture/overview.md`](architecture/overview.md).
- Per-subsystem spec (decisions + KPI) → [`architecture/spec.md`](architecture/spec.md);
  live acceptance matrix → [`architecture/kpi.md`](architecture/kpi.md).
- Why it is built this way, one file per subsystem → [`decisions/`](decisions/).
- Credential-seam design and providers → [`design/`](design/), [`providers/`](providers/).

Build, test, and house rules are in the repo-root [`AGENTS.md`](../AGENTS.md).
