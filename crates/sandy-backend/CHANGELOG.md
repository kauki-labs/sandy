# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1](https://github.com/kauki-labs/sandy/releases/tag/sandy-backend-v0.1.1) - 2026-10-16

### Added

- *(fabric)* sandy-fabric seam contracts and contract-test harness ([#104](https://github.com/kauki-labs/sandy/pull/104)) ([#157](https://github.com/kauki-labs/sandy/pull/157))
- *(backend)* Containment seam + cgroup reaping for the process backend ([#135](https://github.com/kauki-labs/sandy/pull/135)) ([#143](https://github.com/kauki-labs/sandy/pull/143))
- *(backend)* local-dir shares + generalized GuestShareTransport (T4, #131) ([#136](https://github.com/kauki-labs/sandy/pull/136))
- *(backend)* ProcessBackend — the all-local process executor (T3, #131) ([#134](https://github.com/kauki-labs/sandy/pull/134))
- *(cli)* --input HOST:/guest/path surfaces an input at an absolute path ([#99](https://github.com/kauki-labs/sandy/pull/99))
- *(run)* writable outputs (catch-all + named) collected from the guest ([#34](https://github.com/kauki-labs/sandy/pull/34)) ([#76](https://github.com/kauki-labs/sandy/pull/76))
- *(run)* read-only inputs staged into the guest ([#34](https://github.com/kauki-labs/sandy/pull/34)) ([#74](https://github.com/kauki-labs/sandy/pull/74))
- *(cred)* drive mid-run credential refresh into the live guest share (#49, part 2) ([#71](https://github.com/kauki-labs/sandy/pull/71))
- *(cred)* guest-side secret consumption — $NAME in the job ([#50](https://github.com/kauki-labs/sandy/pull/50)) ([#66](https://github.com/kauki-labs/sandy/pull/66))
- *(run)* capture the guest console into the result envelope ([#64](https://github.com/kauki-labs/sandy/pull/64))
- *(egress)* guest-scoped forward nftables + phase_d live egress gate ([#47](https://github.com/kauki-labs/sandy/pull/47))
- native boot + live acceptance gates (live_boot #26, host_matrix #27) ([#41](https://github.com/kauki-labs/sandy/pull/41))
- native VmBackend implementations — VfkitBackend + QemuBackend (#32 #35) ([#39](https://github.com/kauki-labs/sandy/pull/39))
- Phase A — the runner ([#6](https://github.com/kauki-labs/sandy/pull/6))
- rust workspace skeleton ([#1](https://github.com/kauki-labs/sandy/pull/1))

### Fixed

- *(backend)* validate the host staging base before staging (CWE-732, #138) ([#140](https://github.com/kauki-labs/sandy/pull/140))
- *(backend)* correct overclaiming share/sandbox docs (adversarial review) ([#93](https://github.com/kauki-labs/sandy/pull/93))
- *(qemu)* serve guest shares as virtiofs, not 9p ([#79](https://github.com/kauki-labs/sandy/pull/79))
- *(qemu)* drain qemu stderr so a chatty boot cannot deadlock ([#77](https://github.com/kauki-labs/sandy/pull/77))

### Other

- *(sandy)* extract sandy-test-support, move the 5 fakes (R4a, refs #131) ([#155](https://github.com/kauki-labs/sandy/pull/155))
- rename the published core lib sandy-box -> sandy-lib ([#164](https://github.com/kauki-labs/sandy/pull/164))
- *(backend)* move the VM-only console driver out of sandy ([#147](https://github.com/kauki-labs/sandy/pull/147)) ([#154](https://github.com/kauki-labs/sandy/pull/154))
- *(backend)* carve sandy-impls-local / sandy-impls-vm and feature-gate the backend hub (R1) ([#146](https://github.com/kauki-labs/sandy/pull/146))
- *(sandy)* extract sandy-api contract crate (R0, mechanical extraction) ([#145](https://github.com/kauki-labs/sandy/pull/145))
- *(backend)* extract the share-staging policy into plan_shares ([#94](https://github.com/kauki-labs/sandy/pull/94))
- FOSS scaffolding and automated crates.io publishing ([#89](https://github.com/kauki-labs/sandy/pull/89))
- two-level architecture spec with per-subsystem KPIs ([#86](https://github.com/kauki-labs/sandy/pull/86))
- *(backend)* extract a GuestShareTransport trait (qemu virtiofsd + vfkit virtio-fs) ([#80](https://github.com/kauki-labs/sandy/pull/80))
- *(shares)* mark the qemu assertions for the virtiofs transport swap ([#78](https://github.com/kauki-labs/sandy/pull/78))
- *(run)* remove the obsolete --mount bind-mount path ([#68](https://github.com/kauki-labs/sandy/pull/68))
