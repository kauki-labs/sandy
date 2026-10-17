# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1](https://github.com/kauki-labs/sandy/releases/tag/sandy-impls-local-v0.1.1) - 2026-10-17

### Added

- *(agent)* [**breaking**] sandy-agent, real OS-process isolation for the sandbox agent ([#216](https://github.com/kauki-labs/sandy/pull/216)) ([#231](https://github.com/kauki-labs/sandy/pull/231))
- *(impls-local)* bwrap filesystem confinement for the process backend ([#142](https://github.com/kauki-labs/sandy/pull/142)) ([#152](https://github.com/kauki-labs/sandy/pull/152))
- *(fabric)* sandy-fabric seam contracts and contract-test harness ([#104](https://github.com/kauki-labs/sandy/pull/104)) ([#157](https://github.com/kauki-labs/sandy/pull/157))
- native boot + live acceptance gates (live_boot #26, host_matrix #27) ([#41](https://github.com/kauki-labs/sandy/pull/41))
- Phase A — the runner ([#6](https://github.com/kauki-labs/sandy/pull/6))
- rust workspace skeleton ([#1](https://github.com/kauki-labs/sandy/pull/1))

### Fixed

- *(fsutil)* [**breaking**] one secret writer; close a credential staging leak (#174, #192, #193) ([#197](https://github.com/kauki-labs/sandy/pull/197))

### Other

- *(api)* move the agent-launch contract into sandy-api ([#238](https://github.com/kauki-labs/sandy/pull/238)) ([#239](https://github.com/kauki-labs/sandy/pull/239))
- *(sandy)* extract sandy-test-support, move the 5 fakes (R4a, refs #131) ([#155](https://github.com/kauki-labs/sandy/pull/155))
- rename the published core lib sandy-box -> sandy-lib ([#164](https://github.com/kauki-labs/sandy/pull/164))
- *(backend)* move the VM-only console driver out of sandy ([#147](https://github.com/kauki-labs/sandy/pull/147)) ([#154](https://github.com/kauki-labs/sandy/pull/154))
- *(egress)* extract the egress seam into sandy-api with a narrow EgressError ([#148](https://github.com/kauki-labs/sandy/pull/148))
- *(backend)* carve sandy-impls-local / sandy-impls-vm and feature-gate the backend hub (R1) ([#146](https://github.com/kauki-labs/sandy/pull/146))
- FOSS scaffolding and automated crates.io publishing ([#89](https://github.com/kauki-labs/sandy/pull/89))
- two-level architecture spec with per-subsystem KPIs ([#86](https://github.com/kauki-labs/sandy/pull/86))
