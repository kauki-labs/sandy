# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1](https://github.com/kauki-labs/sandy/releases/tag/sandy-fabric-local-v0.1.1) - 2026-10-17

### Added

- *(agent)* [**breaking**] sandy-agent, real OS-process isolation for the sandbox agent ([#216](https://github.com/kauki-labs/sandy/pull/216)) ([#231](https://github.com/kauki-labs/sandy/pull/231))
- *(fabric-local)* the escalation channel's reading side (#113, #205 B8) ([#228](https://github.com/kauki-labs/sandy/pull/228))
- *(fabric)* end an already-open subscribe() stream on leave() ([#184](https://github.com/kauki-labs/sandy/pull/184)) ([#208](https://github.com/kauki-labs/sandy/pull/208))
- *(fabric-local)* channel roles over Channel ([#113](https://github.com/kauki-labs/sandy/pull/113)) ([#202](https://github.com/kauki-labs/sandy/pull/202))
- *(fabric-local)* the sandbox agent gateway + RawConsole seam ([#109](https://github.com/kauki-labs/sandy/pull/109)) ([#203](https://github.com/kauki-labs/sandy/pull/203))
- *(fabric-local)* VmBackendExecutor adapter over the Executor seam ([#108](https://github.com/kauki-labs/sandy/pull/108)) ([#168](https://github.com/kauki-labs/sandy/pull/168))
- *(fabric-local)* local-first telemetry log and LocalFirst sink ([#114](https://github.com/kauki-labs/sandy/pull/114)) ([#182](https://github.com/kauki-labs/sandy/pull/182))
- *(fabric)* the Channel abstraction — membership, caps, delivery ([#106](https://github.com/kauki-labs/sandy/pull/106)) ([#170](https://github.com/kauki-labs/sandy/pull/170))
- *(fabric-local)* agent-local minter, secret staging, cap handoff encoding ([#111](https://github.com/kauki-labs/sandy/pull/111)) ([#176](https://github.com/kauki-labs/sandy/pull/176))
- *(fabric-local)* placement impls and place policy ([#112](https://github.com/kauki-labs/sandy/pull/112)) ([#167](https://github.com/kauki-labs/sandy/pull/167))
- *(fabric)* HMAC-SHA256 local attenuable CapAuthority ([#110](https://github.com/kauki-labs/sandy/pull/110)) ([#178](https://github.com/kauki-labs/sandy/pull/178))
- *(fabric-local)* InMem, the trivial local ChannelBackend ([#107](https://github.com/kauki-labs/sandy/pull/107)) ([#169](https://github.com/kauki-labs/sandy/pull/169))
- *(fabric)* sandy-fabric seam contracts and contract-test harness ([#104](https://github.com/kauki-labs/sandy/pull/104)) ([#157](https://github.com/kauki-labs/sandy/pull/157))
- native boot + live acceptance gates (live_boot #26, host_matrix #27) ([#41](https://github.com/kauki-labs/sandy/pull/41))
- Phase A — the runner ([#6](https://github.com/kauki-labs/sandy/pull/6))
- rust workspace skeleton ([#1](https://github.com/kauki-labs/sandy/pull/1))

### Fixed

- *(fsutil)* [**breaking**] one secret writer; close a credential staging leak (#174, #192, #193) ([#197](https://github.com/kauki-labs/sandy/pull/197))

### Other

- rename the published core lib sandy-box -> sandy-lib ([#164](https://github.com/kauki-labs/sandy/pull/164))
- *(backend)* move the VM-only console driver out of sandy ([#147](https://github.com/kauki-labs/sandy/pull/147)) ([#154](https://github.com/kauki-labs/sandy/pull/154))
- FOSS scaffolding and automated crates.io publishing ([#89](https://github.com/kauki-labs/sandy/pull/89))
- two-level architecture spec with per-subsystem KPIs ([#86](https://github.com/kauki-labs/sandy/pull/86))
