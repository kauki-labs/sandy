# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1](https://github.com/kauki-labs/sandy/releases/tag/sandy-environment-v0.1.1) - 2026-11-06

### Added

- *(environment)* a connected client renews the idle-stop lease ([#645](https://github.com/kauki-labs/sandy/pull/645)) ([#681](https://github.com/kauki-labs/sandy/pull/681))
- *(environment)* VM service env, boot budget, and a guard that ends with the run ([#587](https://github.com/kauki-labs/sandy/pull/587)) ([#656](https://github.com/kauki-labs/sandy/pull/656))
- *(environment)* VM environment backend holding one agent-mode run per environment ([#587](https://github.com/kauki-labs/sandy/pull/587)) ([#650](https://github.com/kauki-labs/sandy/pull/650))
- *(sandyd)* opt-in process backend so environments run end to end ([#587](https://github.com/kauki-labs/sandy/pull/587)) ([#636](https://github.com/kauki-labs/sandy/pull/636))
- *(sandyd)* per-job isolation class on Submit ([#442](https://github.com/kauki-labs/sandy/pull/442))
- *(fabric)* sandy-fabric seam contracts and contract-test harness ([#104](https://github.com/kauki-labs/sandy/pull/104)) ([#157](https://github.com/kauki-labs/sandy/pull/157))
- native boot + live acceptance gates (live_boot #26, host_matrix #27) ([#41](https://github.com/kauki-labs/sandy/pull/41))
- Phase A — the runner ([#6](https://github.com/kauki-labs/sandy/pull/6))
- rust workspace skeleton ([#1](https://github.com/kauki-labs/sandy/pull/1))

### Other

- split the instrumented coverage build out of the PR gate ([#561](https://github.com/kauki-labs/sandy/pull/561))
- public-domain readiness pass (operator/codename cleanup, escalation, mesh, licensing) ([#428](https://github.com/kauki-labs/sandy/pull/428))
- *(readme)* document running sandyd across multiple hosts ([#422](https://github.com/kauki-labs/sandy/pull/422))
- /project-docs conformance pass for the first release ([#419](https://github.com/kauki-labs/sandy/pull/419))
- *(readme)* trim to binary usage, drop dev setup, add the seams diagram ([#260](https://github.com/kauki-labs/sandy/pull/260))
- *(license)* [**breaking**] relicense MIT → AGPL-3.0 + commercial dual + CLA ([#242](https://github.com/kauki-labs/sandy/pull/242))
- rename the published core lib sandy-box -> sandy-lib ([#164](https://github.com/kauki-labs/sandy/pull/164))
- *(backend)* move the VM-only console driver out of sandy ([#147](https://github.com/kauki-labs/sandy/pull/147)) ([#154](https://github.com/kauki-labs/sandy/pull/154))
- FOSS scaffolding and automated crates.io publishing ([#89](https://github.com/kauki-labs/sandy/pull/89))
- two-level architecture spec with per-subsystem KPIs ([#86](https://github.com/kauki-labs/sandy/pull/86))
