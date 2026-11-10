# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1](https://github.com/kauki-labs/sandy/releases/tag/sandy-environment-v0.1.1) - 2026-11-10

### Added

- _(sandyd)_ a failed provision carries the guest console tail in its reason (refs #727) ([#731](https://github.com/kauki-labs/sandy/pull/731))
- _(sandyd)_ per-environment forge credential, minted before boot, renewed in place, revoked at stop (refs #706) ([#725](https://github.com/kauki-labs/sandy/pull/725))
- _(sandyd)_ vm-vfkit environment backend, stale-socket sweep, qemu orphan sweep call ([#587](https://github.com/kauki-labs/sandy/pull/587)) ([#672](https://github.com/kauki-labs/sandy/pull/672))
- _(environment)_ compose the qemu VM environment backend in sandyd ([#587](https://github.com/kauki-labs/sandy/pull/587)) ([#661](https://github.com/kauki-labs/sandy/pull/661))
- _(environment)_ mesh setup and teardown sequencer ([#671](https://github.com/kauki-labs/sandy/pull/671)) ([#686](https://github.com/kauki-labs/sandy/pull/686))
- _(environment)_ HTTP readiness probe for a bridged VM service ([#587](https://github.com/kauki-labs/sandy/pull/587)) ([#654](https://github.com/kauki-labs/sandy/pull/654))
- _(agent)_ stop a job gracefully before the VM is cancelled ([#670](https://github.com/kauki-labs/sandy/pull/670)) ([#673](https://github.com/kauki-labs/sandy/pull/673))
- _(environment)_ a connected client renews the idle-stop lease ([#645](https://github.com/kauki-labs/sandy/pull/645)) ([#681](https://github.com/kauki-labs/sandy/pull/681))
- _(environment)_ VM service env, boot budget, and a guard that ends with the run ([#587](https://github.com/kauki-labs/sandy/pull/587)) ([#656](https://github.com/kauki-labs/sandy/pull/656))
- _(environment)_ VM environment backend holding one agent-mode run per environment ([#587](https://github.com/kauki-labs/sandy/pull/587)) ([#650](https://github.com/kauki-labs/sandy/pull/650))
- _(sandyd)_ opt-in process backend so environments run end to end ([#587](https://github.com/kauki-labs/sandy/pull/587)) ([#636](https://github.com/kauki-labs/sandy/pull/636))
- _(sandyd)_ per-job isolation class on Submit ([#442](https://github.com/kauki-labs/sandy/pull/442))
- _(fabric)_ sandy-fabric seam contracts and contract-test harness ([#104](https://github.com/kauki-labs/sandy/pull/104)) ([#157](https://github.com/kauki-labs/sandy/pull/157))
- native boot + live acceptance gates (live_boot #26, host_matrix #27) ([#41](https://github.com/kauki-labs/sandy/pull/41))
- Phase A — the runner ([#6](https://github.com/kauki-labs/sandy/pull/6))
- rust workspace skeleton ([#1](https://github.com/kauki-labs/sandy/pull/1))

### Fixed

- _(environment)_ one secrets operation in flight per directory ([#713](https://github.com/kauki-labs/sandy/pull/713)) ([#726](https://github.com/kauki-labs/sandy/pull/726))
- _(environment)_ an unreadable stat file makes the port scan inconclusive (refs #637) ([#697](https://github.com/kauki-labs/sandy/pull/697))
- _(environment)_ a dead group member is not an unreadable table (fixes the #691 queue failure, refs #637) ([#694](https://github.com/kauki-labs/sandy/pull/694))
- _(environment)_ Ready only when the service's own process group holds the port (fixes #637) ([#691](https://github.com/kauki-labs/sandy/pull/691))

### Other

- _(environment)_ wait for the beat counter to advance instead of one tick (fixes #679) ([#702](https://github.com/kauki-labs/sandy/pull/702))
- split the instrumented coverage build out of the PR gate ([#561](https://github.com/kauki-labs/sandy/pull/561))
- public-domain readiness pass (operator/codename cleanup, escalation, mesh, licensing) ([#428](https://github.com/kauki-labs/sandy/pull/428))
- _(readme)_ document running sandyd across multiple hosts ([#422](https://github.com/kauki-labs/sandy/pull/422))
- /project-docs conformance pass for the first release ([#419](https://github.com/kauki-labs/sandy/pull/419))
- _(readme)_ trim to binary usage, drop dev setup, add the seams diagram ([#260](https://github.com/kauki-labs/sandy/pull/260))
- _(license)_ [**breaking**] relicense MIT → AGPL-3.0 + commercial dual + CLA ([#242](https://github.com/kauki-labs/sandy/pull/242))
- rename the published core lib sandy-box -> sandy-lib ([#164](https://github.com/kauki-labs/sandy/pull/164))
- _(backend)_ move the VM-only console driver out of sandy ([#147](https://github.com/kauki-labs/sandy/pull/147)) ([#154](https://github.com/kauki-labs/sandy/pull/154))
- FOSS scaffolding and automated crates.io publishing ([#89](https://github.com/kauki-labs/sandy/pull/89))
- two-level architecture spec with per-subsystem KPIs ([#86](https://github.com/kauki-labs/sandy/pull/86))
