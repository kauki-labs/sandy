# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1](https://github.com/kauki-labs/sandy/releases/tag/sandy-api-v0.1.1) - 2026-10-17

### Added

- *(vm)* run the vfkit job behind the guest agent over vsock ([#238](https://github.com/kauki-labs/sandy/pull/238)) ([#244](https://github.com/kauki-labs/sandy/pull/244))
- *(impls-local)* bwrap filesystem confinement for the process backend ([#142](https://github.com/kauki-labs/sandy/pull/142)) ([#152](https://github.com/kauki-labs/sandy/pull/152))
- *(sandy-api,sandy-cli)* the fake-free acceptance capstone (R4b, Closes #131) ([#172](https://github.com/kauki-labs/sandy/pull/172))
- *(fabric)* sandy-fabric seam contracts and contract-test harness ([#104](https://github.com/kauki-labs/sandy/pull/104)) ([#157](https://github.com/kauki-labs/sandy/pull/157))
- native boot + live acceptance gates (live_boot #26, host_matrix #27) ([#41](https://github.com/kauki-labs/sandy/pull/41))
- Phase A — the runner ([#6](https://github.com/kauki-labs/sandy/pull/6))
- rust workspace skeleton ([#1](https://github.com/kauki-labs/sandy/pull/1))

### Other

- *(api)* move the agent-launch contract into sandy-api ([#238](https://github.com/kauki-labs/sandy/pull/238)) ([#239](https://github.com/kauki-labs/sandy/pull/239))
- rename the published core lib sandy-box -> sandy-lib ([#164](https://github.com/kauki-labs/sandy/pull/164))
- *(backend)* move the VM-only console driver out of sandy ([#147](https://github.com/kauki-labs/sandy/pull/147)) ([#154](https://github.com/kauki-labs/sandy/pull/154))
- *(egress)* extract the egress seam into sandy-api with a narrow EgressError ([#148](https://github.com/kauki-labs/sandy/pull/148))
- *(backend)* carve sandy-impls-local / sandy-impls-vm and feature-gate the backend hub (R1) ([#146](https://github.com/kauki-labs/sandy/pull/146))
- *(sandy)* extract sandy-api contract crate (R0, mechanical extraction) ([#145](https://github.com/kauki-labs/sandy/pull/145))
- FOSS scaffolding and automated crates.io publishing ([#89](https://github.com/kauki-labs/sandy/pull/89))
- two-level architecture spec with per-subsystem KPIs ([#86](https://github.com/kauki-labs/sandy/pull/86))
