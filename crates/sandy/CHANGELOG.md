# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1](https://github.com/kauki-labs/sandy/releases/tag/sandy-lib-v0.1.1) - 2026-10-27

### Added

- *(sandyd)* per-job isolation class on Submit ([#442](https://github.com/kauki-labs/sandy/pull/442))
- *(result)* define and implement envelope receipts v1 ([#361](https://github.com/kauki-labs/sandy/pull/361)) ([#414](https://github.com/kauki-labs/sandy/pull/414))
- *(sandyd)* notify a job's host-executor of attach-state transitions ([#344](https://github.com/kauki-labs/sandy/pull/344))
- *(ci)* scope release-plz's PR and document its CI-trigger gap ([#249](https://github.com/kauki-labs/sandy/pull/249))

### Fixed

- *(deps)* route App-JWT key construction through octocrab's own jsonwebtoken ([#431](https://github.com/kauki-labs/sandy/pull/431))
- *(egress)* refuse hostname allow-list entries on the nftables path ([#418](https://github.com/kauki-labs/sandy/pull/418))
- *(egress)* close the guest's path to the host (input chain) ([#416](https://github.com/kauki-labs/sandy/pull/416))
- *(sandy-fsutil,sandy,sandy-cli)* bind credential and guest-share staging to a validated fingerprint ([#323](https://github.com/kauki-labs/sandy/pull/323)) ([#410](https://github.com/kauki-labs/sandy/pull/410))
- *(doctor)* report a group/world-writable trust-roots dir ([#411](https://github.com/kauki-labs/sandy/pull/411))
- *(containment)* record and enforce the untrusted-is-VM-only decision ([#150](https://github.com/kauki-labs/sandy/pull/150)) ([#382](https://github.com/kauki-labs/sandy/pull/382))
- *(sandy-cli)* gc sweeps stale cred-*/verify-* staging dirs ([#352](https://github.com/kauki-labs/sandy/pull/352))
- *(sandy)* don't revoke a refreshed token when only the dir sync fails ([#353](https://github.com/kauki-labs/sandy/pull/353))
- *(sandy)* construct nix's own subprocess PATH for its internal git fetcher ([#338](https://github.com/kauki-labs/sandy/pull/338))
- *(sandy)* bypass PATH for qemu/nix/virtiofsd, retry Submit until ws01 registers ([#336](https://github.com/kauki-labs/sandy/pull/336))
- *(sandy-cli)* redact secrets from console tail, surface revoke failures as warnings ([#320](https://github.com/kauki-labs/sandy/pull/320))

### Other

- public-domain readiness pass (operator/codename cleanup, escalation, mesh, licensing) ([#428](https://github.com/kauki-labs/sandy/pull/428))
- *(readme)* document running sandyd across multiple hosts ([#422](https://github.com/kauki-labs/sandy/pull/422))
- /project-docs conformance pass for the first release ([#419](https://github.com/kauki-labs/sandy/pull/419))
- *(privacy)* rename ws01-specific identifiers to a generic placeholder ([#350](https://github.com/kauki-labs/sandy/pull/350))
- *(deps)* Bump the cargo-major group with 2 updates ([#307](https://github.com/kauki-labs/sandy/pull/307))
- *(readme)* trim to binary usage, drop dev setup, add the seams diagram ([#260](https://github.com/kauki-labs/sandy/pull/260))
- *(license)* [**breaking**] relicense MIT → AGPL-3.0 + commercial dual + CLA ([#242](https://github.com/kauki-labs/sandy/pull/242))
