# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1](https://github.com/kauki-labs/sandy/releases/tag/sandy-impls-vm-v0.1.1) - 2026-10-27

### Added

- *(sandy-cli)* prove the Executor seam against the real qemu/vfkit backend ([#443](https://github.com/kauki-labs/sandy/pull/443))
- *(sandyd)* per-job isolation class on Submit ([#442](https://github.com/kauki-labs/sandy/pull/442))
- *(sandyd)* notify a job's host-executor of attach-state transitions ([#344](https://github.com/kauki-labs/sandy/pull/344))
- *(ci)* scope release-plz's PR and document its CI-trigger gap ([#249](https://github.com/kauki-labs/sandy/pull/249))

### Fixed

- *(sandy-impls-vm)* honor RunControl cancellation and deadline in the console driver ([#366](https://github.com/kauki-labs/sandy/pull/366))
- *(sandy)* bypass PATH for qemu/nix/virtiofsd, retry Submit until ws01 registers ([#336](https://github.com/kauki-labs/sandy/pull/336))

### Other

- *(sandy-impls-vm)* PhaseDeadline replaces run_console's loop-local deadline state ([#433](https://github.com/kauki-labs/sandy/pull/433))
- public-domain readiness pass (operator/codename cleanup, escalation, mesh, licensing) ([#428](https://github.com/kauki-labs/sandy/pull/428))
- *(readme)* document running sandyd across multiple hosts ([#422](https://github.com/kauki-labs/sandy/pull/422))
- /project-docs conformance pass for the first release ([#419](https://github.com/kauki-labs/sandy/pull/419))
- *(privacy)* rename ws01-specific identifiers to a generic placeholder ([#350](https://github.com/kauki-labs/sandy/pull/350))
- *(readme)* trim to binary usage, drop dev setup, add the seams diagram ([#260](https://github.com/kauki-labs/sandy/pull/260))
- *(license)* [**breaking**] relicense MIT → AGPL-3.0 + commercial dual + CLA ([#242](https://github.com/kauki-labs/sandy/pull/242))
