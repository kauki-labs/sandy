# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1](https://github.com/kauki-labs/sandy/releases/tag/sandy-impls-local-v0.1.1) - 2026-10-27

### Added

- *(sandyd)* per-job isolation class on Submit ([#442](https://github.com/kauki-labs/sandy/pull/442))
- *(sandyd)* notify a job's host-executor of attach-state transitions ([#344](https://github.com/kauki-labs/sandy/pull/344))
- *(fabric-local,sandyd)* add Resize and Archive LinkFrame variants ([#345](https://github.com/kauki-labs/sandy/pull/345))
- *(sandy-agent)* wrap the job in a detached tmux session behind a real PTY ([#342](https://github.com/kauki-labs/sandy/pull/342))
- *(ci)* scope release-plz's PR and document its CI-trigger gap ([#249](https://github.com/kauki-labs/sandy/pull/249))

### Fixed

- *(containment)* record and enforce the untrusted-is-VM-only decision ([#150](https://github.com/kauki-labs/sandy/pull/150)) ([#382](https://github.com/kauki-labs/sandy/pull/382))
- *(local)* spawn with POSIX_SPAWN_CLOEXEC_DEFAULT on Apple ([#281](https://github.com/kauki-labs/sandy/pull/281)) ([#286](https://github.com/kauki-labs/sandy/pull/286))
- *(local)* create each run's agent link and spawn under one lock ([#230](https://github.com/kauki-labs/sandy/pull/230)) ([#282](https://github.com/kauki-labs/sandy/pull/282))

### Other

- public-domain readiness pass (operator/codename cleanup, escalation, mesh, licensing) ([#428](https://github.com/kauki-labs/sandy/pull/428))
- *(readme)* document running sandyd across multiple hosts ([#422](https://github.com/kauki-labs/sandy/pull/422))
- /project-docs conformance pass for the first release ([#419](https://github.com/kauki-labs/sandy/pull/419))
- *(privacy)* rename ws01-specific identifiers to a generic placeholder ([#350](https://github.com/kauki-labs/sandy/pull/350))
- *(readme)* trim to binary usage, drop dev setup, add the seams diagram ([#260](https://github.com/kauki-labs/sandy/pull/260))
- *(license)* [**breaking**] relicense MIT → AGPL-3.0 + commercial dual + CLA ([#242](https://github.com/kauki-labs/sandy/pull/242))
