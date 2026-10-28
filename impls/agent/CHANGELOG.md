# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.1](https://github.com/kauki-labs/sandy/compare/sandy-agent-v0.2.0...sandy-agent-v0.2.1) - 2026-10-28

### Added

- *(qemu)* run the egress proxy per launch on a vsock port with a peer-CID check ([#468](https://github.com/kauki-labs/sandy/pull/468))
- *(receipts)* opt-in sha256 content digests of inputs and outputs ([#469](https://github.com/kauki-labs/sandy/pull/469))
- *(egress)* RunSpec egress policy, proxy plan variant, and band-3 EgressProxyDied ([#453](https://github.com/kauki-labs/sandy/pull/453))

## [0.2.0](https://github.com/kauki-labs/sandy/compare/sandy-agent-v0.1.1...sandy-agent-v0.2.0) - 2026-10-27

### Added

- _(sandyd)_ per-job isolation class on Submit ([#442](https://github.com/kauki-labs/sandy/pull/442))
- _(sandy-agent,sandyd)_ close #340's remaining scope (items 3, 4) ([#378](https://github.com/kauki-labs/sandy/pull/378))
- _(sandyd)_ notify a job's host-executor of attach-state transitions ([#344](https://github.com/kauki-labs/sandy/pull/344))
- _(fabric-local,sandyd)_ add Resize and Archive LinkFrame variants ([#345](https://github.com/kauki-labs/sandy/pull/345))
- _(sandy-agent)_ wrap the job in a detached tmux session behind a real PTY ([#342](https://github.com/kauki-labs/sandy/pull/342))
- _(ci)_ scope release-plz's PR and document its CI-trigger gap ([#249](https://github.com/kauki-labs/sandy/pull/249))
- _(agent)_ the job's peer socket and sandy-agent peer send|recv ([#238](https://github.com/kauki-labs/sandy/pull/238)) ([#247](https://github.com/kauki-labs/sandy/pull/247))

### Fixed

- _(local)_ spawn with POSIX_SPAWN_CLOEXEC_DEFAULT on Apple ([#281](https://github.com/kauki-labs/sandy/pull/281)) ([#286](https://github.com/kauki-labs/sandy/pull/286))
- _(local)_ create each run's agent link and spawn under one lock ([#230](https://github.com/kauki-labs/sandy/pull/230)) ([#282](https://github.com/kauki-labs/sandy/pull/282))
- _(agent)_ report refused peer posts and stop claiming delivery ([#256](https://github.com/kauki-labs/sandy/pull/256)) ([#262](https://github.com/kauki-labs/sandy/pull/262))

### Other

- public-domain readiness pass (operator/codename cleanup, escalation, mesh, licensing) ([#428](https://github.com/kauki-labs/sandy/pull/428))
- _(readme)_ document running sandyd across multiple hosts ([#422](https://github.com/kauki-labs/sandy/pull/422))
- /project-docs conformance pass for the first release ([#419](https://github.com/kauki-labs/sandy/pull/419))
- _(readme)_ trim to binary usage, drop dev setup, add the seams diagram ([#260](https://github.com/kauki-labs/sandy/pull/260))
- _(license)_ [**breaking**] relicense MIT → AGPL-3.0 + commercial dual + CLA ([#242](https://github.com/kauki-labs/sandy/pull/242))
