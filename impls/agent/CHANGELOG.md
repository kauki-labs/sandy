# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.4](https://github.com/kauki-labs/sandy/compare/sandy-agent-v0.2.3...sandy-agent-v0.2.4) - 2026-11-14

### Other

- *(api)* rename VmBackend to VirtualizationBackend ([#869](https://github.com/kauki-labs/sandy/pull/869))

## [0.2.3](https://github.com/kauki-labs/sandy/compare/sandy-agent-v0.2.2...sandy-agent-v0.2.3) - 2026-11-13

### Added

- _(cli)_ doctor refuses without a sandyd or an executor, docs for the daemon-backed verbs (refs #483) ([#861](https://github.com/kauki-labs/sandy/pull/861))
- _(cli)_ run, ls, status, wait, kill and gc are daemon-backed (refs #483) ([#860](https://github.com/kauki-labs/sandy/pull/860))

### Other

- _(vm)_ remove the guest NIC profile (refs #483) ([#864](https://github.com/kauki-labs/sandy/pull/864))
- _(cli)_ delete the direct execution path and the Journal (refs #483, #221) ([#863](https://github.com/kauki-labs/sandy/pull/863))
- _(t3)_ replace the T3 guest with a generic service guest (part 2 of 3) ([#777](https://github.com/kauki-labs/sandy/pull/777))
- _(t3)_ strip T3 names from crates/impls code (part 1 of 3) ([#766](https://github.com/kauki-labs/sandy/pull/766))

## [0.2.2](https://github.com/kauki-labs/sandy/compare/sandy-agent-v0.2.1...sandy-agent-v0.2.2) - 2026-11-10

### Added

- _(agent)_ stop a job gracefully before the VM is cancelled ([#670](https://github.com/kauki-labs/sandy/pull/670)) ([#673](https://github.com/kauki-labs/sandy/pull/673))
- _(agent)_ start the port relay for a service that declares a port ([#589](https://github.com/kauki-labs/sandy/pull/589)) ([#649](https://github.com/kauki-labs/sandy/pull/649))
- _(agent)_ probe a declared service and report readiness over the link ([#589](https://github.com/kauki-labs/sandy/pull/589)) ([#632](https://github.com/kauki-labs/sandy/pull/632))
- _(agent)_ guest port relay for the service bridge ([#590](https://github.com/kauki-labs/sandy/pull/590)) ([#620](https://github.com/kauki-labs/sandy/pull/620))

### Fixed

- _(agent)_ wait for the port relay to bind before a service can report Ready ([#657](https://github.com/kauki-labs/sandy/pull/657)) ([#663](https://github.com/kauki-labs/sandy/pull/663))
- _(vm)_ pass SANDY_HISTORY_LINES to the guest agent ([#398](https://github.com/kauki-labs/sandy/pull/398)) ([#570](https://github.com/kauki-labs/sandy/pull/570))

### Other

- _(privacy)_ scrub the Linux host's nickname to role language ([#581](https://github.com/kauki-labs/sandy/pull/581))
- split the instrumented coverage build out of the PR gate ([#561](https://github.com/kauki-labs/sandy/pull/561))
- _(agent)_ widen every real-spawn wait in this file, not just one ([#297](https://github.com/kauki-labs/sandy/pull/297)) ([#552](https://github.com/kauki-labs/sandy/pull/552))
- _(agent)_ give the sibling-channel test's startup wait its own, longer budget ([#297](https://github.com/kauki-labs/sandy/pull/297)) ([#550](https://github.com/kauki-labs/sandy/pull/550))

## [0.2.1](https://github.com/kauki-labs/sandy/compare/sandy-agent-v0.2.0...sandy-agent-v0.2.1) - 2026-10-28

### Added

- _(qemu)_ run the egress proxy per launch on a vsock port with a peer-CID check ([#468](https://github.com/kauki-labs/sandy/pull/468))
- _(receipts)_ opt-in sha256 content digests of inputs and outputs ([#469](https://github.com/kauki-labs/sandy/pull/469))
- _(egress)_ RunSpec egress policy, proxy plan variant, and band-3 EgressProxyDied ([#453](https://github.com/kauki-labs/sandy/pull/453))

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
