# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1](https://github.com/kauki-labs/sandy/releases/tag/sandy-fabric-local-v0.1.1) - 2026-10-27

### Added

- _(sandyd)_ per-job isolation class on Submit ([#442](https://github.com/kauki-labs/sandy/pull/442))
- _(sandy-fabric)_ resolve Control and Escalate envelope contracts ([#439](https://github.com/kauki-labs/sandy/pull/439))
- _(sandyd)_ notify a job's host-executor of attach-state transitions ([#344](https://github.com/kauki-labs/sandy/pull/344))
- _(fabric-local,sandyd)_ add Resize and Archive LinkFrame variants ([#345](https://github.com/kauki-labs/sandy/pull/345))
- _(sandyd,sandy-cli)_ interactive attach over a new data-plane socket ([#330](https://github.com/kauki-labs/sandy/pull/330))
- _(sandy-host-client)_ the main loop (#263, #269, #288) ([#294](https://github.com/kauki-labs/sandy/pull/294))
- _(fabric-local)_ relay_agent_link, the OnLink <-> dial_and_forward bridge ([#274](https://github.com/kauki-labs/sandy/pull/274))
- _(sandyd)_ C-at-Submit — bearer submitter_caps, bound via derive_job_caps ([#273](https://github.com/kauki-labs/sandy/pull/273))
- _(fabric-local)_ dial_and_forward, the executor-host entry point ([#159](https://github.com/kauki-labs/sandy/pull/159)) ([#265](https://github.com/kauki-labs/sandy/pull/265))
- _(ci)_ scope release-plz's PR and document its CI-trigger gap ([#249](https://github.com/kauki-labs/sandy/pull/249))

### Fixed

- _(sandyd)_ keepalive on the agent-link path (#289 item 1 follow-up) ([#445](https://github.com/kauki-labs/sandy/pull/445))
- _(sandy-fabric-local)_ validate the telemetry log's parent dir ([#412](https://github.com/kauki-labs/sandy/pull/412))
- _(sandy)_ don't revoke a refreshed token when only the dir sync fails ([#353](https://github.com/kauki-labs/sandy/pull/353))
- _(fabric-local)_ restrict Archive to ARCHIVE_TRANSCRIPT, ignore duplicates ([#349](https://github.com/kauki-labs/sandy/pull/349))
- _(sandyd)_ six audit hardening findings + privatize Cap fields ([#319](https://github.com/kauki-labs/sandy/pull/319))
- _(fabric-local)_ CursorStream deregisters its own waker on drop ([#225](https://github.com/kauki-labs/sandy/pull/225)) ([#254](https://github.com/kauki-labs/sandy/pull/254))
- _(fabric-local)_ keep reading the agent link after the job closes stdout ([#261](https://github.com/kauki-labs/sandy/pull/261)) ([#267](https://github.com/kauki-labs/sandy/pull/267))
- _(agent)_ report refused peer posts and stop claiming delivery ([#256](https://github.com/kauki-labs/sandy/pull/256)) ([#262](https://github.com/kauki-labs/sandy/pull/262))
- _(fabric-local)_ a refused peer post no longer ends the agent link ([#238](https://github.com/kauki-labs/sandy/pull/238)) ([#255](https://github.com/kauki-labs/sandy/pull/255))
- _(fabric-local)_ repair main's broken build (LinkFrame shape after #246) ([#251](https://github.com/kauki-labs/sandy/pull/251))

### Other

- public-domain readiness pass (operator/codename cleanup, escalation, mesh, licensing) ([#428](https://github.com/kauki-labs/sandy/pull/428))
- _(readme)_ document running sandyd across multiple hosts ([#422](https://github.com/kauki-labs/sandy/pull/422))
- /project-docs conformance pass for the first release ([#419](https://github.com/kauki-labs/sandy/pull/419))
- _(sandy-fabric-local)_ deterministic concurrency harness for Channel/CursorStream ([#354](https://github.com/kauki-labs/sandy/pull/354))
- _(readme)_ trim to binary usage, drop dev setup, add the seams diagram ([#260](https://github.com/kauki-labs/sandy/pull/260))
- _(license)_ [**breaking**] relicense MIT → AGPL-3.0 + commercial dual + CLA ([#242](https://github.com/kauki-labs/sandy/pull/242))
