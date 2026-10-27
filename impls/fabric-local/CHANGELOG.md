# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1](https://github.com/kauki-labs/sandy/releases/tag/sandy-fabric-local-v0.1.1) - 2026-10-27

### Added

- *(sandyd)* per-job isolation class on Submit ([#442](https://github.com/kauki-labs/sandy/pull/442))
- *(sandy-fabric)* resolve Control and Escalate envelope contracts ([#439](https://github.com/kauki-labs/sandy/pull/439))
- *(sandyd)* notify a job's host-executor of attach-state transitions ([#344](https://github.com/kauki-labs/sandy/pull/344))
- *(fabric-local,sandyd)* add Resize and Archive LinkFrame variants ([#345](https://github.com/kauki-labs/sandy/pull/345))
- *(sandyd,sandy-cli)* interactive attach over a new data-plane socket ([#330](https://github.com/kauki-labs/sandy/pull/330))
- *(sandy-host-client)* the main loop (#263, #269, #288) ([#294](https://github.com/kauki-labs/sandy/pull/294))
- *(fabric-local)* relay_agent_link, the OnLink <-> dial_and_forward bridge ([#274](https://github.com/kauki-labs/sandy/pull/274))
- *(sandyd)* C-at-Submit — bearer submitter_caps, bound via derive_job_caps ([#273](https://github.com/kauki-labs/sandy/pull/273))
- *(fabric-local)* dial_and_forward, the executor-host entry point ([#159](https://github.com/kauki-labs/sandy/pull/159)) ([#265](https://github.com/kauki-labs/sandy/pull/265))
- *(ci)* scope release-plz's PR and document its CI-trigger gap ([#249](https://github.com/kauki-labs/sandy/pull/249))

### Fixed

- *(sandyd)* keepalive on the agent-link path (#289 item 1 follow-up) ([#445](https://github.com/kauki-labs/sandy/pull/445))
- *(sandy-fabric-local)* validate the telemetry log's parent dir ([#412](https://github.com/kauki-labs/sandy/pull/412))
- *(sandy)* don't revoke a refreshed token when only the dir sync fails ([#353](https://github.com/kauki-labs/sandy/pull/353))
- *(fabric-local)* restrict Archive to ARCHIVE_TRANSCRIPT, ignore duplicates ([#349](https://github.com/kauki-labs/sandy/pull/349))
- *(sandyd)* six audit hardening findings + privatize Cap fields ([#319](https://github.com/kauki-labs/sandy/pull/319))
- *(fabric-local)* CursorStream deregisters its own waker on drop ([#225](https://github.com/kauki-labs/sandy/pull/225)) ([#254](https://github.com/kauki-labs/sandy/pull/254))
- *(fabric-local)* keep reading the agent link after the job closes stdout ([#261](https://github.com/kauki-labs/sandy/pull/261)) ([#267](https://github.com/kauki-labs/sandy/pull/267))
- *(agent)* report refused peer posts and stop claiming delivery ([#256](https://github.com/kauki-labs/sandy/pull/256)) ([#262](https://github.com/kauki-labs/sandy/pull/262))
- *(fabric-local)* a refused peer post no longer ends the agent link ([#238](https://github.com/kauki-labs/sandy/pull/238)) ([#255](https://github.com/kauki-labs/sandy/pull/255))
- *(fabric-local)* repair main's broken build (LinkFrame shape after #246) ([#251](https://github.com/kauki-labs/sandy/pull/251))

### Other

- public-domain readiness pass (operator/codename cleanup, escalation, mesh, licensing) ([#428](https://github.com/kauki-labs/sandy/pull/428))
- *(readme)* document running sandyd across multiple hosts ([#422](https://github.com/kauki-labs/sandy/pull/422))
- /project-docs conformance pass for the first release ([#419](https://github.com/kauki-labs/sandy/pull/419))
- *(sandy-fabric-local)* deterministic concurrency harness for Channel/CursorStream ([#354](https://github.com/kauki-labs/sandy/pull/354))
- *(readme)* trim to binary usage, drop dev setup, add the seams diagram ([#260](https://github.com/kauki-labs/sandy/pull/260))
- *(license)* [**breaking**] relicense MIT → AGPL-3.0 + commercial dual + CLA ([#242](https://github.com/kauki-labs/sandy/pull/242))
