# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.1](https://github.com/kauki-labs/sandy/compare/sandyd-v0.2.0...sandyd-v0.2.1) - 2026-10-28

### Added

- *(sandyd)* wire orchestrator Cancel through to a remote host-executor's RunControl ([#478](https://github.com/kauki-labs/sandy/pull/478))

### Fixed

- *(sandy-fabric)* compile the Cap mutators only for tests and contract-tests ([#467](https://github.com/kauki-labs/sandy/pull/467))
- *(sandyd)* cap pre-auth concurrency on the mesh and attach accept loops (NV-06, #395) ([#460](https://github.com/kauki-labs/sandy/pull/460))

## [0.2.0](https://github.com/kauki-labs/sandy/compare/sandyd-v0.1.1...sandyd-v0.2.0) - 2026-10-27

### Added

- _(sandyd)_ per-job isolation class on Submit ([#442](https://github.com/kauki-labs/sandy/pull/442))
- _(sandy-agent,sandyd)_ close #340's remaining scope (items 3, 4) ([#378](https://github.com/kauki-labs/sandy/pull/378))
- _(sandyd)_ notify a job's host-executor of attach-state transitions ([#344](https://github.com/kauki-labs/sandy/pull/344))
- _(fabric-local,sandyd)_ add Resize and Archive LinkFrame variants ([#345](https://github.com/kauki-labs/sandy/pull/345))
- _(sandy-host-executor,sandyd,sandy-cli)_ dispatch flake-templated VM jobs to a remote host-executor ([#333](https://github.com/kauki-labs/sandy/pull/333))
- _(sandyd,sandy-cli)_ interactive attach over a new data-plane socket ([#330](https://github.com/kauki-labs/sandy/pull/330))
- _(sandy)_ report remote job outcomes back to the orchestrator ([#292](https://github.com/kauki-labs/sandy/pull/292)) ([#316](https://github.com/kauki-labs/sandy/pull/316))
- _(sandyd)_ read_frame cancel-safety in the host-executor loop ([#289](https://github.com/kauki-labs/sandy/pull/289)) ([#312](https://github.com/kauki-labs/sandy/pull/312))
- _(sandyd)_ cross-machine connection robustness, part 1 ([#289](https://github.com/kauki-labs/sandy/pull/289)) ([#311](https://github.com/kauki-labs/sandy/pull/311))
- _(sandyd)_ orchestrator placement wiring - submit to send_dispatch ([#298](https://github.com/kauki-labs/sandy/pull/298)) ([#301](https://github.com/kauki-labs/sandy/pull/301))
- _(sandyd)_ the mesh accept loop for remote agent-link streams (#279, #212) ([#290](https://github.com/kauki-labs/sandy/pull/290))
- _(sandyd)_ mesh bind-address config + the host_conn listener ([#291](https://github.com/kauki-labs/sandy/pull/291)) ([#293](https://github.com/kauki-labs/sandy/pull/293))
- _(sandyd)_ the orchestrator side of the host-client contract ([#263](https://github.com/kauki-labs/sandy/pull/263)) ([#277](https://github.com/kauki-labs/sandy/pull/277))
- _(sandyd)_ C-at-Submit — bearer submitter_caps, bound via derive_job_caps ([#273](https://github.com/kauki-labs/sandy/pull/273))
- _(sandyd)_ the remote agent-link authentication gate (#212 decision 6) ([#266](https://github.com/kauki-labs/sandy/pull/266))
- _(sandyd)_ mint a real per-job channel and caps on Submit (#212, B2 slice) ([#227](https://github.com/kauki-labs/sandy/pull/227))
- _(ci)_ scope release-plz's PR and document its CI-trigger gap ([#249](https://github.com/kauki-labs/sandy/pull/249))

### Fixed

- _(sandyd)_ keepalive on the agent-link path (#289 item 1 follow-up) ([#445](https://github.com/kauki-labs/sandy/pull/445))
- _(sandyd)_ reap terminal jobs from JobRegistry on a grace period ([#440](https://github.com/kauki-labs/sandy/pull/440))
- _(containment)_ record and enforce the untrusted-is-VM-only decision ([#150](https://github.com/kauki-labs/sandy/pull/150)) ([#382](https://github.com/kauki-labs/sandy/pull/382))
- _(sandyd)_ never silently strand a placed dispatch as Pending ([#368](https://github.com/kauki-labs/sandy/pull/368))
- _(sandyd)_ six audit hardening findings + privatize Cap fields ([#319](https://github.com/kauki-labs/sandy/pull/319))
- _(sandyd)_ signal same-host_id reclaim instead of silent close (#292 item 4) ([#315](https://github.com/kauki-labs/sandy/pull/315))
- _(sandyd)_ invalidate an unclaimed remote link on cancel (#269, #212) ([#285](https://github.com/kauki-labs/sandy/pull/285))

### Other

- _(sandyd)_ split serve_host_executor's register and relay phases ([#430](https://github.com/kauki-labs/sandy/pull/430))
- public-domain readiness pass (operator/codename cleanup, escalation, mesh, licensing) ([#428](https://github.com/kauki-labs/sandy/pull/428))
- _(readme)_ document running sandyd across multiple hosts ([#422](https://github.com/kauki-labs/sandy/pull/422))
- /project-docs conformance pass for the first release ([#419](https://github.com/kauki-labs/sandy/pull/419))
- _(sandyd)_ prove no log line or error carries the link token ([#367](https://github.com/kauki-labs/sandy/pull/367))
- _(deps)_ Bump the cargo-major group with 2 updates ([#307](https://github.com/kauki-labs/sandy/pull/307))
- _(sandyd)_ real-wire registration + submit-to-dispatch coverage, plus placement tracing ([#313](https://github.com/kauki-labs/sandy/pull/313))
- _(rename)_ sandy-host-client -> sandy-host-executor ([#308](https://github.com/kauki-labs/sandy/pull/308))
- _(readme)_ trim to binary usage, drop dev setup, add the seams diagram ([#260](https://github.com/kauki-labs/sandy/pull/260))
- _(license)_ [**breaking**] relicense MIT → AGPL-3.0 + commercial dual + CLA ([#242](https://github.com/kauki-labs/sandy/pull/242))
