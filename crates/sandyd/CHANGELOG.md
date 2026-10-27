# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0](https://github.com/kauki-labs/sandy/compare/sandyd-v0.1.1...sandyd-v0.2.0) - 2026-10-27

### Added

- *(sandyd)* per-job isolation class on Submit ([#442](https://github.com/kauki-labs/sandy/pull/442))
- *(sandy-agent,sandyd)* close #340's remaining scope (items 3, 4) ([#378](https://github.com/kauki-labs/sandy/pull/378))
- *(sandyd)* notify a job's host-executor of attach-state transitions ([#344](https://github.com/kauki-labs/sandy/pull/344))
- *(fabric-local,sandyd)* add Resize and Archive LinkFrame variants ([#345](https://github.com/kauki-labs/sandy/pull/345))
- *(sandy-host-executor,sandyd,sandy-cli)* dispatch flake-templated VM jobs to a remote host-executor ([#333](https://github.com/kauki-labs/sandy/pull/333))
- *(sandyd,sandy-cli)* interactive attach over a new data-plane socket ([#330](https://github.com/kauki-labs/sandy/pull/330))
- *(sandy)* report remote job outcomes back to the orchestrator ([#292](https://github.com/kauki-labs/sandy/pull/292)) ([#316](https://github.com/kauki-labs/sandy/pull/316))
- *(sandyd)* read_frame cancel-safety in the host-executor loop ([#289](https://github.com/kauki-labs/sandy/pull/289)) ([#312](https://github.com/kauki-labs/sandy/pull/312))
- *(sandyd)* cross-machine connection robustness, part 1 ([#289](https://github.com/kauki-labs/sandy/pull/289)) ([#311](https://github.com/kauki-labs/sandy/pull/311))
- *(sandyd)* orchestrator placement wiring - submit to send_dispatch ([#298](https://github.com/kauki-labs/sandy/pull/298)) ([#301](https://github.com/kauki-labs/sandy/pull/301))
- *(sandyd)* the mesh accept loop for remote agent-link streams (#279, #212) ([#290](https://github.com/kauki-labs/sandy/pull/290))
- *(sandyd)* mesh bind-address config + the host_conn listener ([#291](https://github.com/kauki-labs/sandy/pull/291)) ([#293](https://github.com/kauki-labs/sandy/pull/293))
- *(sandyd)* the orchestrator side of the host-client contract ([#263](https://github.com/kauki-labs/sandy/pull/263)) ([#277](https://github.com/kauki-labs/sandy/pull/277))
- *(sandyd)* C-at-Submit — bearer submitter_caps, bound via derive_job_caps ([#273](https://github.com/kauki-labs/sandy/pull/273))
- *(sandyd)* the remote agent-link authentication gate (#212 decision 6) ([#266](https://github.com/kauki-labs/sandy/pull/266))
- *(sandyd)* mint a real per-job channel and caps on Submit (#212, B2 slice) ([#227](https://github.com/kauki-labs/sandy/pull/227))
- *(ci)* scope release-plz's PR and document its CI-trigger gap ([#249](https://github.com/kauki-labs/sandy/pull/249))

### Fixed

- *(sandyd)* keepalive on the agent-link path (#289 item 1 follow-up) ([#445](https://github.com/kauki-labs/sandy/pull/445))
- *(sandyd)* reap terminal jobs from JobRegistry on a grace period ([#440](https://github.com/kauki-labs/sandy/pull/440))
- *(containment)* record and enforce the untrusted-is-VM-only decision ([#150](https://github.com/kauki-labs/sandy/pull/150)) ([#382](https://github.com/kauki-labs/sandy/pull/382))
- *(sandyd)* never silently strand a placed dispatch as Pending ([#368](https://github.com/kauki-labs/sandy/pull/368))
- *(sandyd)* six audit hardening findings + privatize Cap fields ([#319](https://github.com/kauki-labs/sandy/pull/319))
- *(sandyd)* signal same-host_id reclaim instead of silent close (#292 item 4) ([#315](https://github.com/kauki-labs/sandy/pull/315))
- *(sandyd)* invalidate an unclaimed remote link on cancel (#269, #212) ([#285](https://github.com/kauki-labs/sandy/pull/285))

### Other

- *(sandyd)* split serve_host_executor's register and relay phases ([#430](https://github.com/kauki-labs/sandy/pull/430))
- public-domain readiness pass (operator/codename cleanup, escalation, mesh, licensing) ([#428](https://github.com/kauki-labs/sandy/pull/428))
- *(readme)* document running sandyd across multiple hosts ([#422](https://github.com/kauki-labs/sandy/pull/422))
- /project-docs conformance pass for the first release ([#419](https://github.com/kauki-labs/sandy/pull/419))
- *(sandyd)* prove no log line or error carries the link token ([#367](https://github.com/kauki-labs/sandy/pull/367))
- *(deps)* Bump the cargo-major group with 2 updates ([#307](https://github.com/kauki-labs/sandy/pull/307))
- *(sandyd)* real-wire registration + submit-to-dispatch coverage, plus placement tracing ([#313](https://github.com/kauki-labs/sandy/pull/313))
- *(rename)* sandy-host-client -> sandy-host-executor ([#308](https://github.com/kauki-labs/sandy/pull/308))
- *(readme)* trim to binary usage, drop dev setup, add the seams diagram ([#260](https://github.com/kauki-labs/sandy/pull/260))
- *(license)* [**breaking**] relicense MIT → AGPL-3.0 + commercial dual + CLA ([#242](https://github.com/kauki-labs/sandy/pull/242))
