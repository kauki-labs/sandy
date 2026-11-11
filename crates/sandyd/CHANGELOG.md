# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.2](https://github.com/kauki-labs/sandy/compare/sandyd-v0.2.1...sandyd-v0.2.2) - 2026-11-10

### Added

- _(sandyd)_ a stub forge trust root for the live broker gate, off by default ([#733](https://github.com/kauki-labs/sandy/pull/733)) ([#737](https://github.com/kauki-labs/sandy/pull/737))
- _(sandyd)_ a failed provision carries the guest console tail in its reason (refs #727) ([#731](https://github.com/kauki-labs/sandy/pull/731))
- _(sandyd)_ per-environment forge credential, minted before boot, renewed in place, revoked at stop (refs #706) ([#725](https://github.com/kauki-labs/sandy/pull/725))
- _(executor-proto)_ transfer capability and data-link messages (refs #482) ([#722](https://github.com/kauki-labs/sandy/pull/722))
- _(sandyd)_ mint a job's credential before dispatch and revoke it on every terminal path (refs #481) ([#710](https://github.com/kauki-labs/sandy/pull/710))
- _(sandyd)_ warn when no identity profile registry is set, test the exit on an untrusted one (refs #704) ([#718](https://github.com/kauki-labs/sandy/pull/718))
- _(sandyd)_ vm-vfkit environment backend, stale-socket sweep, qemu orphan sweep call ([#587](https://github.com/kauki-labs/sandy/pull/587)) ([#672](https://github.com/kauki-labs/sandy/pull/672))
- _(environment)_ compose the qemu VM environment backend in sandyd ([#587](https://github.com/kauki-labs/sandy/pull/587)) ([#661](https://github.com/kauki-labs/sandy/pull/661))
- _(sandyd)_ operator secret store reads one 0600 file per secret name (refs #705) ([#712](https://github.com/kauki-labs/sandy/pull/712))
- _(sandyd)_ load the identity-profile registry and validate an environment's profile ([#704](https://github.com/kauki-labs/sandy/pull/704)) ([#711](https://github.com/kauki-labs/sandy/pull/711))
- _(sandyd)_ audit client environment create, stop and delete, failing closed (refs #596) ([#703](https://github.com/kauki-labs/sandy/pull/703))
- _(broker)_ serve a job's output by offset, with a sandyd collector cap (refs #643) ([#693](https://github.com/kauki-labs/sandy/pull/693))
- _(sandyd)_ refuse environment creates from untrusted clients under the process backend ([#641](https://github.com/kauki-labs/sandy/pull/641)) ([#651](https://github.com/kauki-labs/sandy/pull/651))
- _(environment)_ a connected client renews the idle-stop lease ([#645](https://github.com/kauki-labs/sandy/pull/645)) ([#681](https://github.com/kauki-labs/sandy/pull/681))
- _(sandyd)_ refuse an invalid flake/v1 service manifest at Submit ([#589](https://github.com/kauki-labs/sandy/pull/589)) ([#660](https://github.com/kauki-labs/sandy/pull/660))
- _(sandyd)_ gc deleted environment rows and page ListEnvironments ([#633](https://github.com/kauki-labs/sandy/pull/633)) ([#648](https://github.com/kauki-labs/sandy/pull/648))
- _(sandyd)_ idle-stop lease for Ready environments ([#587](https://github.com/kauki-labs/sandy/pull/587)) ([#646](https://github.com/kauki-labs/sandy/pull/646))
- _(sandyd)_ opt-in process backend so environments run end to end ([#587](https://github.com/kauki-labs/sandy/pull/587)) ([#636](https://github.com/kauki-labs/sandy/pull/636))
- _(sandyd)_ environment launch driver over a new EnvironmentBackend seam ([#587](https://github.com/kauki-labs/sandy/pull/587)) ([#635](https://github.com/kauki-labs/sandy/pull/635))
- _(sandyd)_ environment operations over the control RPC ([#587](https://github.com/kauki-labs/sandy/pull/587)) ([#623](https://github.com/kauki-labs/sandy/pull/623))
- _(sandyd)_ environment store and state machine ([#587](https://github.com/kauki-labs/sandy/pull/587)) ([#613](https://github.com/kauki-labs/sandy/pull/613))
- _(sandyd)_ refuse UDS peers whose uid differs from the daemon's ([#533](https://github.com/kauki-labs/sandy/pull/533)) ([#571](https://github.com/kauki-labs/sandy/pull/571))
- _(sandyd)_ add sandyd cancel <job-id> for jobs the RPC cannot cancel ([#545](https://github.com/kauki-labs/sandy/pull/545)) ([#572](https://github.com/kauki-labs/sandy/pull/572))
- _(sandyd)_ report the git build revision in --version and the startup log ([#559](https://github.com/kauki-labs/sandy/pull/559))
- _(sandyd)_ Cancel requires the job attach token ([#540](https://github.com/kauki-labs/sandy/pull/540)) ([#543](https://github.com/kauki-labs/sandy/pull/543))
- _(sandyd)_ wire mesh-TLS into host_conn and mesh_accept listeners ([#504](https://github.com/kauki-labs/sandy/pull/504)) ([#519](https://github.com/kauki-labs/sandy/pull/519))
- _(sandy-conn)_ mutual-TLS mesh transport tier ([#495](https://github.com/kauki-labs/sandy/pull/495)) ([#506](https://github.com/kauki-labs/sandy/pull/506))
- _(sandyd)_ path fields for local dispatch, gated on a declared locality flag ([#496](https://github.com/kauki-labs/sandy/pull/496)) ([#508](https://github.com/kauki-labs/sandy/pull/508))

### Fixed

- _(sandyd)_ operator store refuses an empty file and a directory open to group or other (refs #705) ([#714](https://github.com/kauki-labs/sandy/pull/714))

### Other

- _(sandy-mcp)_ un-ignore the live broker scenario over the stub trust root, record boot-to-Ready ([#727](https://github.com/kauki-labs/sandy/pull/727)) ([#738](https://github.com/kauki-labs/sandy/pull/738))
- _(sandyd)_ probe Provisioning environments concurrently in the launch driver ([#709](https://github.com/kauki-labs/sandy/pull/709)) ([#730](https://github.com/kauki-labs/sandy/pull/730))
- _(privacy)_ scrub the Linux host's nickname to role language ([#581](https://github.com/kauki-labs/sandy/pull/581))
- split the instrumented coverage build out of the PR gate ([#561](https://github.com/kauki-labs/sandy/pull/561))
- _(sandyd)_ renumber the duplicate §20 ([#532](https://github.com/kauki-labs/sandy/pull/532))

## [0.2.1](https://github.com/kauki-labs/sandy/compare/sandyd-v0.2.0...sandyd-v0.2.1) - 2026-10-28

### Added

- _(sandyd)_ wire orchestrator Cancel through to a remote host-executor's RunControl ([#478](https://github.com/kauki-labs/sandy/pull/478))

### Fixed

- _(sandy-fabric)_ compile the Cap mutators only for tests and contract-tests ([#467](https://github.com/kauki-labs/sandy/pull/467))
- _(sandyd)_ cap pre-auth concurrency on the mesh and attach accept loops (NV-06, #395) ([#460](https://github.com/kauki-labs/sandy/pull/460))

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
