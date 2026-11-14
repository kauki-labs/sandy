# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.4](https://github.com/kauki-labs/sandy/compare/sandyd-v0.2.3...sandyd-v0.2.4) - 2026-11-14

### Fixed

- *(sandyd)* refuse a Submit with no capable host instead of leaving it Pending (refs #868) ([#882](https://github.com/kauki-labs/sandy/pull/882))
- *(sandyd)* prune and gc keep a live job's cred dir whatever its age (closes #834) ([#880](https://github.com/kauki-labs/sandy/pull/880))

### Other

- *(api)* rename VmBackend to VirtualizationBackend ([#869](https://github.com/kauki-labs/sandy/pull/869))

## [0.2.3](https://github.com/kauki-labs/sandy/compare/sandyd-v0.2.2...sandyd-v0.2.3) - 2026-11-13

### Added

- _(cli)_ doctor refuses without a sandyd or an executor, docs for the daemon-backed verbs (refs #483) ([#861](https://github.com/kauki-labs/sandy/pull/861))
- _(cli)_ run, ls, status, wait, kill and gc are daemon-backed (refs #483) ([#860](https://github.com/kauki-labs/sandy/pull/860))
- _(cli)_ the doctor's check of sandyd and its executors (refs #483) ([#857](https://github.com/kauki-labs/sandy/pull/857))
- _(sandyd)_ ListHosts lists the connected executors (refs #483) ([#854](https://github.com/kauki-labs/sandy/pull/854))
- _(sandyd)_ revoke the credentials a dead daemon left, at the next start and on offline cancel (refs #830) ([#847](https://github.com/kauki-labs/sandy/pull/847))
- _(sandyd)_ fail the jobs a killed daemon left open at the next start (refs #830) ([#844](https://github.com/kauki-labs/sandy/pull/844))
- _(host-executor,sandyd,cli)_ digests over the daemon, hashed by the executor and recorded in the receipt (refs #483) ([#840](https://github.com/kauki-labs/sandy/pull/840))
- _(proto)_ digest fields on SubmitRequest, Dispatch, Capabilities and JobResult, wire only (refs #483) ([#839](https://github.com/kauki-labs/sandy/pull/839))
- _(sandyd)_ the daemon's envelope lists the outputs left at the declared destinations (refs #483) ([#837](https://github.com/kauki-labs/sandy/pull/837))
- _(host-executor,sandyd)_ the executor reports its egress outcome and the envelope receipt reads it (refs #483) ([#835](https://github.com/kauki-labs/sandy/pull/835))
- _(sandyd,cli)_ daemon prune, the gc equivalent over the control RPC (refs #483) ([#832](https://github.com/kauki-labs/sandy/pull/832))
- _(sandyd)_ a terminal job records and serves the result envelope (refs #483) ([#828](https://github.com/kauki-labs/sandy/pull/828))
- _(sandyd)_ cap the inputs and outputs one Submit may declare (slice 7 of #482) ([#826](https://github.com/kauki-labs/sandy/pull/826))
- _(sandyd,host-executor,cli)_ daemon submit --allow, placed on an egress_proxy host and applied by the executor (refs #483) ([#818](https://github.com/kauki-labs/sandy/pull/818))
- _(sandyd)_ refuse an unsafe input or output name at Submit ([#822](https://github.com/kauki-labs/sandy/pull/822))
- _(sandyd)_ place a job with inputs or outputs on a host that declares transfer ([#825](https://github.com/kauki-labs/sandy/pull/825))
- _(cli)_ daemon submit takes a TEMPLATE, --from-devshell and the plain flags without --flake (refs #483) ([#813](https://github.com/kauki-labs/sandy/pull/813))
- _(sandyd)_ the driver deletes an ephemeral environment when its TTL runs out (refs #812) ([#821](https://github.com/kauki-labs/sandy/pull/821))
- _(proto)_ EgressPolicy on SubmitRequest and Dispatch, an egress_proxy capability, wire only (refs #360) ([#816](https://github.com/kauki-labs/sandy/pull/816))
- _(sandyd)_ receive a job's outputs over the data link and record the job once they are in place (refs #482) ([#805](https://github.com/kauki-labs/sandy/pull/805))
- _(sandyd)_ receive a host's outputs beneath their destinations (refs #482) ([#778](https://github.com/kauki-labs/sandy/pull/778))
- _(sandyd)_ send a job's inputs over the claimed data link (refs #482) ([#768](https://github.com/kauki-labs/sandy/pull/768))
- _(sandyd)_ a second per-job data link, minted at dispatch and demuxed by token (refs #482) ([#752](https://github.com/kauki-labs/sandy/pull/752))
- _(executor-proto)_ Dispatch.data_link_token and JobResult.outputs_follow, wire only (refs #482) ([#751](https://github.com/kauki-labs/sandy/pull/751))
- _(sandyd)_ SANDY_ENV_VM_HOST_CHECK picks the host readiness check, connect for a non-HTTP service ([#732](https://github.com/kauki-labs/sandy/pull/732)) ([#748](https://github.com/kauki-labs/sandy/pull/748))

### Fixed

- _(sandyd)_ an input digest must belong to a declared input and each path is reported once ([#845](https://github.com/kauki-labs/sandy/pull/845))
- _(sandy,sandyd)_ the output listing's walk stops at the cap (fixes #838) ([#843](https://github.com/kauki-labs/sandy/pull/843))
- _(sandyd)_ a result that never booted is not Succeeded, whatever its exit code (fixes #829) ([#831](https://github.com/kauki-labs/sandy/pull/831))
- _(sandyd)_ bound the input send by a read timeout and the job's end ([#824](https://github.com/kauki-labs/sandy/pull/824))
- _(sandyd)_ the input sender validates wire names and refuses duplicate declared names ([#809](https://github.com/kauki-labs/sandy/pull/809))
- _(sandyd)_ release a job's credential when its result arrives, not when its outputs settle (fixes #481) ([#808](https://github.com/kauki-labs/sandy/pull/808))
- _(sandyd)_ sweep the stale .sandy-recv-* temp files of dead processes (fixes #782) ([#801](https://github.com/kauki-labs/sandy/pull/801))
- _(fsutil,sandyd)_ refuse a rename onto a file the receive completed, decided by file identity (fixes #787) ([#798](https://github.com/kauki-labs/sandy/pull/798))
- _(sandyd)_ a failed flush removes the file first; the temp-name retry counts per file (fixes #793) ([#796](https://github.com/kauki-labs/sandy/pull/796))
- _(sandyd)_ the output receive remembers entries by a fixed-size key (fixes #780) ([#795](https://github.com/kauki-labs/sandy/pull/795))
- _(sandyd)_ run the output receive's filesystem work on the blocking pool (fixes #779) ([#792](https://github.com/kauki-labs/sandy/pull/792))
- _(sandyd)_ bound the whole output receive in time and in frames (fixes #781) ([#790](https://github.com/kauki-labs/sandy/pull/790))
- _(sandyd)_ escape the peer-chosen path in a write error (fixes #786) ([#789](https://github.com/kauki-labs/sandy/pull/789))

### Other

- _(vm)_ remove the guest NIC profile (refs #483) ([#864](https://github.com/kauki-labs/sandy/pull/864))
- _(cli)_ delete the direct execution path and the Journal (refs #483, #221) ([#863](https://github.com/kauki-labs/sandy/pull/863))
- _(sandyd)_ the crate doc says what the daemon does now (refs #205) ([#853](https://github.com/kauki-labs/sandy/pull/853))
- _(sandyd)_ a named file output equals the locally collected file; an ancestor symlink is followed (refs #783, #784) ([#800](https://github.com/kauki-labs/sandy/pull/800))
- _(t3)_ replace the T3 guest with a generic service guest (part 2 of 3) ([#777](https://github.com/kauki-labs/sandy/pull/777))
- _(t3)_ strip T3 names from crates/impls code (part 1 of 3) ([#766](https://github.com/kauki-labs/sandy/pull/766))

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
