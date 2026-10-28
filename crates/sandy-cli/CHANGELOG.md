# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.2](https://github.com/kauki-labs/sandy/compare/sandy-cli-v0.2.1...sandy-cli-v0.2.2) - 2026-10-28

### Other

- *(egress)* live tests for hostname allow-list entries at the proxy ([#377](https://github.com/kauki-labs/sandy/pull/377)) ([#489](https://github.com/kauki-labs/sandy/pull/489))

## [0.2.1](https://github.com/kauki-labs/sandy/compare/sandy-cli-v0.2.0...sandy-cli-v0.2.1) - 2026-10-28

### Added

- _(sandy-host-executor)_ manifest-parity local-first fields ([#480](https://github.com/kauki-labs/sandy/pull/480)) ([#487](https://github.com/kauki-labs/sandy/pull/487))
- _(receipts)_ opt-in sha256 content digests of inputs and outputs ([#469](https://github.com/kauki-labs/sandy/pull/469))
- _(egress)_ RunSpec egress policy, proxy plan variant, and band-3 EgressProxyDied ([#453](https://github.com/kauki-labs/sandy/pull/453))

### Other

- _(egress)_ KP7 live test for a proxy that cannot start ([#406](https://github.com/kauki-labs/sandy/pull/406)) ([#484](https://github.com/kauki-labs/sandy/pull/484))
- _(egress)_ live parity gate for the egress proxy, and -nic none for tap-less qemu guests ([#406](https://github.com/kauki-labs/sandy/pull/406)) ([#476](https://github.com/kauki-labs/sandy/pull/476))

## [0.2.0](https://github.com/kauki-labs/sandy/compare/sandy-cli-v0.1.1...sandy-cli-v0.2.0) - 2026-10-27

### Added

- _(sandy-cli)_ add --cap to sandy daemon submit ([#444](https://github.com/kauki-labs/sandy/pull/444))
- _(sandy-cli)_ prove the Executor seam against the real qemu/vfkit backend ([#443](https://github.com/kauki-labs/sandy/pull/443))
- _(sandyd)_ per-job isolation class on Submit ([#442](https://github.com/kauki-labs/sandy/pull/442))
- _(result)_ define and implement envelope receipts v1 ([#361](https://github.com/kauki-labs/sandy/pull/361)) ([#414](https://github.com/kauki-labs/sandy/pull/414))
- _(sandyd)_ notify a job's host-executor of attach-state transitions ([#344](https://github.com/kauki-labs/sandy/pull/344))
- _(sandy-cli)_ ssh-style ~. detach, SIGWINCH resize, archived transcript ([#347](https://github.com/kauki-labs/sandy/pull/347))
- _(fabric-local,sandyd)_ add Resize and Archive LinkFrame variants ([#345](https://github.com/kauki-labs/sandy/pull/345))
- _(sandy-guest-template,sandy-cli,sandy-host-executor)_ configurable scrollback/transcript line bound ([#343](https://github.com/kauki-labs/sandy/pull/343))
- _(sandy-host-executor,sandyd,sandy-cli)_ dispatch flake-templated VM jobs to a remote host-executor ([#333](https://github.com/kauki-labs/sandy/pull/333))
- _(sandy-cli,nix)_ sandy run --from-devshell wraps a devShell as a guest ([#331](https://github.com/kauki-labs/sandy/pull/331))
- _(sandy-cli)_ sandy run --flake wraps an arbitrary flake as a guest ([#329](https://github.com/kauki-labs/sandy/pull/329))
- _(sandyd,sandy-cli)_ interactive attach over a new data-plane socket ([#330](https://github.com/kauki-labs/sandy/pull/330))
- _(sandy)_ report remote job outcomes back to the orchestrator ([#292](https://github.com/kauki-labs/sandy/pull/292)) ([#316](https://github.com/kauki-labs/sandy/pull/316))
- _(sandy-cli)_ scaffold the M2 cross-machine e2e acceptance test ([#272](https://github.com/kauki-labs/sandy/pull/272))
- _(sandyd)_ C-at-Submit — bearer submitter_caps, bound via derive_job_caps ([#273](https://github.com/kauki-labs/sandy/pull/273))
- _(sandyd)_ mint a real per-job channel and caps on Submit (#212, B2 slice) ([#227](https://github.com/kauki-labs/sandy/pull/227))
- _(ci)_ scope release-plz's PR and document its CI-trigger gap ([#249](https://github.com/kauki-labs/sandy/pull/249))
- _(agent)_ the job's peer socket and sandy-agent peer send|recv ([#238](https://github.com/kauki-labs/sandy/pull/238)) ([#247](https://github.com/kauki-labs/sandy/pull/247))

### Fixed

- _(sandy-cli)_ give live_egress's host tap a per-process name ([#437](https://github.com/kauki-labs/sandy/pull/437))
- _(cli)_ check stderr, not stdout, for live_attach's terminal-state assertion ([#420](https://github.com/kauki-labs/sandy/pull/420))
- _(egress)_ warn when --allow has no effect on a NIC-less guest ([#417](https://github.com/kauki-labs/sandy/pull/417))
- _(egress)_ refuse hostname allow-list entries on the nftables path ([#418](https://github.com/kauki-labs/sandy/pull/418))
- _(supervisor)_ defer the credentialed terminal journal write ([#322](https://github.com/kauki-labs/sandy/pull/322)) ([#415](https://github.com/kauki-labs/sandy/pull/415))
- _(egress)_ close the guest's path to the host (input chain) ([#416](https://github.com/kauki-labs/sandy/pull/416))
- _(sandy-fsutil,sandy,sandy-cli)_ bind credential and guest-share staging to a validated fingerprint ([#323](https://github.com/kauki-labs/sandy/pull/323)) ([#410](https://github.com/kauki-labs/sandy/pull/410))
- _(doctor)_ report a group/world-writable trust-roots dir ([#411](https://github.com/kauki-labs/sandy/pull/411))
- _(sandy-cli)_ assert the real tmux pty, not a stale pipe, in the VM job fd test ([#365](https://github.com/kauki-labs/sandy/pull/365))
- _(sandy-cli)_ gc sweeps stale cred-_/verify-_ staging dirs ([#352](https://github.com/kauki-labs/sandy/pull/352))
- _(sandy-cli)_ inject the macOS nix/builder probe for sandy doctor ([#363](https://github.com/kauki-labs/sandy/pull/363))
- _(sandy-guest-template)_ use path: scheme for a non-git wrapper root ([#339](https://github.com/kauki-labs/sandy/pull/339))
- _(sandy)_ bypass PATH for qemu/nix/virtiofsd, retry Submit until ws01 registers ([#336](https://github.com/kauki-labs/sandy/pull/336))
- _(sandy-cli)_ redact secrets from console tail, surface revoke failures as warnings ([#320](https://github.com/kauki-labs/sandy/pull/320))
- _(agent)_ report refused peer posts and stop claiming delivery ([#256](https://github.com/kauki-labs/sandy/pull/256)) ([#262](https://github.com/kauki-labs/sandy/pull/262))

### Other

- _(sandy-cli)_ split supervisor.rs into 5 submodules ([#434](https://github.com/kauki-labs/sandy/pull/434))
- public-domain readiness pass (operator/codename cleanup, escalation, mesh, licensing) ([#428](https://github.com/kauki-labs/sandy/pull/428))
- _(readme)_ document running sandyd across multiple hosts ([#422](https://github.com/kauki-labs/sandy/pull/422))
- /project-docs conformance pass for the first release ([#419](https://github.com/kauki-labs/sandy/pull/419))
- _(privacy)_ rename ws01-specific identifiers to a generic placeholder ([#350](https://github.com/kauki-labs/sandy/pull/350))
- _(deps)_ Bump the cargo-major group with 2 updates ([#307](https://github.com/kauki-labs/sandy/pull/307))
- _(rename)_ sandy-host-client -> sandy-host-executor ([#308](https://github.com/kauki-labs/sandy/pull/308))
- _(daemon_e2e)_ nix builds sandyd and passes SANDYD_BIN, no nested cargo build ([#268](https://github.com/kauki-labs/sandy/pull/268))
- _(readme)_ trim to binary usage, drop dev setup, add the seams diagram ([#260](https://github.com/kauki-labs/sandy/pull/260))
- _(license)_ [**breaking**] relicense MIT → AGPL-3.0 + commercial dual + CLA ([#242](https://github.com/kauki-labs/sandy/pull/242))
