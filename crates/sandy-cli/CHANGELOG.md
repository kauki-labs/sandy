# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0](https://github.com/kauki-labs/sandy/compare/sandy-cli-v0.1.1...sandy-cli-v0.2.0) - 2026-10-27

### Added

- *(sandy-cli)* add --cap to sandy daemon submit ([#444](https://github.com/kauki-labs/sandy/pull/444))
- *(sandy-cli)* prove the Executor seam against the real qemu/vfkit backend ([#443](https://github.com/kauki-labs/sandy/pull/443))
- *(sandyd)* per-job isolation class on Submit ([#442](https://github.com/kauki-labs/sandy/pull/442))
- *(result)* define and implement envelope receipts v1 ([#361](https://github.com/kauki-labs/sandy/pull/361)) ([#414](https://github.com/kauki-labs/sandy/pull/414))
- *(sandyd)* notify a job's host-executor of attach-state transitions ([#344](https://github.com/kauki-labs/sandy/pull/344))
- *(sandy-cli)* ssh-style ~. detach, SIGWINCH resize, archived transcript ([#347](https://github.com/kauki-labs/sandy/pull/347))
- *(fabric-local,sandyd)* add Resize and Archive LinkFrame variants ([#345](https://github.com/kauki-labs/sandy/pull/345))
- *(sandy-guest-template,sandy-cli,sandy-host-executor)* configurable scrollback/transcript line bound ([#343](https://github.com/kauki-labs/sandy/pull/343))
- *(sandy-host-executor,sandyd,sandy-cli)* dispatch flake-templated VM jobs to a remote host-executor ([#333](https://github.com/kauki-labs/sandy/pull/333))
- *(sandy-cli,nix)* sandy run --from-devshell wraps a devShell as a guest ([#331](https://github.com/kauki-labs/sandy/pull/331))
- *(sandy-cli)* sandy run --flake wraps an arbitrary flake as a guest ([#329](https://github.com/kauki-labs/sandy/pull/329))
- *(sandyd,sandy-cli)* interactive attach over a new data-plane socket ([#330](https://github.com/kauki-labs/sandy/pull/330))
- *(sandy)* report remote job outcomes back to the orchestrator ([#292](https://github.com/kauki-labs/sandy/pull/292)) ([#316](https://github.com/kauki-labs/sandy/pull/316))
- *(sandy-cli)* scaffold the M2 cross-machine e2e acceptance test ([#272](https://github.com/kauki-labs/sandy/pull/272))
- *(sandyd)* C-at-Submit — bearer submitter_caps, bound via derive_job_caps ([#273](https://github.com/kauki-labs/sandy/pull/273))
- *(sandyd)* mint a real per-job channel and caps on Submit (#212, B2 slice) ([#227](https://github.com/kauki-labs/sandy/pull/227))
- *(ci)* scope release-plz's PR and document its CI-trigger gap ([#249](https://github.com/kauki-labs/sandy/pull/249))
- *(agent)* the job's peer socket and sandy-agent peer send|recv ([#238](https://github.com/kauki-labs/sandy/pull/238)) ([#247](https://github.com/kauki-labs/sandy/pull/247))

### Fixed

- *(sandy-cli)* give live_egress's host tap a per-process name ([#437](https://github.com/kauki-labs/sandy/pull/437))
- *(cli)* check stderr, not stdout, for live_attach's terminal-state assertion ([#420](https://github.com/kauki-labs/sandy/pull/420))
- *(egress)* warn when --allow has no effect on a NIC-less guest ([#417](https://github.com/kauki-labs/sandy/pull/417))
- *(egress)* refuse hostname allow-list entries on the nftables path ([#418](https://github.com/kauki-labs/sandy/pull/418))
- *(supervisor)* defer the credentialed terminal journal write ([#322](https://github.com/kauki-labs/sandy/pull/322)) ([#415](https://github.com/kauki-labs/sandy/pull/415))
- *(egress)* close the guest's path to the host (input chain) ([#416](https://github.com/kauki-labs/sandy/pull/416))
- *(sandy-fsutil,sandy,sandy-cli)* bind credential and guest-share staging to a validated fingerprint ([#323](https://github.com/kauki-labs/sandy/pull/323)) ([#410](https://github.com/kauki-labs/sandy/pull/410))
- *(doctor)* report a group/world-writable trust-roots dir ([#411](https://github.com/kauki-labs/sandy/pull/411))
- *(sandy-cli)* assert the real tmux pty, not a stale pipe, in the VM job fd test ([#365](https://github.com/kauki-labs/sandy/pull/365))
- *(sandy-cli)* gc sweeps stale cred-*/verify-* staging dirs ([#352](https://github.com/kauki-labs/sandy/pull/352))
- *(sandy-cli)* inject the macOS nix/builder probe for sandy doctor ([#363](https://github.com/kauki-labs/sandy/pull/363))
- *(sandy-guest-template)* use path: scheme for a non-git wrapper root ([#339](https://github.com/kauki-labs/sandy/pull/339))
- *(sandy)* bypass PATH for qemu/nix/virtiofsd, retry Submit until ws01 registers ([#336](https://github.com/kauki-labs/sandy/pull/336))
- *(sandy-cli)* redact secrets from console tail, surface revoke failures as warnings ([#320](https://github.com/kauki-labs/sandy/pull/320))
- *(agent)* report refused peer posts and stop claiming delivery ([#256](https://github.com/kauki-labs/sandy/pull/256)) ([#262](https://github.com/kauki-labs/sandy/pull/262))

### Other

- *(sandy-cli)* split supervisor.rs into 5 submodules ([#434](https://github.com/kauki-labs/sandy/pull/434))
- public-domain readiness pass (operator/codename cleanup, escalation, mesh, licensing) ([#428](https://github.com/kauki-labs/sandy/pull/428))
- *(readme)* document running sandyd across multiple hosts ([#422](https://github.com/kauki-labs/sandy/pull/422))
- /project-docs conformance pass for the first release ([#419](https://github.com/kauki-labs/sandy/pull/419))
- *(privacy)* rename ws01-specific identifiers to a generic placeholder ([#350](https://github.com/kauki-labs/sandy/pull/350))
- *(deps)* Bump the cargo-major group with 2 updates ([#307](https://github.com/kauki-labs/sandy/pull/307))
- *(rename)* sandy-host-client -> sandy-host-executor ([#308](https://github.com/kauki-labs/sandy/pull/308))
- *(daemon_e2e)* nix builds sandyd and passes SANDYD_BIN, no nested cargo build ([#268](https://github.com/kauki-labs/sandy/pull/268))
- *(readme)* trim to binary usage, drop dev setup, add the seams diagram ([#260](https://github.com/kauki-labs/sandy/pull/260))
- *(license)* [**breaking**] relicense MIT → AGPL-3.0 + commercial dual + CLA ([#242](https://github.com/kauki-labs/sandy/pull/242))
