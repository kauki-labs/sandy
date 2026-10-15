# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1](https://github.com/kauki-labs/sandy/releases/tag/sandy-cli-v0.1.1) - 2026-10-15

### Added

- *(fabric)* extract a Discovery seam from static placement (#131 T2) ([#137](https://github.com/kauki-labs/sandy/pull/137))
- *(fabric)* job-dispatcher seam injection via a run Profile (#131 T1) ([#133](https://github.com/kauki-labs/sandy/pull/133))
- *(cli)* --input HOST:/guest/path surfaces an input at an absolute path ([#99](https://github.com/kauki-labs/sandy/pull/99))
- *(cli)* populate ResultEnvelope.outputs + default to -o plain ([#81](https://github.com/kauki-labs/sandy/pull/81))
- *(run)* writable outputs (catch-all + named) collected from the guest ([#34](https://github.com/kauki-labs/sandy/pull/34)) ([#76](https://github.com/kauki-labs/sandy/pull/76))
- *(run)* read-only inputs staged into the guest ([#34](https://github.com/kauki-labs/sandy/pull/34)) ([#74](https://github.com/kauki-labs/sandy/pull/74))
- *(cred)* drive mid-run credential refresh into the live guest share (#49, part 2) ([#71](https://github.com/kauki-labs/sandy/pull/71))
- *(guest)* GitHub credential consumer in the job guest ([#49](https://github.com/kauki-labs/sandy/pull/49)) ([#70](https://github.com/kauki-labs/sandy/pull/70))
- *(cred)* refresh_once re-delivers a scoped token mid-run (#49, part 1) ([#69](https://github.com/kauki-labs/sandy/pull/69))
- *(cred)* guest-side secret consumption — $NAME in the job ([#50](https://github.com/kauki-labs/sandy/pull/50)) ([#66](https://github.com/kauki-labs/sandy/pull/66))
- *(run)* capture the guest console into the result envelope ([#64](https://github.com/kauki-labs/sandy/pull/64))
- *(cli)* sandy run --credential mints a scoped token from a trust root ([#49](https://github.com/kauki-labs/sandy/pull/49)) ([#62](https://github.com/kauki-labs/sandy/pull/62))
- *(trust-root)* sandy app register/verify/import/deregister (in-code installer) ([#55](https://github.com/kauki-labs/sandy/pull/55))
- *(cred)* run_job credential bracket + should_refresh (Block 2, #49) ([#56](https://github.com/kauki-labs/sandy/pull/56))
- *(cred)* provider-agnostic CredentialProvider seam + TrustRoot (Block 1, #49) ([#54](https://github.com/kauki-labs/sandy/pull/54))
- *(egress)* guest-scoped forward nftables + phase_d live egress gate ([#47](https://github.com/kauki-labs/sandy/pull/47))
- *(nix)* Nix-free boot from a prebuilt topology file + phase_c gate ([#28](https://github.com/kauki-labs/sandy/pull/28)) ([#46](https://github.com/kauki-labs/sandy/pull/46))
- *(cli)* wire egress boundary and scoped cred into the run path ([#45](https://github.com/kauki-labs/sandy/pull/45))
- native boot + live acceptance gates (live_boot #26, host_matrix #27) ([#41](https://github.com/kauki-labs/sandy/pull/41))
- sandy CLI — run/ls/status/wait/kill/gc ([#22](https://github.com/kauki-labs/sandy/pull/22)) ([#40](https://github.com/kauki-labs/sandy/pull/40))
- Phase A — the runner ([#6](https://github.com/kauki-labs/sandy/pull/6))
- rust workspace skeleton ([#1](https://github.com/kauki-labs/sandy/pull/1))

### Fixed

- *(backend)* correct overclaiming share/sandbox docs (adversarial review) ([#93](https://github.com/kauki-labs/sandy/pull/93))
- *(cred)* harden credential teardown against leaks (adversarial review) ([#92](https://github.com/kauki-labs/sandy/pull/92))
- *(qemu)* serve guest shares as virtiofs, not 9p ([#79](https://github.com/kauki-labs/sandy/pull/79))
- *(test)* live egress gate passes; rename phase_d to live_egress ([#48](https://github.com/kauki-labs/sandy/pull/48))

### Other

- *(sandy)* extract sandy-api contract crate (R0, mechanical extraction) ([#145](https://github.com/kauki-labs/sandy/pull/145))
- *(cli)* extract per-command handlers from dispatch ([#96](https://github.com/kauki-labs/sandy/pull/96))
- FOSS scaffolding and automated crates.io publishing ([#89](https://github.com/kauki-labs/sandy/pull/89))
- two-level architecture spec with per-subsystem KPIs ([#86](https://github.com/kauki-labs/sandy/pull/86))
- *(cred)* credential e2e scenarios (git-helper refresh + everything compose) ([#84](https://github.com/kauki-labs/sandy/pull/84))
- *(e2e)* multi-share live scenario + timeout exit band ([#83](https://github.com/kauki-labs/sandy/pull/83))
- *(cred)* live acceptance for mid-run credential refresh ([#49](https://github.com/kauki-labs/sandy/pull/49)) ([#73](https://github.com/kauki-labs/sandy/pull/73))
- *(run)* remove the obsolete --mount bind-mount path ([#68](https://github.com/kauki-labs/sandy/pull/68))
- *(cli)* nest trust-root commands by provider + concise provider docs ([#63](https://github.com/kauki-labs/sandy/pull/63))
- *(crates)* consolidate 7 crates into a deep sandy library + sandy-cli ([#17](https://github.com/kauki-labs/sandy/pull/17))
