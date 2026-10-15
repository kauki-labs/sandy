# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1](https://github.com/kauki-labs/sandy/releases/tag/sandy-box-v0.1.1) - 2026-10-15

### Added

- *(backend)* ProcessBackend — the all-local process executor (T3, #131) ([#134](https://github.com/kauki-labs/sandy/pull/134))
- *(cli)* --input HOST:/guest/path surfaces an input at an absolute path ([#99](https://github.com/kauki-labs/sandy/pull/99))
- *(run)* writable outputs (catch-all + named) collected from the guest ([#34](https://github.com/kauki-labs/sandy/pull/34)) ([#76](https://github.com/kauki-labs/sandy/pull/76))
- *(run)* read-only inputs staged into the guest ([#34](https://github.com/kauki-labs/sandy/pull/34)) ([#74](https://github.com/kauki-labs/sandy/pull/74))
- *(cred)* drive mid-run credential refresh into the live guest share (#49, part 2) ([#71](https://github.com/kauki-labs/sandy/pull/71))
- *(cred)* refresh_once re-delivers a scoped token mid-run (#49, part 1) ([#69](https://github.com/kauki-labs/sandy/pull/69))
- *(cred)* guest-side secret consumption — $NAME in the job ([#50](https://github.com/kauki-labs/sandy/pull/50)) ([#66](https://github.com/kauki-labs/sandy/pull/66))
- *(run)* capture the guest console into the result envelope ([#64](https://github.com/kauki-labs/sandy/pull/64))
- *(trust-root)* sandy app register/verify/import/deregister (in-code installer) ([#55](https://github.com/kauki-labs/sandy/pull/55))
- *(cred)* live GitHub App adapter, verified end-to-end (Block 3, #49) ([#60](https://github.com/kauki-labs/sandy/pull/60))
- *(cred)* provider-agnostic CredentialProvider seam + TrustRoot (Block 1, #49) ([#54](https://github.com/kauki-labs/sandy/pull/54))
- *(egress)* guest-scoped forward nftables + phase_d live egress gate ([#47](https://github.com/kauki-labs/sandy/pull/47))
- *(nix)* Nix-free boot from a prebuilt topology file + phase_c gate ([#28](https://github.com/kauki-labs/sandy/pull/28)) ([#46](https://github.com/kauki-labs/sandy/pull/46))
- *(cli)* wire egress boundary and scoped cred into the run path ([#45](https://github.com/kauki-labs/sandy/pull/45))
- *(cred)* scoped GitHub token minting with TTL clamp ([#25](https://github.com/kauki-labs/sandy/pull/25)) ([#44](https://github.com/kauki-labs/sandy/pull/44))
- *(egress)* typed enforcement plan + applier seam + macOS honesty ([#43](https://github.com/kauki-labs/sandy/pull/43))
- native boot + live acceptance gates (live_boot #26, host_matrix #27) ([#41](https://github.com/kauki-labs/sandy/pull/41))
- native backend Wave 0-2 — Topology seam, console driver, staging+mounts (#31 #33 #34) ([#38](https://github.com/kauki-labs/sandy/pull/38))
- Phase A — the runner ([#6](https://github.com/kauki-labs/sandy/pull/6))
- rust workspace skeleton ([#1](https://github.com/kauki-labs/sandy/pull/1))

### Fixed

- *(cred)* harden credential teardown against leaks (adversarial review) ([#92](https://github.com/kauki-labs/sandy/pull/92))
- *(test)* live egress gate passes; rename phase_d to live_egress ([#48](https://github.com/kauki-labs/sandy/pull/48))

### Other

- FOSS scaffolding and automated crates.io publishing ([#89](https://github.com/kauki-labs/sandy/pull/89))
- *(ci)* gate unused dependencies with cargo-shear ([#87](https://github.com/kauki-labs/sandy/pull/87))
- two-level architecture spec with per-subsystem KPIs ([#86](https://github.com/kauki-labs/sandy/pull/86))
- *(deps)* bump the cargo-major group (octocrab 0.54, sha2 0.11, minisign-verify 0.3, base64 0.23) ([#72](https://github.com/kauki-labs/sandy/pull/72))
- *(run)* remove the obsolete --mount bind-mount path ([#68](https://github.com/kauki-labs/sandy/pull/68))
- *(cli)* nest trust-root commands by provider + concise provider docs ([#63](https://github.com/kauki-labs/sandy/pull/63))
- *(crates)* consolidate 7 crates into a deep sandy library + sandy-cli ([#17](https://github.com/kauki-labs/sandy/pull/17))
