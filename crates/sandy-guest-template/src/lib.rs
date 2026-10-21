//! `sandy-guest-template`: resolve an arbitrary flake with no sandy awareness
//! at all (#325/#326) into a bootable guest topology, and the `flake/v1`
//! dispatch manifest that carries a flake reference across the wire (#332) —
//! shared by `sandy-cli` (`sandy run --flake`, `sandy daemon submit --flake`)
//! and `sandy-host-executor` (the remote `SandboxKind::Vm` dispatch branch),
//! so a flake-templated VM job is resolved identically on whichever host
//! actually boots it, never a prebuilt artifact shipped from the submitter's
//! own machine.
//!
//! Extracted from `sandy-cli` by #332 as a pure move: this crate's public API
//! is unchanged in shape from `sandy-cli`'s own former `flake_wrap`/
//! `host_target` modules (`resolve_flake_template` gains one new parameter,
//! the injected macOS-prereq-check callback, so this crate never depends on
//! a caller's own `doctor` module). Kept separate from the published
//! `sandy-lib` facade (`sandy`) rather than folded into it: this module's
//! resolution logic is CLI/operator-shaped (shells out to `nix`, reports
//! `anyhow`-chained errors), not the typed-error library discipline
//! `sandy-lib`'s curated public API holds everywhere else.

mod flake_wrap;
pub mod host_target;
pub mod manifest;

pub use flake_wrap::{
    ResolvedTemplate, TemplateKind, guest_wrapper_present, nix_bin, parse_kind, resolve_flake_template,
};
