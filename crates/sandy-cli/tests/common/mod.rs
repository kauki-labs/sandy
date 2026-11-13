//! Shared helpers for the live acceptance gates.
//!
//! Only compiled into a gate binary that is itself behind the `live` feature, so
//! these never reach CI. `dead_code` is allowed because not every gate uses every
//! helper. `LiveTarget`/`guest_flake`/`require_live`/`on_path`/`build_guest` live in
//! the `sandy_cli::live_target` lib module (re-exported here), shared with the
//! `live-vfkit-guest` binary so both consumers of "boot a real guest on this host"
//! use one implementation.
#![allow(dead_code, unused_imports)]

pub use sandy_cli::live_target::{LiveTarget, build_guest, guest_flake, on_path, require_live};
