//! Secret staging and mount-arg assembly (E2/E3), owned by the backend.
//!
//! [`stage_secrets`] writes each caller secret to a per-instance `0600` file by
//! atomic rename, and [`wipe`] clears the staging dir on teardown — the bytes
//! travel this on-disk channel only, never argv, env, or the Nix store (INV-1).
//! [`mount_args`] turns a [`Mount`](crate::Mount) slice into the virtiofs share
//! argv, tagging each share from a [`TagPool`] (E3).
//!
//! The module is private (INV-FACADE); `lib.rs` re-exports only the items a
//! backend (#32/#35) calls.
//!
//! The tier-1 suites here prove staging perms, atomic rename, the no-leak
//! invariant, and mount-arg shape without a hypervisor. The tier-3 round-trip —
//! secret readable in-guest, RW host-write visible, RO write failing with
//! `EROFS` on a real boot — is host-gated and binds into #26 (INV-S9); it is
//! not run from this crate.

mod mounts;
mod secrets;

pub use mounts::{TagPool, mount_args};
pub use secrets::{StagedSecret, stage_secrets, wipe};
