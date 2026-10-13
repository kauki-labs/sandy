//! Secret and input staging (E2), owned by the backend.
//!
//! [`stage_secrets`] writes each caller secret to a per-instance `0600` file by
//! atomic rename, and [`wipe`] clears the staging dir on teardown — the bytes
//! travel this on-disk channel only, never argv, env, or the Nix store (INV-1).
//! [`stage_inputs`] copies each read-only input into a separate `0700` share dir
//! mounted at `/run/sandy/inputs`. [`prepare_outputs`] / [`collect_outputs`] back
//! the writable `/run/sandy/outputs` share and copy it to host destinations at
//! teardown.
//!
//! The module is private (INV-FACADE); `lib.rs` re-exports only the items a
//! backend (#32/#35) calls.
//!
//! The tier-1 suites here prove staging perms, atomic rename, and the no-leak
//! invariant without a hypervisor. The tier-3 round-trip — secret readable
//! in-guest under its `$NAME` — is host-gated (INV-S9) and lives in the
//! `sandy-cli` live tests, not here.

mod inputs;
mod outputs;
mod secrets;

pub use inputs::{INPUT_MOUNT_TAG, stage_inputs};
pub use outputs::{OUTPUT_MOUNT_TAG, collect_outputs, prepare_outputs};
pub use secrets::{SECRET_MOUNT_TAG, StagedSecret, stage_secrets, wipe};
