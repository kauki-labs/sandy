//! `sandy-provider` — `VmBackend` implementations over `nix-vm` (Block 5).
//!
//! Scaffold stub. Block 5 (`LauncherBackend`) lands here and implements the
//! `VmBackend` trait from `sandy-core` identically to `FakeBackend`.
//!
//! [`router`] is the Phase B HostNix router (block 6a): it routes a
//! `ProvisioningStrategy` to Phase A's backend or refuses with a stage pointer.

pub mod router;
