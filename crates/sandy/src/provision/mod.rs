//! `sandy-provider` — `VmBackend` implementations over `nix-vm` (Block 5).
//!
//! Scaffold stub. Block 5 (`LauncherBackend`) lands here and implements the
//! `VmBackend` trait from `sandy` identically to `FakeBackend`.
//!
//! [`router`] is the Phase B HostNix router (block 6a): it routes a
//! `ProvisioningStrategy` to Phase A's backend or refuses with a stage pointer.
//!
//! Phase D adds [`remote`] (the `RemoteBuild` eval-local / build-remote
//! orchestration, D.1) and [`fallback`] (the locked-down-Linux fallback decision,
//! D.2).

pub mod fallback;
pub mod remote;
pub mod router;

pub use fallback::decide_fallback;
pub use remote::{RemoteArtifacts, RemoteBuilder, RemoteError, provision_remote_build};
pub use router::{HostNixProvisioner, Job, ProvisionOutcome, provision};
