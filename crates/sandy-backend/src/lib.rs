//! The sandy backend hub: selects which [`VmBackend`](sandy::VmBackend)
//! implementation crates compile in, via cargo features, and re-exports the
//! chosen impls plus the shared share contract so downstream (sandy-cli) imports
//! one backend surface regardless of which impls are enabled.
//!
//! - **`impl-local`** (default) — the raw-process backend, local-dir transport, and host containment, from
//!   [`sandy-impls-local`](sandy_impls_local).
//! - **`impl-vm`** (opt-in) — the qemu/vfkit VM backends and their virtio-fs transports, from
//!   [`sandy-impls-vm`](sandy_impls_vm), so a local-only build never compiles the VM stack or its dependencies.

// The share-transport contract and the shared staging helpers both impl tiers
// use, re-exported so the hub is the single backend surface downstream imports.
pub use sandy::{ShareDirs, kill_children, plan_shares};
pub use sandy_api::share::{GuestShareTransport, Placement, Presentation, ShareSpec};
#[cfg(feature = "impl-local")]
pub use sandy_impls_local::{LocalDirTransport, NoEgress, ProcessBackend, SystemdRunContainment};
#[cfg(feature = "impl-vm")]
pub use sandy_impls_vm::{
    QemuBackend, QemuStagedArgs, VfkitBackend, VfkitStagedArgs, VirtioFsTransport, VirtiofsdTransport, qemu_args,
    vfkit_args, virtiofsd_args,
};
