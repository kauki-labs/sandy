//! VM sandy seam implementations.
//!
//! The Linux/KVM [`QemuBackend`] and macOS [`VfkitBackend`] (both concrete
//! [`VmBackend`](sandy::VmBackend) impls), plus their per-hypervisor virtio-fs
//! [`GuestShareTransport`](sandy_api::share::GuestShareTransport)s
//! ([`VirtiofsdTransport`] for qemu, [`VirtioFsTransport`] for vfkit). The seam
//! contracts live in `sandy-api`; the runtime helpers (console driver, nix
//! topology, staging, collection, the share planner) live in the `sandy` core.

mod qemu;
mod share;
mod vfkit;

pub use qemu::{QemuBackend, StagedArgs as QemuStagedArgs, qemu_args};
pub use share::{VirtioFsTransport, VirtiofsdTransport, virtiofsd_args};
pub use vfkit::{StagedArgs as VfkitStagedArgs, VfkitBackend, vfkit_args};
