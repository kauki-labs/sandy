//! VM sandy seam implementations.
//!
//! The Linux/KVM [`QemuBackend`] and macOS [`VfkitBackend`] (both concrete
//! [`VmBackend`](sandy::VmBackend) impls), plus their per-hypervisor virtio-fs
//! [`GuestShareTransport`](sandy_api::share::GuestShareTransport)s
//! ([`VirtiofsdTransport`] for qemu, [`VirtioFsTransport`] for vfkit) and the
//! native [console driver](console) the backends drive. The seam contracts live
//! in `sandy-api`; the remaining runtime helpers (nix topology, staging,
//! collection, the share planner) live in the `sandy` core.
//!
//! The console driver is VM-only — only the qemu/vfkit boots inject a command
//! over a guest serial console — so it lives here rather than in `sandy`, which
//! keeps its heavy PTY dependency (`portable-pty`) out of a local-only build
//! (`sandy-backend` default features, `impl-vm` off). See #147.

mod agent;
mod console;
mod qemu;
mod share;
mod vfkit;

pub use console::{
    Markers, PipeTransport, Protocol, ProtocolStep, PtyTransport, ReadEvent, TimeoutPolicy, Transport, parse_exit,
    run_console,
};
pub use qemu::{QemuBackend, StagedArgs as QemuStagedArgs, qemu_args, qemu_bin_override};
pub use share::{VirtioFsTransport, VirtiofsdTransport, virtiofsd_args};
pub use vfkit::{StagedArgs as VfkitStagedArgs, VfkitBackend, vfkit_args};
