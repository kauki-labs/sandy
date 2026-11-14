//! VM sandy seam implementations.
//!
//! The Linux/KVM [`QemuBackend`] and macOS [`VfkitBackend`] (both concrete
//! [`VirtualizationBackend`](sandy::VirtualizationBackend) impls), plus their per-hypervisor virtio-fs
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
mod egress_proxy;
mod orphans;
mod qemu;
mod share;
mod vfkit;

/// What a run that was cancelled before its guest booted returns (#687): classified like any cancelled run (band 1,
/// not retryable), not as a boot fault a platform would retry. `booted` is `true` only so the outcome classifies that
/// way; no guest ran and the console is empty.
fn cancelled_before_boot() -> sandy::Outcome {
    sandy::Outcome {
        digests: None,
        booted: true,
        guest_exit: None,
        transport_error: None,
        timed_out: true,
        console: String::new(),
    }
}

pub use console::{
    Markers, PipeTransport, Protocol, ProtocolStep, PtyTransport, ReadEvent, TimeoutPolicy, Transport, parse_exit,
    run_console,
};
#[cfg(target_os = "linux")]
pub use orphans::Procfs;
#[cfg(target_os = "macos")]
pub use orphans::Ps;
pub use orphans::{
    BoxRecord, Kill, ProcId, ProcState, ProcessTable, RECORD_FILE, RecordWriter, SweepReport, sweep_orphaned_vms,
    sweep_orphans,
};
pub use qemu::{QemuBackend, StagedArgs as QemuStagedArgs, qemu_args, qemu_bin_override};
pub use share::{VirtioFsTransport, VirtiofsdTransport, virtiofsd_args};
pub use vfkit::{StagedArgs as VfkitStagedArgs, VfkitBackend, vfkit_args};
