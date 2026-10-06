//! Native [`VmBackend`](sandy::VmBackend) implementations for sandy.
//!
//! The run-plane seam and its contract types live in the [`sandy`] library; this
//! crate holds the two hypervisor-specific backends that satisfy that seam, kept
//! out of the deep `sandy` crate so the backend set can grow without widening the
//! library's public surface:
//!
//! - **vfkit backend** — the macOS [`VfkitBackend`]: assemble the `vfkit` argv from a [`Topology`](sandy::Topology),
//!   launch it under the PTY console transport, and return the pinned [`Outcome`](sandy::Outcome) (host-tier boot; the
//!   argv assembly in [`vfkit_args`] is sandbox-provable).
//! - **qemu backend** — [`QemuBackend`] (the Linux/KVM backend) with its pure argv assembler [`qemu_args`] over the
//!   pre-staged virtiofs shares (INV-8/INV-TOPOLOGY).

mod qemu;
mod vfkit;

pub use qemu::{QemuBackend, StagedArgs as QemuStagedArgs, qemu_args};
pub use vfkit::{StagedArgs as VfkitStagedArgs, VfkitBackend, vfkit_args};
