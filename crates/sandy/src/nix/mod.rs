//! The Nix eval → JSON [`Topology`] seam (Block 31).
//!
//! sandy obtains the VM topology by evaluating the guest config itself
//! (`nix … --json`), not by shelling to nix-vm's `vm run`. Nix still *builds*
//! the artifacts; this module only *reads* the topology into a typed value the
//! native backends consume to assemble the hypervisor argv.
//!
//! - [`topology`] shells the Nix CLI (tier-2/host) and parses its output.
//! - [`parse_topology`] is the pure parse seam (tier-1, sandbox-testable).
//! - [`Topology`], [`StoreBacking`], [`Hypervisor`], [`Share`] are the typed result, deserialized `snake_case` with no
//!   rename layer.

mod topology;

pub use topology::{Hypervisor, Share, StoreBacking, Topology, parse_topology, topology};
