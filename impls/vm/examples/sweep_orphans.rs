//! Run the start-up sweep for orphaned qemu VMs once and print what it did (#666).
//!
//! The live gate `scripts/dev/live-orphan-sweep.sh` uses it to prove that a SIGKILLed host's VM is found and
//! stopped. `sandyd` calls [`QemuBackend::sweep_orphans`] itself at start-up; this is the same call, on its own.
//! It reads the staging base under `$TMPDIR/sandy`, like a launch does.

use sandy_impls_vm::QemuBackend;

fn main() {
    let report = QemuBackend::sweep_orphans();
    println!("{report:?}");
}
