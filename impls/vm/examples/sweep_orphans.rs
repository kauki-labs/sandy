//! Run the start-up sweep for orphaned qemu VMs once and print what it did (#666).
//!
//! The live gate `scripts/dev/live-orphan-sweep.sh` uses it to prove that a SIGKILLed host's VM is found and
//! stopped. It is the call `sandyd` will make once at start-up (the wiring is separate work on the environment
//! backend); no shipped binary calls [`QemuBackend::sweep_orphans`] yet, so this is its only caller. It reads the
//! staging base under `$TMPDIR/sandy`, like a launch does.

use sandy_impls_vm::QemuBackend;

fn main() {
    let report = QemuBackend::sweep_orphans();
    println!("{report:?}");
}
