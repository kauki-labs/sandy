//! Ties what an environment holds beside its run (a host bridge and its probe registration) to the run itself
//! (#587, slice C3b).
//!
//! The qemu backend reports the guest's CID to a hook after the guest has booted (vfkit has no CID: the agent link
//! coming up starts the bridge). The bridge must stop when `run()` returns: a CID then belongs to nobody, and another
//! VM can take it. A
//! [`GuardedBackend`] wraps the hypervisor backend the factory builds and drops the [`RunGuards`] it shares with
//! the hook as soon as `run()` returns, however it ends. A hook that fires after that point has its guard dropped
//! on the spot.

use std::sync::{Arc, Mutex, PoisonError};

use sandy_api::backend::{BackendError, BoxState, Outcome, RunSpec, SandboxKind, VirtualizationBackend};

/// What an environment holds while its run is up. Dropping it releases it.
pub type RunGuard = Box<dyn Send>;

#[derive(Default)]
struct Slot {
    closed: bool,
    guard: Option<RunGuard>,
}

/// The place a hook puts the guard of what it started. Clone it into the hook and into [`guarded`].
#[derive(Clone, Default)]
pub struct RunGuards(Arc<Mutex<Slot>>);

impl RunGuards {
    /// A new, open slot.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Hold `guard` until the run ends. A slot whose run already ended drops it at once, so a hook that fires late
    /// cannot leave a bridge behind. A second guard replaces the first, which is dropped.
    pub fn hold(&self, guard: RunGuard) {
        let dropped = {
            let mut slot = self.0.lock().unwrap_or_else(PoisonError::into_inner);
            if slot.closed {
                Some(guard)
            } else {
                slot.guard.replace(guard)
            }
        };
        release(dropped); // outside the lock: a guard's drop may take other locks
    }

    /// Build a guard and hold it, but only while the run is up. `make` runs under the slot's lock, so a run that
    /// ended before it could start never has `make` called: whatever `make` registers elsewhere (a probe address)
    /// cannot outlive its run or be replaced by a late hook of an earlier one. Keep `make` short and free of
    /// calls back into this slot. Returns whether `make` ran.
    pub fn hold_if_open(&self, make: impl FnOnce() -> RunGuard) -> bool {
        let (ran, dropped) = {
            let mut slot = self.0.lock().unwrap_or_else(PoisonError::into_inner);
            if slot.closed {
                (false, None)
            } else {
                (true, slot.guard.replace(make()))
            }
        };
        release(dropped);
        ran
    }

    /// Close the slot and drop what it holds.
    fn close(&self) {
        let dropped = {
            let mut slot = self.0.lock().unwrap_or_else(PoisonError::into_inner);
            slot.closed = true;
            slot.guard.take()
        };
        release(dropped);
    }
}

/// Drops a guard, containing a panic in its `Drop`: this can run during an unwind, where a second panic aborts
/// the daemon.
fn release(guard: Option<RunGuard>) {
    if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(guard))).is_err() {
        tracing::error!("a run guard panicked while it was released");
    }
}

/// A [`VirtualizationBackend`] that closes its [`RunGuards`] when `run` returns.
pub struct GuardedBackend<B> {
    inner: B,
    guards: RunGuards,
}

/// Wrap `inner` so `guards` are released when its run ends.
#[must_use]
pub fn guarded<B>(inner: B, guards: &RunGuards) -> GuardedBackend<B> {
    GuardedBackend {
        inner,
        guards: guards.clone(),
    }
}

impl<B: VirtualizationBackend> VirtualizationBackend for GuardedBackend<B> {
    fn run(&self, spec: &RunSpec) -> Result<Outcome, BackendError> {
        let outcome = self.inner.run(spec);
        self.guards.close();
        outcome
    }

    fn kill(&self, box_id: &str) -> Result<(), BackendError> {
        self.inner.kill(box_id)
    }

    fn boxes(&self) -> Result<Vec<BoxState>, BackendError> {
        self.inner.boxes()
    }

    fn kind(&self) -> SandboxKind {
        self.inner.kind()
    }
}

impl<B> Drop for GuardedBackend<B> {
    fn drop(&mut self) {
        // A run that panicked never reached `close` above.
        self.guards.close();
    }
}
