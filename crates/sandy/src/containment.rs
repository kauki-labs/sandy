//! The containment seam: how a non-VM executor confines a job so its whole
//! process tree — including a `setsid`/`setpgid`-escaped descendant — is reaped,
//! and (later) resource-bounded and path-faithful.
//!
//! This is the process backend's real isolation story (#135). The VM backend is
//! the strong boundary; a process backend whose containment is not
//! [`ContainmentStatus::Available`] must not run an untrusted job — the fail-closed
//! gate [`admits_untrusted`]. A disabled gate is observably distinguishable from a
//! working one: the gate is a pure function with an asserted refusal.
//!
//! Pure/IO split (run-plane decision #1, mirroring the share transport's
//! `plan`/`activate`): [`Containment::wrap`] computes the launch-command prefix
//! with no IO, so the exact argv is tier-1 testable; [`Containment::reap`] does the
//! IO (destroy the container, reaping escapees). [`Containment::status`] reports
//! availability for the gate and `sandy doctor`.
//!
//! The concrete mechanism (`systemd-run --user --scope`, cgroup v2) lives behind
//! the seam in `sandy-backend` so it stays swappable; this crate carries only the
//! contract and the trivial [`NoContainment`]. The `FakeContainment` double lives in
//! `sandy-test-support`.

pub use sandy_api::containment::{Containment, ContainmentStatus, Mount, ResourceLimits};

use crate::{BackendError, SandboxKind};

/// Whether a backend providing `kind` may run an **untrusted** job. Untrusted jobs
/// are VM-only (`docs/decisions/process-containment.md` §6, #150):
///
/// - a [`SandboxKind::Vm`] backend is the isolation boundary, so it admits an untrusted job;
/// - a [`SandboxKind::Process`] backend never admits one, whatever its containment reports. `_status` does not change
///   the result, not even [`ContainmentStatus::is_untrusted_boundary`].
///
/// This is a dispatch-time admission check, parallel to
/// [`backend_accepts`](crate::backend_accepts).
#[must_use]
pub fn admits_untrusted(kind: SandboxKind, _status: &ContainmentStatus) -> bool {
    match kind {
        SandboxKind::Vm => true,
        SandboxKind::Process => false,
    }
}

/// The trivial containment: never available, never wraps, never reaps. The library
/// default so unit tests and the uncontained trusted MVP stay hermetic; the real
/// host containment is wired at the composition root (sandy-cli).
#[derive(Debug, Clone, Copy, Default)]
pub struct NoContainment;

impl Containment for NoContainment {
    fn status(&self) -> ContainmentStatus {
        ContainmentStatus::Unavailable("no containment configured".to_string())
    }

    fn wrap(&self, _id: &str, _limits: ResourceLimits, _mounts: &[Mount]) -> Vec<String> {
        Vec::new()
    }

    fn reap(&self, _id: &str) -> Result<(), BackendError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use sandy_test_support::FakeContainment;

    use super::*;

    /// The gate is fail-closed AND honest: a process backend admits an untrusted job
    /// only when its containment is an untrusted BOUNDARY (reap + isolation).
    /// Tree-reaping alone (`Available { isolates_untrusted: false }`, a plain
    /// systemd-run scope with a reachable user bus, CWE-269), Unavailable, and
    /// Unsupported are all REFUSED. A VM backend always admits. Asserts the BAD path.
    #[test]
    fn the_gate_refuses_every_untrusted_process_job() {
        assert!(
            !admits_untrusted(
                SandboxKind::Process,
                &ContainmentStatus::Available {
                    isolates_untrusted: false
                }
            ),
            "tree-reaping alone is not an untrusted boundary (the user bus is reachable); refuse"
        );
        assert!(
            !admits_untrusted(
                SandboxKind::Process,
                &ContainmentStatus::Unavailable("no user systemd".into())
            ),
            "unavailable containment must refuse an untrusted process job"
        );
        assert!(
            !admits_untrusted(SandboxKind::Process, &ContainmentStatus::Unsupported("macos".into())),
            "unsupported containment must refuse an untrusted process job"
        );
        assert!(
            !admits_untrusted(
                SandboxKind::Process,
                &ContainmentStatus::Available {
                    isolates_untrusted: true
                }
            ),
            "untrusted is VM-only (process-containment.md §6): even an isolating containment refuses"
        );
        assert!(
            admits_untrusted(SandboxKind::Vm, &ContainmentStatus::Unavailable("irrelevant".into())),
            "a VM backend is the strong boundary, it always admits"
        );
    }

    /// NoContainment is inert: never available, empty wrap, Ok reap.
    #[test]
    fn no_containment_is_inert() {
        let c = NoContainment;
        assert!(matches!(c.status(), ContainmentStatus::Unavailable(_)));
        assert!(c.wrap("run-1", ResourceLimits::default(), &[]).is_empty());
        assert!(!c.confines_filesystem(), "NoContainment provides no mount namespace");
        assert!(c.reap("run-1").is_ok());
    }

    /// FakeContainment records reaped ids in order, for the backend wiring tests.
    #[test]
    fn fake_containment_records_reaps() {
        let c = FakeContainment::available();
        c.reap("a").expect("reap a");
        c.reap("b").expect("reap b");
        assert_eq!(c.reaped(), vec!["a".to_string(), "b".to_string()]);
    }
}
