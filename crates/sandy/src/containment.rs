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
//! contract, the trivial [`NoContainment`], and the [`FakeContainment`] double.

use std::sync::Mutex;

pub use sandy_api::containment::{Containment, ContainmentStatus, ResourceLimits};

use crate::{BackendError, SandboxKind};

/// Whether a backend providing `kind`, with containment reporting `status`, may run
/// an **untrusted** job. Fail-closed:
///
/// - a [`SandboxKind::Vm`] backend is the strong isolation boundary, so it always admits an untrusted job regardless of
///   process-level containment;
/// - a [`SandboxKind::Process`] backend admits one only when its containment is an untrusted boundary
///   ([`ContainmentStatus::is_untrusted_boundary`]) — reap + user-bus/namespace isolation, NOT merely tree-reaping. A
///   plain `systemd-run` scope (reaps but leaves the user bus reachable, CWE-269), and any `Unavailable`/`Unsupported`
///   status, is REFUSED.
///
/// The untrusted-OK path therefore depends on the mount-namespace / bus-isolation
/// work (#142); until it lands, a process backend refuses untrusted jobs even where
/// cgroup reaping is Available. This is a dispatch-time admission check (parallel to
/// [`backend_accepts`](crate::backend_accepts)); the process backend is
/// library-only today, so the live enforcer is the fabric dispatcher.
#[must_use]
pub fn admits_untrusted(kind: SandboxKind, status: &ContainmentStatus) -> bool {
    match kind {
        SandboxKind::Vm => true,
        SandboxKind::Process => status.is_untrusted_boundary(),
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

    fn wrap(&self, _id: &str, _limits: ResourceLimits) -> Vec<String> {
        Vec::new()
    }

    fn reap(&self, _id: &str) -> Result<(), BackendError> {
        Ok(())
    }
}

/// A test double: a fixed [`ContainmentStatus`], an optional recorded `wrap` prefix,
/// and a reaped-id log, so tests exercise the gate and the backend wiring (reap on
/// timeout and on kill) without a real cgroup.
#[derive(Debug)]
pub struct FakeContainment {
    status: ContainmentStatus,
    wrap_prefix: Vec<String>,
    reaped: Mutex<Vec<String>>,
}

impl FakeContainment {
    /// A reaping-only containment with no wrap prefix (the job runs directly, so the
    /// double is spawnable in a unit test) that records every reaped id. Reaps trees
    /// but is NOT an untrusted boundary, so the gate still refuses untrusted jobs on
    /// it — the common state for exercising the reap/teardown wiring.
    #[must_use]
    pub fn available() -> Self {
        Self::with_status(ContainmentStatus::Available {
            isolates_untrusted: false,
        })
    }

    /// An untrusted-safe containment (reap + isolation): the only state the gate
    /// admits an untrusted process job on.
    #[must_use]
    pub fn isolating() -> Self {
        Self::with_status(ContainmentStatus::Available {
            isolates_untrusted: true,
        })
    }

    fn with_status(status: ContainmentStatus) -> Self {
        Self {
            status,
            wrap_prefix: Vec::new(),
            reaped: Mutex::new(Vec::new()),
        }
    }

    /// A reaping-only containment whose `wrap` returns `prefix` (to assert the
    /// backend prepends it). `prefix` should still spawn the appended program.
    #[must_use]
    pub fn available_wrapping(prefix: Vec<String>) -> Self {
        Self {
            status: ContainmentStatus::Available {
                isolates_untrusted: false,
            },
            wrap_prefix: prefix,
            reaped: Mutex::new(Vec::new()),
        }
    }

    /// An unavailable containment (supported platform, not usable now).
    #[must_use]
    pub fn unavailable(reason: &str) -> Self {
        Self {
            status: ContainmentStatus::Unavailable(reason.to_string()),
            wrap_prefix: Vec::new(),
            reaped: Mutex::new(Vec::new()),
        }
    }

    /// The ids passed to [`reap`](Containment::reap), in call order.
    #[must_use]
    pub fn reaped(&self) -> Vec<String> {
        self.reaped.lock().map(|r| r.clone()).unwrap_or_default()
    }
}

impl Containment for FakeContainment {
    fn status(&self) -> ContainmentStatus {
        self.status.clone()
    }

    fn wrap(&self, _id: &str, _limits: ResourceLimits) -> Vec<String> {
        self.wrap_prefix.clone()
    }

    fn reap(&self, id: &str) -> Result<(), BackendError> {
        if let Ok(mut reaped) = self.reaped.lock() {
            reaped.push(id.to_string());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The gate is fail-closed AND honest: a process backend admits an untrusted job
    /// only when its containment is an untrusted BOUNDARY (reap + isolation).
    /// Tree-reaping alone (`Available { isolates_untrusted: false }`, a plain
    /// systemd-run scope with a reachable user bus, CWE-269), Unavailable, and
    /// Unsupported are all REFUSED. A VM backend always admits. Asserts the BAD path.
    #[test]
    fn the_gate_refuses_an_untrusted_process_job_without_an_isolating_containment() {
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
            admits_untrusted(
                SandboxKind::Process,
                &ContainmentStatus::Available {
                    isolates_untrusted: true
                }
            ),
            "an isolating containment admits an untrusted process job"
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
        assert!(c.wrap("run-1", ResourceLimits::default()).is_empty());
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
