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

use std::sync::{Arc, Mutex};

use crate::{BackendError, SandboxKind};

/// Whether host containment is usable for a process-backend job right now.
///
/// Two capabilities are deliberately split (CWE-269 honesty): *tree-reaping*
/// (`Available`) and *untrusted isolation* (`Available { isolates_untrusted: true }`).
/// A cgroup scope reaps the whole process tree and bounds resources, but a job
/// inside it can still reach the user session bus and spawn units OUTSIDE the scope
/// that teardown never reaps — so tree-reaping alone is NOT a boundary for untrusted
/// code. [`admits_untrusted`] keys off the stronger capability; reaping/teardown key
/// off [`is_available`](ContainmentStatus::is_available).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContainmentStatus {
    /// Real containment is available: the whole process tree is reaped on teardown
    /// and resources are bounded. `isolates_untrusted` is whether this host ALSO
    /// isolates an adversary (reap + user-bus / mount-namespace isolation); a plain
    /// `systemd-run` scope sets it `false` (it reaps but does not contain a job that
    /// talks to the user bus). The untrusted boundary lands with the mount-namespace
    /// work (#142).
    Available {
        /// Whether this containment is a safe boundary for UNTRUSTED code, not only
        /// a reaper of cooperative trees.
        isolates_untrusted: bool,
    },
    /// Supported on this platform but not usable now (e.g. no user `systemd`
    /// instance or cgroup v2, common in headless/CI). The string is the diagnostic
    /// reason. An untrusted job is refused ([`admits_untrusted`]).
    Unavailable(String),
    /// Not supported on this platform at all (macOS has no cgroup; the real
    /// boundary is the vfkit VM). The string is the diagnostic reason. An untrusted
    /// job is refused.
    Unsupported(String),
}

impl ContainmentStatus {
    /// Whether containment can reap the job's process tree (and bound resources).
    /// Drives teardown/`kill`/`wrap`; NOT sufficient on its own to admit an
    /// untrusted job (see [`admits_untrusted`]).
    #[must_use]
    pub fn is_available(&self) -> bool {
        matches!(self, ContainmentStatus::Available { .. })
    }

    /// Whether this containment is a safe boundary for untrusted code (reap + bus /
    /// namespace isolation). `false` for a plain reaper and for any unavailable or
    /// unsupported status.
    #[must_use]
    pub fn is_untrusted_boundary(&self) -> bool {
        matches!(
            self,
            ContainmentStatus::Available {
                isolates_untrusted: true
            }
        )
    }
}

/// Resource bounds for a contained job, derived from the run's cpu/mem request.
/// Honoured only by a containment that supports them; a [`None`] field is left
/// unbounded.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ResourceLimits {
    /// vCPU budget in whole cores, mapped to a cgroup CPU quota.
    pub cpu: Option<u32>,
    /// Memory budget in MiB, mapped to a cgroup memory max.
    pub mem_mib: Option<u32>,
}

/// How a non-VM executor confines a job. One implementation per mechanism: the
/// trivial [`NoContainment`], the host `SystemdRunContainment` (sandy-backend), and
/// the [`FakeContainment`] test double.
///
/// The pure/IO split is preserved so [`wrap`](Containment::wrap) stays tier-1
/// testable (no IO) while [`reap`](Containment::reap) does the teardown IO.
pub trait Containment: std::fmt::Debug + Send + Sync {
    /// Whether containment is usable right now. Drives the fail-closed gate and
    /// `sandy doctor`.
    fn status(&self) -> ContainmentStatus;

    /// The launch-command prefix that runs a job confined under container `id`
    /// (e.g. `["systemd-run", "--user", "--scope", …, "--"]`); the caller appends
    /// the real program and args. Empty means run the job directly (no
    /// containment). PURE: no IO, so the exact argv is unit-testable.
    fn wrap(&self, id: &str, limits: ResourceLimits) -> Vec<String>;

    /// Reap container `id`'s whole process tree, including a `setsid`/`setpgid`
    /// escapee a process-group kill would miss. Idempotent and best-effort:
    /// reaping an already-gone container is `Ok`.
    ///
    /// # Errors
    /// [`BackendError`] if the reap mechanism itself cannot be run.
    fn reap(&self, id: &str) -> Result<(), BackendError>;

    /// Host environment variable NAMES the [`wrap`](Containment::wrap) prefix needs
    /// passed through from the host to function (e.g. `systemd-run --user` reaches
    /// the user bus via `XDG_RUNTIME_DIR`). These are plumbing, never secrets, so the
    /// backend passes them from the host env in addition to `PATH`; they are absent
    /// when the backend clears the rest of the ambient env (INV-1). Defaults to none
    /// (a containment that wraps nothing needs nothing passed through).
    fn passthrough_env(&self) -> Vec<String> {
        Vec::new()
    }
}

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

/// Shared ownership of a containment is a containment, so a backend can hold a
/// `Box<dyn Containment>` built from an `Arc` while a test keeps a clone to inspect
/// (the [`FakeContainment`] reap log).
impl<C: Containment + ?Sized> Containment for Arc<C> {
    fn status(&self) -> ContainmentStatus {
        (**self).status()
    }

    fn wrap(&self, id: &str, limits: ResourceLimits) -> Vec<String> {
        (**self).wrap(id, limits)
    }

    fn reap(&self, id: &str) -> Result<(), BackendError> {
        (**self).reap(id)
    }

    fn passthrough_env(&self) -> Vec<String> {
        (**self).passthrough_env()
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
