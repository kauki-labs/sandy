//! The containment seam: how a non-VM executor confines a job so its whole
//! process tree — including a `setsid`/`setpgid`-escaped descendant — is reaped,
//! and (later) resource-bounded.
//!
//! This is the contract only: the trait, its status/limits types, and the shared-
//! ownership blanket impl. The concrete mechanisms (the host `SystemdRunContainment`,
//! the trivial `NoContainment`, the fake), and the `admits_untrusted` gate, live in
//! the crates that depend on this one.

use std::{path::PathBuf, sync::Arc};

use crate::backend::BackendError;

/// Whether host containment is usable for a process-backend job right now.
///
/// Two capabilities are deliberately split (CWE-269 honesty): *tree-reaping*
/// (`Available`) and *untrusted isolation* (`Available { isolates_untrusted: true }`).
/// A cgroup scope reaps the whole process tree and bounds resources, but a job
/// inside it can still reach the user session bus and spawn units OUTSIDE the scope
/// that teardown never reaps — so tree-reaping alone is NOT a boundary for untrusted
/// code. The core's `admits_untrusted` keys off the stronger capability; reaping/
/// teardown key off [`is_available`](ContainmentStatus::is_available).
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
    /// reason. An untrusted job is refused.
    Unavailable(String),
    /// Not supported on this platform at all (macOS has no cgroup; the real
    /// boundary is the vfkit VM). The string is the diagnostic reason. An untrusted
    /// job is refused.
    Unsupported(String),
}

impl ContainmentStatus {
    /// Whether containment can reap the job's process tree (and bound resources).
    /// Drives teardown/`kill`/`wrap`; NOT sufficient on its own to admit an
    /// untrusted job (see the core's `admits_untrusted`).
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

/// One filesystem share to present inside the job's mount namespace: the host
/// directory [`host`](Mount::host) bind-mounted at [`guest`](Mount::guest)
/// (read-only for inputs/secrets, writable for outputs).
///
/// A containment that provides a mount namespace ([`confines_filesystem`](Containment::confines_filesystem))
/// binds these at faithful paths (e.g. `/run/sandy/inputs`) with hard read-only;
/// one that does not ignores them, and the backend exposes the host dirs directly
/// (via `SANDY_*_DIR` pointers) with only cooperative read-only (#142).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mount {
    /// Host directory holding the staged bytes.
    pub host: PathBuf,
    /// Path the job sees it at inside the namespace (e.g. `/run/sandy/inputs`).
    pub guest: PathBuf,
    /// Deny the job writes (inputs, secrets); outputs are writable.
    pub readonly: bool,
}

/// How a non-VM executor confines a job. One implementation per mechanism: the
/// trivial `NoContainment`, the host `SystemdRunContainment`, and the fake test
/// double.
///
/// The pure/IO split is preserved so [`wrap`](Containment::wrap) stays tier-1
/// testable (no IO) while [`reap`](Containment::reap) does the teardown IO.
pub trait Containment: std::fmt::Debug + Send + Sync {
    /// Whether containment is usable right now. Drives the fail-closed gate and
    /// `sandy doctor`.
    fn status(&self) -> ContainmentStatus;

    /// The launch-command prefix that runs a job confined under container `id`
    /// (e.g. `["systemd-run", "--user", "--scope", …, "--"]`); the caller appends
    /// the real program and args. `mounts` are the shares to present inside the
    /// namespace — honoured only when [`confines_filesystem`](Containment::confines_filesystem)
    /// is true (bound at their `guest` paths, hard read-only), ignored otherwise.
    /// Empty return means run the job directly (no containment). PURE: no IO, so the
    /// exact argv is unit-testable.
    fn wrap(&self, id: &str, limits: ResourceLimits, mounts: &[Mount]) -> Vec<String>;

    /// Whether [`wrap`](Containment::wrap) puts the job in a mount namespace that
    /// binds `mounts` at their faithful `guest` paths with hard read-only and hides
    /// the user-session bus. When true the backend advertises the faithful
    /// `/run/sandy/<tag>` paths (and need not enforce cooperative read-only); when
    /// false it exposes the host staging dirs and keeps the cooperative fallback.
    /// This is a confinement-feature flag, NOT an untrusted-safety claim — it does
    /// not imply [`ContainmentStatus::is_untrusted_boundary`] (#142; the untrusted
    /// gate-flip is tracked separately in #150). Defaults to false.
    fn confines_filesystem(&self) -> bool {
        false
    }

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

/// Shared ownership of a containment is a containment, so a backend can hold a
/// `Box<dyn Containment>` built from an `Arc` while a test keeps a clone to inspect
/// (the fake's reap log).
impl<C: Containment + ?Sized> Containment for Arc<C> {
    fn status(&self) -> ContainmentStatus {
        (**self).status()
    }

    fn wrap(&self, id: &str, limits: ResourceLimits, mounts: &[Mount]) -> Vec<String> {
        (**self).wrap(id, limits, mounts)
    }

    fn confines_filesystem(&self) -> bool {
        (**self).confines_filesystem()
    }

    fn reap(&self, id: &str) -> Result<(), BackendError> {
        (**self).reap(id)
    }

    fn passthrough_env(&self) -> Vec<String> {
        (**self).passthrough_env()
    }
}
