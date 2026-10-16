//! [`FakeContainment`]: a [`Containment`] test double with a fixed status, an
//! optional recorded `wrap` prefix, and a reaped-id log.

use std::sync::Mutex;

use sandy_api::{
    backend::BackendError,
    containment::{Containment, ContainmentStatus, Mount, ResourceLimits},
};

/// A test double: a fixed [`ContainmentStatus`], an optional recorded `wrap` prefix,
/// and a reaped-id log, so tests exercise the gate and the backend wiring (reap on
/// timeout and on kill) without a real cgroup.
#[derive(Debug)]
pub struct FakeContainment {
    status: ContainmentStatus,
    wrap_prefix: Vec<String>,
    confines: bool,
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

    /// A reaping containment that also reports filesystem confinement
    /// ([`confines_filesystem`](Containment::confines_filesystem) true) with an empty
    /// wrap (still spawnable), so a test can assert the backend advertises the
    /// faithful `/run/sandy/<tag>` paths. Still NOT an untrusted boundary.
    #[must_use]
    pub fn confining() -> Self {
        Self {
            status: ContainmentStatus::Available {
                isolates_untrusted: false,
            },
            wrap_prefix: Vec::new(),
            confines: true,
            reaped: Mutex::new(Vec::new()),
        }
    }

    fn with_status(status: ContainmentStatus) -> Self {
        Self {
            status,
            wrap_prefix: Vec::new(),
            confines: false,
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
            confines: false,
            reaped: Mutex::new(Vec::new()),
        }
    }

    /// An unavailable containment (supported platform, not usable now).
    #[must_use]
    pub fn unavailable(reason: &str) -> Self {
        Self {
            status: ContainmentStatus::Unavailable(reason.to_string()),
            wrap_prefix: Vec::new(),
            confines: false,
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

    fn wrap(&self, _id: &str, _limits: ResourceLimits, _mounts: &[Mount]) -> Vec<String> {
        self.wrap_prefix.clone()
    }

    fn confines_filesystem(&self) -> bool {
        self.confines
    }

    fn reap(&self, id: &str) -> Result<(), BackendError> {
        if let Ok(mut reaped) = self.reaped.lock() {
            reaped.push(id.to_string());
        }
        Ok(())
    }
}
