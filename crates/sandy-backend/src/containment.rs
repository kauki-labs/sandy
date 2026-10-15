//! The host containment implementation: an unprivileged cgroup-v2 confinement via
//! `systemd-run --user --scope` (#135).
//!
//! This is the concrete mechanism behind the [`Containment`] seam (the trait lives
//! in the `sandy` lib). It is kept in its own module beside [`ProcessBackend`](crate::ProcessBackend)
//! so the api/impls split stays mechanical: the trait is the api surface, this is a
//! local impl.
//!
//! Why `systemd-run --user --scope`: the hole #135 exists for is a descendant that
//! escapes the process group via `setsid`/`setpgid` — a `killpg` (and the backend's
//! existing group-reap) miss it, so it survives as a host orphan. Running the job in
//! a delegated cgroup (`-p Delegate=yes`) and destroying the scope at teardown
//! (`systemctl --user stop`) reaps the WHOLE cgroup, escapees included, with no
//! privilege and no `unsafe` (the crates are `forbid(unsafe_code)`). The tool is
//! swappable behind the seam.
//!
//! Availability is a capability answer, never a crash: a headless/CI host with no
//! user `systemd` instance or no cgroup v2 reports [`ContainmentStatus::Unavailable`];
//! macOS (no cgroup) reports [`ContainmentStatus::Unsupported`], and its real
//! boundary stays the vfkit VM. The fail-closed gate ([`sandy::admits_untrusted`])
//! refuses an untrusted job in either case.

use std::process::{Command, Stdio};

use sandy::{BackendError, Containment, ContainmentStatus, ResourceLimits};

/// Host containment via `systemd-run --user --scope` over cgroup v2. Its
/// [`status`](Containment::status) is probed once at [`detect`](SystemdRunContainment::detect)
/// and cached, so per-run calls do no IO.
#[derive(Debug, Clone)]
pub struct SystemdRunContainment {
    status: ContainmentStatus,
}

impl SystemdRunContainment {
    /// Probe host containment once and cache the verdict. On a non-Linux host this
    /// is [`ContainmentStatus::Unsupported`] without probing; on Linux it runs a
    /// throwaway `systemd-run --user --scope -- true` (cleaned up by `--collect`) —
    /// the honest capability test — and reports [`ContainmentStatus::Available`] on
    /// success, else [`ContainmentStatus::Unavailable`] with the reason.
    #[must_use]
    pub fn detect() -> Self {
        Self {
            status: detect_status(),
        }
    }

    /// Build a containment from an already-known status (for `sandy doctor`, which
    /// probes once and reuses the verdict).
    #[must_use]
    pub fn from_status(status: ContainmentStatus) -> Self {
        Self { status }
    }
}

impl Containment for SystemdRunContainment {
    fn status(&self) -> ContainmentStatus {
        self.status.clone()
    }

    fn wrap(&self, id: &str, limits: ResourceLimits) -> Vec<String> {
        // Only wrap when containment is actually available; otherwise run directly
        // (the backend's existing best-effort group-reap still applies, and an
        // untrusted job never reaches here — the gate refused it upstream).
        if !self.status.is_available() {
            return Vec::new();
        }
        systemd_run_prefix(id, limits)
    }

    fn passthrough_env(&self) -> Vec<String> {
        // `systemd-run --user` reaches the user systemd instance over the session
        // bus, found via these; without them the wrapped launch fails to connect.
        // They are paths/addresses, not secrets (INV-1), and only pass through when
        // containment actually wraps. `wrap` strips them from the inner job again.
        if !self.status.is_available() {
            return Vec::new();
        }
        WRAPPER_BUS_ENV.iter().map(|s| (*s).to_string()).collect()
    }

    fn reap(&self, id: &str) -> Result<(), BackendError> {
        // Nothing was contained if containment is unavailable, so there is no scope
        // to destroy — a no-op, not an error.
        if !self.status.is_available() {
            return Ok(());
        }
        let unit = scope_unit(id);
        // Destroying the scope reaps its whole cgroup (setsid escapees included).
        let out = Command::new("systemctl")
            .args(["--user", "stop", &unit])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            // The reap MECHANISM could not run (systemctl absent) — surface it.
            .output()
            .map_err(|err| BackendError::Transport(format!("reap scope {unit}: systemctl: {err}")))?;
        if out.status.success() {
            return Ok(());
        }
        // Exit 5 is systemd's "unit not loaded": the scope already exited and was
        // auto-collected (the common success path), so there is nothing left to reap.
        if out.status.code() == Some(5) {
            return Ok(());
        }
        // Any OTHER non-zero is a real reap failure — do not swallow it (the
        // silent-gate smell): the backend warn-logs and falls back to the group-kill.
        let stderr = String::from_utf8_lossy(&out.stderr);
        Err(BackendError::Transport(format!(
            "reap scope {unit}: systemctl --user stop exited {:?}: {}",
            out.status.code(),
            stderr.trim()
        )))
    }
}

/// The host env vars `systemd-run --user` needs to reach the user session bus. The
/// backend passes them to the WRAPPER (so it can connect), and [`SystemdRunContainment::wrap`]
/// strips them from the inner JOB's env (`env -u`) so an untrusted job cannot read the
/// bus address from its own environment. Defence in depth only: it is NOT a full
/// boundary (the socket still exists at its default path), which is why this
/// containment reports `isolates_untrusted: false` and the real boundary is the
/// mount-namespace work (#142).
const WRAPPER_BUS_ENV: [&str; 2] = ["XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"];

/// The transient scope unit name for container `id`. Derived deterministically so
/// `wrap` and `reap` agree with no shared state (mirroring the share transport's
/// deterministic socket paths).
fn scope_unit(id: &str) -> String {
    format!("sandy-{id}.scope")
}

/// The `systemd-run --user --scope` launch prefix (pure). The caller appends the
/// real program and args after the trailing `--`. `Delegate=yes` gives the scope a
/// delegated cgroup subtree so the whole tree is reaped on `stop`; the optional
/// `MemoryMax`/`CPUQuota` bound the run's resources.
fn systemd_run_prefix(id: &str, limits: ResourceLimits) -> Vec<String> {
    let mut prefix = vec![
        "systemd-run".to_string(),
        "--user".to_string(),
        "--scope".to_string(),
        "--quiet".to_string(),
        "--collect".to_string(),
        format!("--unit={}", scope_unit(id)),
        "--property=Delegate=yes".to_string(),
    ];
    if let Some(mem) = limits.mem_mib {
        prefix.push(format!("--property=MemoryMax={mem}M"));
    }
    if let Some(cpu) = limits.cpu {
        // CPUQuota is a percentage of one core, so N whole cores is N*100%.
        prefix.push(format!("--property=CPUQuota={}%", cpu * 100));
    }
    prefix.push("--".to_string());
    // Strip the wrapper's user-bus env from the JOB (defence in depth, CWE-269): the
    // scope inherits systemd-run's env, so without this the job could read the bus
    // address and spawn units outside the scope. `env -u` unsets them before exec'ing
    // the job; `env` resolves via the PATH the backend keeps.
    prefix.push("env".to_string());
    for key in WRAPPER_BUS_ENV {
        prefix.push("-u".to_string());
        prefix.push(key.to_string());
    }
    prefix
}

/// Probe the host containment capability (see [`SystemdRunContainment::detect`]).
fn detect_status() -> ContainmentStatus {
    if !cfg!(target_os = "linux") {
        return ContainmentStatus::Unsupported(
            "process containment needs Linux cgroup v2; on this platform the vfkit VM is the isolation boundary"
                .to_string(),
        );
    }
    // The honest test: can we actually open a delegated user scope? A missing user
    // systemd instance or cgroup v2 (headless/CI) fails here — a capability answer,
    // not a crash. `--collect` cleans the throwaway scope up.
    match Command::new("systemd-run")
        .args([
            "--user",
            "--scope",
            "--quiet",
            "--collect",
            "--property=Delegate=yes",
            "--",
            "true",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
    {
        // Available for REAPING, but isolates_untrusted: false — a plain systemd-run
        // scope reaps the tree and bounds resources, yet a job in it can reach the
        // user bus and spawn units outside the scope (CWE-269). The untrusted boundary
        // (mount namespace hiding the bus socket) is #142; until then the gate refuses
        // untrusted jobs even here.
        Ok(out) if out.status.success() => ContainmentStatus::Available {
            isolates_untrusted: false,
        },
        Ok(out) => {
            let reason = String::from_utf8_lossy(&out.stderr);
            let reason = reason.trim();
            ContainmentStatus::Unavailable(if reason.is_empty() {
                "systemd-run --user --scope failed (no user systemd instance or cgroup v2?)".to_string()
            } else {
                format!("systemd-run --user --scope failed: {reason}")
            })
        }
        Err(err) => ContainmentStatus::Unavailable(format!("systemd-run not runnable: {err}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The wrap prefix (pure) is the exact `systemd-run --user --scope` invocation,
    /// names the deterministic scope unit, and ends by stripping the wrapper's bus env
    /// from the inner job (`env -u …`).
    #[test]
    fn wrap_prefix_is_the_systemd_run_scope_invocation() {
        let prefix = systemd_run_prefix("run-abc", ResourceLimits::default());
        assert_eq!(
            prefix,
            vec![
                "systemd-run",
                "--user",
                "--scope",
                "--quiet",
                "--collect",
                "--unit=sandy-run-abc.scope",
                "--property=Delegate=yes",
                "--",
                "env",
                "-u",
                "XDG_RUNTIME_DIR",
                "-u",
                "DBUS_SESSION_BUS_ADDRESS",
            ]
        );
    }

    /// Resource limits map to cgroup properties: MiB → MemoryMax, whole cores →
    /// CPUQuota as a percentage of one core.
    #[test]
    fn wrap_prefix_includes_resource_limits() {
        let prefix = systemd_run_prefix(
            "run-1",
            ResourceLimits {
                cpu: Some(2),
                mem_mib: Some(512),
            },
        );
        assert!(
            prefix.contains(&"--property=MemoryMax=512M".to_string()),
            "mem_mib maps to MemoryMax, got {prefix:?}"
        );
        assert!(
            prefix.contains(&"--property=CPUQuota=200%".to_string()),
            "2 cores maps to CPUQuota=200%, got {prefix:?}"
        );
    }

    /// An unavailable containment never wraps (the job runs directly) and reaping is
    /// a no-op success (nothing was contained).
    #[test]
    fn unavailable_containment_does_not_wrap_or_fail_to_reap() {
        let c = SystemdRunContainment::from_status(ContainmentStatus::Unavailable("test".to_string()));
        assert!(c.wrap("run-1", ResourceLimits::default()).is_empty());
        assert!(c.reap("run-1").is_ok());
    }

    /// An available containment passes the systemd-run user-bus plumbing through;
    /// an unavailable one passes nothing (it wraps nothing).
    #[test]
    fn available_containment_passes_through_the_user_bus_env() {
        let available = SystemdRunContainment::from_status(ContainmentStatus::Available {
            isolates_untrusted: false,
        });
        assert!(
            available.passthrough_env().contains(&"XDG_RUNTIME_DIR".to_string()),
            "systemd-run needs XDG_RUNTIME_DIR to reach the user bus"
        );
        let unavailable = SystemdRunContainment::from_status(ContainmentStatus::Unavailable("x".to_string()));
        assert!(
            unavailable.passthrough_env().is_empty(),
            "an unavailable containment wraps nothing, so passes nothing through"
        );
    }

    /// An available containment wraps with the scope prefix and scrubs the bus env
    /// from the inner job, but reports itself as NOT an untrusted boundary (the user
    /// bus is still reachable; CWE-269) so the gate refuses untrusted jobs on it.
    #[test]
    fn available_containment_wraps_but_is_not_an_untrusted_boundary() {
        let c = SystemdRunContainment::from_status(ContainmentStatus::Available {
            isolates_untrusted: false,
        });
        let prefix = c.wrap("run-1", ResourceLimits::default());
        assert_eq!(prefix.first().map(String::as_str), Some("systemd-run"));
        assert!(
            prefix.contains(&"XDG_RUNTIME_DIR".to_string()) && prefix.contains(&"-u".to_string()),
            "wrap strips the wrapper bus env from the job, got {prefix:?}"
        );
        assert!(
            !c.status().is_untrusted_boundary(),
            "a plain systemd-run scope is not an untrusted boundary"
        );
    }

    /// macOS (and any non-Linux host) reports Unsupported — honest, mirroring the
    /// macOS-egress-unenforced posture. The real boundary is the vfkit VM.
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn non_linux_reports_unsupported() {
        assert!(matches!(detect_status(), ContainmentStatus::Unsupported(_)));
    }
}
