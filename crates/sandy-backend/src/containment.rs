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
        // containment actually wraps.
        if !self.status.is_available() {
            return Vec::new();
        }
        vec!["XDG_RUNTIME_DIR".to_string(), "DBUS_SESSION_BUS_ADDRESS".to_string()]
    }

    fn reap(&self, id: &str) -> Result<(), BackendError> {
        // Nothing was contained if containment is unavailable, so there is no scope
        // to destroy — a no-op, not an error.
        if !self.status.is_available() {
            return Ok(());
        }
        let unit = scope_unit(id);
        // Destroying the scope reaps its whole cgroup (setsid escapees included).
        // Best-effort: a unit that already exited (the common success path, auto-
        // collected) makes `stop` report "not loaded" — not a failure to reap.
        match Command::new("systemctl")
            .args(["--user", "stop", &unit])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
        {
            Ok(_) => Ok(()),
            // The reap MECHANISM could not run (systemctl absent). Surface it so the
            // backend warn-logs rather than silently dropping the reap; the backend
            // still falls back to its process-group kill.
            Err(err) => Err(BackendError::Transport(format!("reap scope {unit}: systemctl: {err}"))),
        }
    }
}

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
        Ok(out) if out.status.success() => ContainmentStatus::Available,
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
    /// ends in `--`, and names the deterministic scope unit.
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
        let available = SystemdRunContainment::from_status(ContainmentStatus::Available);
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

    /// An available containment wraps with the scope prefix.
    #[test]
    fn available_containment_wraps() {
        let c = SystemdRunContainment::from_status(ContainmentStatus::Available);
        let prefix = c.wrap("run-1", ResourceLimits::default());
        assert_eq!(prefix.first().map(String::as_str), Some("systemd-run"));
        assert_eq!(prefix.last().map(String::as_str), Some("--"));
    }

    /// macOS (and any non-Linux host) reports Unsupported — honest, mirroring the
    /// macOS-egress-unenforced posture. The real boundary is the vfkit VM.
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn non_linux_reports_unsupported() {
        assert!(matches!(detect_status(), ContainmentStatus::Unsupported(_)));
    }
}
