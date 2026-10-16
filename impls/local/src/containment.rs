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

use sandy::{BackendError, Containment, ContainmentStatus, Mount, ResourceLimits};

/// Host containment via `systemd-run --user --scope` over cgroup v2, optionally
/// composed with a `bwrap` mount namespace for path-faithful shares, hard read-only,
/// and user-bus hiding (#142). Both capabilities are probed once at
/// [`detect`](SystemdRunContainment::detect) and cached, so per-run calls do no IO.
///
/// `confines` (the bwrap layer) is a confinement-feature flag only: it does NOT make
/// the status an untrusted boundary (`isolates_untrusted` stays false — the job can
/// still read the host rootfs under the A1 `--ro-bind / /` and the net namespace is
/// shared). The untrusted gate-flip decision is tracked in #150.
#[derive(Debug, Clone)]
pub struct SystemdRunContainment {
    status: ContainmentStatus,
    confines: bool,
}

impl SystemdRunContainment {
    /// Probe host containment once and cache the verdict. On a non-Linux host the
    /// status is [`ContainmentStatus::Unsupported`] without probing; on Linux it runs
    /// a throwaway `systemd-run --user --scope -- true` (cleaned up by `--collect`)
    /// for reaping, and a throwaway `bwrap … -- true` for the mount-namespace layer
    /// (unprivileged user namespaces may be disabled by sysctl/AppArmor). `confines`
    /// is set only when both pass.
    #[must_use]
    pub fn detect() -> Self {
        let status = detect_status();
        let confines = status.is_available() && detect_bwrap_confinement();
        Self { status, confines }
    }

    /// Build a containment from an already-known status, reaping-only (no bwrap).
    /// For `sandy doctor` and tests.
    #[must_use]
    pub fn from_status(status: ContainmentStatus) -> Self {
        Self {
            status,
            confines: false,
        }
    }

    /// Build a containment with both the status and the bwrap-confinement flag set
    /// explicitly (tests exercise the confining `wrap` path without a real bwrap).
    #[must_use]
    pub fn from_parts(status: ContainmentStatus, confines: bool) -> Self {
        Self { status, confines }
    }
}

impl Containment for SystemdRunContainment {
    fn status(&self) -> ContainmentStatus {
        self.status.clone()
    }

    fn wrap(&self, id: &str, limits: ResourceLimits, mounts: &[Mount]) -> Vec<String> {
        // Only wrap when containment is actually available; otherwise run directly
        // (the backend's existing best-effort group-reap still applies, and an
        // untrusted job never reaches here — the gate refused it upstream).
        if !self.status.is_available() {
            return Vec::new();
        }
        let mut cmd = scope_prefix(id, limits);
        if self.confines {
            // bwrap inside the scope: path-faithful shares, hard RO, user-bus hidden
            // (#142). bwrap's `--unsetenv` handles the bus-env strip the non-confining
            // path does with `env -u`.
            cmd.extend(bwrap_segment(mounts));
        } else {
            // No mount namespace: strip the wrapper's bus env from the job (the #135
            // defence-in-depth), then exec the job directly in the scope.
            cmd.push("env".to_string());
            for key in WRAPPER_BUS_ENV {
                cmd.push("-u".to_string());
                cmd.push(key.to_string());
            }
        }
        cmd
    }

    fn confines_filesystem(&self) -> bool {
        self.confines
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

/// The faithful in-namespace root the shares are bound under, matching the VM's
/// fixed mount paths (`/run/sandy/{inputs,outputs,secrets}`).
const SANDY_RUN_DIR: &str = "/run/sandy";

/// The `systemd-run --user --scope` launch prefix through the trailing `--` (pure).
/// `Delegate=yes` gives the scope a delegated cgroup subtree so the whole tree is
/// reaped on `stop`; the optional `MemoryMax`/`CPUQuota` bound the run's resources.
/// What follows the `--` (a `bwrap` segment, or a bus-env strip + the job) is chosen
/// by [`SystemdRunContainment::wrap`].
fn scope_prefix(id: &str, limits: ResourceLimits) -> Vec<String> {
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
        // Saturating: `cpu` is an unvalidated request, and a panic/wrap in library
        // code on an absurd value is worse than a clamped quota.
        prefix.push(format!("--property=CPUQuota={}%", cpu.saturating_mul(100)));
    }
    prefix.push("--".to_string());
    prefix
}

/// The `bwrap` segment (through its trailing `--`) that confines the job in a mount
/// namespace (#142): the host rootfs read-only (A1, so host binaries resolve), fresh
/// `/dev` + `/proc`, the user-session bus hidden (a tmpfs over `/run/user` plus
/// unsetting the bus env, so the job cannot reach the user systemd manager), and each
/// share bound at its faithful `/run/sandy/<tag>` path — read-only for inputs/secrets,
/// writable for outputs. Non-net namespaces are unshared (net stays shared; egress is
/// a separate concern). Pure, so the exact argv is unit-testable.
///
/// NOTE: A1 `--ro-bind / /` leaves the host filesystem READABLE to the job, so this
/// is write-confinement + reaping + bus-hide, not read-confidentiality — hence
/// `isolates_untrusted` stays false (#150).
fn bwrap_segment(mounts: &[Mount]) -> Vec<String> {
    let mut seg = vec![
        "bwrap".to_string(),
        "--ro-bind".to_string(),
        "/".to_string(),
        "/".to_string(),
        "--dev".to_string(),
        "/dev".to_string(),
        "--proc".to_string(),
        "/proc".to_string(),
        // Hide the user session bus: a tmpfs over /run/user drops the socket, and
        // unsetting the pointers removes the fallback address.
        "--tmpfs".to_string(),
        "/run/user".to_string(),
        "--unsetenv".to_string(),
        "XDG_RUNTIME_DIR".to_string(),
        "--unsetenv".to_string(),
        "DBUS_SESSION_BUS_ADDRESS".to_string(),
        // A clean writable mountpoint for the faithful share paths, independent of
        // the read-only host /run.
        "--tmpfs".to_string(),
        SANDY_RUN_DIR.to_string(),
    ];
    for m in mounts {
        seg.push(if m.readonly {
            "--ro-bind".to_string()
        } else {
            "--bind".to_string()
        });
        seg.push(m.host.display().to_string());
        seg.push(m.guest.display().to_string());
    }
    seg.extend([
        "--unshare-pid".to_string(),
        "--unshare-ipc".to_string(),
        "--unshare-uts".to_string(),
        "--unshare-cgroup".to_string(),
        "--die-with-parent".to_string(),
        "--chdir".to_string(),
        "/".to_string(),
        "--".to_string(),
    ]);
    seg
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

/// Probe whether `bwrap` can open an unprivileged mount namespace here (#142). A
/// throwaway `bwrap … -- true`: it succeeds only when the bubblewrap binary is
/// present AND unprivileged user namespaces are permitted (they can be disabled by
/// `kernel.unprivileged_userns_clone=0` or an AppArmor profile). On failure the
/// confinement features stay off and the backend keeps its `SANDY_*_DIR` + cooperative
/// read-only behaviour. Non-Linux never confines.
fn detect_bwrap_confinement() -> bool {
    if !cfg!(target_os = "linux") {
        return false;
    }
    Command::new("bwrap")
        .args([
            "--ro-bind",
            "/",
            "/",
            "--dev",
            "/dev",
            "--unshare-pid",
            "--die-with-parent",
            "--",
            "true",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The scope prefix (pure) is the exact `systemd-run --user --scope` invocation
    /// through the trailing `--`, naming the deterministic scope unit. What follows
    /// the `--` is chosen by `wrap` (bwrap, or a bus-env strip).
    #[test]
    fn scope_prefix_is_the_systemd_run_scope_invocation() {
        let prefix = scope_prefix("run-abc", ResourceLimits::default());
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
    fn scope_prefix_includes_resource_limits() {
        let prefix = scope_prefix(
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
        assert!(c.wrap("run-1", ResourceLimits::default(), &[]).is_empty());
        assert!(!c.confines_filesystem());
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

    /// A reaping-only (non-confining) available containment wraps with the scope
    /// prefix and scrubs the bus env from the inner job via `env -u`, does NOT
    /// confine the filesystem, and is NOT an untrusted boundary (CWE-269).
    #[test]
    fn non_confining_wrap_strips_bus_env_and_is_not_a_boundary() {
        let c = SystemdRunContainment::from_status(ContainmentStatus::Available {
            isolates_untrusted: false,
        });
        let prefix = c.wrap("run-1", ResourceLimits::default(), &[]);
        assert_eq!(prefix.first().map(String::as_str), Some("systemd-run"));
        assert!(
            prefix.windows(2).any(|w| w == ["-u", "XDG_RUNTIME_DIR"]),
            "non-confining wrap strips the bus env with `env -u`, got {prefix:?}"
        );
        assert!(!prefix.iter().any(|a| a == "bwrap"), "no bwrap when not confining");
        assert!(!c.confines_filesystem());
        assert!(!c.status().is_untrusted_boundary());
    }

    /// A confining available containment composes bwrap inside the scope: host
    /// rootfs read-only, the user bus hidden, and each share bound at its faithful
    /// `/run/sandy/<tag>` path (read-only for inputs, writable for outputs). It
    /// confines the filesystem but STILL is not an untrusted boundary (#150).
    #[test]
    fn confining_wrap_emits_bwrap_with_faithful_binds() {
        let c = SystemdRunContainment::from_parts(
            ContainmentStatus::Available {
                isolates_untrusted: false,
            },
            true,
        );
        let mounts = [
            Mount {
                host: "/tmp/sandy/run-1-inputs".into(),
                guest: "/run/sandy/inputs".into(),
                readonly: true,
            },
            Mount {
                host: "/tmp/sandy/run-1-outputs".into(),
                guest: "/run/sandy/outputs".into(),
                readonly: false,
            },
        ];
        let cmd = c.wrap("run-1", ResourceLimits::default(), &mounts);

        assert_eq!(cmd.first().map(String::as_str), Some("systemd-run"));
        assert!(
            cmd.iter().any(|a| a == "bwrap"),
            "confining wrap composes bwrap, got {cmd:?}"
        );
        assert_eq!(cmd.last().map(String::as_str), Some("--"), "ends ready for the job");
        // Host rootfs read-only, bus hidden.
        assert!(
            cmd.windows(3).any(|w| w == ["--ro-bind", "/", "/"]),
            "host rootfs ro-bound"
        );
        assert!(
            cmd.windows(2).any(|w| w == ["--tmpfs", "/run/user"]),
            "user-bus dir hidden"
        );
        assert!(
            cmd.windows(2).any(|w| w == ["--unsetenv", "DBUS_SESSION_BUS_ADDRESS"]),
            "bus env unset"
        );
        // Faithful binds: inputs read-only, outputs writable.
        assert!(
            cmd.windows(3)
                .any(|w| w == ["--ro-bind", "/tmp/sandy/run-1-inputs", "/run/sandy/inputs"]),
            "inputs bound read-only at the faithful path, got {cmd:?}"
        );
        assert!(
            cmd.windows(3)
                .any(|w| w == ["--bind", "/tmp/sandy/run-1-outputs", "/run/sandy/outputs"]),
            "outputs bound writable at the faithful path, got {cmd:?}"
        );
        assert!(c.confines_filesystem(), "reports filesystem confinement");
        assert!(
            !c.status().is_untrusted_boundary(),
            "confinement is hardening, not an untrusted-safety claim (#150)"
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
