//! The host→guest hypervisor/system pairing (#325): which native backend and
//! which Linux guest arch this host's `sandy run` drives, with no hypervisor
//! on `PATH` required to ask. Shared by callers that previously each carried
//! their own copy of this mapping (or, for `--flake`, had none yet):
//! `sandy-cli`'s `live_target::require_live()` (behind the `live` feature),
//! `doctor`'s macOS builder-prereq check, and `flake_wrap`'s `--flake`
//! auto-detection — plus, since #332, `sandy-host-executor`'s own flake/v1 VM
//! dispatch, which runs this same pairing on ITS OWN host (e.g. the remote host) rather
//! than the submitting Mac. Ungated — unlike `live_target` — because
//! `--flake` resolution needs it in every build, not only the live
//! acceptance gates.

/// One host→guest pairing: the hypervisor this host's native backend drives,
/// and the Linux guest system it boots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostTarget {
    /// `"vfkit"` or `"qemu"` — the `microvm.hypervisor` value and the
    /// `topologies.<system>.<_>` leaf this host's native backend speaks.
    pub hypervisor: String,
    /// The Linux guest system this host builds and boots, e.g. `"aarch64-linux"`.
    pub guest_system: String,
}

/// This host's native target, as a pure function of `host_os`/`host_arch`
/// (`std::env::consts::OS`/`ARCH` at the real call sites) so it is
/// unit-testable without `cfg!`.
///
/// macOS → vfkit/`<host-arch>-linux` (vfkit requires a matching host/guest
/// arch); everything else → qemu/x86_64-linux (the Linux/CI leg, always
/// x86_64 regardless of host arch — qemu does not need arch-matching).
#[must_use]
pub fn host_target_for(host_os: &str, host_arch: &str) -> HostTarget {
    if host_os == "macos" {
        HostTarget {
            hypervisor: "vfkit".to_string(),
            guest_system: format!("{host_arch}-linux"),
        }
    } else {
        HostTarget {
            hypervisor: "qemu".to_string(),
            guest_system: "x86_64-linux".to_string(),
        }
    }
}

/// [`host_target_for`] applied to the real host this process runs on.
#[must_use]
pub fn host_target() -> HostTarget {
    host_target_for(std::env::consts::OS, std::env::consts::ARCH)
}

#[cfg(test)]
mod tests {
    use super::host_target_for;

    /// macOS pairs with vfkit and a guest arch matching the host's own.
    #[test]
    fn macos_pairs_with_vfkit_and_matching_guest_arch() {
        let target = host_target_for("macos", "aarch64");
        assert_eq!(target.hypervisor, "vfkit");
        assert_eq!(target.guest_system, "aarch64-linux");

        let target = host_target_for("macos", "x86_64");
        assert_eq!(
            target.guest_system, "x86_64-linux",
            "vfkit still matches the host's own arch"
        );
    }

    /// Every non-macOS host pairs with qemu and the x86_64-linux guest leg,
    /// regardless of the host's own arch.
    #[test]
    fn non_macos_pairs_with_qemu_and_x86_64_linux() {
        for os in ["linux", "freebsd", "windows"] {
            let target = host_target_for(os, "aarch64");
            assert_eq!(target.hypervisor, "qemu");
            assert_eq!(target.guest_system, "x86_64-linux", "qemu leg for host_os={os}");
        }
    }
}
