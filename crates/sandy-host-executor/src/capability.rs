//! Host-executor capability detection (#275, M2 stage 1; VM detection since
//! #332).
//!
//! Probes the actual environment and declares real capabilities to the
//! orchestrator — never a hardcoded constant (spec D2,
//! `docs/design/host-executor/spec.md`). A host that cannot actually
//! provide a backend declares nothing for it, fail-closed, rather than a
//! capability it cannot honor.
//!
//! [`Capabilities`] itself is owned by #263 (`sandy_fabric::executor`); this
//! module consumes it, never redefines it. It stays the single-kind, one-
//! executor-instance-per-kind domain type it always was (#332 deliberately
//! leaves it and `capabilities_satisfy` alone — that seam is unrelated to
//! this one host's own wire registration). The wire
//! `sandy_executor_proto::Capabilities.supported_sandbox_kinds` this module
//! builds is the broader, M2-specific concept: the SET of kinds one
//! host-executor process can run, which [`to_wire_capabilities`] derives
//! from this domain `Capabilities` (always `Process`, when containment is
//! available) plus [`detect_vm_capability`]'s own independent probe.

use sandy_api::{
    backend::SandboxKind,
    containment::{Containment, ContainmentStatus},
};
use sandy_executor_proto::IsolationClass;
use sandy_fabric::executor::{Arch, Capabilities};
use sandy_impls_local::SystemdRunContainment;

/// A capability-detection failure: the host cannot provide any backend this
/// probing understands. Never silently declared anyway — the orchestrator
/// must not dispatch to a host that didn't actually declare the capability.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DetectError {
    /// The running process's own architecture is not one sandy supports.
    #[error("host architecture {0:?} is not one sandy supports")]
    UnsupportedArch(String),
    /// The trusted-process backend's own containment mechanism
    /// (`systemd-run --user --scope` over cgroup v2, #135) is not usable
    /// here — the same probe `ProcessBackend` itself relies on at run time,
    /// not a separate, narrower or broader check.
    #[error("trusted-process containment is not available: {0}")]
    ContainmentUnavailable(String),
}

/// Detect this host's architecture from the running process's own build
/// target: what matters for dispatch is what THIS process can execute on,
/// which `std::env::consts::ARCH` reports exactly (a cross-compiled or
/// emulated binary would still report its own real target here, not the
/// physical CPU it happens to be emulated on — the correct answer for "what
/// can a job dispatched to this process run as").
fn detect_arch() -> Result<Arch, DetectError> {
    match std::env::consts::ARCH {
        "x86_64" => Ok(Arch::X86_64),
        "aarch64" => Ok(Arch::Aarch64),
        other => Err(DetectError::UnsupportedArch(other.to_owned())),
    }
}

/// Derive the capability this host can declare from an already-probed
/// `arch`/containment `status` — pure, so the decision logic is unit
/// testable against every `ContainmentStatus` variant without a real Linux
/// host. [`detect_capabilities`] is the real entry point; this is what it
/// delegates to once it has probed both inputs for real.
///
/// Declares `SandboxKind::Process` only when `status.is_available()` — the
/// exact check `ProcessBackend` itself relies on to decide whether it can
/// safely wrap and reap a job. Declaring `Process` does not require the
/// stronger untrusted-isolation boundary (`is_untrusted_boundary`): stage 1
/// accepts trusted jobs only (spec D4), and the orchestrator's separate
/// isolation-class gate — not this declaration — is what keeps an untrusted
/// job off a host that only declared `Process`.
fn capabilities_from(arch: Arch, status: &ContainmentStatus) -> Result<Capabilities, DetectError> {
    if !status.is_available() {
        return Err(DetectError::ContainmentUnavailable(unavailable_reason(status)));
    }
    Ok(Capabilities {
        kind: SandboxKind::Process,
        arch,
        attestation: None,
    })
}

/// Derive the isolation classes this host's containment can actually honor,
/// for `Register`'s wire `Capabilities.supported_isolation_classes` (#280's
/// orchestrator-side gate refuses a dispatch whose required class isn't in
/// this list — an empty or hardcoded list would silently refuse every
/// dispatch to this host, functional-but-dead). Mirrors the admission logic
/// [`dispatch::check_isolation_class`](crate::dispatch::check_isolation_class)
/// re-checks per dispatch: `is_available()` always honors `Trusted`;
/// `is_untrusted_boundary()` additionally honors `Untrusted`. A non-available
/// status honors neither — the empty list is the correct, fail-closed
/// declaration for a host that can't contain anything at all.
fn detected_isolation_classes(status: &ContainmentStatus) -> Vec<IsolationClass> {
    if !status.is_available() {
        return Vec::new();
    }
    let mut classes = vec![IsolationClass::Trusted];
    if status.is_untrusted_boundary() {
        classes.push(IsolationClass::Untrusted);
    }
    classes
}

/// Detect this host's real capabilities: the real entry point, probing both
/// the architecture and [`SystemdRunContainment::detect`] (the exact probe
/// `ProcessBackend` itself uses at run time) before deriving the
/// declaration via [`capabilities_from`].
///
/// # Errors
/// [`DetectError::UnsupportedArch`] if the running process's own
/// architecture isn't one sandy supports;
/// [`DetectError::ContainmentUnavailable`] if `systemd-run --user --scope`
/// over cgroup v2 is not usable here (no user systemd instance, no cgroup
/// v2, or not Linux at all).
pub fn detect_capabilities() -> Result<Capabilities, DetectError> {
    let arch = detect_arch()?;
    let status = SystemdRunContainment::detect().status();
    capabilities_from(arch, &status)
}

/// Convert this host's declared [`Capabilities`] into the wire
/// `Register.capabilities` shape, with `supported_isolation_classes`
/// populated from `status` via [`detected_isolation_classes`] — never
/// empty or hardcoded, since the orchestrator's isolation-class gate (#280)
/// refuses any dispatch whose required class isn't in this list.
///
/// `supported_sandbox_kinds` (#332) is a SET: `capabilities.kind` (always
/// `Process`, the only kind [`capabilities_from`] ever derives) plus `Vm`
/// when `vm_available` — additive, never replacing the existing `Process`
/// declaration, so a host gaining VM capability never silently stops
/// declaring the process backend it already had (the existing
/// `ProcessBackend`/`argv/v1` dispatch path must be completely unaffected).
fn to_wire_capabilities(
    capabilities: Capabilities,
    status: &ContainmentStatus,
    vm_available: bool,
) -> sandy_executor_proto::Capabilities {
    let process_kind = match capabilities.kind {
        SandboxKind::Process => sandy_executor_proto::SandboxKind::Process,
        SandboxKind::Vm => sandy_executor_proto::SandboxKind::Vm,
    };
    let arch = match capabilities.arch {
        Arch::X86_64 => sandy_executor_proto::Arch::X8664,
        Arch::Aarch64 => sandy_executor_proto::Arch::Aarch64,
    };
    let mut kinds = vec![i32::from(process_kind)];
    if vm_available {
        kinds.push(i32::from(sandy_executor_proto::SandboxKind::Vm));
    }
    sandy_executor_proto::Capabilities {
        supported_sandbox_kinds: kinds,
        arch: arch.into(),
        attestation: capabilities.attestation.is_some(),
        supported_isolation_classes: detected_isolation_classes(status).into_iter().map(Into::into).collect(),
    }
}

/// Detect this host's real capabilities in the wire shape `Register` carries
/// — the real entry point for registration, as [`detect_capabilities`] is
/// for the domain type it wraps. Additionally probes VM capability (#332,
/// [`detect_vm_capability`]) and folds it into `supported_sandbox_kinds`
/// alongside the existing `Process` declaration.
///
/// # Errors
/// Same as [`detect_capabilities`].
pub fn detect_register_capabilities() -> Result<sandy_executor_proto::Capabilities, DetectError> {
    let arch = detect_arch()?;
    let status = SystemdRunContainment::detect().status();
    let capabilities = capabilities_from(arch, &status)?;
    Ok(to_wire_capabilities(capabilities, &status, detect_vm_capability()))
}

/// The facts [`vm_capability_from`] derives a VM-capability verdict from —
/// probed once by [`detect_vm_capability`], pure from there so the
/// derivation is unit-testable without a real `/dev/kvm`/`nix`/
/// `qemu-system-x86_64`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct VmProbeFacts {
    /// `qemu-system-x86_64` runs — the only qemu target this host ever needs
    /// (`host_target_for`'s own invariant: every non-macOS host pairs with
    /// qemu/x86_64-linux, regardless of the host's own arch).
    qemu_runnable: bool,
    /// `nix` runs — the `flake/v1` dispatch branch resolves+builds the guest
    /// with it, same as `sandy run --flake` does locally.
    nix_runnable: bool,
    /// `/dev/kvm` is openable read-write by this process — hardware
    /// acceleration, the same probe `impls/vm/src/qemu.rs`'s own
    /// `kvm_available` uses at boot time.
    kvm_usable: bool,
    /// `/dev/vhost-vsock` is openable read-write by this process — the
    /// agent-link's AF_VSOCK transport (#238); without it a VM boots but the
    /// sandbox agent can never connect back.
    vhost_vsock_usable: bool,
    /// `sandy_guest_template::guest_wrapper_present()` — the packaged
    /// `nix/guest-wrapper` flake (plus its `nix/lib`/`nix/overlays`
    /// dependencies) this host's `flake/v1` dispatch branch resolves+builds
    /// against is actually present (CodeRabbit finding on PR #333): a host
    /// whose package does not ship it, or never set `$SANDY_GUEST_WRAPPER`,
    /// would otherwise advertise `Vm` and only fail once a real dispatch
    /// reaches `resolve_flake_template`.
    guest_wrapper_present: bool,
}

/// Whether `facts` satisfy declaring `SandboxKind::Vm`: every probed fact
/// must hold — a host missing any one of them cannot actually complete a VM
/// dispatch, so declaring the capability anyway would be exactly the kind of
/// "a capability it cannot honor" this module's own doc rules out.
fn vm_capability_from(facts: VmProbeFacts) -> bool {
    facts.qemu_runnable
        && facts.nix_runnable
        && facts.kvm_usable
        && facts.vhost_vsock_usable
        && facts.guest_wrapper_present
}

/// Whether `binary --version` runs successfully — a real-usability probe
/// (not just PATH presence), matching the spirit of
/// `SystemdRunContainment::detect`'s own "try the real thing" discipline
/// rather than a weaker existence check.
fn runs_successfully(binary: &str) -> bool {
    std::process::Command::new(binary)
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

/// Whether `path` can actually be opened read-write by this process — a
/// device node can exist (`Path::exists`) while this process lacks the
/// permission to use it (e.g. outside the `kvm` group, or a root-only
/// `/dev/vhost-vsock`), which would make a host falsely advertise a
/// capability it cannot service. Same "try the real thing" discipline
/// [`runs_successfully`] applies to the binaries.
fn device_openable(path: &str) -> bool {
    std::fs::OpenOptions::new().read(true).write(true).open(path).is_ok()
}

/// Probe this host's real VM-capability facts.
fn probe_vm_facts() -> VmProbeFacts {
    VmProbeFacts {
        qemu_runnable: runs_successfully("qemu-system-x86_64"),
        nix_runnable: runs_successfully("nix"),
        kvm_usable: device_openable("/dev/kvm"),
        vhost_vsock_usable: device_openable("/dev/vhost-vsock"),
        guest_wrapper_present: sandy_guest_template::guest_wrapper_present(),
    }
}

/// Whether this host can actually run a `SandboxKind::Vm` dispatch (#332):
/// the real entry point, probing qemu/nix/kvm/vhost-vsock before deriving
/// the verdict via [`vm_capability_from`]. Called both at registration
/// ([`detect_register_capabilities`]) and freshly re-probed at dispatch time
/// ([`crate::dispatch::handle_dispatch`]'s own defense-in-depth re-check,
/// same discipline as [`crate::dispatch::check_isolation_class`]'s re-probe
/// — never trust an earlier registration alone).
#[must_use]
pub fn detect_vm_capability() -> bool {
    vm_capability_from(probe_vm_facts())
}

/// The diagnostic string carried by a non-`Available` [`ContainmentStatus`].
fn unavailable_reason(status: &ContainmentStatus) -> String {
    match status {
        ContainmentStatus::Available { .. } => unreachable!("caller already checked is_available()"),
        ContainmentStatus::Unavailable(reason) | ContainmentStatus::Unsupported(reason) => reason.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_arch_matches_the_running_processs_own_target() -> anyhow::Result<()> {
        let arch = detect_arch()?;
        let expected = match std::env::consts::ARCH {
            "x86_64" => Arch::X86_64,
            "aarch64" => Arch::Aarch64,
            other => anyhow::bail!("test host architecture {other:?} is not one this test covers"),
        };
        assert_eq!(arch, expected);
        Ok(())
    }

    /// Positive: an available, trusted-reaping-only containment (the common
    /// case — no bus/mount-namespace isolation, stage 1 doesn't need it)
    /// yields `SandboxKind::Process`.
    #[test]
    fn an_available_reaping_only_containment_declares_process() -> anyhow::Result<()> {
        let status = ContainmentStatus::Available {
            isolates_untrusted: false,
        };
        let capabilities = capabilities_from(Arch::X86_64, &status)?;
        assert_eq!(
            capabilities,
            Capabilities {
                kind: SandboxKind::Process,
                arch: Arch::X86_64,
                attestation: None,
            }
        );
        Ok(())
    }

    /// Positive: the stronger untrusted-isolation boundary ALSO satisfies the
    /// declaration — declaring `Process` never requires LESS than the
    /// available status provides, only AT LEAST `is_available()`.
    #[test]
    fn an_untrusted_isolating_containment_also_declares_process() -> anyhow::Result<()> {
        let status = ContainmentStatus::Available {
            isolates_untrusted: true,
        };
        let capabilities = capabilities_from(Arch::Aarch64, &status)?;
        assert_eq!(capabilities.kind, SandboxKind::Process);
        Ok(())
    }

    /// Adversarial: a host with no usable containment declares nothing —
    /// fail-closed, never a capability it cannot honor — and the refusal
    /// names the real diagnostic reason, not a generic placeholder.
    #[test]
    fn an_unavailable_containment_declares_nothing_and_names_why() {
        let status = ContainmentStatus::Unavailable("no user systemd instance".to_owned());
        let err = capabilities_from(Arch::X86_64, &status).expect_err("unavailable containment must refuse");
        assert_eq!(
            err,
            DetectError::ContainmentUnavailable("no user systemd instance".to_owned())
        );
    }

    /// Adversarial: a platform with no containment mechanism at all (macOS)
    /// declares nothing, same as `Unavailable` — both are non-`Available`,
    /// neither is a silent default.
    #[test]
    fn an_unsupported_platform_declares_nothing_and_names_why() {
        let status = ContainmentStatus::Unsupported("macOS has no cgroup".to_owned());
        let err = capabilities_from(Arch::X86_64, &status).expect_err("unsupported platform must refuse");
        assert_eq!(
            err,
            DetectError::ContainmentUnavailable("macOS has no cgroup".to_owned())
        );
    }

    /// Positive: a reaping-only containment declares exactly `[Trusted]` —
    /// this is the case #284's merge-blocker exists for: an unpopulated
    /// `supported_isolation_classes` would make the orchestrator's isolation
    /// gate refuse every dispatch, even trusted ones.
    #[test]
    fn an_available_reaping_only_containment_declares_trusted_only() {
        let status = ContainmentStatus::Available {
            isolates_untrusted: false,
        };
        assert_eq!(detected_isolation_classes(&status), vec![IsolationClass::Trusted]);
    }

    /// Positive: an untrusted boundary declares both classes — at least what
    /// a reaping-only host declares, plus `Untrusted`.
    #[test]
    fn an_untrusted_boundary_declares_trusted_and_untrusted() {
        let status = ContainmentStatus::Available {
            isolates_untrusted: true,
        };
        assert_eq!(
            detected_isolation_classes(&status),
            vec![IsolationClass::Trusted, IsolationClass::Untrusted]
        );
    }

    /// Adversarial: a host with no usable containment declares no isolation
    /// class at all — never a hardcoded `[Trusted]` for a host that can't
    /// actually honor it.
    #[test]
    fn an_unavailable_containment_declares_no_isolation_class() {
        let status = ContainmentStatus::Unavailable("no user systemd instance".to_owned());
        assert_eq!(detected_isolation_classes(&status), Vec::<IsolationClass>::new());
    }

    /// The load-bearing property for #284: the wire `Capabilities` Register
    /// actually carries declares `[Trusted]`, derived from a real
    /// `ContainmentStatus`, never empty or hardcoded.
    #[test]
    fn to_wire_capabilities_populates_supported_isolation_classes_from_status() {
        let status = ContainmentStatus::Available {
            isolates_untrusted: false,
        };
        let capabilities = Capabilities {
            kind: SandboxKind::Process,
            arch: Arch::X86_64,
            attestation: None,
        };
        let wire = to_wire_capabilities(capabilities, &status, false);
        assert_eq!(
            wire.supported_isolation_classes,
            vec![i32::from(IsolationClass::Trusted)]
        );
        assert_eq!(
            wire.supported_sandbox_kinds,
            vec![i32::from(sandy_executor_proto::SandboxKind::Process)]
        );
        assert_eq!(wire.arch, i32::from(sandy_executor_proto::Arch::X8664));
        assert!(!wire.attestation);
    }

    /// Positive (#332): `vm_available = true` ADDS `Vm` to the declared
    /// kinds — the existing `Process` declaration is completely unaffected,
    /// never replaced.
    #[test]
    fn to_wire_capabilities_adds_vm_alongside_process_when_available() {
        let status = ContainmentStatus::Available {
            isolates_untrusted: false,
        };
        let capabilities = Capabilities {
            kind: SandboxKind::Process,
            arch: Arch::X86_64,
            attestation: None,
        };
        let wire = to_wire_capabilities(capabilities, &status, true);
        assert_eq!(
            wire.supported_sandbox_kinds,
            vec![
                i32::from(sandy_executor_proto::SandboxKind::Process),
                i32::from(sandy_executor_proto::SandboxKind::Vm),
            ]
        );
    }

    /// Adversarial (#332): every one of qemu/nix/kvm/vhost-vsock/
    /// guest-wrapper must hold — a host missing any single one cannot
    /// actually complete a VM dispatch, so it must not declare the
    /// capability anyway.
    #[test]
    fn vm_capability_requires_every_probed_fact() {
        let all_true = VmProbeFacts {
            qemu_runnable: true,
            nix_runnable: true,
            kvm_usable: true,
            vhost_vsock_usable: true,
            guest_wrapper_present: true,
        };
        assert!(vm_capability_from(all_true));

        assert!(!vm_capability_from(VmProbeFacts {
            qemu_runnable: false,
            ..all_true
        }));
        assert!(!vm_capability_from(VmProbeFacts {
            nix_runnable: false,
            ..all_true
        }));
        assert!(!vm_capability_from(VmProbeFacts {
            kvm_usable: false,
            ..all_true
        }));
        assert!(!vm_capability_from(VmProbeFacts {
            vhost_vsock_usable: false,
            ..all_true
        }));
        assert!(!vm_capability_from(VmProbeFacts {
            guest_wrapper_present: false,
            ..all_true
        }));
    }

    /// Regression (CodeRabbit finding on this PR): existence alone must not
    /// pass. A file this process cannot write to exists but is not usable —
    /// the exact "device node present, permission denied" case the old
    /// `Path::exists()` probe could not tell apart from a real `/dev/kvm`.
    /// Assumes the test process is not running as root (root can open a
    /// read-only file for writing anyway).
    #[test]
    fn device_openable_requires_a_real_readwrite_open_not_just_existence() -> anyhow::Result<()> {
        use std::os::unix::fs::PermissionsExt as _;

        use anyhow::Context as _;

        let dir = std::env::temp_dir();
        let path = dir.join(format!("sandy-device-openable-test-{}", std::process::id()));
        std::fs::write(&path, b"").context("create a scratch file")?;
        let path_str = path.to_str().context("scratch path is valid UTF-8")?.to_owned();

        assert!(device_openable(&path_str), "a plain writable file must be openable");

        let mut perms = std::fs::metadata(&path).context("stat the scratch file")?.permissions();
        perms.set_mode(0o400);
        std::fs::set_permissions(&path, perms).context("chmod the scratch file read-only")?;
        assert!(
            !device_openable(&path_str),
            "a read-only file must not be reported as read-write openable"
        );

        std::fs::remove_file(&path).ok();
        assert!(
            !device_openable(&path_str),
            "a nonexistent path must not be reported as openable"
        );
        Ok(())
    }
}
