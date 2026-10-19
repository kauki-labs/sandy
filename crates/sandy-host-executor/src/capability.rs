//! Host-executor capability detection (#275, M2 stage 1).
//!
//! Probes the actual environment and declares real capabilities to the
//! orchestrator — never a hardcoded constant (spec D2,
//! `docs/design/host-executor/spec.md`). A host that cannot actually
//! provide a backend declares nothing for it, fail-closed, rather than a
//! capability it cannot honor.
//!
//! [`Capabilities`] itself is owned by #263 (`sandy_fabric::executor`); this
//! module consumes it, never redefines it.

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
fn to_wire_capabilities(capabilities: Capabilities, status: &ContainmentStatus) -> sandy_executor_proto::Capabilities {
    let kind = match capabilities.kind {
        SandboxKind::Process => sandy_executor_proto::SandboxKind::Process,
        SandboxKind::Vm => sandy_executor_proto::SandboxKind::Vm,
    };
    let arch = match capabilities.arch {
        Arch::X86_64 => sandy_executor_proto::Arch::X8664,
        Arch::Aarch64 => sandy_executor_proto::Arch::Aarch64,
    };
    sandy_executor_proto::Capabilities {
        kind: kind.into(),
        arch: arch.into(),
        attestation: capabilities.attestation.is_some(),
        supported_isolation_classes: detected_isolation_classes(status).into_iter().map(Into::into).collect(),
    }
}

/// Detect this host's real capabilities in the wire shape `Register` carries
/// — the real entry point for registration, as [`detect_capabilities`] is
/// for the domain type it wraps.
///
/// # Errors
/// Same as [`detect_capabilities`].
pub fn detect_register_capabilities() -> Result<sandy_executor_proto::Capabilities, DetectError> {
    let arch = detect_arch()?;
    let status = SystemdRunContainment::detect().status();
    let capabilities = capabilities_from(arch, &status)?;
    Ok(to_wire_capabilities(capabilities, &status))
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
        let wire = to_wire_capabilities(capabilities, &status);
        assert_eq!(
            wire.supported_isolation_classes,
            vec![i32::from(IsolationClass::Trusted)]
        );
        assert_eq!(wire.kind, i32::from(sandy_executor_proto::SandboxKind::Process));
        assert_eq!(wire.arch, i32::from(sandy_executor_proto::Arch::X8664));
        assert!(!wire.attestation);
    }
}
