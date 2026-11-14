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
    /// An operator flag is set to something other than a yes or a no spelling. A silent `false` would hide a typo the
    /// operator meant as opt-in, so the executor refuses to start.
    #[error("{name}={value:?} is not one of 1, true, yes, 0, false, no (or empty)")]
    InvalidFlag {
        /// The environment variable.
        name: &'static str,
        /// The value found.
        value: String,
    },
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

/// Derive the isolation classes this host's backends can actually honor, for
/// `Register`'s wire `Capabilities.supported_isolation_classes` (#280's
/// orchestrator-side gate refuses a dispatch whose required class isn't in
/// this list — an empty or hardcoded list would silently refuse every
/// dispatch to this host, functional-but-dead). Mirrors
/// [`dispatch::check_isolation_class`](crate::dispatch::check_isolation_class)'s
/// own fail-closed rule (`process-containment.md` decision 6, #150, #381):
/// `is_available()` honors `Trusted`; `Untrusted` is honored only when
/// `vm_available` — the process backend never admits an untrusted job, with
/// ANY containment, on any host, so declaring `Untrusted` off
/// `ContainmentStatus::is_untrusted_boundary()` alone (as this function did
/// before #381) would advertise a capability the re-check could never honor.
/// A non-available status honors neither — the empty list is the correct,
/// fail-closed declaration for a host that can't contain anything at all. A
/// vfkit host with a VM and no process containment is handled by
/// [`to_wire_capabilities`], not here (macOS, #483).
fn detected_isolation_classes(status: &ContainmentStatus, vm_available: bool) -> Vec<IsolationClass> {
    if !status.is_available() {
        return Vec::new();
    }
    let mut classes = vec![IsolationClass::Trusted];
    if vm_available {
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
    shares_submitter_filesystem: bool,
    egress_proxy: bool,
    transfer: bool,
) -> sandy_executor_proto::Capabilities {
    let process_kind = match capabilities.kind {
        SandboxKind::Process => sandy_executor_proto::SandboxKind::Process,
        SandboxKind::Vm => sandy_executor_proto::SandboxKind::Vm,
    };
    let arch = match capabilities.arch {
        Arch::X86_64 => sandy_executor_proto::Arch::X8664,
        Arch::Aarch64 => sandy_executor_proto::Arch::Aarch64,
    };
    // A VM-only host (a Mac, see `capabilities_for_host`) has no process containment to read the classes from: a VM
    // honours both.
    let classes = if capabilities.kind == SandboxKind::Vm {
        vec![IsolationClass::Trusted, IsolationClass::Untrusted]
    } else {
        detected_isolation_classes(status, vm_available)
    };
    let mut kinds = vec![i32::from(process_kind)];
    if vm_available && process_kind != sandy_executor_proto::SandboxKind::Vm {
        kinds.push(i32::from(sandy_executor_proto::SandboxKind::Vm));
    }
    sandy_executor_proto::Capabilities {
        // Both backends hash a run's inputs and outputs when `RunSpec.digests` is set (#373), so this is an
        // implementation fact, not an operator declaration.
        digests: true,
        supported_sandbox_kinds: kinds,
        arch: arch.into(),
        attestation: capabilities.attestation.is_some(),
        supported_isolation_classes: classes.into_iter().map(Into::into).collect(),
        shares_submitter_filesystem,
        transfer,
        // Declared only with VM capability: a process job has no egress boundary to apply a policy with.
        egress_proxy: vm_available && egress_proxy,
    }
}

/// The operator-set deployment declarations (never auto-detected, fail-closed). All three read through [`flag_from`].
const SHARES_SUBMITTER_FS_FLAG: &str = "SANDY_HOST_SHARES_SUBMITTER_FS";
const EGRESS_PROXY_FLAG: &str = "SANDY_HOST_EGRESS_PROXY";
const TRANSFER_FLAG: &str = "SANDY_HOST_TRANSFER";

/// Knobs that older executors read and this one ignores (the guest NIC profile was removed, #864).
const REMOVED_KNOBS: [&str; 2] = ["SANDY_NETWORK", "SANDY_TAP"];

/// Parse an operator flag: a yes spelling (`1`, `true`, `yes`) is `true`; a no spelling (`0`, `false`, `no`), empty or
/// unset is `false`; case-insensitive and trimmed. Anything else is refused by name rather than read as `false`, so a
/// typo meant as opt-in does not hide.
fn flag_from(name: &'static str, value: Option<&str>) -> Result<bool, DetectError> {
    match value.map(|v| v.trim().to_ascii_lowercase()).as_deref() {
        None | Some("" | "0" | "false" | "no") => Ok(false),
        Some("1" | "true" | "yes") => Ok(true),
        Some(_) => Err(DetectError::InvalidFlag {
            name,
            value: value.unwrap_or_default().to_owned(),
        }),
    }
}

/// The removed knobs that `lookup` finds set, in [`REMOVED_KNOBS`] order.
fn removed_knobs_from(lookup: impl Fn(&str) -> Option<String>) -> Vec<&'static str> {
    REMOVED_KNOBS
        .into_iter()
        .filter(|knob| lookup(knob).is_some())
        .collect()
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
    let ignored = removed_knobs_from(|k| std::env::var(k).ok());
    if !ignored.is_empty() {
        tracing::warn!(knobs = ?ignored, "these environment variables were removed and are ignored");
    }
    let env_flag = |name: &'static str| flag_from(name, std::env::var(name).ok().as_deref());
    let shares_submitter_fs = env_flag(SHARES_SUBMITTER_FS_FLAG)?;
    let egress_proxy = env_flag(EGRESS_PROXY_FLAG)?;
    let transfer = env_flag(TRANSFER_FLAG)?;
    let arch = detect_arch()?;
    let status = SystemdRunContainment::detect().status();
    let vm_available = detect_vm_capability();
    let capabilities = capabilities_for_host(
        arch,
        &status,
        vm_available,
        crate::dispatch::hypervisor_for_os(std::env::consts::OS),
    )?;
    Ok(to_wire_capabilities(
        capabilities,
        &status,
        vm_available,
        shares_submitter_fs,
        egress_proxy,
        transfer,
    ))
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

/// The facts [`vfkit_capability_from`] derives a VM-capability verdict from on macOS, where the hypervisor is vfkit
/// and there is no `/dev/kvm` or `/dev/vhost-vsock` to probe (the agent link rides vfkit's own vsock socket).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct VfkitProbeFacts {
    /// The vfkit binary (`SANDY_VFKIT_BIN`, else `vfkit`) runs.
    vfkit_runnable: bool,
    /// `nix` runs: the `flake/v1` branch resolves and builds the guest with it.
    nix_runnable: bool,
    /// The packaged guest wrapper flake is present (see [`VmProbeFacts::guest_wrapper_present`]).
    guest_wrapper_present: bool,
}

/// Whether `facts` satisfy declaring `SandboxKind::Vm` on a vfkit host.
fn vfkit_capability_from(facts: VfkitProbeFacts) -> bool {
    facts.vfkit_runnable && facts.nix_runnable && facts.guest_wrapper_present
}

/// The capability a host declares from its containment `status` and whether it can run a VM: `Process` when the
/// containment is available. Without it, a vfkit host (a Mac, which has no process containment at all) declares `Vm`
/// alone when a VM can run; any other host declares nothing, since reaping gates a Linux host (decision 6).
fn capabilities_for_host(
    arch: Arch,
    status: &ContainmentStatus,
    vm_available: bool,
    hypervisor: crate::dispatch::Hypervisor,
) -> Result<Capabilities, DetectError> {
    match capabilities_from(arch, status) {
        Err(_) if vm_available && hypervisor == crate::dispatch::Hypervisor::Vfkit => Ok(Capabilities {
            kind: SandboxKind::Vm,
            arch,
            attestation: None,
        }),
        other => other,
    }
}

/// The vfkit binary: `SANDY_VFKIT_BIN`, else `vfkit` on `PATH`, the same lookup `sandy run` does. The probe and the
/// real boot share it, so they cannot drift onto different binaries.
pub(crate) fn vfkit_bin() -> String {
    std::env::var("SANDY_VFKIT_BIN").unwrap_or_else(|_| "vfkit".to_string())
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
        // `unwrap_or_else` to the bare name, not the override check alone:
        // on a host with no override set, this still wants the normal PATH
        // lookup `runs_successfully` does. The override and the fallback
        // name are the exact same ones `impls_vm::QemuBackend`'s own spawn
        // uses (`qemu_bin_override`), so the probe and the real boot can
        // never drift onto different binaries (#335 follow-up: the remote host's
        // resolved PATH silently dropped qemu/virtiofsd/git despite the
        // unit's own `path =` listing them — this and `nix_bin` below
        // bypass that entirely rather than depend on PATH being trustworthy).
        qemu_runnable: runs_successfully(
            &sandy_impls_vm::qemu_bin_override().unwrap_or_else(|| "qemu-system-x86_64".to_string()),
        ),
        nix_runnable: runs_successfully(&sandy_guest_template::nix_bin()),
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
    match crate::dispatch::hypervisor_for_os(std::env::consts::OS) {
        crate::dispatch::Hypervisor::Qemu => vm_capability_from(probe_vm_facts()),
        crate::dispatch::Hypervisor::Vfkit => vfkit_capability_from(VfkitProbeFacts {
            vfkit_runnable: runs_successfully(&vfkit_bin()),
            nix_runnable: runs_successfully(&sandy_guest_template::nix_bin()),
            guest_wrapper_present: sandy_guest_template::guest_wrapper_present(),
        }),
    }
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
    use anyhow::Context as _;

    use super::*;
    use crate::dispatch::Hypervisor;

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

    /// Positive: an available containment with no VM capability declares
    /// exactly `[Trusted]` — this is the case #284's merge-blocker exists
    /// for: an unpopulated `supported_isolation_classes` would make the
    /// orchestrator's isolation gate refuse every dispatch, even trusted
    /// ones. An `isolates_untrusted: true` status does NOT add `Untrusted`
    /// on its own (#381, process-containment.md decision 6): the process
    /// backend never admits an untrusted job regardless of containment.
    #[test]
    fn an_available_containment_with_no_vm_declares_trusted_only() {
        let status = ContainmentStatus::Available {
            isolates_untrusted: true,
        };
        assert_eq!(
            detected_isolation_classes(&status, false),
            vec![IsolationClass::Trusted]
        );
    }

    /// Positive (#381): VM capability declares both classes — `Trusted` plus
    /// `Untrusted` — regardless of what the process containment's own
    /// `isolates_untrusted` flag reports, since `Untrusted` is gated on
    /// `vm_available` alone.
    #[test]
    fn vm_capability_declares_trusted_and_untrusted() {
        let status = ContainmentStatus::Available {
            isolates_untrusted: false,
        };
        assert_eq!(
            detected_isolation_classes(&status, true),
            vec![IsolationClass::Trusted, IsolationClass::Untrusted]
        );
    }

    /// Adversarial: a host with no usable containment declares no isolation
    /// class at all — never a hardcoded `[Trusted]` for a host that can't
    /// actually honor it — even when `vm_available` is true (no reaping
    /// means no backend can run anything at all).
    #[test]
    fn an_unavailable_containment_declares_no_isolation_class() {
        let status = ContainmentStatus::Unavailable("no user systemd instance".to_owned());
        assert_eq!(detected_isolation_classes(&status, true), Vec::<IsolationClass>::new());
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
        let wire = to_wire_capabilities(capabilities, &status, false, false, false, false);
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
        assert!(!wire.shares_submitter_filesystem);
    }

    /// Positive (#332, #381): `vm_available = true` ADDS `Vm` to the declared
    /// kinds — the existing `Process` declaration is completely unaffected,
    /// never replaced — AND adds `Untrusted` to the declared isolation
    /// classes, the only way a host can ever advertise it.
    #[test]
    fn to_wire_capabilities_adds_vm_and_untrusted_when_available() {
        let status = ContainmentStatus::Available {
            isolates_untrusted: false,
        };
        let capabilities = Capabilities {
            kind: SandboxKind::Process,
            arch: Arch::X86_64,
            attestation: None,
        };
        let wire = to_wire_capabilities(capabilities, &status, true, false, false, false);
        assert_eq!(
            wire.supported_sandbox_kinds,
            vec![
                i32::from(sandy_executor_proto::SandboxKind::Process),
                i32::from(sandy_executor_proto::SandboxKind::Vm),
            ]
        );
        assert_eq!(
            wire.supported_isolation_classes,
            vec![i32::from(IsolationClass::Trusted), i32::from(IsolationClass::Untrusted)]
        );
    }

    #[test]
    fn to_wire_capabilities_declares_shares_submitter_filesystem_when_asked() {
        let status = ContainmentStatus::Available {
            isolates_untrusted: false,
        };
        let capabilities = Capabilities {
            kind: SandboxKind::Process,
            arch: Arch::X86_64,
            attestation: None,
        };
        let wire = to_wire_capabilities(capabilities, &status, false, true, false, false);
        assert!(wire.shares_submitter_filesystem);
    }

    /// #833: each operator flag refuses a value that is neither a yes nor a no spelling, by variable name and value.
    #[test]
    fn every_operator_flag_refuses_an_unknown_value_by_name() -> anyhow::Result<()> {
        for name in FLAG_NAMES {
            for value in ["junk", "2", "ture", "ye5", "y"] {
                let err = flag_from(name, Some(value))
                    .err()
                    .with_context(|| format!("{name}={value:?} should be refused"))?;
                assert_eq!(
                    err,
                    DetectError::InvalidFlag {
                        name,
                        value: value.to_owned()
                    }
                );
                let text = err.to_string();
                assert!(text.contains(name) && text.contains(value), "{text}");
            }
            for value in ["1", "true", "TRUE", "Yes", " yes "] {
                assert_eq!(flag_from(name, Some(value)), Ok(true), "{name}={value:?}");
            }
            for value in ["0", "false", "No", "", "  "] {
                assert_eq!(flag_from(name, Some(value)), Ok(false), "{name}={value:?}");
            }
            assert_eq!(flag_from(name, None), Ok(false), "{name} unset");
        }
        Ok(())
    }

    /// #833: a removed knob that is still set is reported by name; an unset one is not.
    #[test]
    fn removed_knobs_still_set_are_reported() {
        let set = |k: &str| (k == "SANDY_TAP" || k == "SANDY_NETWORK").then(|| "x".to_owned());
        assert_eq!(removed_knobs_from(set), vec!["SANDY_NETWORK", "SANDY_TAP"]);
        assert!(removed_knobs_from(|_| None).is_empty());
    }

    /// #807: the registration carries `transfer` only when asked, whatever else the host declares.
    #[test]
    fn to_wire_capabilities_declares_transfer_only_when_asked() {
        let capabilities = || Capabilities {
            kind: SandboxKind::Process,
            arch: Arch::X86_64,
            attestation: None,
        };
        let status = ContainmentStatus::Available {
            isolates_untrusted: false,
        };
        for asked in [false, true] {
            let wire = to_wire_capabilities(capabilities(), &status, false, false, false, asked);
            assert_eq!(wire.transfer, asked, "asked={asked}");
        }
    }

    /// A2c (#483): this executor's backends hash a run's inputs and outputs when asked, so every registration declares
    /// `digests`, whatever else the host has.
    #[test]
    fn to_wire_capabilities_always_declares_digests() {
        let status = ContainmentStatus::Available {
            isolates_untrusted: false,
        };
        let capabilities = || Capabilities {
            kind: SandboxKind::Process,
            arch: Arch::X86_64,
            attestation: None,
        };
        for vm in [false, true] {
            let wire = to_wire_capabilities(capabilities(), &status, vm, false, false, false);
            assert!(wire.digests, "vm={vm}: digests not declared");
        }
    }

    /// A1 (#483): `egress_proxy` needs both the operator's declaration and a VM path. A process-only host never
    /// declares it, whatever the flag says, and a VM host without the flag does not either.
    #[test]
    fn egress_proxy_is_declared_only_by_a_vm_host_whose_operator_asked() {
        let status = ContainmentStatus::Available {
            isolates_untrusted: false,
        };
        let capabilities = || Capabilities {
            kind: SandboxKind::Process,
            arch: Arch::X86_64,
            attestation: None,
        };
        for (vm, flag, want) in [
            (true, true, true),
            (true, false, false),
            (false, true, false),
            (false, false, false),
        ] {
            let wire = to_wire_capabilities(capabilities(), &status, vm, false, flag, false);
            assert_eq!(wire.egress_proxy, want, "vm={vm} flag={flag}");
        }
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

    const FLAG_NAMES: [&str; 3] = [SHARES_SUBMITTER_FS_FLAG, EGRESS_PROXY_FLAG, TRANSFER_FLAG];

    fn unsupported() -> ContainmentStatus {
        ContainmentStatus::Unsupported("process containment needs Linux cgroup v2".to_owned())
    }

    /// A macOS host runs VMs through vfkit: with vfkit, nix and the guest wrapper present it can declare `Vm`, and it
    /// needs neither `/dev/kvm` nor `/dev/vhost-vsock`. Each missing fact refuses.
    #[test]
    fn a_vfkit_host_needs_vfkit_nix_and_the_wrapper_and_no_kvm() {
        let all = VfkitProbeFacts {
            vfkit_runnable: true,
            nix_runnable: true,
            guest_wrapper_present: true,
        };
        assert!(vfkit_capability_from(all), "every fact holds");
        assert!(!vfkit_capability_from(VfkitProbeFacts {
            vfkit_runnable: false,
            ..all
        }));
        assert!(!vfkit_capability_from(VfkitProbeFacts {
            nix_runnable: false,
            ..all
        }));
        assert!(!vfkit_capability_from(VfkitProbeFacts {
            guest_wrapper_present: false,
            ..all
        }));
    }

    /// A host with no process containment but a working VM (a Mac) declares the VM kind alone: no `Process`, which it
    /// could only run uncontained. With no VM either it still declares nothing, and names the containment reason.
    #[test]
    fn a_host_with_no_process_containment_declares_vm_only_when_a_vm_can_run() -> anyhow::Result<()> {
        let capabilities = capabilities_for_host(Arch::Aarch64, &unsupported(), true, Hypervisor::Vfkit)?;
        assert_eq!(capabilities.kind, SandboxKind::Vm);
        let wire = to_wire_capabilities(capabilities, &unsupported(), true, false, false, false);
        assert_eq!(
            wire.supported_sandbox_kinds,
            vec![i32::from(sandy_executor_proto::SandboxKind::Vm)],
            "no process kind without containment"
        );
        assert_eq!(
            wire.supported_isolation_classes,
            vec![i32::from(IsolationClass::Trusted), i32::from(IsolationClass::Untrusted)],
            "a VM honours both classes"
        );
        let err = capabilities_for_host(Arch::Aarch64, &unsupported(), false, Hypervisor::Vfkit)
            .expect_err("neither backend can run");
        assert!(matches!(err, DetectError::ContainmentUnavailable(_)), "{err:?}");
        Ok(())
    }

    /// A Linux host (qemu) with no process containment still refuses to start, even with a working VM: reaping gates a
    /// Linux host, and only a vfkit host (a Mac, which has no process containment at all) declares VM alone.
    #[test]
    fn a_qemu_host_without_process_containment_still_refuses_to_start() {
        let status = ContainmentStatus::Unavailable("no user systemd instance".to_owned());
        let err = capabilities_for_host(Arch::X86_64, &status, true, Hypervisor::Qemu)
            .expect_err("a Linux host needs its containment");
        assert_eq!(
            err,
            DetectError::ContainmentUnavailable("no user systemd instance".to_owned())
        );
    }

    /// A host with process containment keeps its declaration whatever its VM state: `Process`, plus `Vm` when a VM can
    /// run, exactly as before.
    #[test]
    fn a_host_with_process_containment_still_declares_process() -> anyhow::Result<()> {
        let status = ContainmentStatus::Available {
            isolates_untrusted: false,
        };
        for vm in [false, true] {
            assert_eq!(
                capabilities_for_host(Arch::X86_64, &status, vm, Hypervisor::Qemu)?.kind,
                SandboxKind::Process
            );
        }
        Ok(())
    }
}
