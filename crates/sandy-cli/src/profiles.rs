//! Reusable run [`Profile`]s — concrete compositions of the run seams that
//! `dispatch_run` threads.
//!
//! The host profile (VM backend + nftables egress + GitHub credentials) is wired
//! in the binary (`main.rs`) because it pulls the live forge setup. This module
//! holds the profiles that need no host forge setup, so they can be reused by the
//! acceptance binaries as well as the CLI: today, [`all_local`].

use std::path::Path;

use sandy::{CredentialProvider, CredentialSource, EgressOs, Profile, Scope};

/// The all-local run profile: the raw-process backend (no hypervisor), no egress
/// boundary, and no forge credential.
///
/// It runs a job fully locally via [`ProcessBackend`](sandy_backend::ProcessBackend)
/// with [`NoContainment`](sandy::NoContainment) — honest about its posture: the
/// backend's containment status is `Unavailable`, so the fail-closed
/// [`admits_untrusted`](sandy::admits_untrusted) gate refuses an untrusted job on
/// it (the live enforcer is future). A process backend has no guest NIC, so the
/// run path's scoped egress plan is `NoBoundary` and the [`NoEgress`](sandy_backend::NoEgress)
/// applier is never invoked; it only fills the seam slot. Credentials are refused
/// — a forge token needs the host profile's trust root.
///
/// This is the profile the acceptance-local binary wires, and a hypervisor-free
/// local run path.
#[must_use]
pub fn all_local() -> Profile {
    Profile::new(
        Box::new(sandy_backend::ProcessBackend::new()),
        Box::new(sandy_backend::NoEgress),
        egress_os(),
        Box::new(NoForgeCred),
    )
}

/// The platform's egress OS model. Cosmetic for the all-local profile (a process
/// backend has no NIC to scope, so its plan is always `NoBoundary`), but kept
/// honest to the host rather than hard-coded.
fn egress_os() -> EgressOs {
    if cfg!(target_os = "macos") {
        EgressOs::MacOs
    } else {
        EgressOs::Linux
    }
}

/// The credential source for a profile with no forge trust root: any credential
/// request is refused with a clear message. The all-local profile mints no forge
/// token — use the host profile for that.
struct NoForgeCred;

impl CredentialSource for NoForgeCred {
    fn provider(
        &self,
        _dir: &Path,
        _name: &str,
        _capabilities: &[String],
    ) -> Result<(Box<dyn CredentialProvider + Sync>, Scope), String> {
        Err("the all-local profile mints no forge credential; use the host profile for a forge token".to_string())
    }
}

#[cfg(test)]
mod tests {
    use sandy::{SandboxKind, backend_accepts};

    use super::*;

    /// The all-local profile selects the raw-process backend (no VM).
    #[test]
    fn all_local_selects_the_process_backend() {
        let profile = all_local();
        assert_eq!(profile.backend().kind(), SandboxKind::Process);
        assert!(
            backend_accepts(profile.backend().kind(), SandboxKind::Process),
            "the all-local backend runs a process-required job"
        );
        assert!(
            !backend_accepts(profile.backend().kind(), SandboxKind::Vm),
            "the all-local backend must not claim to run a VM-required job"
        );
    }

    /// The all-local profile refuses a forge credential (no trust root).
    #[test]
    fn all_local_refuses_a_forge_credential() {
        let profile = all_local();
        let result = profile
            .cred()
            .provider(Path::new("/nonexistent"), "any", &["read-code".to_string()]);
        assert!(result.is_err(), "all-local mints no forge credential");
    }
}
