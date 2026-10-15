//! The run composition root: one implementation per seam that `dispatch` selects.
//!
//! The run-dispatch path chooses exactly three seams at the composition boundary —
//! the sandbox backend ([`VmBackend`]), the egress applier ([`EgressApplier`]), and
//! (when `--credential` is given) the credential provider ([`CredentialProvider`]).
//! A [`Profile`] bundles that choice so the host, local-VM, and all-local profiles
//! differ only in which impls they carry, not in the dispatch code.
//!
//! This crate defines the bundle over the seam **traits** only; the concrete
//! profiles (`host` today, all-local later) are built in `sandy-cli`, which may
//! depend on `sandy-backend` — so no `sandy` → `sandy-backend` edge is introduced.
//!
//! The other seams (guest share, console transport, signature verifier,
//! provisioner, remote builder) are owned by the backend impl or the provision
//! flow, not selected here.

use std::path::Path;

use crate::{CredentialProvider, EgressApplier, EgressOs, Scope, VmBackend};

/// How a profile obtains its credential provider.
///
/// The provider is runtime-constructed from `--credential` plus the trust root, so
/// a profile carries the *construction*, not a prebuilt provider: the host profile
/// loads the named trust root and builds the live adapter; the all-local profile
/// selects a local/fake provider. Returns the boxed provider and the [`Scope`] to
/// mint for, or a human-readable config fault.
pub trait CredentialSource {
    /// Build the provider and the scope for a run. `dir` is the user config dir,
    /// `name` the trust-root name, `capabilities` the requested capabilities.
    fn provider(
        &self,
        dir: &Path,
        name: &str,
        capabilities: &[String],
    ) -> Result<(Box<dyn CredentialProvider + Sync>, Scope), String>;
}

/// One implementation per run seam — the sandbox backend, the egress applier, and
/// the credential source. The host profile reproduces today's wiring; a different
/// profile (all-local, local-VM) swaps the impls without touching the dispatch
/// code that threads them.
pub struct Profile {
    backend: Box<dyn VmBackend>,
    egress: Box<dyn EgressApplier>,
    egress_os: EgressOs,
    cred: Box<dyn CredentialSource>,
}

impl Profile {
    /// Bundle a chosen impl for each run seam. The concrete choices live in the
    /// composition root (`sandy-cli`); this constructor is the seam-neutral bundle.
    pub fn new(
        backend: Box<dyn VmBackend>,
        egress: Box<dyn EgressApplier>,
        egress_os: EgressOs,
        cred: Box<dyn CredentialSource>,
    ) -> Self {
        Self {
            backend,
            egress,
            egress_os,
            cred,
        }
    }

    /// The selected sandbox backend.
    pub fn backend(&self) -> &dyn VmBackend {
        self.backend.as_ref()
    }

    /// The selected egress applier.
    pub fn egress(&self) -> &dyn EgressApplier {
        self.egress.as_ref()
    }

    /// The egress OS model to plan against (Linux enforces, macOS is unenforced).
    pub fn egress_os(&self) -> EgressOs {
        self.egress_os
    }

    /// The credential source for this profile.
    pub fn cred(&self) -> &dyn CredentialSource {
        self.cred.as_ref()
    }
}
