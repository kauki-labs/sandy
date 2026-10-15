//! The trust-root installer seam: the [`Provisioner`] contract and its data/error
//! types. The register/deregister pipeline and the live GitHub provisioner live in
//! the crates that depend on this one.

use std::path::PathBuf;

use crate::cred::{Capability, CredError, TrustRoot};

/// What to show the user before the one manual registration step: the URL to open
/// and the concise steps to follow there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrationPlan {
    /// The pre-filled URL the user opens (the manifest form, or the token page).
    pub open_url: String,
    /// Concise, ordered steps to follow at that URL.
    pub steps: Vec<String>,
}

/// The result of the forge-side teardown in the core's `deregister`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevokeOutcome {
    /// Whether the forge-side credential/installation was removed.
    pub uninstalled: bool,
    /// For GitHub, where the App *registration* can't be deleted via API, the URL
    /// at which the user manually deletes the now-powerless App shell. `None` when
    /// nothing remains (e.g. GitLab, or a local-only teardown).
    pub registration_residue: Option<String>,
}

/// Errors raised while registering or deregistering a trust root.
#[derive(Debug, thiserror::Error)]
pub enum InstallError {
    /// The provisioner failed to register/capture the credential at the forge.
    #[error("capture failed: {0}")]
    Capture(String),
    /// The verify probe failed: the credential does not mint, or grants more than
    /// requested. A registration that reaches this writes no config.
    #[error("verification failed: {0}")]
    Verify(String),
    /// The forge-side revoke failed during deregister.
    #[error("forge revoke failed: {0}")]
    Revoke(String),
    /// A trust root with this name already exists; register refuses to overwrite
    /// it (which would orphan the existing App at the forge). Deregister it first,
    /// or choose another name.
    #[error("a trust root already exists at {path}; deregister it first or choose another name")]
    AlreadyExists {
        /// The existing config path.
        path: PathBuf,
    },
    /// A credential-seam error (e.g. reading/writing the trust-root config).
    #[error(transparent)]
    Cred(#[from] CredError),
    /// A local filesystem error, naming the action and path.
    #[error("{action} {path}: {source}")]
    Io {
        /// What was being attempted.
        action: &'static str,
        /// The path involved.
        path: PathBuf,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },
}

/// A per-forge registration backend. The pipeline owns the ordering invariants;
/// an implementation owns the forge-specific registration, capture, probe, and
/// revoke. The real GitHub implementation (manifest flow + REST) lives in
/// `sandy-cli`; a fake covers the pipeline without a network.
pub trait Provisioner {
    /// The URL + steps to present before the manual registration click.
    fn plan(&self, capabilities: &[Capability]) -> RegistrationPlan;
    /// Register at the forge and capture the trust root, staging its secret to a
    /// `0600` file referenced by the returned [`TrustRoot`].
    ///
    /// # Errors
    /// [`InstallError::Capture`] when registration or capture fails.
    fn capture(&self, capabilities: &[Capability]) -> Result<TrustRoot, InstallError>;
    /// Prove the captured credential mints at the requested scope and grants no
    /// more than requested.
    ///
    /// # Errors
    /// [`InstallError::Verify`] when the credential does not work or is broader
    /// than requested.
    fn verify(&self, root: &TrustRoot, capabilities: &[Capability]) -> Result<(), InstallError>;
    /// Revoke the credential at the forge (uninstall the App / revoke the token).
    ///
    /// # Errors
    /// [`InstallError::Revoke`] when the forge call fails.
    fn revoke(&self, root: &TrustRoot) -> Result<RevokeOutcome, InstallError>;
}
