//! The provider-agnostic credential seam: the [`CredentialProvider`] contract and
//! its data/error types. The clamp-and-stage flow, the fakes, and the live
//! GitHub/GitLab adapters live in the crates that depend on this one.

use std::{
    fmt,
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

use serde::{Deserialize, Serialize};

use crate::backend::SecretRef;

/// The maximum credential TTL hint: 50 minutes. A larger request is clamped to
/// this bound before minting. The clamp only bounds a credential's real lifetime
/// when paired with revoke-at-expiry (Block 2); a provider's own token may outlive
/// it (GitHub issues a fixed-hour token regardless of the request).
pub const MAX_TTL_SECS: u32 = 3000;

/// A capability a job needs at a forge, provider-neutral. Each adapter renders a
/// capability into provider permissions (GitHub) or scopes plus a role (GitLab);
/// see the core's `render_github_permissions`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Capability {
    /// Read repository contents.
    ReadCode,
    /// Read and write repository contents.
    WriteCode,
    /// Read pull/merge requests.
    ReadPr,
    /// Open and update pull/merge requests.
    WritePr,
}

/// A repository (GitHub) or project (GitLab) a credential is scoped to, as the
/// provider's own path (e.g. `"owner/repo"`). The GitHub adapter renders this to a
/// bare repo name for the installation token's `repositories` param (the owner is
/// fixed by the installation), so it strips any `owner/` prefix.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Target(pub String);

/// The provider-neutral scope of one credential: the targets it may reach and the
/// capabilities granted. An adapter renders this onto its provider's own model.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Scope {
    /// Repositories or projects the credential is limited to.
    pub targets: Vec<Target>,
    /// Capabilities granted on those targets.
    pub capabilities: Vec<Capability>,
}

/// An opaque, provider-defined handle to revoke or refresh a credential. Carries a
/// provider id (e.g. a GitLab token id, or a GitHub installation id), never secret
/// bytes, so it is safe to log (INV-1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialHandle {
    /// Provider-defined id, interpreted by the adapter that issued it.
    pub id: String,
}

/// The transient result of a mint: the secret bytes plus the lease metadata,
/// immediately staged into a [`Lease`] by the core's `mint_lease`. Its
/// [`fmt::Debug`] redacts the secret so a stray log never leaks it (INV-1).
pub struct Minted {
    secret: String,
    /// When the provider's token expires (the backstop, not the primary bound).
    pub expires_at: SystemTime,
    /// The handle to revoke or refresh this credential.
    pub handle: CredentialHandle,
}

impl Minted {
    /// Build a mint result. Adapters call this; the secret is read back only by
    /// the core's `mint_lease` when staging to the `0600` file.
    #[must_use]
    pub fn new(secret: String, expires_at: SystemTime, handle: CredentialHandle) -> Self {
        Self {
            secret,
            expires_at,
            handle,
        }
    }

    /// The minted secret bytes, for the core's staging path ONLY — the one reader
    /// that writes them to the `0600` file. Not a general getter: the bytes travel
    /// the secret channel only, never argv/env/store/logs (INV-1), and `Debug`
    /// redacts them. Do not reach for this elsewhere.
    #[must_use]
    pub fn secret(&self) -> &str {
        &self.secret
    }
}

impl fmt::Debug for Minted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Minted")
            .field("secret", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .field("handle", &self.handle)
            .finish()
    }
}

/// A staged, loggable credential: a `0600` secret-file reference, the expiry, and
/// the handle to revoke or refresh it. Carries no secret bytes (INV-1); the bytes
/// live only in the file [`SecretRef`] points at.
#[derive(Debug)]
pub struct Lease {
    /// The staged secret the guest reads.
    pub secret_ref: SecretRef,
    /// When the underlying token expires (teardown revokes before relying on this).
    pub expires_at: SystemTime,
    /// The handle to revoke or refresh this credential.
    pub handle: CredentialHandle,
}

/// Errors raised while minting, revoking, or staging a credential.
#[derive(Debug, thiserror::Error)]
pub enum CredError {
    /// Minting failed. An infra fault: it maps to the exit-3 retryable band
    /// (INV-7/INV-11), so the caller fails retryable and never runs the job with no
    /// credential.
    #[error("credential mint failed: {0}")]
    Mint(String),
    /// Revoking a credential failed.
    #[error("credential revoke failed: {0}")]
    Revoke(String),
    /// Staging the minted secret to its `0600` file failed.
    #[error("staging credential failed: {0}")]
    Stage(String),
}

/// The seam a forge adapter implements: mint a scoped credential, revoke it, and
/// refresh it. The live GitHub/GitLab adapters implement this; a fake is the
/// tier-2 double.
///
/// `revoke` and `refresh` take the whole [`Lease`], not just the handle, because a
/// GitHub revoke (`DELETE /installation/token`) authenticates with the token in the
/// lease's secret file, while a GitLab revoke needs only the handle id.
pub trait CredentialProvider {
    /// Mint a credential for `scope`, valid for about `ttl_hint` (clamped by the
    /// caller to [`MAX_TTL_SECS`]; the provider may issue a coarser native TTL).
    ///
    /// # Errors
    /// [`CredError::Mint`] when the credential cannot be minted.
    fn mint(&self, scope: &Scope, ttl_hint: Duration) -> Result<Minted, CredError>;

    /// Revoke a staged credential so it is invalid before its native expiry.
    ///
    /// # Errors
    /// [`CredError::Revoke`] when the revoke call fails.
    fn revoke(&self, lease: &Lease) -> Result<(), CredError>;

    /// Refresh a credential whose job outlives the provider's token cap, returning
    /// fresh bytes to re-stage.
    ///
    /// # Errors
    /// [`CredError::Mint`] when the refresh mint fails.
    fn refresh(&self, lease: &Lease) -> Result<Minted, CredError>;
}

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

/// The operator-provided trust root the installer writes and an adapter reads to
/// mint. Carries only non-secret config: the secret material (GitHub App private
/// key, GitLab PAT) lives in a `0600` file referenced by path, never inline
/// (INV-1). GitHub is supported now; the GitLab variant is reserved (adapter
/// deferred). The load/write IO lives in the core crate (contract-only here).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TrustRoot {
    /// A GitHub App installation.
    Github {
        /// API base, for GitHub Enterprise Server; `None` is github.com.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        base_url: Option<String>,
        /// The GitHub App id.
        app_id: String,
        /// Path to the App private key (`0600` PEM), never the bytes.
        private_key_path: PathBuf,
        /// The installation id the token is minted for.
        installation_id: u64,
        /// Repositories the credential may be scoped to.
        targets: Vec<Target>,
    },
    /// A GitLab project or group access-token root (adapter deferred).
    Gitlab {
        /// API base, for self-managed GitLab; `None` is gitlab.com.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        base_url: Option<String>,
        /// Path to the service-account PAT (`0600`), never the bytes.
        token_path: PathBuf,
        /// The project or group the token is scoped to.
        account: GitlabAccount,
        /// Projects the credential may be scoped to.
        targets: Vec<Target>,
    },
}

/// Whether a GitLab trust root is scoped to a single project or a whole group.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "scope", rename_all = "snake_case")]
pub enum GitlabAccount {
    /// A single project (preferred, no group blast radius).
    Project {
        /// The project id or path.
        id: String,
    },
    /// A whole group.
    Group {
        /// The group id or path.
        id: String,
    },
}
