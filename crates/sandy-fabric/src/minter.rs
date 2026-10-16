//! The minter seam (spec §3.8): mints a job's work-secret.
//!
//! The default impl is agent-local, so the secret never leaves the host (INV-1);
//! controller-transit is the opt-in alternative. Work-secrets ride as scoped
//! payloads, never bundled into a channel join cap. Minting is CPU-bound, so this
//! seam is synchronous.

/// What to mint a work-secret for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretRequest {
    /// The job the secret is scoped to.
    pub job: String,
}

/// A freshly minted work-secret. `Debug` redacts the bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct MintedSecret {
    /// The secret bytes. Staged in over the secret channel only (INV-1).
    pub bytes: Vec<u8>,
}

impl std::fmt::Debug for MintedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MintedSecret").field("bytes", &"<redacted>").finish()
    }
}

/// A minting failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MinterError {
    /// No entropy or key material was available.
    #[error("mint failed: {0}")]
    Mint(String),
}

/// Mints job work-secrets. Every mint is fresh: no two calls return the same bytes.
pub trait Minter {
    /// Mint a new work-secret for `req`.
    fn mint(&self, req: &SecretRequest) -> Result<MintedSecret, MinterError>;
}
