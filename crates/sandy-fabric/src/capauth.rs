//! The capability-authority seam (spec §3.8): signs, verifies, and attenuates
//! channel capabilities.
//!
//! A channel credential is a join/use capability scoped `{peer, channel, rights,
//! TTL}`, minted outside the sandbox (INV-1). A sub-agent joins with an attenuated
//! derivative of its parent's cap, which may only ever narrow. The proof format
//! (biscuit placeholder, minisign identity root, platform attestation, …) stays
//! behind the seam: callers see only [`Cap`] and its [`CapScope`]. The seam is
//! synchronous: verify sits on the hot path of every join, post and subscribe and
//! is pure crypto. A root backed by remote state (a chain) verifies against a
//! locally synced cache and syncs out of band.

use serde::{Deserialize, Serialize};

use crate::types::{ChannelId, PeerId};

/// What a capability lets its holder do on its channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct CapRights {
    /// Post messages.
    pub post: bool,
    /// Read (subscribe to) messages.
    pub read: bool,
    /// Invite further members with an attenuated cap.
    pub invite: bool,
}

impl CapRights {
    /// Whether every right in `self` is also held by `other`.
    pub fn is_subset_of(&self, other: &CapRights) -> bool {
        (!self.post || other.post) && (!self.read || other.read) && (!self.invite || other.invite)
    }
}

/// The authority a capability carries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapScope {
    /// The peer the capability is issued to.
    pub peer: PeerId,
    /// The one channel it authorizes (boundedness).
    pub channel: ChannelId,
    /// The rights granted on that channel.
    pub rights: CapRights,
    /// Expiry as Unix seconds; `None` means the authority's default TTL.
    pub expires_at: Option<u64>,
}

/// A signed capability: its scope plus the authority's opaque proof.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cap {
    /// The claimed scope. Only trust it after [`CapAuthority::verify`].
    pub scope: CapScope,
    /// The opaque proof binding `scope` to the authority. Bearer credential
    /// material (a holder can present it as this `scope`): the `Debug` impl
    /// below redacts it from `{:?}` output, but `Cap` still derives
    /// `Serialize`/`Deserialize` over the real bytes — this does NOT guard
    /// `serde_json::to_string`, a JSON-mode tracing subscriber, or any future
    /// audit sink that serializes a `Cap` directly.
    pub proof: Vec<u8>,
}

impl std::fmt::Debug for Cap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Cap")
            .field("scope", &self.scope)
            .field("proof", &"<redacted>")
            .finish()
    }
}

/// A capability-authority failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CapError {
    /// The proof does not match the scope, or was not issued by this authority.
    #[error("capability is forged or tampered")]
    Forged,
    /// The capability is past its expiry.
    #[error("capability expired")]
    Expired,
    /// The capability was revoked before its expiry (#129).
    #[error("capability revoked")]
    Revoked,
    /// An attenuation asked for rights the parent does not hold.
    #[error("attenuation would widen the parent's rights")]
    Widened,
    /// The authority itself failed (key store, …).
    #[error("authority error: {0}")]
    Authority(String),
}

/// Signs, verifies and attenuates channel capabilities.
pub trait CapAuthority: Send + Sync {
    /// Mint a capability for `scope`.
    fn mint(&self, scope: CapScope) -> Result<Cap, CapError>;
    /// Verify `cap` and return the scope it actually authorizes.
    fn verify(&self, cap: &Cap) -> Result<CapScope, CapError>;
    /// Derive a capability from `parent` narrowed to `rights`, for a sub-agent that
    /// joins as the parent's representative. Must fail with [`CapError::Widened`]
    /// when `rights` is not a subset of the parent's.
    fn attenuate(&self, parent: &Cap, rights: CapRights) -> Result<Cap, CapError>;
}
