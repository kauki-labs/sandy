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

/// A capability could not be encoded or decoded.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("malformed capability encoding: {0}")]
pub struct CapCodecError(String);

/// Encode `cap` for handoff: the bytes one side writes and [`decode_cap`] reads,
/// for example over the consume-once pipe that carries the bootstrap cap from the
/// executor to the agent (#108, #109).
pub fn encode_cap(cap: &Cap) -> Result<Vec<u8>, CapCodecError> {
    serde_json::to_vec(cap).map_err(|e| CapCodecError(e.to_string()))
}

/// Decode bytes written by [`encode_cap`].
///
/// This parses; it does not verify. A decoded cap is only a claim until
/// [`CapAuthority::verify`] accepts it.
pub fn decode_cap(bytes: &[u8]) -> Result<Cap, CapCodecError> {
    serde_json::from_slice(bytes).map_err(|e| CapCodecError(e.to_string()))
}

/// The file descriptor a launched sandbox agent reads its bootstrap
/// orchestrator-channel cap from (#109), on the local process backend.
///
/// NOT a staged file: the guest's login shell exports every file under
/// `/run/sandy/secrets` into the job's environment, so a cap staged there would
/// let the untrusted job present it and act as the agent (see `docs/decisions/`,
/// #177). Instead the executor that launches the agent opens a pipe, writes the
/// cap ([`encode_cap`]) to the write end, closes it, and passes the read end to
/// the agent at this fixed descriptor — never `0`/`1`/`2`. The agent reads it to
/// EOF exactly once ([`decode_cap`]), then closes it before spawning the job, so
/// the job never inherits the descriptor or anything derived from it. A VM
/// sandbox's equivalent handoff rides a reserved vsock port instead; this
/// constant is for the local/process backend only.
pub const AGENT_CAP_FD: std::os::unix::io::RawFd = 3;

#[cfg(test)]
mod tests {
    use super::*;

    fn cap() -> Cap {
        Cap {
            scope: CapScope {
                peer: "agent".into(),
                channel: "orchestrator".into(),
                rights: CapRights {
                    post: true,
                    read: true,
                    invite: false,
                },
                expires_at: Some(4_102_444_800),
            },
            proof: vec![0xc0, 0xff, 0xee],
        }
    }

    #[test]
    fn a_cap_round_trips_through_its_encoding() -> Result<(), CapCodecError> {
        let encoded = encode_cap(&cap())?;
        // Not assert_eq!: on failure it would print the proof through Cap's Debug.
        assert!(decode_cap(&encoded)? == cap(), "the cap changed in the round trip");
        Ok(())
    }

    #[test]
    fn truncated_or_foreign_bytes_do_not_decode() -> Result<(), CapCodecError> {
        let encoded = encode_cap(&cap())?;
        assert!(
            decode_cap(&encoded[..encoded.len() / 2]).is_err(),
            "a truncated cap decoded"
        );
        assert!(decode_cap(b"").is_err(), "an empty handoff decoded");
        assert!(decode_cap(b"{\"scope\":{}}").is_err(), "a cap without a proof decoded");
        Ok(())
    }
}
