//! [`LocalCapAuthority`]: the step-1 local [`CapAuthority`] (issue #110) — a
//! single-process, HMAC-SHA256 attenuable signer (spec §3.8's "biscuit-style
//! placeholder"). Attenuation always goes through the authority (no holder-side
//! offline attenuation): spec §3.4 has membership orchestrator-assigned for now,
//! and the orchestrator is the party that can reach the authority, so this matches
//! the all-local MVP rather than cutting a corner. Real-biscuit offline
//! attenuation is the deferred, richer impl behind the same seam.

use std::{
    sync::{Mutex, PoisonError},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use hmac::{Hmac, KeyInit, Mac};
use sandy_fabric::capauth::{Cap, CapAuthority, CapError, CapRights, CapScope};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// A single-process [`CapAuthority`] signing with a random per-instance key.
///
/// The key never leaves the process that holds it: a sandbox is never handed the
/// authority, only caps it mints (INV-1), so a cap minted anywhere else fails
/// [`verify`](CapAuthority::verify) as [`CapError::Forged`].
pub struct LocalCapAuthority {
    key: [u8; 32],
    /// Applied to a minted scope's `expires_at` when the caller leaves it `None`,
    /// so "`None` means the authority's default TTL" is literally true: every
    /// signed scope carries a concrete expiry (CWE-613, no unbounded cap).
    default_ttl: Duration,
    /// Revoked caps' proof bytes (#129): the proof already uniquely identifies a
    /// minted cap, so it doubles as the stable id to revoke by with no new field
    /// on `Cap`. Distribution of this set over the transport is deferred; step 1
    /// is in-process only, per the issuer-owns-its-set governance in #129.
    revoked: Mutex<std::collections::HashSet<Vec<u8>>>,
}

impl LocalCapAuthority {
    /// Create an authority with a fresh random key and `default_ttl` applied to
    /// any scope minted without an explicit `expires_at`.
    ///
    /// # Errors
    /// [`CapError::Authority`] if the system RNG is unavailable.
    pub fn new(default_ttl: Duration) -> Result<Self, CapError> {
        let mut key = [0u8; 32];
        getrandom::fill(&mut key).map_err(|e| CapError::Authority(format!("rng: {e}")))?;
        Ok(Self {
            key,
            default_ttl,
            revoked: Mutex::new(std::collections::HashSet::new()),
        })
    }

    /// Mark `cap` as revoked ahead of its TTL (#129). A no-op if already revoked.
    pub fn revoke(&self, cap: &Cap) {
        self.revoked
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(cap.proof.clone());
    }

    /// Whether `cap` has been revoked. Does not check the proof or expiry;
    /// [`verify`](CapAuthority::verify) combines all three.
    pub fn is_revoked(&self, cap: &Cap) -> bool {
        self.revoked
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains(&cap.proof)
    }

    /// Key the MAC over `scope`'s canonical bytes.
    fn mac(&self, scope: &CapScope) -> Result<HmacSha256, CapError> {
        let mut mac =
            HmacSha256::new_from_slice(&self.key).map_err(|e| CapError::Authority(format!("hmac key: {e}")))?;
        mac.update(&canonical_scope_bytes(scope));
        Ok(mac)
    }
}

impl CapAuthority for LocalCapAuthority {
    fn mint(&self, mut scope: CapScope) -> Result<Cap, CapError> {
        if scope.expires_at.is_none() {
            scope.expires_at = Some(unix_now()?.saturating_add(self.default_ttl.as_secs()));
        }
        let proof = self.mac(&scope)?.finalize().into_bytes().to_vec();
        Ok(Cap { scope, proof })
    }

    fn verify(&self, cap: &Cap) -> Result<CapScope, CapError> {
        self.mac(&cap.scope)?
            .verify_slice(&cap.proof)
            .map_err(|_| CapError::Forged)?;
        // Expiry is a pure clock check; revocation needs the set lock. Order is
        // otherwise arbitrary: #129 treats a cap as valid only if both hold.
        let now = unix_now()?;
        if cap.scope.expires_at.is_some_and(|t| t <= now) {
            return Err(CapError::Expired);
        }
        if self.is_revoked(cap) {
            return Err(CapError::Revoked);
        }
        Ok(cap.scope.clone())
    }

    fn attenuate(&self, parent: &Cap, rights: CapRights) -> Result<Cap, CapError> {
        let parent_scope = self.verify(parent)?;
        if !rights.is_subset_of(&parent_scope.rights) {
            return Err(CapError::Widened);
        }
        // expires_at carries over from the verified parent scope unchanged, so
        // attenuation can only narrow rights, never extend the TTL.
        self.mint(CapScope { rights, ..parent_scope })
    }
}

/// Seconds since the Unix epoch, or [`CapError::Authority`] if the clock is
/// unavailable (e.g. set before 1970) — never silently treated as epoch zero.
fn unix_now() -> Result<u64, CapError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| CapError::Authority(format!("clock: {e}")))
}

/// A length-prefixed, field-order-fixed encoding of `scope`'s contents, so no
/// concatenation of two fields can collide with a different split between them.
fn canonical_scope_bytes(scope: &CapScope) -> Vec<u8> {
    let mut buf = Vec::new();
    write_field(&mut buf, scope.peer.0.as_bytes());
    write_field(&mut buf, scope.channel.0.as_bytes());
    buf.push(u8::from(scope.rights.post));
    buf.push(u8::from(scope.rights.read));
    buf.push(u8::from(scope.rights.invite));
    match scope.expires_at {
        None => buf.push(0),
        Some(t) => {
            buf.push(1);
            buf.extend_from_slice(&t.to_be_bytes());
        }
    }
    buf
}

fn write_field(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    buf.extend_from_slice(bytes);
}

/// A `CapAuthority`'s key material must never print (never log secrets).
impl std::fmt::Debug for LocalCapAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalCapAuthority").finish_non_exhaustive()
    }
}
