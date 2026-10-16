//! [`LocalCapAuthority`]: the step-1 local [`CapAuthority`] (issue #110).

use std::sync::Mutex;

use sandy_fabric::capauth::{Cap, CapAuthority, CapError, CapRights, CapScope};

/// A single-process [`CapAuthority`] signing with a random per-instance key.
///
/// TODO(#110): HMAC-SHA256 signing, revocation, and the canonical scope encoding.
pub struct LocalCapAuthority {
    key: [u8; 32],
    revoked: Mutex<()>,
}

impl LocalCapAuthority {
    /// Create an authority with a fresh random key.
    ///
    /// # Errors
    /// [`CapError::Authority`] if the system RNG is unavailable.
    pub fn new() -> Result<Self, CapError> {
        Ok(Self {
            key: [0; 32],
            revoked: Mutex::new(()),
        })
    }

    /// Mark `cap` as revoked ahead of its TTL (#129).
    pub fn revoke(&self, _cap: &Cap) {}

    /// Whether `cap` has been revoked.
    pub fn is_revoked(&self, _cap: &Cap) -> bool {
        false
    }
}

impl CapAuthority for LocalCapAuthority {
    fn mint(&self, _scope: CapScope) -> Result<Cap, CapError> {
        Err(CapError::Authority("not yet implemented".into()))
    }

    fn verify(&self, _cap: &Cap) -> Result<CapScope, CapError> {
        Err(CapError::Authority("not yet implemented".into()))
    }

    fn attenuate(&self, _parent: &Cap, _rights: CapRights) -> Result<Cap, CapError> {
        Err(CapError::Authority("not yet implemented".into()))
    }
}
