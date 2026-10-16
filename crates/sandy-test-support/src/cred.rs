//! [`FakeProvider`]: an in-memory [`CredentialProvider`] test double.

use std::{
    sync::{Mutex, PoisonError},
    time::{Duration, SystemTime},
};

use sandy_api::cred::{CredError, CredentialHandle, CredentialProvider, Lease, MAX_TTL_SECS, Minted, Scope};

/// An in-memory [`CredentialProvider`] test double.
///
/// Built with [`FakeProvider::returning`] to hand back a scripted secret, or
/// [`FakeProvider::failing`] to fail every mint. Records the `(scope, ttl_hint)` of
/// each mint and the handle of each revoke, inspectable via [`FakeProvider::mints`]
/// and [`FakeProvider::revoked`].
pub struct FakeProvider {
    token: String,
    fail: bool,
    mints: Mutex<Vec<(Scope, Duration)>>,
    revokes: Mutex<Vec<CredentialHandle>>,
}

impl FakeProvider {
    /// A provider whose every mint/refresh returns `token`.
    #[must_use]
    pub fn returning(token: &str) -> Self {
        Self {
            token: token.to_string(),
            fail: false,
            mints: Mutex::new(Vec::new()),
            revokes: Mutex::new(Vec::new()),
        }
    }

    /// A provider whose every mint/refresh fails with [`CredError::Mint`].
    #[must_use]
    pub fn failing() -> Self {
        Self {
            token: String::new(),
            fail: true,
            mints: Mutex::new(Vec::new()),
            revokes: Mutex::new(Vec::new()),
        }
    }

    /// The `(scope, ttl_hint)` of every [`CredentialProvider::mint`] call.
    #[must_use]
    pub fn mints(&self) -> Vec<(Scope, Duration)> {
        self.mints.lock().unwrap_or_else(PoisonError::into_inner).clone()
    }

    /// The handle of every [`CredentialProvider::revoke`] call.
    #[must_use]
    pub fn revoked(&self) -> Vec<CredentialHandle> {
        self.revokes.lock().unwrap_or_else(PoisonError::into_inner).clone()
    }

    fn mint_inner(&self, scope: &Scope, ttl_hint: Duration) -> Result<Minted, CredError> {
        if self.fail {
            return Err(CredError::Mint("fake provider configured to fail".to_string()));
        }
        self.mints
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((scope.clone(), ttl_hint));
        Ok(Minted::new(
            self.token.clone(),
            SystemTime::now() + ttl_hint,
            CredentialHandle {
                id: "fake-installation".to_string(),
            },
        ))
    }
}

impl CredentialProvider for FakeProvider {
    fn mint(&self, scope: &Scope, ttl_hint: Duration) -> Result<Minted, CredError> {
        self.mint_inner(scope, ttl_hint)
    }

    fn revoke(&self, lease: &Lease) -> Result<(), CredError> {
        self.revokes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(lease.handle.clone());
        Ok(())
    }

    fn refresh(&self, lease: &Lease) -> Result<Minted, CredError> {
        if self.fail {
            return Err(CredError::Mint("fake provider configured to fail".to_string()));
        }
        Ok(Minted::new(
            self.token.clone(),
            SystemTime::now() + Duration::from_secs(MAX_TTL_SECS as u64),
            lease.handle.clone(),
        ))
    }
}
