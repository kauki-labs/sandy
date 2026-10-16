//! [`FakeProvisioner`]: a [`Provisioner`] test double with canned capture, a
//! toggleable verify, and a recorded revoke.

use std::{cell::RefCell, fs, os::unix::fs::PermissionsExt, path::Path};

use sandy_api::{
    cred::{Capability, TrustRoot},
    trust_root::{InstallError, Provisioner, RegistrationPlan, RevokeOutcome},
};

/// A [`Provisioner`] test double: canned capture, a toggleable verify, and a
/// recorded revoke. Public (not `cfg(test)`) so `sandy-cli` tier-2 tests can
/// drive the pipeline without a forge, mirroring the seam's `FakeProvider`.
pub struct FakeProvisioner {
    root: TrustRoot,
    fail_verify: bool,
    revoked: RefCell<bool>,
    secret_present_at_revoke: RefCell<Option<bool>>,
}

impl FakeProvisioner {
    /// A fake whose verify passes.
    #[must_use]
    pub fn new(root: TrustRoot) -> Self {
        Self {
            root,
            fail_verify: false,
            revoked: RefCell::new(false),
            secret_present_at_revoke: RefCell::new(None),
        }
    }

    /// A fake whose verify always fails, to drive the register cleanup path.
    #[must_use]
    pub fn failing_verify(root: TrustRoot) -> Self {
        Self {
            fail_verify: true,
            ..Self::new(root)
        }
    }

    /// Whether [`Provisioner::revoke`] was called.
    #[must_use]
    pub fn was_revoked(&self) -> bool {
        *self.revoked.borrow()
    }

    /// Whether the secret file still existed at the moment revoke was called, or
    /// `None` if revoke never ran. Proves revoke precedes the shred (D7).
    #[must_use]
    pub fn secret_present_at_revoke(&self) -> Option<bool> {
        *self.secret_present_at_revoke.borrow()
    }
}

/// The `0600` secret file a trust root references (the GitHub App key or the GitLab
/// token). Inlined here (not shared with the core's private `secret_path`) so this
/// crate stays sandy-api-only.
fn secret_path(root: &TrustRoot) -> &Path {
    match root {
        TrustRoot::Github { private_key_path, .. } => private_key_path,
        TrustRoot::Gitlab { token_path, .. } => token_path,
    }
}

impl Provisioner for FakeProvisioner {
    fn plan(&self, _capabilities: &[Capability]) -> RegistrationPlan {
        RegistrationPlan {
            open_url: "https://example.test/apps/new".to_string(),
            steps: vec!["click Create".to_string(), "click Install".to_string()],
        }
    }

    fn capture(&self, _capabilities: &[Capability]) -> Result<TrustRoot, InstallError> {
        // Stage a fake secret at the root's referenced path, so the shred paths
        // have a real file to remove.
        let path = secret_path(&self.root);
        fs::write(path, b"fake-secret-bytes").map_err(|source| InstallError::Io {
            action: "stage fake secret",
            path: path.to_path_buf(),
            source,
        })?;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
        Ok(self.root.clone())
    }

    fn verify(&self, _root: &TrustRoot, _capabilities: &[Capability]) -> Result<(), InstallError> {
        if self.fail_verify {
            Err(InstallError::Verify("fake verify failure".to_string()))
        } else {
            Ok(())
        }
    }

    fn revoke(&self, root: &TrustRoot) -> Result<RevokeOutcome, InstallError> {
        *self.secret_present_at_revoke.borrow_mut() = Some(secret_path(root).exists());
        *self.revoked.borrow_mut() = true;
        Ok(RevokeOutcome {
            uninstalled: true,
            registration_residue: Some("https://example.test/apps/sandy-runner/advanced".to_string()),
        })
    }
}
