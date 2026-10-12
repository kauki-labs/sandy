//! Trust-root installer: provisions the forge trust root the credential seam
//! consumes (`sandy app register`), as specified in
//! `docs/design/trust-root-installer/`.
//!
//! The pure, provider-neutral parts live here in the library; the network
//! provisioners (the GitHub manifest flow, REST calls) live in `sandy-cli`, so
//! the core crate carries no HTTP client. The one contract this module binds to
//! is [`crate::cred::render_github_permissions`]: the registered App's permission
//! ceiling is rendered by the SAME function a minted token is later scoped
//! through, so the two can never drift.
//!
//! The [`register`] / [`deregister`] pipeline is provider-neutral: a per-forge
//! [`Provisioner`] supplies the registration steps, the capture, the verify
//! probe, and the forge-side revoke; the pipeline enforces the invariants
//! (verify before a config is written; revoke before the local secret is
//! shredded). [`FakeProvisioner`] exercises it without a network or a real
//! trust root.

use std::{
    cell::RefCell,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use serde_json::{Map, Value};

use crate::cred::{Capability, CredError, TrustRoot, render_github_permissions};

/// Parse a [`Capability`] from its CLI spelling (`read-code`, `write-code`,
/// `read-pr`, `write-pr`).
///
/// # Errors
/// Returns the unrecognized token when it matches no capability.
pub fn parse_capability(token: &str) -> Result<Capability, String> {
    match token {
        "read-code" => Ok(Capability::ReadCode),
        "write-code" => Ok(Capability::WriteCode),
        "read-pr" => Ok(Capability::ReadPr),
        "write-pr" => Ok(Capability::WritePr),
        other => Err(other.to_string()),
    }
}

/// Build the GitHub App manifest for the manifest-registration flow, pre-filled
/// from the requested capabilities.
///
/// Permissions come from [`render_github_permissions`] so the registered App's
/// ceiling matches exactly what a minted token will later request. The webhook is
/// disabled (`hook_attributes.active = false`, sandy receives none) and the App is
/// private (`public = false`, "Only on this account"), per the spec's manifest.
#[must_use]
pub fn github_app_manifest(name: &str, url: &str, capabilities: &[Capability]) -> Value {
    let permissions: Map<String, Value> = render_github_permissions(capabilities)
        .into_iter()
        .map(|(key, level)| (key, Value::String(level)))
        .collect();

    let mut hook = Map::new();
    hook.insert("active".to_string(), Value::Bool(false));

    let mut manifest = Map::new();
    manifest.insert("name".to_string(), Value::String(name.to_string()));
    manifest.insert("url".to_string(), Value::String(url.to_string()));
    manifest.insert("public".to_string(), Value::Bool(false));
    manifest.insert("hook_attributes".to_string(), Value::Object(hook));
    manifest.insert("default_events".to_string(), Value::Array(Vec::new()));
    manifest.insert("default_permissions".to_string(), Value::Object(permissions));
    Value::Object(manifest)
}

/// What to show the user before the one manual registration step: the URL to open
/// and the concise steps to follow there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrationPlan {
    /// The pre-filled URL the user opens (the manifest form, or the token page).
    pub open_url: String,
    /// Concise, ordered steps to follow at that URL.
    pub steps: Vec<String>,
}

/// The result of the forge-side teardown in [`deregister`].
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
/// `sandy-cli`; [`FakeProvisioner`] covers the pipeline without a network.
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

/// Register a trust root: capture, verify, then write the config, and only in
/// that order. The config is written *after* the verify probe passes; on a verify
/// failure the just-created credential is torn down (best-effort forge revoke)
/// and its staged secret shredded, so a failed register leaves no usable trust
/// root (REQ-7/REQ-8).
///
/// # Errors
/// Propagates the provisioner's capture/verify error, or a config write error.
pub fn register(
    provisioner: &dyn Provisioner,
    capabilities: &[Capability],
    config_path: &Path,
) -> Result<TrustRoot, InstallError> {
    reject_existing(config_path)?;
    let root = provisioner.capture(capabilities)?;
    if let Err(err) = provisioner.verify(&root, capabilities) {
        // Tear down what capture created; write no config. Revoke needs the secret,
        // so it runs before the shred (the same order deregister keeps).
        let _ = provisioner.revoke(&root);
        shred_secret(&root);
        return Err(err);
    }
    root.write(config_path)?;
    Ok(root)
}

/// Register a trust root WITHOUT the verify probe: capture, then write the
/// config. This exists only for the pilot bootstrap window before the live
/// credential adapter (and thus the dry-run mint) exists, and is reached solely
/// behind an explicit `--skip-verify` flag, never by default, so an unverified
/// registration is a deliberate choice and never a silent no-op (REQ-7). Prefer
/// [`register`], which proves the credential before it writes the config.
///
/// # Errors
/// Propagates the provisioner's capture error, or a config write error.
pub fn register_skip_verify(
    provisioner: &dyn Provisioner,
    capabilities: &[Capability],
    config_path: &Path,
) -> Result<TrustRoot, InstallError> {
    reject_existing(config_path)?;
    let root = provisioner.capture(capabilities)?;
    root.write(config_path)?;
    Ok(root)
}

/// Refuse to register over an existing trust-root config. Checked before capture,
/// so a re-run never creates a second (orphaned) App at the forge.
fn reject_existing(config_path: &Path) -> Result<(), InstallError> {
    if config_path.exists() {
        return Err(InstallError::AlreadyExists {
            path: config_path.to_path_buf(),
        });
    }
    Ok(())
}

/// Deregister a trust root: revoke at the forge **before** shredding the local
/// secret (a GitHub revoke needs the key to sign its JWT), then remove the secret
/// file and the config record. `keep_remote` shreds locally only, for when the
/// user will remove the installation in the UI themselves (REQ-9, decision D7).
///
/// # Errors
/// [`InstallError::Cred`] if the config can't be read, [`InstallError::Revoke`]
/// if the forge revoke fails, or [`InstallError::Io`] removing the config.
pub fn deregister(
    provisioner: &dyn Provisioner,
    config_path: &Path,
    keep_remote: bool,
) -> Result<RevokeOutcome, InstallError> {
    let root = TrustRoot::load(config_path)?;
    let outcome = if keep_remote {
        RevokeOutcome {
            uninstalled: false,
            registration_residue: None,
        }
    } else {
        provisioner.revoke(&root)? // before the shred — order invariant (D7)
    };
    shred_secret(&root);
    remove_path("remove trust-root config", config_path)?;
    Ok(outcome)
}

/// The `0600` secret file a trust root references (the GitHub App key or the
/// GitLab token).
fn secret_path(root: &TrustRoot) -> &Path {
    match root {
        TrustRoot::Github { private_key_path, .. } => private_key_path,
        TrustRoot::Gitlab { token_path, .. } => token_path,
    }
}

/// Best-effort shred of a trust root's secret file: overwrite the bytes, then
/// unlink. Media-level shredding isn't guaranteed on a modern filesystem; this
/// clears the content at the path and removes the file. Absent file is a no-op.
fn shred_secret(root: &TrustRoot) {
    let path = secret_path(root);
    if let Ok(meta) = fs::metadata(path) {
        let len = usize::try_from(meta.len()).unwrap_or(0);
        let _ = fs::write(path, vec![0u8; len]);
    }
    let _ = fs::remove_file(path);
}

/// Remove a file, mapping the error to a named [`InstallError::Io`].
fn remove_path(action: &'static str, path: &Path) -> Result<(), InstallError> {
    fs::remove_file(path).map_err(|source| InstallError::Io {
        action,
        path: path.to_path_buf(),
        source,
    })
}

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

#[cfg(test)]
mod tests {
    use serde_json::json;
    use tempfile::TempDir;

    use super::*;
    use crate::cred::Target;

    fn github_root(key: &Path) -> TrustRoot {
        TrustRoot::Github {
            base_url: None,
            app_id: "1".to_string(),
            private_key_path: key.to_path_buf(),
            installation_id: 42,
            targets: vec![Target("owner/repo".to_string())],
        }
    }

    #[test]
    fn capability_tokens_parse() {
        assert_eq!(parse_capability("read-code"), Ok(Capability::ReadCode));
        assert_eq!(parse_capability("write-code"), Ok(Capability::WriteCode));
        assert_eq!(parse_capability("read-pr"), Ok(Capability::ReadPr));
        assert_eq!(parse_capability("write-pr"), Ok(Capability::WritePr));
    }

    #[test]
    fn an_unknown_capability_token_is_rejected_with_the_token() {
        assert_eq!(parse_capability("admin"), Err("admin".to_string()));
    }

    #[test]
    fn the_manifest_pins_the_webhook_off_and_keeps_the_app_private() {
        let manifest = github_app_manifest(
            "sandy-runner",
            "https://github.com/kauki-labs/sandy",
            &[Capability::WriteCode, Capability::WritePr],
        );
        assert_eq!(manifest["public"], json!(false));
        assert_eq!(manifest["hook_attributes"]["active"], json!(false));
        assert_eq!(manifest["default_events"], json!([]));
    }

    #[test]
    fn manifest_permissions_track_the_shared_renderer() {
        let manifest = github_app_manifest("n", "u", &[Capability::WriteCode, Capability::WritePr]);
        let permissions = &manifest["default_permissions"];
        assert_eq!(permissions["metadata"], json!("read"));
        assert_eq!(permissions["contents"], json!("write"));
        assert_eq!(permissions["pull_requests"], json!("write"));
    }

    #[test]
    fn a_read_only_request_renders_read_and_omits_unrequested_permissions() {
        let manifest = github_app_manifest("n", "u", &[Capability::ReadCode]);
        let permissions = &manifest["default_permissions"];
        assert_eq!(permissions["contents"], json!("read"));
        assert_eq!(permissions["metadata"], json!("read"));
        assert!(permissions.get("pull_requests").is_none());
    }

    #[test]
    fn register_writes_the_config_only_after_verify_passes() -> anyhow::Result<()> {
        let tmp = TempDir::new()?;
        let key = tmp.path().join("key.pem");
        let cfg = tmp.path().join("root.json");
        let provisioner = FakeProvisioner::new(github_root(&key));

        let root = register(&provisioner, &[Capability::WriteCode], &cfg)?;

        assert!(cfg.exists(), "config is written after a passing verify");
        assert!(key.exists(), "the secret stays staged on success");
        assert_eq!(TrustRoot::load(&cfg)?, root, "the written config round-trips");
        Ok(())
    }

    #[test]
    fn register_refuses_an_existing_name_before_creating_anything() -> anyhow::Result<()> {
        let tmp = TempDir::new()?;
        let key = tmp.path().join("key.pem");
        let cfg = tmp.path().join("root.json");
        std::fs::write(&cfg, "{}")?; // a trust root of this name already exists
        let provisioner = FakeProvisioner::new(github_root(&key));

        let err = register(&provisioner, &[Capability::WriteCode], &cfg).expect_err("must refuse");

        assert!(matches!(err, InstallError::AlreadyExists { .. }), "got {err:?}");
        assert!(
            !key.exists(),
            "capture must not run, so no App is created and no secret is staged"
        );
        Ok(())
    }

    #[test]
    fn register_skip_verify_writes_the_config_without_running_verify() -> anyhow::Result<()> {
        // A fake whose verify would FAIL; --skip-verify must still succeed, because
        // it never calls verify. Proves the bypass is a real bypass, not a no-op verify.
        let tmp = TempDir::new()?;
        let key = tmp.path().join("key.pem");
        let cfg = tmp.path().join("root.json");
        let provisioner = FakeProvisioner::failing_verify(github_root(&key));

        let root = register_skip_verify(&provisioner, &[Capability::WriteCode], &cfg)?;

        assert!(cfg.exists(), "skip-verify still writes the config");
        assert_eq!(TrustRoot::load(&cfg)?, root);
        Ok(())
    }

    #[test]
    fn a_failed_verify_writes_no_config_and_shreds_the_secret_and_revokes() -> anyhow::Result<()> {
        let tmp = TempDir::new()?;
        let key = tmp.path().join("key.pem");
        let cfg = tmp.path().join("root.json");
        let provisioner = FakeProvisioner::failing_verify(github_root(&key));

        let err = register(&provisioner, &[Capability::WriteCode], &cfg).expect_err("verify must fail");

        assert!(matches!(err, InstallError::Verify(_)), "got {err:?}");
        assert!(!cfg.exists(), "a failed verify writes no trust-root config");
        assert!(!key.exists(), "a failed verify shreds the staged secret");
        assert!(
            provisioner.was_revoked(),
            "a failed verify tears down the created credential"
        );
        Ok(())
    }

    #[test]
    fn deregister_revokes_before_it_shreds_then_removes_the_config() -> anyhow::Result<()> {
        let tmp = TempDir::new()?;
        let key = tmp.path().join("key.pem");
        let cfg = tmp.path().join("root.json");
        let root = github_root(&key);
        fs::write(&key, b"real-secret")?;
        root.write(&cfg)?;
        let provisioner = FakeProvisioner::new(root);

        let outcome = deregister(&provisioner, &cfg, false)?;

        assert_eq!(
            provisioner.secret_present_at_revoke(),
            Some(true),
            "revoke must run while the secret still exists (before the shred)"
        );
        assert!(outcome.uninstalled);
        assert!(
            outcome.registration_residue.is_some(),
            "the GitHub App-shell residue is reported"
        );
        assert!(!key.exists(), "the secret is shredded");
        assert!(!cfg.exists(), "the config is removed");
        Ok(())
    }

    #[test]
    fn deregister_keep_remote_shreds_locally_without_a_forge_revoke() -> anyhow::Result<()> {
        let tmp = TempDir::new()?;
        let key = tmp.path().join("key.pem");
        let cfg = tmp.path().join("root.json");
        let root = github_root(&key);
        fs::write(&key, b"real-secret")?;
        root.write(&cfg)?;
        let provisioner = FakeProvisioner::new(root);

        let outcome = deregister(&provisioner, &cfg, true)?;

        assert!(!provisioner.was_revoked(), "keep_remote skips the forge revoke");
        assert!(!outcome.uninstalled);
        assert!(!key.exists(), "the local secret is still shredded");
        assert!(!cfg.exists(), "the config is still removed");
        Ok(())
    }
}
