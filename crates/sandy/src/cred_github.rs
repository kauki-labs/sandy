//! Live GitHub App credential adapter (Block 3 / #49).
//!
//! Mints a scoped installation access token from a GitHub App trust root: sign an
//! App JWT from the private key, `POST /app/installations/{id}/access_tokens` with
//! the repositories and permissions rendered from the [`Scope`], and return the
//! token as a [`Minted`]. octocrab's built-in `installation_and_token` mints a
//! FULL-scope token (it sends an empty body), so this adapter issues the scoped
//! request itself. `revoke` is `DELETE /installation/token` (it authenticates with
//! the token), `refresh` re-mints (GitHub has no rotate API).
//!
//! The App private key and every minted token stay in the controller process: the
//! key is read once through [`read_secret_0600`] (a group/world-readable key is
//! refused), and each token is held in memory keyed by an opaque handle so revoke
//! and refresh need neither the staged (by-teardown wiped) secret file nor a
//! re-passed scope. Only the scoped, short-lived token reaches the guest, over the
//! [`Lease`] secret channel (INV-1).
//!
//! Tier-3: the live test runs plain HTTPS to GitHub (no VM), gated on a real App
//! trust root, and is never counted green from a stub (INV-S9).

use std::{
    collections::HashMap,
    sync::{Mutex, PoisonError},
    time::{Duration, SystemTime},
};

use octocrab::{Octocrab, models::AppId};
use uuid::Uuid;

use crate::cred::{
    CredError, CredentialHandle, CredentialProvider, Lease, Minted, Scope, TrustRoot, read_secret_0600,
    render_github_permissions,
};

/// GitHub's default API base when the trust root names none.
const GITHUB_API: &str = "https://api.github.com";
/// GitHub's fixed installation-token lifetime: one hour, not configurable. The
/// seam's revoke-at-teardown is the real bound; this is only the backstop.
const GITHUB_TOKEN_TTL: Duration = Duration::from_secs(3600);

/// The scoped body for `POST /app/installations/{id}/access_tokens`.
#[derive(serde::Serialize)]
struct CreateTokenBody {
    repositories: Vec<String>,
    permissions: HashMap<String, String>,
}

/// What a mint retained so [`CredentialProvider::revoke`] and
/// [`CredentialProvider::refresh`] need neither the staged file nor a re-passed
/// scope: the scope to re-mint from, and the token to authenticate a revoke.
struct MintRecord {
    scope: Scope,
    token: String,
}

/// A live [`CredentialProvider`] backed by a GitHub App installation.
pub struct GithubAdapter {
    app_id: u64,
    installation_id: u64,
    api_base: String,
    key_pem: Vec<u8>,
    runtime: tokio::runtime::Runtime,
    mints: Mutex<HashMap<String, MintRecord>>,
}

impl GithubAdapter {
    /// Build the adapter from a GitHub [`TrustRoot`], reading the App private key
    /// through [`read_secret_0600`] (a group/world-readable key is refused).
    ///
    /// # Errors
    /// [`CredError::Mint`] when the trust root is not a GitHub App, the key is
    /// unreadable or too permissive, the `app_id` is not numeric, or the tokio
    /// runtime cannot be built.
    pub fn from_trust_root(root: &TrustRoot) -> Result<Self, CredError> {
        let TrustRoot::Github {
            base_url,
            app_id,
            private_key_path,
            installation_id,
            ..
        } = root
        else {
            return Err(CredError::Mint("trust root is not a GitHub App".to_string()));
        };
        let key_pem = read_secret_0600(private_key_path)?;
        let app_id = app_id
            .parse::<u64>()
            .map_err(|e| CredError::Mint(format!("app_id {app_id:?} is not numeric: {e}")))?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| CredError::Mint(format!("build tokio runtime: {e}")))?;
        Ok(Self {
            app_id,
            installation_id: *installation_id,
            api_base: base_url.clone().unwrap_or_else(|| GITHUB_API.to_string()),
            key_pem,
            runtime,
            mints: Mutex::new(HashMap::new()),
        })
    }

    /// An App-JWT-authenticated octocrab client (authenticates as the App itself).
    fn app_client(&self) -> Result<Octocrab, CredError> {
        let key = jsonwebtoken::EncodingKey::from_rsa_pem(&self.key_pem)
            .map_err(|e| CredError::Mint(format!("parse App private key: {e}")))?;
        Octocrab::builder()
            .base_uri(&self.api_base)
            .map_err(|e| CredError::Mint(format!("base_uri {:?}: {e}", self.api_base)))?
            .app(AppId(self.app_id), key)
            .build()
            .map_err(|e| CredError::Mint(format!("build App client: {e}")))
    }

    /// The installation's actually-granted permissions (`GET /app/installations/{id}`
    /// `.permissions`), read from raw JSON so pull-request and other grants octocrab's
    /// typed `InstallationPermissions` omits are included. Feeds the "not broader than
    /// requested" ceiling check against [`render_github_permissions`].
    ///
    /// # Errors
    /// [`CredError::Mint`] when the App client or the call fails.
    pub fn installation_permissions(&self) -> Result<HashMap<String, String>, CredError> {
        let route = format!("/app/installations/{}", self.installation_id);
        // Build the client INSIDE the runtime: octocrab's tower Buffer spawns a
        // worker at build time, which needs an active reactor.
        let value: serde_json::Value = self.runtime.block_on(async {
            let app = self.app_client()?;
            app.get::<serde_json::Value, _, ()>(&route, None)
                .await
                .map_err(|e| CredError::Mint(format!("get installation: {e}")))
        })?;
        Ok(permissions_from_json(&value))
    }

    /// Uninstall the App from its installation (`DELETE /app/installations/{id}`),
    /// the forge step of the trust-root installer's `deregister`. Authenticated as
    /// the App itself.
    ///
    /// # Errors
    /// [`CredError::Revoke`] when the App client or the call fails, or GitHub returns
    /// a non-success status.
    pub fn uninstall(&self) -> Result<(), CredError> {
        let uri = format!("{}/app/installations/{}", self.api_base, self.installation_id);
        let status = self.runtime.block_on(async {
            let app = self
                .app_client()
                .map_err(|e| CredError::Revoke(format!("build App client: {e}")))?;
            let response = app
                ._delete(uri, None::<&()>)
                .await
                .map_err(|e| CredError::Revoke(format!("delete installation: {e}")))?;
            Ok::<_, CredError>(response.status())
        })?;
        if !status.is_success() {
            return Err(CredError::Revoke(format!("delete installation returned {status}")));
        }
        Ok(())
    }

    /// Mint a scoped installation token for `scope`.
    fn mint_token(&self, scope: &Scope) -> Result<String, CredError> {
        let body = CreateTokenBody {
            repositories: scope.targets.iter().map(|t| bare_repo(&t.0)).collect(),
            permissions: render_github_permissions(&scope.capabilities).into_iter().collect(),
        };
        let route = format!("/app/installations/{}/access_tokens", self.installation_id);
        let token: octocrab::models::InstallationToken = self.runtime.block_on(async {
            let app = self.app_client()?;
            app.post(route, Some(&body))
                .await
                .map_err(|e| CredError::Mint(format!("create installation token: {e}")))
        })?;
        Ok(token.token)
    }

    /// Record a minted token under a fresh handle so revoke/refresh need neither the
    /// staged file nor a re-passed scope, and build the [`Minted`].
    fn record(&self, scope: &Scope, token: String) -> Minted {
        let id = Uuid::new_v4().to_string();
        self.mints.lock().unwrap_or_else(PoisonError::into_inner).insert(
            id.clone(),
            MintRecord {
                scope: scope.clone(),
                token: token.clone(),
            },
        );
        Minted::new(token, SystemTime::now() + GITHUB_TOKEN_TTL, CredentialHandle { id })
    }
}

impl CredentialProvider for GithubAdapter {
    fn mint(&self, scope: &Scope, _ttl_hint: Duration) -> Result<Minted, CredError> {
        // GitHub ignores a requested TTL (the token is always ~1h); the seam's
        // revoke-at-teardown enforces the real bound, so `ttl_hint` is unused here.
        let token = self.mint_token(scope)?;
        Ok(self.record(scope, token))
    }

    fn revoke(&self, lease: &Lease) -> Result<(), CredError> {
        let record = self
            .mints
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&lease.handle.id);
        let Some(record) = record else {
            // Unknown handle: nothing retained to revoke with. The native 1h expiry
            // is the backstop; report it rather than silently succeed.
            return Err(CredError::Revoke(format!(
                "no retained token for handle {}",
                lease.handle.id
            )));
        };
        // Authenticate with the token being revoked and DELETE /installation/token.
        // Build the client inside the runtime (octocrab's Buffer needs a reactor).
        let uri = format!("{}/installation/token", self.api_base);
        let status = self.runtime.block_on(async {
            let client = Octocrab::builder()
                .build()
                .and_then(|c| c.user_access_token(record.token))
                .map_err(|e| CredError::Revoke(format!("build token client: {e}")))?;
            let response = client
                ._delete(uri, None::<&()>)
                .await
                .map_err(|e| CredError::Revoke(format!("delete installation token: {e}")))?;
            Ok::<_, CredError>(response.status())
        })?;
        if !status.is_success() {
            return Err(CredError::Revoke(format!(
                "delete installation token returned {status}"
            )));
        }
        Ok(())
    }

    fn refresh(&self, lease: &Lease) -> Result<Minted, CredError> {
        let scope = self
            .mints
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&lease.handle.id)
            .map(|r| r.scope.clone());
        let Some(scope) = scope else {
            return Err(CredError::Mint(format!(
                "no retained scope for handle {}",
                lease.handle.id
            )));
        };
        let token = self.mint_token(&scope)?;
        Ok(self.record(&scope, token))
    }
}

/// Strip an `owner/` prefix so a target renders to the bare repo name GitHub's
/// installation-token `repositories` param wants (the owner is fixed by the
/// installation).
fn bare_repo(target: &str) -> String {
    target.rsplit('/').next().unwrap_or(target).to_string()
}

/// Read `.permissions` from a `GET /app/installations/{id}` JSON body as a
/// `(name, level)` map, matching what [`render_github_permissions`] produces so the
/// ceiling check compares like for like.
fn permissions_from_json(value: &serde_json::Value) -> HashMap<String, String> {
    value
        .get("permissions")
        .and_then(serde_json::Value::as_object)
        .map(|obj| {
            obj.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `bare_repo` strips the owner so the installation-token `repositories` param
    /// gets the bare name (the installation fixes the owner).
    #[test]
    fn bare_repo_strips_owner() {
        assert_eq!(bare_repo("kauki-labs/sandy-pilot-test"), "sandy-pilot-test");
        assert_eq!(bare_repo("sandy-pilot-test"), "sandy-pilot-test");
    }

    /// `permissions_from_json` pulls the string-valued permission map and ignores
    /// non-string members, so the ceiling check sees exactly the granted levels.
    #[test]
    fn permissions_from_json_reads_string_levels() {
        let value = serde_json::json!({
            "id": 1,
            "permissions": { "contents": "read", "pull_requests": "write", "metadata": "read", "nested": {"x": 1} }
        });
        let perms = permissions_from_json(&value);
        assert_eq!(perms.get("contents"), Some(&"read".to_string()));
        assert_eq!(perms.get("pull_requests"), Some(&"write".to_string()));
        assert_eq!(perms.get("metadata"), Some(&"read".to_string()));
        assert!(!perms.contains_key("nested"), "non-string members are ignored");
    }
}
