//! Scoped GitHub token minting (Block 8).
//!
//! A job that needs GitHub access is handed a short-lived **installation token**
//! scoped to exactly the repositories and permissions it declares, with a TTL
//! clamped to [`MAX_TTL_SECS`] — a larger request is clamped, never honored. The
//! minted token travels the secret channel only: [`mint_token`] writes it to a
//! `0600` staged file and returns a [`SecretRef`], so the bytes never reach
//! argv, env, or the Nix store (INV-1).
//!
//! The hypervisor-free seam is [`InstallationTokenMinter`]: the clamp-and-stage
//! flow is tier-2 testable over [`FakeMinter`] without a real GitHub App. A mint
//! failure is an infra fault — [`CredError::Mint`] maps to the exit-3 retryable
//! band (INV-7/INV-11); the caller must fail retryable, never run the job with no
//! token.
//!
//! The real client (octocrab, App → installation token) and the live
//! cred-in-the-loop flow are tier-3 and WALLED on the manual GitHub App
//! registration that does not yet exist; they are not built here. The live flow
//! binds into `cargo test --test phase_a` (#26) once the App is registered.

use std::{
    fs,
    io::Write,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::{Mutex, PoisonError},
};

use crate::backend::{SecretRef, SecretSource};

/// The maximum installation-token TTL: 50 minutes. A requested TTL is clamped to
/// this bound — a larger request is clamped, never honored.
pub const MAX_TTL_SECS: u32 = 3000;

/// The installation-token scope for one job: the repositories it may reach and
/// the permissions granted, as `(name, level)` pairs (e.g. `("contents",
/// "read")`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TokenScope {
    /// Repositories the token is scoped to (e.g. `"owner/repo"`).
    pub repositories: Vec<String>,
    /// Granted permissions as `(name, level)` pairs.
    pub permissions: Vec<(String, String)>,
}

/// Errors raised while minting and staging a scoped token.
#[derive(Debug, thiserror::Error)]
pub enum CredError {
    /// Minting the installation token failed. This is an infra fault: it maps to
    /// the exit-3 retryable band (INV-7/INV-11), so the caller fails retryable
    /// and never runs the job with no token.
    #[error("installation token mint failed: {0}")]
    Mint(String),
    /// Staging the minted token to its `0600` secret file failed.
    #[error("staging minted token failed: {0}")]
    Stage(String),
}

/// The seam that mints a scoped installation token.
///
/// Implemented by the real GitHub App client (tier-3, WALLED) and by
/// [`FakeMinter`] for tier-2 tests. `mint` returns the opaque token string for
/// the given `scope` and `ttl_secs`.
pub trait InstallationTokenMinter {
    /// Mint an installation token for `scope`, valid for `ttl_secs`.
    ///
    /// # Errors
    ///
    /// Returns [`CredError::Mint`] when the installation token cannot be minted.
    fn mint(&self, scope: &TokenScope, ttl_secs: u32) -> Result<String, CredError>;
}

/// An in-memory [`InstallationTokenMinter`] test double.
///
/// Built with [`FakeMinter::returning`] to hand back a scripted token, or
/// [`FakeMinter::failing`] to fail every mint. Each call records the `(scope,
/// ttl_secs)` it was asked for, inspectable via [`FakeMinter::calls`].
#[derive(Debug)]
pub struct FakeMinter {
    /// The token handed back on success.
    token: String,
    /// Whether every mint fails with [`CredError::Mint`].
    fail: bool,
    /// The `(scope, ttl_secs)` of every `mint` call, in order.
    calls: Mutex<Vec<(TokenScope, u32)>>,
}

impl FakeMinter {
    /// A minter that hands back `token` and records each call.
    #[must_use]
    pub fn returning(token: impl Into<String>) -> Self {
        Self {
            token: token.into(),
            fail: false,
            calls: Mutex::new(Vec::new()),
        }
    }

    /// A minter that fails every mint with [`CredError::Mint`].
    #[must_use]
    pub fn failing() -> Self {
        Self {
            token: String::new(),
            fail: true,
            calls: Mutex::new(Vec::new()),
        }
    }

    /// The `(scope, ttl_secs)` of every [`InstallationTokenMinter::mint`] call,
    /// in order.
    #[must_use]
    pub fn calls(&self) -> Vec<(TokenScope, u32)> {
        self.calls.lock().unwrap_or_else(PoisonError::into_inner).clone()
    }
}

impl InstallationTokenMinter for FakeMinter {
    fn mint(&self, scope: &TokenScope, ttl_secs: u32) -> Result<String, CredError> {
        self.calls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((scope.clone(), ttl_secs));
        if self.fail {
            return Err(CredError::Mint("scripted mint failure".to_string()));
        }
        Ok(self.token.clone())
    }
}

/// Mint a scoped token and stage it to a `0600` file under `out_dir`, returning
/// the [`SecretRef`] that carries it.
///
/// `requested_ttl_secs` is clamped to [`MAX_TTL_SECS`] before minting — a larger
/// request is clamped, never honored. On a successful mint the token bytes are
/// written to a `0600` staged file (atomic temp → fsync → rename) and returned
/// as [`SecretSource::File`]; the bytes travel the secret channel only, never
/// argv, env, or the Nix store (INV-1).
///
/// # Errors
///
/// Returns [`CredError::Mint`] when `minter.mint` fails — an infra fault, so the
/// caller fails exit-3 retryable and no token file is written (INV-7/INV-11).
/// Returns [`CredError::Stage`] when the staged file cannot be written.
pub fn mint_token(
    minter: &impl InstallationTokenMinter,
    scope: &TokenScope,
    requested_ttl_secs: u32,
    secret_name: &str,
    out_dir: &Path,
) -> Result<SecretRef, CredError> {
    let ttl_secs = requested_ttl_secs.min(MAX_TTL_SECS);
    // On a mint failure we return before any file is written, so the caller
    // fails exit-3 retryable rather than running the job with no token (INV-7).
    let token = minter.mint(scope, ttl_secs)?;
    let path = stage_token(out_dir, secret_name, token.as_bytes())?;
    tracing::debug!(name = secret_name, path = %path.display(), ttl_secs, "staged scoped token (0600)");
    Ok(SecretRef {
        name: secret_name.to_string(),
        source: SecretSource::File(path),
    })
}

/// Write `bytes` to a `0600` file `<secret_name>.token` under `out_dir` via
/// atomic temp → sync → rename, fsyncing the directory so the rename is durable
/// (INV-1). The error message never carries the token bytes.
fn stage_token(out_dir: &Path, secret_name: &str, bytes: &[u8]) -> Result<PathBuf, CredError> {
    let dest = out_dir.join(format!("{secret_name}.token"));
    let tmp = dest.with_extension("tmp");
    let mut file = fs::File::create(&tmp).map_err(|e| stage_err("create token temp", &tmp, &e))?;
    file.write_all(bytes)
        .map_err(|e| stage_err("write token temp", &tmp, &e))?;
    file.sync_all().map_err(|e| stage_err("sync token temp", &tmp, &e))?;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))
        .map_err(|e| stage_err("tighten token to 0600", &tmp, &e))?;
    fs::rename(&tmp, &dest).map_err(|e| stage_err("rename token into place", &dest, &e))?;
    crate::fsync_dir(out_dir).map_err(|e| stage_err("fsync out dir", out_dir, &e))?;
    Ok(dest)
}

/// Build a [`CredError::Stage`] for an IO failure without leaking token bytes.
fn stage_err(action: &str, path: &Path, err: &std::io::Error) -> CredError {
    CredError::Stage(format!("{action} at {}: {err}", path.display()))
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use anyhow::Context;

    use super::*;

    fn scope() -> TokenScope {
        TokenScope {
            repositories: vec!["acme/widgets".to_string()],
            permissions: vec![("contents".to_string(), "read".to_string())],
        }
    }

    /// Adversarial (TTL clamp): a requested TTL above [`MAX_TTL_SECS`] is clamped
    /// to the bound — the minter is asked for 3000, not the larger value.
    #[test]
    fn ttl_above_max_is_clamped() -> anyhow::Result<()> {
        let tmp = tempfile::TempDir::new()?;
        let minter = FakeMinter::returning("tok");

        mint_token(&minter, &scope(), 7_200, "GH_TOKEN", tmp.path()).context("mint_token")?;

        let calls = minter.calls();
        assert_eq!(calls.len(), 1, "exactly one mint call");
        assert_eq!(
            calls[0].1, MAX_TTL_SECS,
            "TTL above the bound must be clamped, not honored"
        );
        Ok(())
    }

    /// A TTL at or below the bound passes through unchanged, and the scope is
    /// passed to the minter verbatim.
    #[test]
    fn ttl_within_bound_and_scope_pass_through() -> anyhow::Result<()> {
        let tmp = tempfile::TempDir::new()?;
        let minter = FakeMinter::returning("tok");
        let scope = scope();

        mint_token(&minter, &scope, 1_800, "GH_TOKEN", tmp.path()).context("mint_token")?;

        let calls = minter.calls();
        assert_eq!(calls[0].1, 1_800, "a TTL within the bound is unchanged");
        assert_eq!(calls[0].0, scope, "scope is passed to the minter verbatim");
        Ok(())
    }

    /// A successful mint returns a [`SecretSource::File`] whose `0600` file holds
    /// the token, and the token bytes live only in that file — never in the
    /// [`SecretRef`] name or any other field (INV-1 leak plane).
    #[test]
    fn successful_mint_stages_0600_file_with_token() -> anyhow::Result<()> {
        let tmp = tempfile::TempDir::new()?;
        let token = "ghs_scoped_marker_value";
        let minter = FakeMinter::returning(token);

        let secret = mint_token(&minter, &scope(), 1_800, "GH_TOKEN", tmp.path()).context("mint_token")?;

        assert_eq!(secret.name, "GH_TOKEN");
        let SecretSource::File(path) = &secret.source else {
            anyhow::bail!("expected a File-sourced secret, got {:?}", secret.source);
        };
        let mode = fs::metadata(path).context("stat staged token")?.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "staged token must be 0600");
        assert_eq!(fs::read(path).context("read staged token")?, token.as_bytes());

        // INV-1 leak plane: the token bytes must not appear in the handle.
        let rendered = format!("{secret:?}");
        assert!(
            !rendered.contains(token),
            "token must not appear in the SecretRef handle"
        );
        assert!(!secret.name.contains(token), "token must not appear in the secret name");
        Ok(())
    }

    /// Adversarial (mint failure → fail, not a run with no token): a failing
    /// minter yields [`CredError::Mint`] and writes no token file.
    #[test]
    fn mint_failure_writes_no_token_file() -> anyhow::Result<()> {
        let tmp = tempfile::TempDir::new()?;
        let minter = FakeMinter::failing();

        let err =
            mint_token(&minter, &scope(), 1_800, "GH_TOKEN", tmp.path()).expect_err("a failing mint must be an error");

        assert!(
            matches!(err, CredError::Mint(_)),
            "expected CredError::Mint, got {err:?}"
        );
        let staged: Vec<_> = fs::read_dir(tmp.path()).context("read out_dir")?.collect();
        assert!(staged.is_empty(), "no token file may be written when minting fails");
        Ok(())
    }
}
