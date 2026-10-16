//! Provider-agnostic credential seam (Block 8 / #49).
//!
//! A job that needs forge access is handed a short-lived credential scoped to the
//! targets and capabilities it declares, delivered as a `0600` [`SecretRef`] only
//! (INV-1: the bytes never reach argv, env, or the Nix store). GitHub and GitLab
//! plug in behind one [`CredentialProvider`] contract ([`CredentialProvider::mint`]
//! / [`revoke`](CredentialProvider::revoke) / [`refresh`](CredentialProvider::refresh));
//! a caller never branches on the provider.
//!
//! The hypervisor-free seam is [`CredentialProvider`]: the clamp-and-stage flow is
//! tier-2 testable over `FakeProvider` (in `sandy-test-support`) without a real
//! forge. A mint failure is an
//! infra fault, [`CredError::Mint`] maps to the exit-3 retryable band
//! (INV-7/INV-11); the caller fails retryable, never runs the job with no
//! credential.
//!
//! Lifetime is bound to the sandbox by a mint-at-boot / revoke-at-teardown bracket
//! (the design of record: `docs/design/credential-seam/`). Both providers' native
//! token TTL is too coarse to be that bound (GitHub a fixed hour, GitLab a day), so
//! [`MAX_TTL_SECS`] is only truly enforced once paired with revocation; that
//! enforcement is Block 2 (the `run_job` bracket), not here.
//!
//! The live GitHub/GitLab clients (App JWT → installation token; service PAT →
//! project token) are tier-3 and walled on the operator trust root; this module
//! ships the seam, the shared [`render_github_permissions`]
//! renderer (so the trust-root installer's verify probe renders identically to the
//! adapter's mint), and the [`TrustRoot`] config both sides share.

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

pub use sandy_api::cred::{
    Capability, CredError, CredentialHandle, CredentialProvider, Lease, MAX_TTL_SECS, Minted, Scope, Target,
};

use crate::backend::{SecretRef, SecretSource};

/// Mint a scoped credential and stage it to a `0600` file under `out_dir`,
/// returning the [`Lease`] that carries it.
///
/// `requested_ttl_secs` is clamped to [`MAX_TTL_SECS`] before minting, a larger
/// request is clamped, never honored. On a successful mint the secret bytes are
/// written to a `0600` staged file (atomic temp → fsync → rename) and returned as
/// [`SecretSource::File`]; the bytes travel the secret channel only, never argv,
/// env, or the Nix store (INV-1).
///
/// # Errors
///
/// Returns [`CredError::Mint`] when the mint fails, an infra fault, so the caller
/// fails exit-3 retryable and no secret file is written (INV-7/INV-11), and
/// [`CredError::Stage`] when the staged file cannot be written.
pub fn mint_lease<P: CredentialProvider + ?Sized>(
    provider: &P,
    scope: &Scope,
    requested_ttl_secs: u32,
    secret_name: &str,
    out_dir: &Path,
) -> Result<Lease, CredError> {
    let ttl = Duration::from_secs(u64::from(requested_ttl_secs.min(MAX_TTL_SECS)));
    // On a mint failure we return before any file is written, so the caller fails
    // exit-3 retryable rather than running the job with no credential (INV-7).
    let minted = provider.mint(scope, ttl)?;
    let path = match stage_token(out_dir, secret_name, minted.secret().as_bytes()) {
        Ok(path) => path,
        Err(e) => {
            // The token was minted at the forge but could not be staged. Revoke it
            // before returning so it does not leak to its native TTL with no lease
            // to revoke it at teardown (the mint half of #49's revoke guarantee).
            revoke_orphan(provider, secret_name, &minted);
            return Err(e);
        }
    };
    tracing::debug!(name = secret_name, path = %path.display(), ?ttl, "staged scoped credential (0600)");
    Ok(Lease {
        secret_ref: SecretRef {
            name: secret_name.to_string(),
            source: SecretSource::File(path),
        },
        expires_at: minted.expires_at,
        handle: minted.handle,
    })
}

/// Revoke a token that was minted but never installed into a lease (its staging or
/// re-staging failed), so it cannot outlive the run with nothing to revoke it. The
/// [`Lease`] is a throwaway carrying only the minted handle, which is all [`revoke`]
/// reads. A failed revoke is logged, not fatal: the native TTL is the backstop.
///
/// [`revoke`]: CredentialProvider::revoke
fn revoke_orphan<P: CredentialProvider + ?Sized>(provider: &P, secret_name: &str, minted: &Minted) {
    let orphan = Lease {
        secret_ref: SecretRef {
            name: secret_name.to_string(),
            source: SecretSource::File(PathBuf::new()),
        },
        expires_at: minted.expires_at,
        handle: minted.handle.clone(),
    };
    if let Err(e) = provider.revoke(&orphan) {
        tracing::warn!(%e, handle = %orphan.handle.id, "failed to revoke an unstaged credential; relying on native expiry");
    }
}

/// Whether a credential should be refreshed now: true once at most `margin`
/// remains before `expires_at`, or it has already expired.
///
/// Drives the mid-run refresh loop (#49): a job that outlives the provider's native
/// token cap (GitHub fixes installation tokens at ~1h) is re-minted before the
/// current token lapses, so `margin` must exceed one refresh's latency.
#[must_use]
pub fn should_refresh(now: SystemTime, expires_at: SystemTime, margin: Duration) -> bool {
    expires_at
        .duration_since(now)
        .map_or(true, |remaining| remaining <= margin)
}

/// Re-mint the lease's credential when it is within `margin` of expiry and re-stage
/// the fresh token over the lease's own secret file, then revoke the superseded
/// token. Returns `true` when a refresh happened, `false` when the lease was not
/// yet due (a no-op). This is the execution-bound half of #49: paired with the
/// caller's teardown revoke, a long job holds a valid scoped token for its whole
/// run and never one past it.
///
/// Order matters. The new token is written over the shared file **before** the old
/// one is revoked, so a consumer reading the file (the guest, over the live secret
/// share) never observes a revoked token; the brief overlap leaves two valid tokens,
/// which is safe (more access, not less). The lease is advanced to the new handle
/// and expiry so the caller's teardown revoke targets the live token. A failed
/// revoke of the *superseded* token is logged, not fatal, its native TTL is the
/// backstop; a failed re-mint or re-stage leaves the lease and file untouched (the
/// current token stays in place) and surfaces as an error for the loop to retry.
///
/// Because the token is re-delivered by overwriting the file, only a consumer that
/// re-reads `/run/sandy/secrets/<NAME>` at use-time sees the refresh; a job that
/// captured `$NAME` into its environment at login holds the boot-time token (#49).
///
/// # Errors
///
/// Returns [`CredError`] when the re-mint or the re-stage fails, or when the lease
/// is not file-sourced (a contract violation: [`mint_lease`] always stages a file).
pub fn refresh_once<P: CredentialProvider + ?Sized>(
    provider: &P,
    lease: &mut Lease,
    now: SystemTime,
    margin: Duration,
) -> Result<bool, CredError> {
    if !should_refresh(now, lease.expires_at, margin) {
        return Ok(false);
    }
    let SecretSource::File(dest) = &lease.secret_ref.source else {
        return Err(CredError::Stage(
            "lease credential is not a file-sourced secret; cannot re-stage".to_string(),
        ));
    };
    let dest = dest.clone();
    // Re-mint under the lease's retained scope (GitHub has no rotate: refresh is a
    // fresh scoped mint keyed off the current handle). On failure the lease is
    // untouched and the current token stays staged.
    let minted = provider.refresh(lease)?;
    // Stage the new token over the shared file BEFORE revoking the old one, so a
    // consumer reading the file never observes a revoked token. If the re-stage
    // fails, the new token was minted but never installed: revoke it so it does not
    // leak (the lease still names the old token, which teardown revokes), then
    // surface the error with the current token left in place.
    if let Err(e) = write_secret_0600(&dest, minted.secret().as_bytes()) {
        revoke_orphan(provider, &lease.secret_ref.name, &minted);
        return Err(e);
    }
    // Revoke the superseded token while `lease` still names it, then advance the
    // lease to the fresh handle/expiry. A revoke failure is logged, not fatal.
    if let Err(e) = provider.revoke(lease) {
        tracing::warn!(%e, handle = %lease.handle.id, "revoke of superseded credential failed; relying on native expiry");
    }
    lease.expires_at = minted.expires_at;
    lease.handle = minted.handle;
    tracing::info!(
        name = %lease.secret_ref.name,
        handle = %lease.handle.id,
        "re-delivered a refreshed scoped credential"
    );
    Ok(true)
}

/// Render a capability set into GitHub App installation-token `permissions`
/// `(name, level)` pairs, the single source of truth shared by the GitHub adapter's
/// mint and the trust-root installer's verify probe, so "verified" cannot drift
/// from what mint requests.
///
/// `metadata:read` is always included (GitHub requires it). `contents` and
/// `pull_requests` are rendered at the highest level any capability asks for
/// (`write` dominates `read`). The result is sorted for a stable comparison.
#[must_use]
pub fn render_github_permissions(capabilities: &[Capability]) -> Vec<(String, String)> {
    let mut contents: Option<&str> = None;
    let mut pulls: Option<&str> = None;
    let raise = |cur: Option<&str>, level: &'static str| -> Option<&'static str> {
        match (cur, level) {
            (Some("write"), _) | (_, "write") => Some("write"),
            _ => Some("read"),
        }
    };
    for cap in capabilities {
        match cap {
            Capability::ReadCode => contents = raise(contents, "read"),
            Capability::WriteCode => contents = raise(contents, "write"),
            Capability::ReadPr => pulls = raise(pulls, "read"),
            Capability::WritePr => pulls = raise(pulls, "write"),
        }
    }
    let mut out = vec![("metadata".to_string(), "read".to_string())];
    if let Some(level) = contents {
        out.push(("contents".to_string(), level.to_string()));
    }
    if let Some(level) = pulls {
        out.push(("pull_requests".to_string(), level.to_string()));
    }
    out.sort();
    out
}

pub use sandy_api::cred::{GitlabAccount, TrustRoot};

/// Filesystem IO for a [`TrustRoot`]: load from / write to its JSON config file.
///
/// The [`TrustRoot`] type is contract-only and lives in `sandy-api`; this IO is
/// behavior and stays in the core. An extension trait (rather than a free fn) so
/// `TrustRoot::load(path)` / `root.write(path)` call sites are unchanged — the
/// trait only has to be in scope.
pub trait TrustRootIo: Sized {
    /// Read a trust root from its JSON config file.
    ///
    /// # Errors
    /// [`CredError::Stage`] when the file cannot be read or parsed.
    fn load(path: &Path) -> Result<Self, CredError>;

    /// Write a trust root to a `0600` JSON config file via atomic temp → rename.
    ///
    /// # Errors
    /// [`CredError::Stage`] when the file cannot be written.
    fn write(&self, path: &Path) -> Result<(), CredError>;
}

impl TrustRootIo for TrustRoot {
    fn load(path: &Path) -> Result<Self, CredError> {
        let (mut file, _) = open_trust_file("trust-root config", path)?;
        let mut text = String::new();
        std::io::Read::read_to_string(&mut file, &mut text).map_err(|e| stage_err("read trust root", path, &e))?;
        serde_json::from_str(&text)
            .map_err(|e| CredError::Stage(format!("parse trust root at {}: {e}", path.display())))
    }

    fn write(&self, path: &Path) -> Result<(), CredError> {
        let text =
            serde_json::to_string_pretty(self).map_err(|e| CredError::Stage(format!("serialize trust root: {e}")))?;
        let (Some(dir), Some(name)) = (
            path.parent().filter(|p| !p.as_os_str().is_empty()),
            path.file_name().and_then(|n| n.to_str()),
        ) else {
            return Err(CredError::Stage(format!(
                "trust root path {} has no parent dir or file name",
                path.display()
            )));
        };
        write_trust_secret(dir, name, text.as_bytes()).map(drop)
    }
}

/// Write trust material (the App private key, a trust-root config) as the `0600`
/// file `name` in the trust-roots `dir`, creating `dir` `0700` if it is missing.
///
/// An existing `dir` that is not this user's or is group- or world-writable is
/// refused and left as it is: another user may already have changed the key or
/// the config in it, so the error asks for a check before the mode is fixed.
///
/// # Errors
///
/// [`CredError::Stage`] when the dir is unsafe or a write step fails.
pub fn write_trust_secret(dir: &Path, name: &str, bytes: &[u8]) -> Result<PathBuf, CredError> {
    open_trust_dir(dir)?
        .write_secret(name, bytes)
        .map_err(|e| CredError::Stage(e.to_string()))
}

/// Open (creating `0700` if missing) the trust-roots dir, refusing one that is
/// group/world-writable or another user owns, with the tamper warning.
pub(crate) fn open_trust_dir(dir: &Path) -> Result<sandy_fsutil::OwnedDir, CredError> {
    sandy_fsutil::OwnedDir::open_or_create(dir).map_err(|e| match e {
        sandy_fsutil::FsError::Unsafe { path, reason } => CredError::Stage(format!(
            "trust-roots dir {} is not private ({reason}); another user may have been able to modify your App key or \
             trust config. Verify the files in it are intact, then make sure the dir is yours (`chown`) and run \
             `chmod 700 {}`, and retry",
            path.display(),
            path.display()
        )),
        other @ sandy_fsutil::FsError::Io { .. } => CredError::Stage(other.to_string()),
    })
}

/// Read a secret file, refusing one that is group- or world-readable (the read
/// side of INV-1). The single reader the forge adapters use for the App private key
/// or service PAT, and the trust-root installer's verify uses for the same, so the
/// mode check has one implementation.
///
/// # Errors
///
/// Returns [`CredError::Stage`] when the file grants group/other read (its mode has
/// any `0o044` bit, e.g. `0644`) or cannot be read; a group/world-readable secret is
/// refused, never read.
pub fn read_secret_0600(path: &Path) -> Result<Vec<u8>, CredError> {
    use std::io::Read;

    let (mut file, meta) = open_trust_file("secret", path)?;
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o044 != 0 {
        return Err(CredError::Stage(format!(
            "secret {} is group/world-readable (mode {mode:#o}); refusing to read it (INV-1)",
            path.display()
        )));
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|e| stage_err("read secret", path, &e))?;
    Ok(bytes)
}

/// Write `bytes` to a `0600` file named exactly `<secret_name>` under `out_dir`,
/// returning its path. The file name IS the secret's env name, matching how the
/// guest's secret share names it, so `out_dir` can be shared into the guest
/// directly (the refresh seam, #49) without a rename. See [`write_secret_0600`]
/// for the atomicity contract.
fn stage_token(out_dir: &Path, secret_name: &str, bytes: &[u8]) -> Result<PathBuf, CredError> {
    let dest = out_dir.join(secret_name);
    write_secret_0600(&dest, bytes)?;
    Ok(dest)
}

/// Write `bytes` over `dest` as a `0600` file via atomic temp → sync → rename,
/// fsyncing the parent so the rename is durable (INV-1). The temp sibling and the
/// rename keep `dest` a single consistent file at every instant, so a consumer
/// reading it (including the guest over the live secret share) never sees a torn
/// or partial write. The error message never carries the secret bytes.
///
/// The temp is created `0600` from birth (`O_CREAT | O_EXCL` + `mode`), not created
/// loose and tightened afterwards, so the secret is never group/world-readable for
/// an instant, even in the `cred_dir` shared into the guest (INV-1). On any failure
/// after creation the temp is unlinked, so a partial or stray secret file never
/// outlives the call (teardown only knows the final path).
///
/// Re-delivery (#49) reuses this to overwrite a lease's staged token in place with
/// a freshly minted one; the rename makes that swap atomic for the reader.
fn write_secret_0600(dest: &Path, bytes: &[u8]) -> Result<(), CredError> {
    let (Some(dir), Some(name)) = (
        dest.parent().filter(|p| !p.as_os_str().is_empty()),
        dest.file_name().and_then(|n| n.to_str()),
    ) else {
        return Err(CredError::Stage(format!(
            "secret path {} has no parent dir or file name",
            dest.display()
        )));
    };
    sandy_fsutil::OwnedDir::open(dir)
        .and_then(|dir| dir.write_secret(name, bytes))
        .map(drop)
        .map_err(|e| CredError::Stage(e.to_string()))
}

/// Build a [`CredError::Stage`] for an IO failure without leaking secret bytes.
/// Refuse trust material owned by another user: sandy writes it as the current
/// user, so a file owned by anyone else was put there by someone else (#200).
fn refuse_foreign_owner(what: &str, path: &Path, uid: u32, current_uid: u32) -> Result<(), CredError> {
    if uid == current_uid {
        return Ok(());
    }
    Err(CredError::Stage(format!(
        "{what} {} is owned by uid {uid}, not the current uid {current_uid}: another user put it there; refusing to \
         use it",
        path.display()
    )))
}

/// The tamper warning for a trust-material dir that others can write to, or that
/// another user owns: the read goes ahead, but the files may have been changed.
fn wide_dir_warning(dir: &Path, dir_uid: u32, dir_mode: u32, current_uid: u32) -> Option<String> {
    (dir_uid != current_uid || dir_mode & 0o022 != 0).then(|| {
        format!(
            "trust-material dir {} is not private (owner uid {dir_uid}, mode {dir_mode:o}); another user may have \
             been able to modify your App key or trust config. Verify the files in it are intact, then make sure the \
             dir is yours and run `chmod 700 {}`",
            dir.display(),
            dir.display()
        )
    })
}

/// Open trust material for reading: the checks run on the opened file, not the
/// path. It must be a regular file (`O_NONBLOCK` keeps a FIFO from hanging the
/// open) owned by the current user. A dir others can write to, or another user
/// owns, logs a tamper warning and the read goes ahead.
fn open_trust_file(what: &str, path: &Path) -> Result<(fs::File, fs::Metadata), CredError> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
        .map_err(|e| stage_err(&format!("open {what}"), path, &e))?;
    let meta = file
        .metadata()
        .map_err(|e| stage_err(&format!("stat {what}"), path, &e))?;
    if !meta.is_file() {
        return Err(CredError::Stage(format!(
            "{what} {} is not a regular file; refusing to read it",
            path.display()
        )));
    }
    let current_uid = rustix::process::getuid().as_raw();
    refuse_foreign_owner(what, path, meta.uid(), current_uid)?;
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        if let Ok(dir_meta) = fs::metadata(dir) {
            if let Some(warning) = wide_dir_warning(dir, dir_meta.uid(), dir_meta.mode() & 0o7777, current_uid) {
                tracing::warn!("{warning}");
            }
        }
    }
    Ok((file, meta))
}

fn stage_err(action: &str, path: &Path, err: &std::io::Error) -> CredError {
    CredError::Stage(format!("{action} at {}: {err}", path.display()))
}

#[cfg(test)]
mod tests {
    use std::{
        os::unix::fs::PermissionsExt,
        sync::{Mutex, PoisonError},
    };

    use anyhow::Context;

    /// A 0700 temp dir whatever the umask: secrets are only staged into a dir
    /// that is this user's and not group- or world-writable (#174).
    fn private_tempdir() -> std::io::Result<tempfile::TempDir> {
        tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
    }
    use sandy_test_support::FakeProvider;

    use super::*;

    fn scope() -> Scope {
        Scope {
            targets: vec![Target("acme/widgets".to_string())],
            capabilities: vec![Capability::ReadCode],
        }
    }

    /// Adversarial (TTL clamp): a requested TTL above [`MAX_TTL_SECS`] is clamped to
    /// the bound, the provider is asked for 3000s, not the larger value.
    #[test]
    fn ttl_above_max_is_clamped() -> anyhow::Result<()> {
        let tmp = private_tempdir()?;
        let provider = FakeProvider::returning("tok");

        mint_lease(&provider, &scope(), 7_200, "GH_TOKEN", tmp.path()).context("mint_lease")?;

        let mints = provider.mints();
        assert_eq!(mints.len(), 1, "exactly one mint call");
        assert_eq!(
            mints[0].1,
            Duration::from_secs(u64::from(MAX_TTL_SECS)),
            "TTL above the bound must be clamped, not honored"
        );
        Ok(())
    }

    /// A TTL at or below the bound passes through unchanged, and the scope reaches
    /// the provider verbatim.
    #[test]
    fn ttl_within_bound_and_scope_pass_through() -> anyhow::Result<()> {
        let tmp = private_tempdir()?;
        let provider = FakeProvider::returning("tok");
        let scope = scope();

        mint_lease(&provider, &scope, 1_800, "GH_TOKEN", tmp.path()).context("mint_lease")?;

        let mints = provider.mints();
        assert_eq!(
            mints[0].1,
            Duration::from_secs(1_800),
            "a TTL within the bound is unchanged"
        );
        assert_eq!(mints[0].0, scope, "scope reaches the provider verbatim");
        Ok(())
    }

    /// A successful mint stages a `0600` file holding the secret, and the bytes live
    /// only in that file, never in the [`Lease`] handle (INV-1 leak plane).
    #[test]
    fn successful_mint_stages_0600_file_with_token() -> anyhow::Result<()> {
        let tmp = private_tempdir()?;
        let token = "ghs_scoped_marker_value";
        let provider = FakeProvider::returning(token);

        let lease = mint_lease(&provider, &scope(), 1_800, "GH_TOKEN", tmp.path()).context("mint_lease")?;

        assert_eq!(lease.secret_ref.name, "GH_TOKEN");
        let SecretSource::File(path) = &lease.secret_ref.source else {
            anyhow::bail!("expected a File-sourced secret, got {:?}", lease.secret_ref.source);
        };
        let mode = fs::metadata(path).context("stat staged token")?.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "staged token must be 0600");
        assert_eq!(fs::read(path).context("read staged token")?, token.as_bytes());

        let rendered = format!("{lease:?}");
        assert!(!rendered.contains(token), "token must not appear in the Lease handle");
        Ok(())
    }

    /// Adversarial (mint failure → fail, not a run with no credential): a failing
    /// provider yields [`CredError::Mint`] and writes no secret file.
    #[test]
    fn mint_failure_writes_no_token_file() -> anyhow::Result<()> {
        let tmp = private_tempdir()?;
        let provider = FakeProvider::failing();

        let err = mint_lease(&provider, &scope(), 1_800, "GH_TOKEN", tmp.path())
            .expect_err("a failing mint must be an error");

        assert!(
            matches!(err, CredError::Mint(_)),
            "expected CredError::Mint, got {err:?}"
        );
        let staged: Vec<_> = fs::read_dir(tmp.path()).context("read out_dir")?.collect();
        assert!(staged.is_empty(), "no secret file may be written when minting fails");
        Ok(())
    }

    /// Adversarial (no residual secret): a stage whose rename fails must leave no
    /// temp sibling holding the secret bytes behind. Under the old create-then-chmod
    /// path the `.tmp` survived the failure; teardown only knows the final path.
    #[test]
    fn write_secret_0600_leaves_no_temp_on_failure() -> anyhow::Result<()> {
        let tmp = private_tempdir()?;
        // `dest` is an existing directory, so the final rename (file → dir) fails
        // after the temp has been created and written.
        let dest = tmp.path().join("adir");
        fs::create_dir(&dest).context("mk dest dir")?;

        let err = write_secret_0600(&dest, b"SECRET").expect_err("renaming a file onto a dir must fail");
        assert!(
            matches!(err, CredError::Stage(_)),
            "expected a stage failure, got {err:?}"
        );

        // Only `adir` may remain: no temp file, whatever its name.
        let left: Vec<_> = fs::read_dir(tmp.path())?
            .map(|e| e.map(|e| e.file_name()))
            .collect::<Result<_, _>>()?;
        assert_eq!(left, ["adir"], "the secret temp must be cleaned up on failure");
        Ok(())
    }

    /// Adversarial (no orphaned token): when staging the minted token fails, the
    /// token is revoked, not left valid to its native TTL with no lease to revoke it.
    #[test]
    fn mint_lease_revokes_the_token_when_staging_fails() -> anyhow::Result<()> {
        let tmp = private_tempdir()?;
        // A non-existent out_dir makes the temp creation fail after a good mint.
        let missing = tmp.path().join("no-such-dir");
        let provider = FakeProvider::returning("tok");

        let err = mint_lease(&provider, &scope(), 1_800, "GH_TOKEN", &missing)
            .expect_err("staging into a missing dir must fail");
        assert!(
            matches!(err, CredError::Stage(_)),
            "expected a stage failure, got {err:?}"
        );
        assert_eq!(
            provider.revoked().len(),
            1,
            "a minted-but-unstaged token must be revoked, not orphaned"
        );
        Ok(())
    }

    /// Adversarial (no orphaned refreshed token): when re-staging a refreshed token
    /// fails, the new token is revoked and the lease is left on the old one.
    #[test]
    fn refresh_once_revokes_the_new_token_when_restaging_fails() -> anyhow::Result<()> {
        let tmp = private_tempdir()?;
        let provider = FakeProvider::returning("tok");
        // A lease due for refresh whose staged file lives under a missing dir, so the
        // re-stage fails after a good re-mint.
        let past = SystemTime::now() - Duration::from_secs(3_600);
        let mut lease = Lease {
            secret_ref: SecretRef {
                name: "GH_TOKEN".to_string(),
                source: SecretSource::File(tmp.path().join("gone").join("GH_TOKEN")),
            },
            expires_at: past,
            handle: CredentialHandle { id: "old".to_string() },
        };

        let err = refresh_once(&provider, &mut lease, SystemTime::now(), Duration::from_secs(300))
            .expect_err("re-staging under a missing dir must fail");
        assert!(
            matches!(err, CredError::Stage(_)),
            "expected a stage failure, got {err:?}"
        );
        assert_eq!(
            provider.revoked().len(),
            1,
            "the re-minted-but-unstaged token must be revoked"
        );
        assert_eq!(
            lease.handle.id, "old",
            "the lease stays on the old token when re-staging fails"
        );
        assert_eq!(
            lease.expires_at, past,
            "the lease expiry is not advanced on a failed refresh"
        );
        Ok(())
    }

    /// Revoke records the staged lease's handle, so a teardown bracket can revoke
    /// before the native expiry.
    #[test]
    fn revoke_records_the_lease_handle() -> anyhow::Result<()> {
        let tmp = private_tempdir()?;
        let provider = FakeProvider::returning("tok");
        let lease = mint_lease(&provider, &scope(), 1_800, "GH_TOKEN", tmp.path()).context("mint_lease")?;

        provider.revoke(&lease).context("revoke")?;

        assert_eq!(
            provider.revoked(),
            vec![lease.handle],
            "revoke must record the lease handle"
        );
        Ok(())
    }

    /// The GitHub renderer maps capabilities to the least permission that works,
    /// with `write` dominating `read` and `metadata:read` always present. One
    /// renderer so the installer's verify probe cannot drift from mint.
    #[test]
    fn github_renderer_maps_to_least_permissions() {
        let perms = render_github_permissions(&[Capability::ReadCode, Capability::WritePr]);
        assert_eq!(
            perms,
            vec![
                ("contents".to_string(), "read".to_string()),
                ("metadata".to_string(), "read".to_string()),
                ("pull_requests".to_string(), "write".to_string()),
            ]
        );
    }

    /// Adversarial (no silent over-grant): read plus write on the same resource
    /// resolves to `write`, never two entries or a dropped grant.
    #[test]
    fn github_renderer_raises_read_and_write_to_write() {
        let perms = render_github_permissions(&[Capability::ReadCode, Capability::WriteCode]);
        assert_eq!(
            perms,
            vec![
                ("contents".to_string(), "write".to_string()),
                ("metadata".to_string(), "read".to_string()),
            ],
            "read+write on contents must resolve to a single write, not drop or duplicate"
        );
    }

    /// [`read_secret_0600`] reads a `0600` secret and refuses a `0644` one with a
    /// named error, the read side of INV-1 shared by adapters and the verify probe.
    #[test]
    fn read_secret_0600_reads_tight_refuses_loose() -> anyhow::Result<()> {
        let tmp = private_tempdir()?;
        let tight = tmp.path().join("tight");
        fs::write(&tight, b"key-bytes").context("write tight secret")?;
        fs::set_permissions(&tight, fs::Permissions::from_mode(0o600)).context("chmod 600")?;
        assert_eq!(read_secret_0600(&tight).context("read 0600")?, b"key-bytes");

        let loose = tmp.path().join("loose");
        fs::write(&loose, b"key-bytes").context("write loose secret")?;
        fs::set_permissions(&loose, fs::Permissions::from_mode(0o644)).context("chmod 644")?;
        let err = read_secret_0600(&loose).expect_err("a 0644 secret must be refused");
        assert!(
            matches!(err, CredError::Stage(_)),
            "expected CredError::Stage, got {err:?}"
        );
        Ok(())
    }

    /// #200: trust material owned by another user is refused on read.
    #[test]
    fn a_secret_owned_by_another_user_is_refused() {
        let err = refuse_foreign_owner("App key", Path::new("/k.pem"), 999, 1000)
            .expect_err("a foreign-owned key must be refused");
        let msg = err.to_string();
        assert!(
            msg.contains("uid 999") && msg.contains("another user"),
            "unexpected: {msg}"
        );
        assert!(refuse_foreign_owner("App key", Path::new("/k.pem"), 1000, 1000).is_ok());
    }

    /// #200: a group/world-writable or foreign-owned dir draws a tamper warning; a
    /// private one does not.
    #[test]
    fn a_wide_or_foreign_dir_draws_a_tamper_warning() {
        let dir = Path::new("/trust-roots");
        for (uid, mode) in [(1000, 0o775), (1000, 0o757), (999, 0o700)] {
            let warning = wide_dir_warning(dir, uid, mode, 1000);
            assert!(
                warning
                    .as_deref()
                    .is_some_and(|w| w.contains("may have been able to modify")),
                "uid {uid} mode {mode:o}: {warning:?}"
            );
        }
        assert!(
            wide_dir_warning(dir, 1000, 0o700, 1000).is_none(),
            "a private dir warned"
        );
        assert!(wide_dir_warning(dir, 1000, 0o755, 1000).is_none(), "a 0755 dir warned");
    }

    /// #200: a key path that is not a regular file is refused, not read.
    #[test]
    fn a_secret_that_is_not_a_regular_file_is_refused() -> anyhow::Result<()> {
        let tmp = private_tempdir()?;
        let dir_at_key = tmp.path().join("key.pem");
        fs::create_dir(&dir_at_key)?;
        let err = read_secret_0600(&dir_at_key).expect_err("a directory at the key path must be refused");
        assert!(err.to_string().contains("not a regular file"), "unexpected: {err}");
        Ok(())
    }

    /// #200: reading your own key in a group-writable dir warns but still works
    /// (refusing that read is the operator's decision, not made here).
    #[test]
    fn an_owned_secret_in_a_wide_dir_is_still_read() -> anyhow::Result<()> {
        let tmp = private_tempdir()?;
        let dir = tmp.path().join("trust-roots");
        fs::create_dir(&dir)?;
        let key = dir.join("acme.pem");
        fs::write(&key, b"key-bytes")?;
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600))?;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o775))?;
        assert_eq!(read_secret_0600(&key)?, b"key-bytes");
        let cfg = dir.join("acme.json");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
        sample_root().write(&cfg)?;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o775))?;
        assert_eq!(
            TrustRoot::load(&cfg)?,
            sample_root(),
            "a config in a wide dir must still load"
        );
        Ok(())
    }

    /// A GitHub [`TrustRoot`] round-trips through its `0600` JSON file, and the file
    /// holds only config (a key path), never the key bytes (INV-1).
    #[test]
    fn github_trust_root_round_trips_0600_without_secret_bytes() -> anyhow::Result<()> {
        let tmp = private_tempdir()?;
        let path = tmp.path().join("trust-root.json");
        let root = TrustRoot::Github {
            base_url: None,
            app_id: "123456".to_string(),
            private_key_path: PathBuf::from("/etc/sandy/app.pem"),
            installation_id: 789,
            targets: vec![Target("acme/widgets".to_string())],
        };

        root.write(&path).context("write trust root")?;

        let mode = fs::metadata(&path)?.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "trust-root config must be 0600");
        let loaded = TrustRoot::load(&path).context("load trust root")?;
        assert_eq!(loaded, root, "trust root must round-trip");
        let text = fs::read_to_string(&path)?;
        assert!(
            text.contains("/etc/sandy/app.pem"),
            "config names the key path, not the key"
        );
        Ok(())
    }

    fn sample_root() -> TrustRoot {
        TrustRoot::Github {
            base_url: None,
            app_id: "123456".to_string(),
            private_key_path: PathBuf::from("/etc/sandy/app.pem"),
            installation_id: 789,
            targets: vec![Target("acme/widgets".to_string())],
        }
    }

    /// #194: a symlink at the trust-root config path is replaced, never written
    /// through. The old writer created a fixed `<path>.tmp` that followed a link.
    #[test]
    fn a_trust_root_write_never_follows_a_symlink_at_its_temp_path() -> anyhow::Result<()> {
        let tmp = private_tempdir()?;
        let path = tmp.path().join("acme.json");
        let victim = tmp.path().join("victim");
        fs::write(&victim, b"untouched")?;
        std::os::unix::fs::symlink(&victim, path.with_extension("tmp"))?;
        sample_root().write(&path).context("write trust root")?;
        assert_eq!(
            fs::read(&victim)?,
            b"untouched",
            "the config was written through a planted symlink"
        );
        assert_eq!(TrustRoot::load(&path)?, sample_root(), "trust root must round-trip");
        Ok(())
    }

    /// #194: a group-writable trust-roots dir is refused, not repaired, with a
    /// message that asks the user to check for tampering before fixing the mode.
    #[test]
    fn a_group_writable_trust_roots_dir_is_refused_with_a_tamper_warning() -> anyhow::Result<()> {
        let tmp = private_tempdir()?;
        let dir = tmp.path().join("trust-roots");
        fs::create_dir(&dir)?;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o775))?;
        let err = sample_root()
            .write(&dir.join("acme.json"))
            .expect_err("a 0775 trust-roots dir must be refused");
        let msg = err.to_string();
        assert!(msg.contains("may have been able to modify"), "no tamper warning: {msg}");
        assert!(msg.contains("chmod 700"), "no fix named: {msg}");
        let mode = fs::metadata(&dir)?.permissions().mode() & 0o777;
        assert_eq!(mode, 0o775, "a refused dir must not be silently repaired");
        Ok(())
    }

    /// #194: a missing trust-roots dir is created 0700 with the config 0600.
    #[test]
    fn a_missing_trust_roots_dir_is_created_private() -> anyhow::Result<()> {
        let tmp = private_tempdir()?;
        let dir = tmp.path().join("sandy").join("trust-roots");
        sample_root().write(&dir.join("acme.json"))?;
        let mode = fs::metadata(&dir)?.permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "a created trust-roots dir must be 0700");
        Ok(())
    }

    /// A provider whose every mint/refresh yields a fresh token and handle
    /// (`token-N` / `h-N`) and that records each revoked handle, so a test can prove
    /// re-delivery rewrote the file, advanced the lease, and revoked the *superseded*
    /// token rather than the live one. `fail_refresh` makes `refresh` error while
    /// `mint` still succeeds, to exercise the untouched-on-failure path.
    struct RotatingProvider {
        counter: Mutex<u32>,
        revoked: Mutex<Vec<String>>,
        fail_refresh: bool,
    }

    impl RotatingProvider {
        fn new() -> Self {
            Self {
                counter: Mutex::new(0),
                revoked: Mutex::new(Vec::new()),
                fail_refresh: false,
            }
        }

        fn failing_refresh() -> Self {
            Self {
                fail_refresh: true,
                ..Self::new()
            }
        }

        fn revoked(&self) -> Vec<String> {
            self.revoked.lock().unwrap_or_else(PoisonError::into_inner).clone()
        }

        fn next_mint(&self) -> Minted {
            let mut n = self.counter.lock().unwrap_or_else(PoisonError::into_inner);
            *n += 1;
            Minted::new(
                format!("token-{n}"),
                SystemTime::now() + Duration::from_secs(u64::from(MAX_TTL_SECS)),
                CredentialHandle { id: format!("h-{n}") },
            )
        }
    }

    impl CredentialProvider for RotatingProvider {
        fn mint(&self, _scope: &Scope, _ttl_hint: Duration) -> Result<Minted, CredError> {
            Ok(self.next_mint())
        }

        fn revoke(&self, lease: &Lease) -> Result<(), CredError> {
            self.revoked
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(lease.handle.id.clone());
            Ok(())
        }

        fn refresh(&self, _lease: &Lease) -> Result<Minted, CredError> {
            if self.fail_refresh {
                return Err(CredError::Mint("rotating provider: refresh forced to fail".to_string()));
            }
            Ok(self.next_mint())
        }
    }

    fn file_of(lease: &Lease) -> PathBuf {
        match &lease.secret_ref.source {
            SecretSource::File(p) => p.clone(),
            other => panic!("expected a file-sourced secret, got {other:?}"),
        }
    }

    /// Below the margin, `refresh_once` is a no-op: the staged file, the lease
    /// handle, and the revoke ledger are all untouched.
    #[test]
    fn refresh_is_a_noop_before_the_margin() -> anyhow::Result<()> {
        let tmp = private_tempdir()?;
        let provider = RotatingProvider::new();
        let mut lease = mint_lease(&provider, &scope(), 3000, "GH_TOKEN", tmp.path()).context("mint")?;
        let path = file_of(&lease);
        assert_eq!(fs::read_to_string(&path)?, "token-1");

        // Expiry is ~MAX_TTL ahead; a 60s margin is nowhere near it.
        let refreshed =
            refresh_once(&provider, &mut lease, SystemTime::now(), Duration::from_secs(60)).context("refresh_once")?;

        assert!(!refreshed, "must not refresh while well outside the margin");
        assert_eq!(fs::read_to_string(&path)?, "token-1", "file unchanged");
        assert_eq!(lease.handle.id, "h-1", "lease unchanged");
        assert!(provider.revoked().is_empty(), "nothing revoked");
        Ok(())
    }

    /// Inside the margin, `refresh_once` re-stages the fresh token over the same
    /// file (still 0600), advances the lease to the new handle, and revokes the
    /// superseded handle, never the new one.
    #[test]
    fn refresh_restages_fresh_token_and_revokes_the_old() -> anyhow::Result<()> {
        let tmp = private_tempdir()?;
        let provider = RotatingProvider::new();
        let mut lease = mint_lease(&provider, &scope(), 3000, "GH_TOKEN", tmp.path()).context("mint")?;
        let path = file_of(&lease);

        // Pull "now" to 10s before expiry so a 60s margin fires.
        let due = lease.expires_at - Duration::from_secs(10);
        let refreshed = refresh_once(&provider, &mut lease, due, Duration::from_secs(60)).context("refresh_once")?;

        assert!(refreshed, "must refresh inside the margin");
        assert_eq!(
            fs::read_to_string(&path)?,
            "token-2",
            "fresh token re-staged over the same file"
        );
        assert_eq!(lease.handle.id, "h-2", "lease advanced to the new handle");
        assert_eq!(
            provider.revoked(),
            vec!["h-1".to_string()],
            "the superseded token is revoked, not the new one"
        );
        let mode = fs::metadata(&path)?.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "re-staged token stays 0600");
        Ok(())
    }

    /// A re-mint failure leaves everything in place: the old token stays staged and
    /// valid, the lease is unchanged, and nothing is revoked (the loop retries).
    #[test]
    fn a_failed_refresh_leaves_the_current_token_in_place() -> anyhow::Result<()> {
        let tmp = private_tempdir()?;
        let provider = RotatingProvider::failing_refresh();
        let mut lease = mint_lease(&provider, &scope(), 3000, "GH_TOKEN", tmp.path()).context("mint")?;
        let path = file_of(&lease);

        let due = lease.expires_at - Duration::from_secs(10);
        let err = refresh_once(&provider, &mut lease, due, Duration::from_secs(60)).unwrap_err();

        assert!(
            matches!(err, CredError::Mint(_)),
            "re-mint failure surfaces as an error"
        );
        assert_eq!(
            fs::read_to_string(&path)?,
            "token-1",
            "current token untouched on failure"
        );
        assert_eq!(lease.handle.id, "h-1", "lease untouched on failure");
        assert!(provider.revoked().is_empty(), "nothing revoked on failure");
        Ok(())
    }

    /// `should_refresh` fires only at or inside the margin, and on an already-lapsed
    /// expiry.
    #[test]
    fn should_refresh_fires_within_margin_only() {
        let now = SystemTime::now();
        let margin = Duration::from_secs(300);
        assert!(
            !should_refresh(now, now + Duration::from_secs(1_800), margin),
            "far from expiry: no"
        );
        assert!(
            should_refresh(now, now + Duration::from_secs(120), margin),
            "inside the margin: yes"
        );
        assert!(
            should_refresh(now, now - Duration::from_secs(1), margin),
            "already expired: yes"
        );
    }
}
