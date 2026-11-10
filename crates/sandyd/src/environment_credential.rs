//! A per-environment forge credential (#706, slices 3 and 4 of #592).
//!
//! An environment's identity profile names a registered trust root. Before the guest boots, [`EnvironmentCredentials`]
//! mints a token for the profile's scope and stages it as a `0600` [`CREDENTIAL_SECRET_NAME`] file in a private
//! directory the guest sees as its read-only secret share. The directory is named from the environment id, so a
//! restarted daemon finds the share a still-running guest has mounted and rewrites the token in it.
//!
//! The lifecycle is the job one ([`sandy::CredentialBracket`], #481): renew before expiry by staging the new token
//! first and revoking the old one after, revoke on release. The token bytes never live here; only the bracket's lease
//! handle does, so a daemon restart loses the handle and the old token then lives until its native expiry.

use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex, PoisonError},
    time::{Duration, SystemTime},
};

use sandy::{CredentialBracket, DirFingerprint, Scope, StagingTarget};

use crate::credential::{CREDENTIAL_SECRET_NAME, CredentialResolver, DAEMON_CALL_TIMEOUT};

/// The staging directory prefix. Not `cred-`: `sandy gc` sweeps those by age, and an environment outlives a token.
const DIR_PREFIX: &str = "env-cred-";

/// Renew once at most this long remains before the token expires. A token lives up to an hour (GitHub ignores the
/// requested TTL).
pub const RENEW_MARGIN: Duration = Duration::from_secs(300);

/// The directory the guest mounts as its secret share.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretShare {
    /// The private directory holding the staged token.
    pub dir: PathBuf,
    /// The `(dev, ino)` of `dir`, captured when it was validated (#323).
    pub fingerprint: DirFingerprint,
}

struct Held {
    bracket: CredentialBracket,
    share: SecretShare,
}

/// The daemon's per-environment credential brackets, keyed by environment id.
pub struct EnvironmentCredentials {
    resolver: Arc<dyn CredentialResolver>,
    /// Where the `env-cred-<id>` directories are created.
    base: PathBuf,
    call_timeout: Duration,
    margin: Duration,
    live: Mutex<HashMap<String, Arc<Held>>>,
}

impl EnvironmentCredentials {
    /// Credentials resolved by `resolver`, staged under `base`, which must be a validated private directory.
    #[must_use]
    pub fn new(resolver: Arc<dyn CredentialResolver>, base: PathBuf) -> Self {
        Self {
            resolver,
            base,
            call_timeout: DAEMON_CALL_TIMEOUT,
            margin: RENEW_MARGIN,
            live: Mutex::new(HashMap::new()),
        }
    }

    /// Bound each provider call by `timeout` instead of [`DAEMON_CALL_TIMEOUT`].
    #[must_use]
    pub fn with_call_timeout(mut self, timeout: Duration) -> Self {
        self.call_timeout = timeout;
        self
    }

    /// Renew at most `margin` before expiry instead of [`RENEW_MARGIN`].
    #[must_use]
    pub fn with_margin(mut self, margin: Duration) -> Self {
        self.margin = margin;
        self
    }

    /// Whether `environment_id` holds a live credential.
    #[must_use]
    pub fn holds(&self, environment_id: &str) -> bool {
        self.lock().contains_key(environment_id)
    }

    /// The secret share of `environment_id`, minting a credential for `scope` from trust root `credential` when it
    /// holds none. A restarted daemon calls this for an environment whose guest still runs: the token is rewritten in
    /// the same share. Blocking: run it off the async runtime.
    ///
    /// # Errors
    /// A human-readable reason when the id is not usable in a path, the trust root cannot be resolved, the directory
    /// cannot be made, or the mint or stage fails. Nothing stays live or staged on an error. It never carries a token.
    pub fn ensure(&self, environment_id: &str, credential: &str, scope: &Scope) -> Result<SecretShare, String> {
        if let Some(held) = self.lock().get(environment_id) {
            return Ok(held.share.clone());
        }
        if !valid_id(environment_id) {
            return Err("the environment id cannot name a credential directory".to_owned());
        }
        let provider = self.resolver.provider(credential)?;
        let path = self.base.join(format!("{DIR_PREFIX}{environment_id}"));
        let dir = sandy_fsutil::OwnedDir::open_or_create(&path)
            .map_err(|e| format!("create the credential staging dir: {e}"))?;
        let (dev, ino) = dir
            .dev_ino()
            .map_err(|e| format!("fingerprint the credential staging dir: {e}"))?;
        let fingerprint = DirFingerprint { dev, ino };
        drop(dir);
        let target = StagingTarget {
            dir: path.clone(),
            fingerprint,
            secret_name: CREDENTIAL_SECRET_NAME.to_owned(),
            remove_dir_on_revoke: true,
        };
        let bracket =
            CredentialBracket::mint_and_stage(provider, scope, target, sandy::MAX_TTL_SECS, self.call_timeout)
                .map_err(|e| {
                    // An empty directory this call made is not a lease; the next attempt reuses or removes it.
                    if let Err(rm) = std::fs::remove_dir(&path) {
                        tracing::debug!(dir = %path.display(), error = %rm, "left the credential staging dir in place");
                    }
                    e.to_string()
                })?;
        let share = SecretShare { dir: path, fingerprint };
        let mut live = self.lock();
        // A concurrent `ensure` for the same id: keep the first, the second revokes on drop.
        let held = live
            .entry(environment_id.to_owned())
            .or_insert_with(|| Arc::new(Held { bracket, share }));
        Ok(held.share.clone())
    }

    /// Renew `environment_id`'s credential when at most the margin remains at `now`: the new token is staged before
    /// the old one is revoked. `Ok(true)` when it was renewed, `Ok(false)` when it was not due or none is held.
    /// Blocking.
    ///
    /// # Errors
    /// The reason the renewal failed. The current token stays staged and valid until it expires.
    pub fn renew(&self, environment_id: &str, now: SystemTime) -> Result<bool, String> {
        // The map lock is not held across the provider call.
        let held = self.lock().get(environment_id).map(Arc::clone);
        match held {
            None => Ok(false),
            Some(held) => held.bracket.renew_if_due(now, self.margin).map_err(|e| e.to_string()),
        }
    }

    /// Revoke `environment_id`'s credential and remove its staged file and directory. Idempotent. A directory left by
    /// an earlier daemon (its lease handle is lost) is removed too, so a stopped environment keeps no token file.
    /// Blocking.
    ///
    /// # Errors
    /// The reason the revoke or the file removal failed. The token then stays valid until its native expiry.
    pub fn release(&self, environment_id: &str) -> Result<(), String> {
        let held = self.lock().remove(environment_id);
        match held {
            Some(held) => held.bracket.revoke().map_err(|e| e.to_string()),
            None => self.remove_leftover(environment_id),
        }
    }

    fn remove_leftover(&self, environment_id: &str) -> Result<(), String> {
        if !valid_id(environment_id) {
            return Ok(());
        }
        let path = self.base.join(format!("{DIR_PREFIX}{environment_id}"));
        let token = path.join(CREDENTIAL_SECRET_NAME);
        for (what, result) in [
            ("token file", std::fs::remove_file(&token)),
            ("directory", std::fs::remove_dir(&path)),
        ] {
            match result {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(format!("remove a leftover credential {what}: {e}")),
            }
        }
        Ok(())
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Arc<Held>>> {
        self.live.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// An id safe to use as one path component.
fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 128 && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Test doubles shared with the driver's tests.
#[cfg(test)]
pub(crate) mod fakes {
    use std::{
        sync::{
            Arc, Mutex, PoisonError,
            atomic::{AtomicUsize, Ordering},
        },
        time::{Duration, SystemTime},
    };

    use sandy::{CredError, CredentialHandle, CredentialProvider, Lease, Minted, Scope};

    use crate::credential::CredentialResolver;

    /// A provider that mints `tok-1`, `tok-2`, ... with handles `h1`, `h2`, ..., and records every revoke.
    #[derive(Default)]
    pub struct Rotating {
        pub next: AtomicUsize,
        pub revoked: Mutex<Vec<String>>,
        pub fail_mint: std::sync::atomic::AtomicBool,
        pub fail_refresh: std::sync::atomic::AtomicBool,
        pub fail_revoke: std::sync::atomic::AtomicBool,
    }

    impl Rotating {
        fn mint_one(&self) -> Result<Minted, CredError> {
            let n = self.next.fetch_add(1, Ordering::SeqCst) + 1;
            Ok(Minted::new(
                format!("tok-{n}"),
                SystemTime::now() + Duration::from_secs(3000),
                CredentialHandle { id: format!("h{n}") },
            ))
        }

        pub fn revoked(&self) -> Vec<String> {
            self.revoked.lock().unwrap_or_else(PoisonError::into_inner).clone()
        }
    }

    impl CredentialProvider for Rotating {
        fn mint(&self, _scope: &Scope, _ttl: Duration) -> Result<Minted, CredError> {
            if self.fail_mint.load(Ordering::SeqCst) {
                return Err(CredError::Mint("the forge refused".to_owned()));
            }
            self.mint_one()
        }

        fn refresh(&self, _lease: &Lease) -> Result<Minted, CredError> {
            if self.fail_refresh.load(Ordering::SeqCst) {
                return Err(CredError::Mint("the forge refused".to_owned()));
            }
            self.mint_one()
        }

        fn revoke(&self, lease: &Lease) -> Result<(), CredError> {
            self.revoked
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(lease.handle.id.clone());
            if self.fail_revoke.load(Ordering::SeqCst) {
                return Err(CredError::Revoke("the forge refused".to_owned()));
            }
            Ok(())
        }
    }

    pub struct Resolver(pub Arc<Rotating>);

    impl CredentialResolver for Resolver {
        fn resolve(&self, _name: &str, _capabilities: &[String]) -> Result<(sandy::SharedProvider, Scope), String> {
            Err("not used".to_owned())
        }

        fn provider(&self, name: &str) -> Result<sandy::SharedProvider, String> {
            if name == "unregistered" {
                return Err("load trust root \"unregistered\": not found".to_owned());
            }
            let provider: sandy::SharedProvider = self.0.clone();
            Ok(provider)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{os::unix::fs::PermissionsExt, sync::atomic::Ordering};

    use anyhow::{Context, Result, ensure};

    use super::{
        fakes::{Resolver, Rotating},
        *,
    };

    struct Rig {
        provider: Arc<Rotating>,
        creds: EnvironmentCredentials,
        base: PathBuf,
        _tmp: tempfile::TempDir,
    }

    fn rig() -> Result<Rig> {
        let tmp = tempfile::tempdir()?;
        let base = tmp.path().join("staging");
        std::fs::create_dir(&base)?;
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700))?;
        let provider = Arc::new(Rotating::default());
        let creds = EnvironmentCredentials::new(Arc::new(Resolver(Arc::clone(&provider))), base.clone());
        Ok(Rig {
            provider,
            creds,
            base,
            _tmp: tmp,
        })
    }

    fn token(share: &SecretShare) -> Result<String> {
        std::fs::read_to_string(share.dir.join(CREDENTIAL_SECRET_NAME)).context("read the staged token")
    }

    fn later() -> SystemTime {
        SystemTime::now() + Duration::from_secs(3000)
    }

    #[test]
    fn ensure_stages_a_0600_token_in_a_0700_dir_named_from_the_environment() -> Result<()> {
        let r = rig()?;
        let share = r
            .creds
            .ensure("env-a", "gh", &Scope::default())
            .map_err(anyhow::Error::msg)?;
        ensure!(share.dir == r.base.join("env-cred-env-a"), "{:?}", share.dir);
        ensure!(token(&share)? == "tok-1");
        let dir_mode = std::fs::metadata(&share.dir)?.permissions().mode() & 0o777;
        let file_mode = std::fs::metadata(share.dir.join(CREDENTIAL_SECRET_NAME))?
            .permissions()
            .mode()
            & 0o777;
        ensure!(dir_mode == 0o700 && file_mode == 0o600, "{dir_mode:o} {file_mode:o}");
        ensure!(r.creds.holds("env-a"));
        Ok(())
    }

    #[test]
    fn a_second_ensure_returns_the_same_share_and_mints_nothing() -> Result<()> {
        let r = rig()?;
        let first = r
            .creds
            .ensure("env-a", "gh", &Scope::default())
            .map_err(anyhow::Error::msg)?;
        let second = r
            .creds
            .ensure("env-a", "gh", &Scope::default())
            .map_err(anyhow::Error::msg)?;
        ensure!(first == second);
        ensure!(r.provider.next.load(Ordering::SeqCst) == 1, "one mint only");
        Ok(())
    }

    #[test]
    fn a_mint_failure_leaves_nothing_live_and_no_directory() -> Result<()> {
        let r = rig()?;
        r.provider.fail_mint.store(true, Ordering::SeqCst);
        let err = r
            .creds
            .ensure("env-a", "gh", &Scope::default())
            .err()
            .context("must fail")?;
        ensure!(err.contains("the forge refused"), "{err}");
        ensure!(!r.creds.holds("env-a"));
        ensure!(!r.base.join("env-cred-env-a").exists(), "no directory may remain");
        Ok(())
    }

    #[test]
    fn an_unregistered_trust_root_fails_closed() -> Result<()> {
        let r = rig()?;
        let err = r
            .creds
            .ensure("env-a", "unregistered", &Scope::default())
            .err()
            .context("must fail")?;
        ensure!(err.contains("not found"), "{err}");
        ensure!(!r.creds.holds("env-a"));
        Ok(())
    }

    #[test]
    fn an_id_that_is_not_one_path_component_is_refused() -> Result<()> {
        let r = rig()?;
        for id in ["", "../x", "a/b", "a b", "a\0b"] {
            ensure!(r.creds.ensure(id, "gh", &Scope::default()).is_err(), "{id:?}");
        }
        ensure!(r.provider.next.load(Ordering::SeqCst) == 0, "nothing may be minted");
        Ok(())
    }

    #[test]
    fn a_renewal_stages_the_new_token_then_revokes_the_old_lease() -> Result<()> {
        let r = rig()?;
        let share = r
            .creds
            .ensure("env-a", "gh", &Scope::default())
            .map_err(anyhow::Error::msg)?;
        ensure!(
            !r.creds.renew("env-a", SystemTime::now()).map_err(anyhow::Error::msg)?,
            "not due yet"
        );
        ensure!(r.creds.renew("env-a", later()).map_err(anyhow::Error::msg)?, "due");
        ensure!(token(&share)? == "tok-2", "the file holds the new token");
        ensure!(
            r.provider.revoked() == vec!["h1".to_owned()],
            "{:?}",
            r.provider.revoked()
        );
        Ok(())
    }

    #[test]
    fn a_failed_renewal_keeps_the_current_token_staged_and_live() -> Result<()> {
        let r = rig()?;
        let share = r
            .creds
            .ensure("env-a", "gh", &Scope::default())
            .map_err(anyhow::Error::msg)?;
        r.provider.fail_refresh.store(true, Ordering::SeqCst);
        ensure!(r.creds.renew("env-a", later()).is_err());
        ensure!(token(&share)? == "tok-1");
        ensure!(
            r.provider.revoked().is_empty(),
            "the held token is not revoked by a failed renewal"
        );
        ensure!(r.creds.holds("env-a"));
        Ok(())
    }

    #[test]
    fn release_revokes_removes_the_file_and_the_dir_and_is_idempotent() -> Result<()> {
        let r = rig()?;
        let share = r
            .creds
            .ensure("env-a", "gh", &Scope::default())
            .map_err(anyhow::Error::msg)?;
        r.creds.release("env-a").map_err(anyhow::Error::msg)?;
        ensure!(r.provider.revoked() == vec!["h1".to_owned()]);
        ensure!(!share.dir.exists(), "the dir is removed with the file");
        ensure!(!r.creds.holds("env-a"));
        r.creds.release("env-a").map_err(anyhow::Error::msg)?;
        ensure!(r.provider.revoked().len() == 1, "a second release revokes nothing");
        Ok(())
    }

    #[test]
    fn a_revoke_failure_is_returned_and_the_file_is_still_removed() -> Result<()> {
        let r = rig()?;
        let share = r
            .creds
            .ensure("env-a", "gh", &Scope::default())
            .map_err(anyhow::Error::msg)?;
        r.provider.fail_revoke.store(true, Ordering::SeqCst);
        let err = r
            .creds
            .release("env-a")
            .err()
            .context("must report the failure")
            .map_err(anyhow::Error::msg)?;
        ensure!(err.contains("the forge refused"), "{err}");
        ensure!(
            !share.dir.join(CREDENTIAL_SECRET_NAME).exists(),
            "the token file is removed anyway"
        );
        ensure!(!r.creds.holds("env-a"));
        Ok(())
    }

    #[test]
    fn a_restarted_daemon_restages_into_the_same_share() -> Result<()> {
        let r = rig()?;
        let share = r
            .creds
            .ensure("env-a", "gh", &Scope::default())
            .map_err(anyhow::Error::msg)?;
        // A restart: a fresh registry over the same base, with the old lease handle lost.
        let restarted = EnvironmentCredentials::new(Arc::new(Resolver(Arc::clone(&r.provider))), r.base.clone());
        let again = restarted
            .ensure("env-a", "gh", &Scope::default())
            .map_err(anyhow::Error::msg)?;
        ensure!(again.dir == share.dir, "the running guest's mount must stay valid");
        ensure!(token(&again)? == "tok-2", "the file holds a fresh token");
        Ok(())
    }

    #[test]
    fn a_leftover_dir_of_a_stopped_environment_is_removed_on_release() -> Result<()> {
        let r = rig()?;
        let share = r
            .creds
            .ensure("env-a", "gh", &Scope::default())
            .map_err(anyhow::Error::msg)?;
        let restarted = EnvironmentCredentials::new(Arc::new(Resolver(Arc::clone(&r.provider))), r.base.clone());
        restarted.release("env-a").map_err(anyhow::Error::msg)?;
        ensure!(!share.dir.exists(), "no token file may outlive a stopped environment");
        Ok(())
    }

    #[test]
    fn the_token_never_appears_in_any_error() -> Result<()> {
        let r = rig()?;
        let share = r
            .creds
            .ensure("env-a", "gh", &Scope::default())
            .map_err(anyhow::Error::msg)?;
        let secret = token(&share)?;
        r.provider.fail_refresh.store(true, Ordering::SeqCst);
        r.provider.fail_revoke.store(true, Ordering::SeqCst);
        let renew = r
            .creds
            .renew("env-a", later())
            .err()
            .context("renew must fail")
            .map_err(anyhow::Error::msg)?;
        let release = r
            .creds
            .release("env-a")
            .err()
            .context("release must fail")
            .map_err(anyhow::Error::msg)?;
        ensure!(!renew.contains(&secret) && !release.contains(&secret));
        Ok(())
    }
}
