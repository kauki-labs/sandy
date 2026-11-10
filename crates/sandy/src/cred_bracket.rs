//! The reusable credential bracket (#481): mint and stage a scoped token, renew it
//! before expiry, revoke it and remove the staged file, exactly once.
//!
//! The bracket knows nothing of jobs or environments. sandyd's job path is its first
//! caller; an environment driver (#706) is the next. It composes the existing
//! [`mint_lease_checked`] and [`refresh_once_checked`] steps, so the staging
//! contract (a `0600` file under a fingerprinted `0700` dir, INV-1, #323) and the
//! renew order (stage the new token first, then revoke the superseded one) are the
//! ones `sandy run` already uses.
//!
//! Every provider call runs under a wall-clock bound ([`CredentialBracket::mint_and_stage`]'s
//! `call_timeout`): a call that does not return in time counts as a failure. A mint
//! or refresh that finishes after its caller gave up is revoked by the worker that
//! ran it, so a late token never outlives the bracket unrevoked.
//!
//! The token bytes never live in the bracket: they exist only inside the provider's
//! [`Minted`] (zeroized, `Debug`-redacted) and the staged file.

use std::{
    os::unix::fs::MetadataExt as _,
    path::PathBuf,
    sync::{
        Arc, Condvar, Mutex, PoisonError,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime},
};

use crate::{
    backend::{DirFingerprint, SecretRef, SecretSource},
    cred::{
        CredError, CredentialHandle, CredentialProvider, Lease, Minted, Scope, mint_lease_checked,
        refresh_once_checked, revoke_orphan,
    },
};

/// Where a bracket stages its token: the file `dir/secret_name`, written `0600`
/// into a `0700` dir the caller validated and fingerprinted (#323).
#[derive(Debug, Clone)]
pub struct StagingTarget {
    /// The private (`0700`) directory the token file is written into.
    pub dir: PathBuf,
    /// The `(dev, ino)` the caller captured when it validated `dir`; every
    /// re-open by path is checked against it.
    pub fingerprint: DirFingerprint,
    /// The file name, which is also the secret's env name in the guest.
    pub secret_name: String,
    /// Remove `dir` itself (it must then be empty) after the token file is
    /// removed: set when the caller created `dir` for this bracket alone.
    pub remove_dir_on_revoke: bool,
}

/// A provider shared across the bracket and its bounded-call workers.
pub type SharedProvider = Arc<dyn CredentialProvider + Send + Sync>;

/// A minted, staged credential with its lifecycle: [`renew_if_due`](Self::renew_if_due)
/// and [`revoke`](Self::revoke). Dropping a bracket that was never revoked revokes
/// it (off the current thread when a tokio runtime is current), so a caller's early
/// return cannot leak a live token.
pub struct CredentialBracket {
    /// `None` only once `Drop` has handed it to its cleanup thread.
    provider: Option<SharedProvider>,
    target: StagingTarget,
    token_path: PathBuf,
    /// The staging dir, opened and checked against the fingerprint before the mint.
    /// Cleanup unlinks through this handle, never through `target.dir` by path.
    dir: Arc<sandy_fsutil::OwnedDir>,
    /// `None` once revoked.
    lease: Mutex<Option<Lease>>,
    /// The staged file is not yet removed. Kept apart from the lease so a removal
    /// that failed after a successful revoke is retried by a later revoke or drop.
    file_staged: AtomicBool,
}

impl std::fmt::Debug for CredentialBracket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialBracket")
            .field("secret_name", &self.target.secret_name)
            .field("token_path", &self.token_path)
            .field("handle", &self.handle())
            .finish_non_exhaustive()
    }
}

/// The longest staged token [`TokenRedactor`] redacts; a longer file fails closed.
const MAX_TOKEN_BYTES: u64 = 64 * 1024;

/// Redacts a staged token from text. It reads the staged file each time, because
/// nothing in memory holds the token.
#[derive(Debug, Clone)]
pub struct TokenRedactor {
    token_path: PathBuf,
}

impl TokenRedactor {
    /// `bytes` with every occurrence of the staged token replaced by `[redacted]`.
    /// Blocking. `None` when the staged file cannot be read or holds no token:
    /// the caller cannot tell the token is absent from `bytes`, so it must not
    /// store them. Only the literal token is replaced: an encoded form (base64,
    /// URL or JSON escaping) or a copy cut by a console tail is not.
    #[must_use]
    pub fn redact_bytes(&self, bytes: Vec<u8>) -> Option<Vec<u8>> {
        use std::{io::Read as _, os::unix::fs::OpenOptionsExt as _};
        // O_NONBLOCK: a FIFO swapped in at the path must not block this open (the
        // regular-file check then refuses it). O_NOFOLLOW: a symlink is refused.
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(&self.token_path)
            .ok()?;
        if !file.metadata().ok()?.is_file() {
            return None;
        }
        let mut token = Vec::new();
        // One byte past the limit tells a token that is too long to redact whole.
        file.take(MAX_TOKEN_BYTES + 1).read_to_end(&mut token).ok()?;
        if token.len() as u64 > MAX_TOKEN_BYTES {
            return None;
        }
        let token = token.trim_ascii();
        if token.is_empty() {
            return None;
        }
        let mut out = Vec::with_capacity(bytes.len());
        let mut rest = bytes.as_slice();
        while let Some(at) = rest.windows(token.len()).position(|w| w == token) {
            out.extend_from_slice(&rest[..at]);
            out.extend_from_slice(b"[redacted]");
            rest = &rest[at + token.len()..];
        }
        out.extend_from_slice(rest);
        Some(out)
    }
}

impl CredentialBracket {
    /// Mint a credential for `scope` and stage it at `target`. The requested TTL
    /// is clamped to [`crate::MAX_TTL_SECS`]. Fail-closed: on any error nothing is
    /// staged and no token stays live (a token minted but not staged is revoked).
    ///
    /// # Errors
    /// [`CredError::Mint`] when the mint fails or does not finish within
    /// `call_timeout`, [`CredError::Stage`] when the token cannot be staged.
    pub fn mint_and_stage(
        provider: SharedProvider,
        scope: &Scope,
        target: StagingTarget,
        requested_ttl_secs: u32,
        call_timeout: Duration,
    ) -> Result<Self, CredError> {
        // Bind to the validated dir before minting: a dir swapped in since the
        // caller's check fails here, with no token minted.
        let dir = sandy_fsutil::OwnedDir::open(&target.dir)
            .map_err(|e| CredError::Stage(format!("open staging dir {}: {e}", target.dir.display())))?;
        let (dev, ino) = dir
            .dev_ino()
            .map_err(|e| CredError::Stage(format!("stat staging dir {}: {e}", target.dir.display())))?;
        if (dev, ino) != (target.fingerprint.dev, target.fingerprint.ino) {
            return Err(CredError::Stage(format!(
                "staging dir {} is not the directory that was validated",
                target.dir.display()
            )));
        }
        let provider: SharedProvider = Arc::new(Bounded {
            inner: provider,
            timeout: call_timeout,
        });
        let lease = mint_lease_checked(
            provider.as_ref(),
            scope,
            requested_ttl_secs,
            &target.secret_name,
            &target.dir,
            target.fingerprint,
        )?;
        let SecretSource::File(token_path) = &lease.secret_ref.source else {
            // mint_lease always stages a file; anything else is a contract break.
            let _ = provider.revoke(&lease);
            return Err(CredError::Stage(
                "minted credential is not a file-sourced secret".to_string(),
            ));
        };
        let token_path = token_path.clone();
        Ok(Self {
            provider: Some(provider),
            target,
            token_path,
            dir: Arc::new(dir),
            lease: Mutex::new(Some(lease)),
            file_staged: AtomicBool::new(true),
        })
    }

    /// The staged secret as a file reference: the path only, never the bytes.
    #[must_use]
    pub fn secret_ref(&self) -> SecretRef {
        SecretRef {
            name: self.target.secret_name.clone(),
            source: SecretSource::File(self.token_path.clone()),
        }
    }

    /// A handle that redacts this bracket's staged token, usable after the lock
    /// that guards the bracket is released.
    #[must_use]
    pub fn redactor(&self) -> TokenRedactor {
        TokenRedactor {
            token_path: self.token_path.clone(),
        }
    }

    /// The live credential's handle, for a caller that records lease state (a
    /// later restart reconcile could revoke by it). `None` once revoked.
    #[must_use]
    pub fn handle(&self) -> Option<CredentialHandle> {
        self.lock_lease().as_ref().map(|l| l.handle.clone())
    }

    /// When the live credential expires. `None` once revoked.
    #[must_use]
    pub fn expires_at(&self) -> Option<SystemTime> {
        self.lock_lease().as_ref().map(|l| l.expires_at)
    }

    /// Re-mint and re-stage the credential when at most `margin` remains before it
    /// expires at `now`, then revoke the superseded token (stage first, so a reader
    /// of the file never sees a revoked token). `Ok(false)` when not yet due or
    /// already revoked.
    ///
    /// # Errors
    /// As [`refresh_once_checked`]: the current token stays staged on an error.
    pub fn renew_if_due(&self, now: SystemTime, margin: Duration) -> Result<bool, CredError> {
        let Some(provider) = &self.provider else {
            return Ok(false);
        };
        let mut guard = self.lock_lease();
        let Some(lease) = guard.as_mut() else {
            return Ok(false);
        };
        refresh_once_checked(provider.as_ref(), lease, now, margin, self.target.fingerprint)
    }

    /// Revoke the live credential and remove its staged file (and the dir, when
    /// [`StagingTarget::remove_dir_on_revoke`] is set). Idempotent: a second call
    /// makes no provider call and returns `Ok(())`. The file is removed even when
    /// the revoke fails.
    ///
    /// # Errors
    /// [`CredError::Revoke`] when the revoke fails or does not finish in time (the
    /// token then stays valid until its native expiry); [`CredError::Stage`] when
    /// the revoke succeeded but the staged file could not be removed.
    pub fn revoke(&self) -> Result<(), CredError> {
        let lease = self.lock_lease().take();
        let Some(provider) = &self.provider else {
            return Ok(());
        };
        let remove_file = self.file_staged.load(Ordering::SeqCst);
        let (revoked, removed) =
            revoke_and_remove(provider.as_ref(), lease.as_ref(), &self.dir, &self.target, remove_file);
        if remove_file && removed.is_ok() {
            self.file_staged.store(false, Ordering::SeqCst);
        }
        revoked.and(removed)
    }

    fn lock_lease(&self) -> std::sync::MutexGuard<'_, Option<Lease>> {
        self.lease.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Drop for CredentialBracket {
    fn drop(&mut self) {
        let lease = self.lease.get_mut().unwrap_or_else(PoisonError::into_inner).take();
        let remove_file = *self.file_staged.get_mut();
        let Some(provider) = self.provider.take() else { return };
        let in_runtime = tokio::runtime::Handle::try_current().is_ok();
        // Nothing to clean up: drop the provider here, unless a runtime is current
        // (a live adapter owns its own runtime): then the cleanup thread drops it.
        if lease.is_none() && !remove_file && !in_runtime {
            return;
        }
        let dir = Arc::clone(&self.dir);
        let target = self.target.clone();
        let cleanup = move || {
            let (revoked, removed) = revoke_and_remove(provider.as_ref(), lease.as_ref(), &dir, &target, remove_file);
            if let Err(e) = revoked.and(removed) {
                tracing::warn!(
                    handle = lease.as_ref().map(|l| l.handle.id.as_str()),
                    error = %e,
                    "credential cleanup on drop failed; a token stays valid until its native expiry"
                );
            }
            // `provider` drops here, off any async worker: a live adapter owns its
            // own tokio runtime, which must not be dropped inside another one.
            drop(provider);
        };
        if in_runtime {
            if let Err(e) = std::thread::Builder::new()
                .name("sandy-cred-drop".to_string())
                .spawn(cleanup)
            {
                tracing::warn!(error = %e, "could not start the credential cleanup thread; the token stays valid until its native expiry");
            }
        } else {
            cleanup();
        }
    }
}

/// Revoke `lease` (when there is one), then remove the staged file when
/// `remove_file` and, when asked, the dir. The file is removed even when the revoke
/// fails. Returns the revoke and the removal results apart.
fn revoke_and_remove(
    provider: &(dyn CredentialProvider + Send + Sync),
    lease: Option<&Lease>,
    dir: &sandy_fsutil::OwnedDir,
    target: &StagingTarget,
    remove_file: bool,
) -> (Result<(), CredError>, Result<(), CredError>) {
    let revoked = lease.map_or(Ok(()), |l| provider.revoke(l));
    let removed = if remove_file {
        remove_staged(dir, target)
    } else {
        Ok(())
    };
    (revoked, removed)
}

/// Unlink the staged file through the dir handle opened at mint time, then remove
/// the dir when asked and `target.dir` still names it. A dir renamed away and
/// replaced at the same path is neither read nor removed.
fn remove_staged(dir: &sandy_fsutil::OwnedDir, target: &StagingTarget) -> Result<(), CredError> {
    match rustix::fs::unlinkat(dir, target.secret_name.as_str(), rustix::fs::AtFlags::empty()) {
        Ok(()) | Err(rustix::io::Errno::NOENT) => {}
        Err(e) => {
            return Err(CredError::Stage(format!(
                "remove staged credential {}: {e}",
                target.dir.join(&target.secret_name).display()
            )));
        }
    }
    let same_dir = std::fs::symlink_metadata(&target.dir)
        .is_ok_and(|m| (m.dev(), m.ino()) == (target.fingerprint.dev, target.fingerprint.ino));
    if target.remove_dir_on_revoke
        && same_dir
        && let Err(e) = std::fs::remove_dir(&target.dir)
        && e.kind() != std::io::ErrorKind::NotFound
    {
        tracing::warn!(dir = %target.dir.display(), error = %e, "could not remove the credential staging dir");
    }
    Ok(())
}

/// A copy of `lease` for a call that must own it (a bounded worker thread). A
/// lease is always file-sourced; any other source copies as an empty path.
fn lease_copy(lease: &Lease) -> Lease {
    let path = match &lease.secret_ref.source {
        SecretSource::File(p) => p.clone(),
        SecretSource::Fd(_) => PathBuf::new(),
    };
    Lease {
        secret_ref: SecretRef {
            name: lease.secret_ref.name.clone(),
            source: SecretSource::File(path),
        },
        expires_at: lease.expires_at,
        handle: lease.handle.clone(),
    }
}

/// A [`CredentialProvider`] decorator that bounds every call by `timeout`. A call
/// that does not return in time is a failure; a mint or refresh that finishes
/// later is revoked by its worker.
struct Bounded {
    inner: SharedProvider,
    timeout: Duration,
}

impl CredentialProvider for Bounded {
    fn mint(&self, scope: &Scope, ttl_hint: Duration) -> Result<Minted, CredError> {
        let (inner, late_inner, scope) = (Arc::clone(&self.inner), Arc::clone(&self.inner), scope.clone());
        run_bounded(
            self.timeout,
            move || inner.mint(&scope, ttl_hint),
            move |late: Result<Minted, CredError>| {
                if let Ok(minted) = late {
                    revoke_orphan(late_inner.as_ref(), "late-mint", &minted);
                }
            },
        )
        .unwrap_or_else(|| {
            Err(CredError::Mint(format!(
                "credential mint did not finish within {:?}",
                self.timeout
            )))
        })
    }

    fn revoke(&self, lease: &Lease) -> Result<(), CredError> {
        let (inner, owned) = (Arc::clone(&self.inner), lease_copy(lease));
        let handle = lease.handle.id.clone();
        run_bounded(
            self.timeout,
            move || inner.revoke(&owned),
            move |late: Result<(), CredError>| {
                if let Err(e) = late {
                    tracing::warn!(handle, error = %e, "a late credential revoke failed");
                }
            },
        )
        .unwrap_or_else(|| {
            Err(CredError::Revoke(format!(
                "credential revoke did not finish within {:?}",
                self.timeout
            )))
        })
    }

    fn refresh(&self, lease: &Lease) -> Result<Minted, CredError> {
        let (inner, late_inner, owned) = (Arc::clone(&self.inner), Arc::clone(&self.inner), lease_copy(lease));
        run_bounded(
            self.timeout,
            move || inner.refresh(&owned),
            move |late: Result<Minted, CredError>| {
                if let Ok(minted) = late {
                    revoke_orphan(late_inner.as_ref(), "late-refresh", &minted);
                }
            },
        )
        .unwrap_or_else(|| {
            Err(CredError::Mint(format!(
                "credential refresh did not finish within {:?}",
                self.timeout
            )))
        })
    }
}

/// The hand-off between a bounded call's caller and its worker thread.
enum Slot<T> {
    Waiting,
    Done(T),
    GaveUp,
}

/// Run `call` on a worker thread and wait at most `timeout` for it. `Some` with the
/// result when it returned in time; `None` when it did not (or no thread could be
/// started), in which case the worker hands its eventual result to `late`. The
/// hand-off is decided under one lock, so a result is either returned or given to
/// `late`, never lost.
fn run_bounded<T: Send + 'static>(
    timeout: Duration,
    call: impl FnOnce() -> T + Send + 'static,
    late: impl FnOnce(T) + Send + 'static,
) -> Option<T> {
    let slot = Arc::new((Mutex::new(Slot::Waiting), Condvar::new()));
    let worker = Arc::clone(&slot);
    let spawned = std::thread::Builder::new()
        .name("sandy-cred-call".to_string())
        .spawn(move || {
            let out = call();
            let (lock, ready) = &*worker;
            let mut state = lock.lock().unwrap_or_else(PoisonError::into_inner);
            if matches!(*state, Slot::GaveUp) {
                drop(state);
                late(out);
            } else {
                *state = Slot::Done(out);
                ready.notify_one();
            }
        });
    if let Err(e) = spawned {
        tracing::warn!(error = %e, "could not start a credential call thread");
        return None;
    }
    let (lock, ready) = &*slot;
    let state = lock.lock().unwrap_or_else(PoisonError::into_inner);
    let (mut state, _) = ready
        .wait_timeout_while(state, timeout, |s| matches!(s, Slot::Waiting))
        .unwrap_or_else(PoisonError::into_inner);
    match std::mem::replace(&mut *state, Slot::GaveUp) {
        Slot::Done(out) => Some(out),
        Slot::Waiting | Slot::GaveUp => None,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        os::unix::fs::PermissionsExt,
        sync::atomic::{AtomicUsize, Ordering},
    };

    use anyhow::Context;

    use super::*;
    use crate::cred::MAX_TTL_SECS;

    /// A scripted provider: each mint/refresh returns the next token in `tokens`
    /// with a `ttl` lifetime, optionally after `delay`; revoke records the handle
    /// and can be made to fail.
    struct Scripted {
        tokens: Vec<&'static str>,
        next: AtomicUsize,
        ttl: Duration,
        delay: Duration,
        fail_revoke: bool,
        revoked: Mutex<Vec<String>>,
        /// A file to read at each revoke, so a test can see what was staged then.
        watch: Mutex<Option<std::path::PathBuf>>,
        staged_at_revoke: Mutex<Vec<String>>,
    }

    impl Scripted {
        fn new(tokens: Vec<&'static str>, ttl: Duration) -> Self {
            Self {
                tokens,
                next: AtomicUsize::new(0),
                ttl,
                delay: Duration::ZERO,
                fail_revoke: false,
                revoked: Mutex::new(Vec::new()),
                watch: Mutex::new(None),
                staged_at_revoke: Mutex::new(Vec::new()),
            }
        }

        fn revoked(&self) -> Vec<String> {
            self.revoked.lock().unwrap_or_else(PoisonError::into_inner).clone()
        }

        fn issue(&self) -> Minted {
            std::thread::sleep(self.delay);
            let i = self.next.fetch_add(1, Ordering::SeqCst);
            let token = self.tokens.get(i).copied().unwrap_or("exhausted");
            Minted::new(
                token.to_string(),
                SystemTime::now() + self.ttl,
                CredentialHandle { id: format!("h{i}") },
            )
        }
    }

    impl CredentialProvider for Scripted {
        fn mint(&self, _scope: &Scope, _ttl: Duration) -> Result<Minted, CredError> {
            Ok(self.issue())
        }

        fn revoke(&self, lease: &Lease) -> Result<(), CredError> {
            self.revoked
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(lease.handle.id.clone());
            if let Some(path) = self.watch.lock().unwrap_or_else(PoisonError::into_inner).clone() {
                let seen = std::fs::read_to_string(path).unwrap_or_else(|_| "<unreadable>".to_string());
                self.staged_at_revoke
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push(seen);
            }
            if self.fail_revoke {
                return Err(CredError::Revoke("scripted revoke failure".to_string()));
            }
            Ok(())
        }

        fn refresh(&self, _lease: &Lease) -> Result<Minted, CredError> {
            Ok(self.issue())
        }
    }

    fn private_dir() -> anyhow::Result<(tempfile::TempDir, StagingTarget)> {
        let tmp = tempfile::tempdir().context("tempdir")?;
        let dir = tmp.path().join("cred-test");
        std::fs::create_dir(&dir).context("create cred dir")?;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).context("0700")?;
        let (dev, ino) = sandy_fsutil::OwnedDir::open(&dir)?.dev_ino()?;
        let target = StagingTarget {
            dir,
            fingerprint: DirFingerprint { dev, ino },
            secret_name: "GITHUB_TOKEN".to_string(),
            remove_dir_on_revoke: true,
        };
        Ok((tmp, target))
    }

    /// Acceptance 4 (#481): with a short TTL, a renew before expiry stages the new
    /// token over the same file FIRST and only then revokes the superseded one.
    #[test]
    fn a_renew_before_expiry_restages_the_new_token_then_revokes_the_old() -> anyhow::Result<()> {
        let (_tmp, target) = private_dir()?;
        let provider = Arc::new(Scripted::new(vec!["tok-one", "tok-two"], Duration::from_secs(2)));
        let bracket = CredentialBracket::mint_and_stage(
            provider.clone(),
            &Scope::default(),
            target,
            MAX_TTL_SECS,
            Duration::from_secs(5),
        )?;
        let SecretSource::File(path) = bracket.secret_ref().source else {
            anyhow::bail!("a bracket's secret must be file-sourced");
        };
        assert_eq!(std::fs::read_to_string(&path)?, "tok-one");

        *provider.watch.lock().unwrap_or_else(PoisonError::into_inner) = Some(path.clone());
        // Not yet due: 2s remain and the margin is 100ms.
        assert!(!bracket.renew_if_due(SystemTime::now(), Duration::from_millis(100))?);
        // Due: the margin covers the remaining lifetime.
        assert!(bracket.renew_if_due(SystemTime::now(), Duration::from_secs(10))?);

        assert_eq!(
            std::fs::read_to_string(&path)?,
            "tok-two",
            "the staged file holds the new token"
        );
        assert_eq!(provider.revoked(), vec!["h0"], "only the superseded token is revoked");
        assert_eq!(bracket.handle().map(|h| h.id), Some("h1".to_string()));
        assert_eq!(
            *provider.staged_at_revoke.lock().unwrap_or_else(PoisonError::into_inner),
            vec!["tok-two"],
            "the new token is already staged when the superseded one is revoked"
        );
        bracket.revoke()?;
        Ok(())
    }

    /// Revoke removes the file and the dir, and a second revoke makes no provider call.
    #[test]
    fn revoke_removes_the_staged_file_and_is_idempotent() -> anyhow::Result<()> {
        let (_tmp, target) = private_dir()?;
        let dir = target.dir.clone();
        let provider = Arc::new(Scripted::new(vec!["tok"], Duration::from_secs(600)));
        let bracket = CredentialBracket::mint_and_stage(
            provider.clone(),
            &Scope::default(),
            target,
            600,
            Duration::from_secs(5),
        )?;
        bracket.revoke()?;
        bracket.revoke()?;
        assert_eq!(provider.revoked(), vec!["h0"]);
        assert!(!dir.exists(), "the staged file and its dir are removed");
        assert!(bracket.handle().is_none());
        Ok(())
    }

    /// A revoke failure comes back typed, and the staged file is still removed.
    #[test]
    fn a_revoke_failure_is_returned_and_the_file_is_still_removed() -> anyhow::Result<()> {
        let (_tmp, target) = private_dir()?;
        let path = target.dir.join("GITHUB_TOKEN");
        let mut scripted = Scripted::new(vec!["tok"], Duration::from_secs(600));
        scripted.fail_revoke = true;
        let bracket = CredentialBracket::mint_and_stage(
            Arc::new(scripted),
            &Scope::default(),
            target,
            600,
            Duration::from_secs(5),
        )?;
        let err = bracket.revoke().expect_err("the scripted revoke fails");
        assert!(matches!(err, CredError::Revoke(_)), "{err:?}");
        assert!(!path.exists(), "the staged file is removed even when the revoke fails");
        Ok(())
    }

    /// A mint that hangs past the call bound is a failure and stages nothing; when
    /// it finally returns, its token is revoked.
    #[test]
    fn a_hung_mint_fails_closed_and_its_late_token_is_revoked() -> anyhow::Result<()> {
        let (_tmp, target) = private_dir()?;
        let path = target.dir.join("GITHUB_TOKEN");
        let mut scripted = Scripted::new(vec!["tok"], Duration::from_secs(600));
        scripted.delay = Duration::from_millis(300);
        let provider = Arc::new(scripted);
        let err = CredentialBracket::mint_and_stage(
            provider.clone(),
            &Scope::default(),
            target,
            600,
            Duration::from_millis(50),
        )
        .expect_err("the mint outlives the bound");
        assert!(matches!(err, CredError::Mint(_)), "{err:?}");
        assert!(!path.exists(), "nothing is staged for a timed-out mint");
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while provider.revoked().is_empty() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(provider.revoked(), vec!["h0"], "the late token is revoked");
        Ok(())
    }

    /// Dropping an unrevoked bracket revokes it and removes the file.
    #[test]
    fn dropping_an_unrevoked_bracket_revokes_it() -> anyhow::Result<()> {
        let (_tmp, target) = private_dir()?;
        let path = target.dir.join("GITHUB_TOKEN");
        let provider = Arc::new(Scripted::new(vec!["tok"], Duration::from_secs(600)));
        let bracket = CredentialBracket::mint_and_stage(
            provider.clone(),
            &Scope::default(),
            target,
            600,
            Duration::from_secs(5),
        )?;
        drop(bracket);
        assert_eq!(provider.revoked(), vec!["h0"]);
        assert!(!path.exists());
        Ok(())
    }

    /// `Debug` names the handle and path, never the token.
    #[test]
    fn debug_output_never_carries_the_token() -> anyhow::Result<()> {
        let (_tmp, target) = private_dir()?;
        let provider = Arc::new(Scripted::new(vec!["ghs_secret_481"], Duration::from_secs(600)));
        let bracket =
            CredentialBracket::mint_and_stage(provider, &Scope::default(), target, 600, Duration::from_secs(5))?;
        let shown = format!("{bracket:?}");
        assert!(!shown.contains("ghs_secret_481"), "{shown}");
        bracket.revoke()?;
        Ok(())
    }

    /// Redaction replaces every occurrence and ignores the staged file's trailing
    /// newline. A missing or empty staged file yields `None`: fail closed.
    #[test]
    fn redact_replaces_every_occurrence_and_fails_closed_without_a_token() -> anyhow::Result<()> {
        let (_tmp, target) = private_dir()?;
        let provider = Arc::new(Scripted::new(vec!["tok-secret"], Duration::from_secs(600)));
        let bracket =
            CredentialBracket::mint_and_stage(provider, &Scope::default(), target, 600, Duration::from_secs(5))?;
        let path = bracket.token_path.clone();
        let redactor = bracket.redactor();
        std::fs::write(&path, "tok-secret\n")?;
        assert_eq!(
            redactor.redact_bytes(b"a tok-secret b tok-secret".to_vec()),
            Some(b"a [redacted] b [redacted]".to_vec())
        );
        assert_eq!(
            redactor.redact_bytes(b"nothing here".to_vec()),
            Some(b"nothing here".to_vec())
        );
        assert_eq!(
            redactor.redact_bytes(b"\xff tok-secret \xfe".to_vec()),
            Some(b"\xff [redacted] \xfe".to_vec())
        );
        std::fs::write(&path, "")?;
        assert_eq!(redactor.redact_bytes(b"tok-secret".to_vec()), None, "an empty token");
        std::fs::remove_file(&path)?;
        assert_eq!(redactor.redact_bytes(b"tok-secret".to_vec()), None, "a missing file");
        Ok(())
    }

    /// A staged file swapped for a FIFO, a symlink or an oversized file fails
    /// closed, and the FIFO case does not block.
    #[test]
    fn redact_fails_closed_on_a_fifo_a_symlink_or_an_oversized_token() -> anyhow::Result<()> {
        let (_tmp, target) = private_dir()?;
        let provider = Arc::new(Scripted::new(vec!["tok-secret"], Duration::from_secs(600)));
        let bracket =
            CredentialBracket::mint_and_stage(provider, &Scope::default(), target, 600, Duration::from_secs(5))?;
        let path = bracket.token_path.clone();
        let redactor = bracket.redactor();

        std::fs::remove_file(&path)?;
        let status = std::process::Command::new("mkfifo").arg(&path).status()?;
        anyhow::ensure!(status.success(), "mkfifo exited {status}");
        let (tx, rx) = std::sync::mpsc::channel();
        let fifo_redactor = redactor.clone();
        std::thread::spawn(move || {
            let _ = tx.send(fifo_redactor.redact_bytes(b"tok-secret".to_vec()));
        });
        let outcome = rx
            .recv_timeout(Duration::from_secs(5))
            .context("redaction blocked on a FIFO")?;
        assert_eq!(outcome, None, "a FIFO fails closed");
        std::fs::remove_file(&path)?;

        let elsewhere = path.with_extension("real");
        std::fs::write(&elsewhere, "tok-secret")?;
        std::os::unix::fs::symlink(&elsewhere, &path)?;
        assert_eq!(
            redactor.redact_bytes(b"tok-secret".to_vec()),
            None,
            "a symlink fails closed"
        );
        std::fs::remove_file(&path)?;
        std::fs::remove_file(&elsewhere)?;

        std::fs::write(&path, vec![b'a'; usize::try_from(MAX_TOKEN_BYTES)? + 1])?;
        assert_eq!(
            redactor.redact_bytes(b"aaaa".to_vec()),
            None,
            "an oversized token fails closed"
        );
        Ok(())
    }

    /// #720: a removal that fails after a successful revoke is retried by the next
    /// `revoke()`, without a second provider call.
    #[test]
    fn a_failed_file_removal_is_retried_by_the_next_revoke() -> anyhow::Result<()> {
        let (_tmp, target) = private_dir()?;
        let dir = target.dir.clone();
        let path = dir.join("GITHUB_TOKEN");
        let provider = Arc::new(Scripted::new(vec!["tok"], Duration::from_secs(600)));
        let bracket = CredentialBracket::mint_and_stage(
            provider.clone(),
            &Scope::default(),
            target,
            600,
            Duration::from_secs(5),
        )?;
        // A dir without write permission makes the unlink fail.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500)).context("0500")?;
        let err = bracket.revoke().expect_err("the unlink is refused");
        assert!(matches!(err, CredError::Stage(_)), "{err:?}");
        assert!(path.exists(), "the file is still staged after the failed removal");

        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).context("0700")?;
        bracket.revoke().context("the retry removes the file")?;
        assert!(!path.exists(), "the retry removed the staged file");
        assert_eq!(
            provider.revoked(),
            vec!["h0"],
            "the retry makes no second provider call"
        );
        Ok(())
    }

    /// #720: cleanup is bound to the directory the token was staged in. A `cred-*`
    /// dir renamed away and replaced at the same path loses nothing from the
    /// replacement, and the original's token is still removed.
    #[test]
    fn cleanup_follows_the_staged_dir_not_the_path_swapped_in_after() -> anyhow::Result<()> {
        let (tmp, target) = private_dir()?;
        let dir = target.dir.clone();
        let provider = Arc::new(Scripted::new(vec!["tok"], Duration::from_secs(600)));
        let bracket =
            CredentialBracket::mint_and_stage(provider, &Scope::default(), target, 600, Duration::from_secs(5))?;
        let moved = tmp.path().join("cred-moved");
        std::fs::rename(&dir, &moved).context("move the staged dir aside")?;
        std::fs::create_dir(&dir).context("substitute")?;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
        std::fs::write(dir.join("GITHUB_TOKEN"), "not-ours")?;

        bracket.revoke()?;
        assert_eq!(
            std::fs::read_to_string(dir.join("GITHUB_TOKEN"))?,
            "not-ours",
            "the replacement's file is untouched"
        );
        assert!(
            !moved.join("GITHUB_TOKEN").exists(),
            "the staged token is removed through the dir it was written to"
        );
        Ok(())
    }

    /// Delegates to a [`Scripted`] and records whether a tokio runtime was current
    /// when the provider was dropped (a live adapter owns a runtime, which must not
    /// be dropped inside another one).
    struct DropProbe {
        inner: Scripted,
        dropped_inside_runtime: Arc<std::sync::Mutex<Option<bool>>>,
    }

    impl CredentialProvider for DropProbe {
        fn mint(&self, scope: &Scope, ttl: Duration) -> Result<Minted, CredError> {
            self.inner.mint(scope, ttl)
        }

        fn revoke(&self, lease: &Lease) -> Result<(), CredError> {
            self.inner.revoke(lease)
        }

        fn refresh(&self, lease: &Lease) -> Result<Minted, CredError> {
            self.inner.refresh(lease)
        }
    }

    impl Drop for DropProbe {
        fn drop(&mut self) {
            *self
                .dropped_inside_runtime
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = Some(tokio::runtime::Handle::try_current().is_ok());
        }
    }

    /// #720 review: a bracket revoked by hand and then dropped inside a runtime
    /// still drops its provider off the runtime's worker.
    #[test]
    fn a_revoked_bracket_dropped_in_a_runtime_drops_its_provider_off_the_runtime() -> anyhow::Result<()> {
        let (_tmp, target) = private_dir()?;
        let seen = Arc::new(std::sync::Mutex::new(None));
        let probe = Arc::new(DropProbe {
            inner: Scripted::new(vec!["tok"], Duration::from_secs(600)),
            dropped_inside_runtime: Arc::clone(&seen),
        });
        let rt = tokio::runtime::Builder::new_current_thread().build()?;
        rt.block_on(async {
            let bracket =
                CredentialBracket::mint_and_stage(probe, &Scope::default(), target, 600, Duration::from_secs(5))?;
            bracket.revoke()?;
            drop(bracket);
            anyhow::Ok(())
        })?;
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while seen.lock().unwrap_or_else(PoisonError::into_inner).is_none() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(
            *seen.lock().unwrap_or_else(PoisonError::into_inner),
            Some(false),
            "the provider drops on a plain thread, never inside the runtime"
        );
        Ok(())
    }

    /// #720 review: a dir swapped in after the caller's check is refused before any
    /// mint, so no token is ever issued for it.
    #[test]
    fn a_dir_swapped_before_the_mint_is_refused_with_no_mint_call() -> anyhow::Result<()> {
        let (tmp, target) = private_dir()?;
        let dir = target.dir.clone();
        std::fs::rename(&dir, tmp.path().join("cred-moved")).context("move aside")?;
        std::fs::create_dir(&dir)?;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
        let provider = Arc::new(Scripted::new(vec!["tok"], Duration::from_secs(600)));
        let err =
            CredentialBracket::mint_and_stage(provider.clone(), &Scope::default(), target, 600, Duration::from_secs(5))
                .expect_err("a swapped dir is refused");
        assert!(matches!(err, CredError::Stage(_)), "{err:?}");
        assert_eq!(provider.next.load(Ordering::SeqCst), 0, "no mint call was made");
        Ok(())
    }
}
