//! Mid-run credential refresh: the teardown guard, the poll loop that keeps a
//! long-running job's forge token alive, and the timing helpers that bound it.
//! Consumed by [`super::run_job_with_credential_timed`].

use std::{
    path::PathBuf,
    sync::{Mutex, PoisonError, mpsc},
    time::{Duration, SystemTime},
};

use sandy::{
    CALL_DEADLINE, CredentialProvider, DirFingerprint, Lease, MAX_TTL_SECS, Scope, SecretSource, refresh_once_checked,
};
use zeroize::Zeroizing;

/// Revokes the live credential and removes its staged `0600` file, exactly once
/// ([`CredTeardown::teardown`]): explicitly, right after [`super::run_job_with_credential`]
/// gets its result, or — if a panic unwinds out of `run_job` first — via `Drop`
/// instead, skipping the explicit call. Either way the credential never outlives
/// the run (INV-1); the explicit path additionally gets a warning string back to
/// fold into the envelope (L-12), which `Drop` has nowhere to return it to.
pub(super) struct CredTeardown<'a, P: CredentialProvider + ?Sized> {
    pub(super) provider: &'a P,
    /// The live lease; the refresh thread advances it to the latest minted token,
    /// so teardown revokes whatever token is current when the run ends.
    pub(super) lease: Mutex<Lease>,
    pub(super) token_path: PathBuf,
    /// The raw secret, read back once after staging, purely for this run's
    /// console redaction (M-6): `run_job` is handed a clone of it (as `redact`)
    /// before this guard is built. Held here only so it zeroizes alongside the
    /// lease revoke, never read back out — the `Lease` it sits beside still
    /// never carries it.
    /// Borrowed by `redact` for the run's duration and zeroized on drop (M-6).
    pub(super) secret: Zeroizing<String>,
    /// The credential's declared name (e.g. `"GH_TOKEN"`), naming it in a
    /// revoke-failure warning without naming the token value (L-12).
    pub(super) secret_name: String,
    /// The credential's scope, logged alongside a revoke failure (L-12).
    pub(super) scope: Scope,
    /// The job id, filled in once `run_job` returns it; empty if teardown runs
    /// from `Drop` during a panic, before the job id is known.
    pub(super) job_id: String,
    /// Set once [`CredTeardown::teardown`] has run, so a later call — including
    /// the implicit one from `Drop` after an explicit call already handled it —
    /// is a no-op.
    pub(super) done: bool,
    /// When [`CredTeardown::teardown`] actually ran, for the receipt's
    /// `credential.revoked_at` (#361). `None` only before `teardown` has run.
    pub(super) revoked_at: Option<SystemTime>,
    /// Whether that revoke call succeeded, for `credential.revoke_succeeded`
    /// (#361). `None` only before `teardown` has run.
    pub(super) revoke_succeeded: Option<bool>,
}

impl<P: CredentialProvider + ?Sized> CredTeardown<'_, P> {
    /// Revoke the live credential and remove its staged file. A revoke failure is
    /// never fatal to the run; it is logged (job id, scope, TTL remaining — never
    /// the token value, L-12) and returned as a warning string naming the
    /// credential, for the caller to fold into the envelope.
    pub(super) fn teardown(&mut self) -> Option<String> {
        if self.done {
            return None;
        }
        self.done = true;
        // The refresh thread has joined (the scope borrowing `lease` ended before
        // this runs), so the lock is uncontended; map poison rather than panic
        // here. Revoke before removing the file (the GitHub revoke path reads it).
        let lease = self.lease.get_mut().unwrap_or_else(PoisonError::into_inner);
        let ttl_remaining = lease
            .expires_at
            .duration_since(SystemTime::now())
            .unwrap_or(Duration::ZERO);
        self.revoked_at = Some(SystemTime::now());
        let revoke_result = self.provider.revoke(lease);
        self.revoke_succeeded = Some(revoke_result.is_ok());
        let warning = revoke_result.err().map(|e| {
            tracing::warn!(
                job_id = %self.job_id,
                scope = ?self.scope,
                ttl_remaining_secs = ttl_remaining.as_secs(),
                %e,
                "credential revoke at teardown failed; relying on native expiry"
            );
            format!(
                "credential \"{}\" revoke failed at teardown; relying on native expiry",
                self.secret_name
            )
        });
        if let Err(e) = std::fs::remove_file(&self.token_path) {
            tracing::warn!(path = %self.token_path.display(), %e, "failed to remove staged credential on teardown");
        }
        warning
    }
}

impl<P: CredentialProvider + ?Sized> Drop for CredTeardown<'_, P> {
    fn drop(&mut self) {
        self.teardown();
    }
}

/// Default margin before token expiry at which a mid-run refresh fires (5 min): it
/// must exceed one refresh's latency so the token never lapses between polls.
pub const DEFAULT_REFRESH_MARGIN_SECS: u64 = 300;
/// Default interval between refresh checks while a credentialed job runs (60s).
pub const DEFAULT_REFRESH_TICK_SECS: u64 = 60;
// #195: `safe_heartbeat_tick`'s fallback relies on this default staying well
// below `MAX_TTL_SECS - CALL_DEADLINE` (the real sweep margin, not
// `MAX_TTL_SECS` alone); enforced at compile time so a future bump of any of
// the three constants can't silently reopen the gap the heartbeat exists to
// close.
const _: () = assert!(DEFAULT_REFRESH_TICK_SECS < MAX_TTL_SECS as u64 - CALL_DEADLINE.as_secs());

/// Read a refresh interval (seconds) from `env_key`, falling back to `default`. The
/// tick is floored at 1s so a misconfigured `0` can't spin the poll loop.
pub(super) fn refresh_interval(env_key: &str, default: u64) -> Duration {
    let secs = std::env::var(env_key)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(default)
        .max(1);
    Duration::from_secs(secs)
}

/// Bump `dir`'s mtime to now: proves to [`super::gc`]'s mtime-based stale-dir sweep
/// (#195) that a credential staging dir is still in active use.
fn touch_dir_mtime(dir: &std::path::Path) -> std::io::Result<()> {
    std::fs::File::open(dir)?.set_modified(SystemTime::now())
}

/// Clamp `tick` so the mid-run heartbeat can never tick slower than [`super::gc`]'s
/// stale-dir sweep threshold (#195), with margin left for one stalled
/// adapter call: a `SANDY_REFRESH_TICK_SECS` at or above
/// `max_ttl_secs - call_deadline` would let a live job's cred dir go stale
/// between heartbeats and get swept out from under it (the gap between two
/// heartbeats is the tick plus however long the adapter call in between can
/// stall, up to `call_deadline`), so a tick that reaches that margin is
/// never honored: it falls back to [`DEFAULT_REFRESH_TICK_SECS`], which is
/// safe by construction (well below any reasonable `MAX_TTL_SECS`). Capping
/// against `max_ttl_secs` alone, without `call_deadline`, left a gap: a tick
/// configured near that uncapped ceiling plus one stalled call could still
/// exceed the sweep threshold (decision 6).
pub(super) fn safe_heartbeat_tick(tick: Duration, max_ttl_secs: u32, call_deadline: Duration) -> Duration {
    let threshold = u64::from(max_ttl_secs).saturating_sub(call_deadline.as_secs());
    if tick.as_secs() >= threshold {
        tracing::warn!(
            configured_secs = tick.as_secs(),
            max_ttl_secs,
            call_deadline_secs = call_deadline.as_secs(),
            "SANDY_REFRESH_TICK_SECS reaches MAX_TTL_SECS minus the adapter call deadline; falling back to the \
             default tick so gc's stale-dir sweep can never outrun the heartbeat plus one stalled call"
        );
        Duration::from_secs(DEFAULT_REFRESH_TICK_SECS)
    } else {
        tick
    }
}

/// Poll `lease` every `tick` and refresh it when within `margin` of expiry, until
/// the sender half of `stop` is dropped (the run finished). Each refresh re-stages
/// the live token file and revokes the superseded token via [`refresh_once_checked`];
/// a refresh error is logged and retried on the next tick, never fatal to the run.
/// `cred_dir_fingerprint` is the `(dev, ino)` the caller validated `cred_dir` under
/// before this loop started (#323): the re-stage is refused, not silently retried
/// into a substitute, if a same-uid, same-mode directory was swapped in at that
/// path since.
///
/// A successful refresh's new token is read back and queued onto `redact_log`
/// (M-6 follow-up): `run_job`'s own redaction pass only ever saw the token staged
/// before it started, so a refreshed token needs its own entry for the
/// post-run re-redaction pass in [`super::run_job_with_credential`] to catch it too.
///
/// Every tick also heartbeats the cred dir's mtime (#195), regardless of
/// whether a refresh actually fires: [`super::gc`] sweeps a `cred-*` staging dir whose
/// mtime is older than `MAX_TTL_SECS` to reclaim one a crash or SIGKILL left
/// behind, but a provider's native token TTL can exceed `MAX_TTL_SECS`, so a
/// genuinely running job can otherwise go longer than that between refreshes.
/// A `kill -9`'d process stops ticking, so an actually abandoned dir still
/// ages out.
#[allow(
    clippy::too_many_arguments,
    reason = "the loop threads the shared lease, both logs it feeds, and the caller's fingerprint check"
)]
pub(super) fn refresh_loop<P: CredentialProvider + Sync + ?Sized>(
    provider: &P,
    lease: &Mutex<Lease>,
    margin: Duration,
    tick: Duration,
    stop: &mpsc::Receiver<()>,
    redact_log: &Mutex<Vec<Zeroizing<String>>>,
    refresh_times_log: &Mutex<Vec<SystemTime>>,
    cred_dir_fingerprint: DirFingerprint,
) {
    loop {
        match stop.recv_timeout(tick) {
            // Sender dropped (run finished) or an explicit stop: leave.
            Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
        let mut guard = lease.lock().unwrap_or_else(PoisonError::into_inner);
        if let SecretSource::File(path) = &guard.secret_ref.source
            && let Some(dir) = path.parent()
            && let Err(e) = touch_dir_mtime(dir)
        {
            tracing::warn!(%e, dir = %dir.display(), "could not heartbeat the credential staging dir's mtime");
        }
        match refresh_once_checked(provider, &mut guard, SystemTime::now(), margin, cred_dir_fingerprint) {
            Ok(true) => {
                // For the receipt (#361): record when this refresh happened,
                // regardless of whether the token can also be read back below.
                refresh_times_log
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push(SystemTime::now());
                if let SecretSource::File(path) = &guard.secret_ref.source {
                    match std::fs::read_to_string(path) {
                        Ok(new_token) => redact_log
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .push(Zeroizing::new(new_token)),
                        Err(e) => {
                            tracing::warn!(%e, "could not read back a refreshed token for console redaction");
                        }
                    }
                }
            }
            Ok(false) => {}
            Err(e) => tracing::warn!(%e, "mid-run credential refresh failed; keeping the current token"),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{Mutex, mpsc},
        time::{Duration, SystemTime},
    };

    use anyhow::Context;
    use sandy::{DirFingerprint, MAX_TTL_SECS, Scope, mint_lease};
    use sandy_test_support::FakeProvider;
    use zeroize::Zeroizing;

    use super::{refresh_loop, safe_heartbeat_tick};

    /// A tick safely below `MAX_TTL_SECS - call_deadline` passes through
    /// unchanged.
    #[test]
    fn safe_heartbeat_tick_passes_through_a_safe_tick() {
        let tick = safe_heartbeat_tick(Duration::from_secs(60), 3000, Duration::from_secs(1500));
        assert_eq!(tick, Duration::from_secs(60));
    }

    /// #195: a tick that reaches `MAX_TTL_SECS` would let a
    /// live job's cred dir go stale between heartbeats and get swept out from
    /// under it, so it must never be honored as-is.
    #[test]
    fn safe_heartbeat_tick_falls_back_when_the_tick_reaches_max_ttl_secs() {
        let tick = safe_heartbeat_tick(Duration::from_secs(3000), 3000, Duration::from_secs(1500));
        assert_eq!(tick, Duration::from_secs(super::DEFAULT_REFRESH_TICK_SECS));
    }

    /// As above, for a tick that exceeds (not just reaches) the threshold.
    #[test]
    fn safe_heartbeat_tick_falls_back_when_the_tick_exceeds_max_ttl_secs() {
        let tick = safe_heartbeat_tick(Duration::from_secs(3_600_000), 3000, Duration::from_secs(1500));
        assert_eq!(tick, Duration::from_secs(super::DEFAULT_REFRESH_TICK_SECS));
    }

    /// #195 follow-up (CodeRabbit, PR #352): before this fix, `safe_heartbeat_tick`
    /// only capped against `max_ttl_secs`, so a tick at `max_ttl_secs -
    /// call_deadline` (the real margin: the heartbeat gap is the tick plus up
    /// to one stalled adapter call) was wrongly accepted, leaving no margin
    /// for that stalled call. Must now fall back.
    #[test]
    fn safe_heartbeat_tick_falls_back_at_max_ttl_secs_minus_call_deadline() {
        let tick = safe_heartbeat_tick(Duration::from_secs(1500), 3000, Duration::from_secs(1500));
        assert_eq!(
            tick,
            Duration::from_secs(super::DEFAULT_REFRESH_TICK_SECS),
            "a tick at max_ttl_secs - call_deadline leaves no margin for a stalled call and must fall back"
        );
    }

    /// As above, the boundary just below the real margin: still safe, passes
    /// through unchanged.
    #[test]
    fn safe_heartbeat_tick_passes_through_just_below_max_ttl_secs_minus_call_deadline() {
        let tick = safe_heartbeat_tick(Duration::from_secs(1499), 3000, Duration::from_secs(1500));
        assert_eq!(tick, Duration::from_secs(1499));
    }

    /// Back-date `dir`'s mtime by `age` so gc's sweep sees it as that old.
    fn set_mtime_age(dir: &std::path::Path, age: Duration) -> anyhow::Result<()> {
        let past = SystemTime::now() - age;
        std::fs::File::open(dir)
            .context("open dir to back-date mtime")?
            .set_modified(past)
            .context("set_modified")?;
        Ok(())
    }

    /// `refresh_loop` refreshes the credential on each tick while the job runs and
    /// stops promptly when the sender is dropped. A margin past the token TTL makes
    /// `should_refresh` fire every tick, so a superseded token is revoked each time.
    /// Also covers the M-6 follow-up: each refresh's new token must land in
    /// `redact_log` so a post-run re-redaction pass can catch it.
    #[test]
    fn refresh_loop_refreshes_until_the_sender_drops() -> anyhow::Result<()> {
        let tmp = tempfile::tempdir().context("tmp")?;
        std::fs::set_permissions(tmp.path(), std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .context("tmp 0700")?;
        let provider = FakeProvider::returning("tok");
        let lease = mint_lease(&provider, &Scope::default(), 1_800, "GITHUB_TOKEN", tmp.path())
            .map_err(|e| anyhow::anyhow!("{e}"))
            .context("mint")?;
        let (dev, ino) = sandy_fsutil::OwnedDir::open(tmp.path())?.dev_ino()?;
        let fingerprint = DirFingerprint { dev, ino };
        let lease = Mutex::new(lease);
        let (tx, rx) = mpsc::channel::<()>();
        let margin = Duration::from_secs(1_000_000);
        let tick = Duration::from_millis(5);
        let redact_log: Mutex<Vec<Zeroizing<String>>> = Mutex::new(Vec::new());
        let refresh_times_log: Mutex<Vec<SystemTime>> = Mutex::new(Vec::new());

        std::thread::scope(|s| {
            let pref = &provider;
            let shared = &lease;
            let shared_log = &redact_log;
            let shared_times = &refresh_times_log;
            s.spawn(move || refresh_loop(pref, shared, margin, tick, &rx, shared_log, shared_times, fingerprint));
            std::thread::sleep(Duration::from_millis(50));
            drop(tx);
        });

        assert!(
            !provider.revoked().is_empty(),
            "refresh_loop must refresh and revoke a superseded token while the job runs"
        );
        assert!(
            !redact_log.into_inner().unwrap().is_empty(),
            "a refreshed token must be queued for post-run console redaction"
        );
        assert!(
            !refresh_times_log.into_inner().unwrap().is_empty(),
            "a refresh's timestamp must be queued for the credential receipt (#361)"
        );
        Ok(())
    }

    /// #195: `refresh_loop` must heartbeat the cred dir's mtime every tick even
    /// when no refresh actually fires (the margin is far smaller than the
    /// lease's TTL, so `should_refresh` never trips here: proven by asserting
    /// nothing was revoked). Without the heartbeat, a long-running job whose
    /// provider TTL outlasts `gc`'s `MAX_TTL_SECS` sweep window would have its
    /// live credential dir deleted out from under it.
    #[test]
    fn refresh_loop_heartbeats_the_cred_dir_mtime_every_tick() -> anyhow::Result<()> {
        let tmp = tempfile::tempdir().context("tmp")?;
        std::fs::set_permissions(tmp.path(), std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .context("tmp 0700")?;
        let provider = FakeProvider::returning("tok");
        let lease = mint_lease(&provider, &Scope::default(), 1_800, "GITHUB_TOKEN", tmp.path())
            .map_err(|e| anyhow::anyhow!("{e}"))
            .context("mint")?;
        // Back-date the dir well past gc's MAX_TTL_SECS window before the loop
        // starts ticking, so a surviving fresh mtime can only be the heartbeat.
        set_mtime_age(tmp.path(), Duration::from_secs(u64::from(MAX_TTL_SECS) + 600))?;
        let (dev, ino) = sandy_fsutil::OwnedDir::open(tmp.path())?.dev_ino()?;
        let fingerprint = DirFingerprint { dev, ino };
        let lease = Mutex::new(lease);
        let (tx, rx) = mpsc::channel::<()>();
        // Far smaller than the lease's 1_800s TTL, so `should_refresh` never
        // trips in this short test: isolates the heartbeat from the
        // already-covered refresh-rewrite path.
        let margin = Duration::from_secs(1);
        let tick = Duration::from_millis(5);
        let redact_log: Mutex<Vec<Zeroizing<String>>> = Mutex::new(Vec::new());
        let refresh_times_log: Mutex<Vec<SystemTime>> = Mutex::new(Vec::new());

        std::thread::scope(|s| {
            let pref = &provider;
            let shared = &lease;
            let shared_log = &redact_log;
            let shared_times = &refresh_times_log;
            s.spawn(move || refresh_loop(pref, shared, margin, tick, &rx, shared_log, shared_times, fingerprint));
            std::thread::sleep(Duration::from_millis(50));
            drop(tx);
        });

        assert!(
            provider.revoked().is_empty(),
            "no refresh may fire in this test; the fresh mtime below must come from the heartbeat alone"
        );
        let age = SystemTime::now().duration_since(std::fs::metadata(tmp.path())?.modified()?)?;
        assert!(
            age < Duration::from_secs(5),
            "the cred dir's mtime must be heartbeated while the loop ticks: age={age:?}"
        );
        Ok(())
    }
}
