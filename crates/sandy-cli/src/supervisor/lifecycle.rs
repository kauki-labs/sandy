//! `gc`'s implementation: evict terminal job records under the keep-last-N +
//! referenced policy, then sweep stale credential staging dirs (#195).

use std::{collections::HashSet, path::Path, time::Duration};

use sandy::{CoreError, JobState, Journal, MAX_TTL_SECS, StagedImage, plan_eviction};

use super::GcReport;

/// [`super::gc`]'s implementation against an already-resolved `staging_base`: evict
/// terminal records, then sweep stale staging dirs under it. [`super::gc`] calls this
/// with the real sandy-owned staging base; tests call it with an injected temp
/// dir instead.
pub(super) fn gc_against(journal: &Journal, keep_last_n: usize, staging_base: &Path) -> Result<GcReport, CoreError> {
    let evicted = gc_records(journal, keep_last_n)?;
    Ok(GcReport {
        evicted,
        swept_staging_dirs: sweep_stale_cred_dirs(staging_base),
    })
}

/// Evict terminal job records under the keep-last-N + referenced policy, the
/// policy half of [`super::gc`]. Split out so it runs, and can be tested,
/// independently of the staging-dir sweep.
pub(super) fn gc_records(journal: &Journal, keep_last_n: usize) -> Result<Vec<String>, CoreError> {
    let records = journal.list()?;

    // Running jobs are referenced and never evicted; every terminal record maps
    // to a StagedImage keyed by job id and ordered by its start time.
    let mut referenced = HashSet::new();
    let mut images = Vec::new();
    for record in &records {
        if record.state == JobState::Running {
            referenced.insert(record.job_id.clone());
        } else {
            images.push(StagedImage {
                id: record.job_id.clone(),
                staged_at: record.started,
            });
        }
    }

    let evicted = plan_eviction(&images, keep_last_n, &referenced);
    for id in &evicted {
        let path = journal.record_path(id);
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            // Already gone: nothing to evict, keep going.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(evicted)
}

/// Sweep stale `cred-*`/`verify-*` dirs under `staging_base` (#195),
/// best-effort: a listing or removal failure is logged and treated as "none
/// swept" rather than propagated, consistent with [`super::gc`]'s contract that the
/// sweep never fails the call.
fn sweep_stale_cred_dirs(staging_base: &Path) -> Vec<String> {
    match sandy_fsutil::sweep_stale_staging_dirs(
        staging_base,
        sandy_fsutil::STALE_STAGING_PREFIXES,
        Duration::from_secs(u64::from(MAX_TTL_SECS)),
    ) {
        Ok(swept) => swept,
        Err(e) => {
            tracing::warn!(%e, "gc: could not sweep stale credential staging dirs");
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use anyhow::Context;
    use sandy::Journal;

    use super::gc_against;

    /// A journal on a fresh local temp `$SANDY_HOME`.
    fn fresh_journal() -> anyhow::Result<(tempfile::TempDir, Journal)> {
        let tmp = tempfile::tempdir().context("creating a temp SANDY_HOME")?;
        let journal = Journal::new(tmp.path());
        journal.ensure_dirs().context("ensure_dirs")?;
        Ok((tmp, journal))
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

    // --- gc sweeps stale credential staging dirs (#195) -------------------------

    /// #195: a `cred-*` dir left behind past `MAX_TTL_SECS` (SIGKILL or a
    /// crash skipped the owner's drop guard) must be swept by `gc`.
    #[test]
    fn gc_sweeps_a_stale_cred_dir_past_max_ttl() -> anyhow::Result<()> {
        use sandy::MAX_TTL_SECS;

        let (_tmp, journal) = fresh_journal()?;
        let staging_parent = tempfile::tempdir().context("staging parent")?;
        let staging_base =
            sandy_fsutil::ensure_staging_base_in(staging_parent.path()).context("ensure staging base")?;
        let stale = staging_base.join("cred-deadbeef");
        std::fs::create_dir(&stale).context("create stale cred dir")?;
        set_mtime_age(&stale, Duration::from_secs(u64::from(MAX_TTL_SECS) + 60))?;

        let report = gc_against(&journal, 20, &staging_base).context("gc")?;

        assert!(
            report.swept_staging_dirs.contains(&"cred-deadbeef".to_string()),
            "a stale cred dir past MAX_TTL_SECS must be swept: {:?}",
            report.swept_staging_dirs
        );
        assert!(
            report.evicted.is_empty(),
            "a swept staging dir must never appear in the evicted job-id list: {:?}",
            report.evicted
        );
        assert!(!stale.exists(), "the stale cred dir must be removed");
        Ok(())
    }

    /// #195 (MUST NOT): a `verify-*` dir younger than `MAX_TTL_SECS` is a
    /// live, in-progress stage and must survive `gc`.
    #[test]
    fn gc_keeps_a_fresh_verify_dir() -> anyhow::Result<()> {
        let (_tmp, journal) = fresh_journal()?;
        let staging_parent = tempfile::tempdir().context("staging parent")?;
        let staging_base =
            sandy_fsutil::ensure_staging_base_in(staging_parent.path()).context("ensure staging base")?;
        let fresh = staging_base.join("verify-cafef00d");
        std::fs::create_dir(&fresh).context("create fresh verify dir")?;

        let report = gc_against(&journal, 20, &staging_base).context("gc")?;

        assert!(
            !report.swept_staging_dirs.contains(&"verify-cafef00d".to_string()),
            "a fresh verify dir must not be swept: {:?}",
            report.swept_staging_dirs
        );
        assert!(fresh.exists(), "the fresh verify dir must survive");
        Ok(())
    }
}
