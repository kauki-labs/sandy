//! Tier-2 integration tests (sandbox-runnable): journal / reconcile /
//! collection flows against fixtures on a generic POSIX FS. No hypervisor —
//! the backend is [`FakeBackend`], `$SANDY_HOME` is a `TempDir`.
//!
//! These cover the Block 4 verification and adversarial rows. Every test is
//! currently RED (the exercised functions are `todo!()`); the implementer turns
//! them green.

use std::time::SystemTime;

use anyhow::Context;
use sandy_core::{
    BackendError, BoxState, CollectionConfig, FakeBackend, JobRecord, JobState, Journal, Outcome, OutputSpec,
    RESULT_SCHEMA_VERSION, ResultEnvelope, RunSpec, Status, VmBackend, collect, reconcile_job,
    result::{Logs, OutputRef, Provenance},
};

const CAP: u64 = 1 << 20;

fn running_record(job_id: &str, box_id: &str, pid: u32) -> JobRecord {
    JobRecord {
        schema_version: sandy_core::JOURNAL_SCHEMA_VERSION,
        job_id: job_id.to_string(),
        box_id: Some(box_id.to_string()),
        state: JobState::Running,
        writer_pid: pid,
        started: SystemTime::UNIX_EPOCH,
        result: None,
    }
}

fn succeeded_envelope(job_id: &str) -> ResultEnvelope {
    ResultEnvelope {
        result_schema_version: RESULT_SCHEMA_VERSION,
        job_id: job_id.to_string(),
        box_id: Some("box-1".to_string()),
        status: Status::Succeeded,
        retryable: false,
        message: "ok".to_string(),
        exit_code: Some(0),
        outputs: vec![OutputRef {
            path: "result.txt".to_string(),
        }],
        receipts: vec![],
        provenance: Provenance {
            template_store_path: "/nix/store/xxx".to_string(),
        },
        logs: Logs { tail: String::new() },
    }
}

fn exit_zero() -> Outcome {
    Outcome {
        booted: true,
        guest_exit: Some(0),
        transport_error: None,
        timed_out: false,
    }
}

/// Verification: exit-0 collect — a declared output is collected to `out/`.
#[test]
fn exit_zero_collects_declared_output() -> anyhow::Result<()> {
    let tmp = tempfile::tempdir()?;
    let source = tmp.path().join("rw");
    let job = tmp.path().join("job");
    std::fs::create_dir_all(&source).context("create rw dir")?;
    std::fs::create_dir_all(&job).context("create job dir")?;
    std::fs::write(source.join("result.txt"), b"hello").context("write output")?;
    let declared = [OutputSpec {
        guest_path: "result.txt".to_string(),
        name: "result.txt".to_string(),
        required: true,
    }];
    let config = CollectionConfig { per_job_cap_bytes: CAP };

    let collected = collect(&exit_zero(), &source, &job, &declared, &config).context("collect declared output")?;

    assert_eq!(collected.len(), 1);
    assert_eq!(collected[0].path, "result.txt");
    assert!(job.join("out").join("result.txt").exists());
    Ok(())
}

/// Verification: result in journal — a terminal record carries the full result
/// envelope and `result_schema_version` (INV-6/INV-11).
#[test]
fn terminal_record_carries_result_in_journal() -> anyhow::Result<()> {
    let tmp = tempfile::tempdir()?;
    let journal = Journal::new(tmp.path());
    journal.ensure_dirs().context("ensure journal dirs")?;
    let mut record = running_record("job-1", "box-1", 1234);
    record.state = JobState::Succeeded;
    record.result = Some(succeeded_envelope("job-1"));
    journal.write_record(&record).context("write record")?;

    let read = journal.read_record("job-1").context("read record")?;
    let result = read.result.context("terminal record has a result")?;
    assert_eq!(result.result_schema_version, RESULT_SCHEMA_VERSION);
    assert_eq!(result.status, Status::Succeeded);
    Ok(())
}

/// Verification: flock round-trip — two writers cannot hold the same job lock.
#[test]
fn flock_round_trip_is_single_writer() -> anyhow::Result<()> {
    let tmp = tempfile::tempdir()?;
    let journal = Journal::new(tmp.path());
    journal.ensure_dirs().context("ensure journal dirs")?;

    let held = journal.lock_job("job-1").context("acquire first lock")?;
    assert_eq!(held.job_id(), "job-1");
    assert!(
        journal.try_lock_job("job-1").context("try second lock")?.is_none(),
        "the lock must be single-writer"
    );
    Ok(())
}

/// Adversarial: required-missing — exit 0 but a required output is absent →
/// error, and no partial `out/`.
#[test]
fn required_missing_fails_without_partial_out() -> anyhow::Result<()> {
    let tmp = tempfile::tempdir()?;
    let source = tmp.path().join("rw");
    let job = tmp.path().join("job");
    std::fs::create_dir_all(&source).context("create rw dir")?;
    std::fs::create_dir_all(&job).context("create job dir")?;
    let declared = [OutputSpec {
        guest_path: "missing.txt".to_string(),
        name: "missing.txt".to_string(),
        required: true,
    }];
    let config = CollectionConfig { per_job_cap_bytes: CAP };

    let result = collect(&exit_zero(), &source, &job, &declared, &config);
    assert!(result.is_err(), "missing required output must fail");
    assert!(!job.join("out").exists(), "no partial out/ may be observable");
    Ok(())
}

/// Adversarial: torn-on-kill — a leftover half-populated `out.tmp/` must never
/// be promoted to `out/`.
#[test]
fn torn_out_tmp_never_promoted() -> anyhow::Result<()> {
    let tmp = tempfile::tempdir()?;
    let source = tmp.path().join("rw");
    let job = tmp.path().join("job");
    std::fs::create_dir_all(&source).context("create rw dir")?;
    std::fs::create_dir_all(job.join("out.tmp")).context("create stale out.tmp")?;
    // A torn partial left by a previous killed run.
    std::fs::write(job.join("out.tmp").join("partial.txt"), b"half").context("write partial")?;
    std::fs::write(source.join("result.txt"), b"hello").context("write real output")?;
    let declared = [OutputSpec {
        guest_path: "result.txt".to_string(),
        name: "result.txt".to_string(),
        required: true,
    }];
    let config = CollectionConfig { per_job_cap_bytes: CAP };

    let _ = collect(&exit_zero(), &source, &job, &declared, &config).context("collect over a torn out.tmp")?;
    assert!(
        !job.join("out").join("partial.txt").exists(),
        "a torn partial must never surface in out/"
    );
    Ok(())
}

/// Adversarial: symlink — an output that is a symlink is refused by
/// `O_NOFOLLOW`; the target bytes are never collected (INV-2).
#[test]
fn symlink_output_is_refused() -> anyhow::Result<()> {
    let tmp = tempfile::tempdir()?;
    let source = tmp.path().join("rw");
    let job = tmp.path().join("job");
    std::fs::create_dir_all(&source).context("create rw dir")?;
    std::fs::create_dir_all(&job).context("create job dir")?;
    let secret = tmp.path().join("host-secret");
    std::fs::write(&secret, b"TOP-SECRET").context("write host secret")?;
    std::os::unix::fs::symlink(&secret, source.join("result.txt")).context("make symlink")?;
    let declared = [OutputSpec {
        guest_path: "result.txt".to_string(),
        name: "result.txt".to_string(),
        required: true,
    }];
    let config = CollectionConfig { per_job_cap_bytes: CAP };

    let result = collect(&exit_zero(), &source, &job, &declared, &config);
    assert!(result.is_err(), "a symlink output must be refused");
    let collected = job.join("out").join("result.txt");
    if collected.exists() {
        let bytes = std::fs::read(&collected).context("read collected")?;
        assert_ne!(bytes, b"TOP-SECRET", "symlink target bytes must not leak");
    }
    Ok(())
}

/// Adversarial: intermediate symlink — an output reachable only through a parent
/// the guest turned into a symlink out of the RW area is refused; host bytes
/// outside the RW area are never collected (INV-2).
#[test]
fn intermediate_symlink_output_is_refused() -> anyhow::Result<()> {
    let tmp = tempfile::tempdir()?;
    let source = tmp.path().join("rw");
    let job = tmp.path().join("job");
    let outside = tmp.path().join("outside");
    std::fs::create_dir_all(&source).context("create rw dir")?;
    std::fs::create_dir_all(&job).context("create job dir")?;
    std::fs::create_dir_all(&outside).context("create outside dir")?;
    std::fs::write(outside.join("host-secret"), b"TOP-SECRET").context("write host secret")?;
    // The guest replaces a parent directory with a link pointing out of the RW area.
    std::os::unix::fs::symlink(&outside, source.join("link")).context("make parent symlink")?;
    let declared = [OutputSpec {
        guest_path: "link/host-secret".to_string(),
        name: "host-secret".to_string(),
        required: true,
    }];
    let config = CollectionConfig { per_job_cap_bytes: CAP };

    let result = collect(&exit_zero(), &source, &job, &declared, &config);
    assert!(
        result.is_err(),
        "an output behind an escaping parent symlink must be refused"
    );
    let collected = job.join("out").join("host-secret");
    if collected.exists() {
        let bytes = std::fs::read(&collected).context("read collected")?;
        assert_ne!(bytes, b"TOP-SECRET", "host bytes outside the RW area must not leak");
    }
    Ok(())
}

/// Adversarial: over-quota — an output beyond the per-job cap fails; the file is
/// not truncated.
#[test]
fn over_quota_fails_without_truncation() -> anyhow::Result<()> {
    let tmp = tempfile::tempdir()?;
    let source = tmp.path().join("rw");
    let job = tmp.path().join("job");
    std::fs::create_dir_all(&source).context("create rw dir")?;
    std::fs::create_dir_all(&job).context("create job dir")?;
    let big = vec![b'x'; 2048];
    std::fs::write(source.join("result.txt"), &big).context("write oversized output")?;
    let declared = [OutputSpec {
        guest_path: "result.txt".to_string(),
        name: "result.txt".to_string(),
        required: true,
    }];
    let config = CollectionConfig {
        per_job_cap_bytes: 1024,
    };

    let result = collect(&exit_zero(), &source, &job, &declared, &config);
    assert!(result.is_err(), "exceeding the cap must fail");
    let meta = std::fs::metadata(source.join("result.txt")).context("stat source")?;
    assert_eq!(meta.len(), 2048, "source must not be truncated");
    Ok(())
}

/// Adversarial: reconcile TOCTOU — a live owner still listed by `boxes()` is
/// never reaped (INV-3).
#[test]
fn reconcile_leaves_a_live_job_alone() -> anyhow::Result<()> {
    let tmp = tempfile::tempdir()?;
    let journal = Journal::new(tmp.path());
    journal.ensure_dirs().context("ensure journal dirs")?;
    let record = running_record("job-1", "box-1", 4242);
    journal.write_record(&record).context("write running record")?;

    // The backend still reports the box as live.
    let live = sandy_core::BoxState {
        box_id: "box-1".to_string(),
        box_name: "job-1".to_string(),
        pid: 4242,
        started: SystemTime::UNIX_EPOCH,
        rvport: None,
    };
    let backend = FakeBackend::new().with_boxes(vec![live]);

    let reconciled = reconcile_job(&journal, &backend, "job-1").context("reconcile live job")?;
    assert_eq!(
        reconciled.state,
        JobState::Running,
        "a live job must not be flipped to crashed"
    );
    assert!(backend.killed().is_empty(), "a live job must not be torn down");
    Ok(())
}

/// Adversarial complement: reconcile reaps a job whose box is gone — but only
/// after taking the lock, flipping to crashed and tearing down.
#[test]
fn reconcile_reaps_a_dead_job() -> anyhow::Result<()> {
    let tmp = tempfile::tempdir()?;
    let journal = Journal::new(tmp.path());
    journal.ensure_dirs().context("ensure journal dirs")?;
    let record = running_record("job-1", "box-1", 4242);
    journal.write_record(&record).context("write running record")?;

    // The backend reports no live boxes — the owner is gone.
    let backend = FakeBackend::new().with_boxes(vec![]);

    let reconciled = reconcile_job(&journal, &backend, "job-1").context("reconcile dead job")?;
    assert_eq!(reconciled.state, JobState::Crashed);
    assert_eq!(backend.killed(), vec!["box-1".to_string()]);
    Ok(())
}

/// A backend that writes a terminal record the moment reconcile queries it,
/// standing in for the real owner finishing between reconcile's first read and
/// its lock acquisition.
struct FinishesDuringQuery<'a> {
    journal: &'a Journal,
    job_id: String,
}

impl VmBackend for FinishesDuringQuery<'_> {
    fn run(&self, _spec: &RunSpec) -> Result<Outcome, BackendError> {
        unreachable!("reconcile never runs a box")
    }

    fn kill(&self, _box_id: &str) -> Result<(), BackendError> {
        Ok(())
    }

    fn boxes(&self) -> Result<Vec<BoxState>, BackendError> {
        let mut record = self
            .journal
            .read_record(&self.job_id)
            .map_err(|e| BackendError::Protocol(e.to_string()))?;
        record.state = JobState::Succeeded;
        record.result = Some(succeeded_envelope(&self.job_id));
        self.journal
            .write_record(&record)
            .map_err(|e| BackendError::Protocol(e.to_string()))?;
        Ok(vec![])
    }
}

/// Regression: a terminal result written after reconcile's first read but before
/// it takes the lock must not be clobbered by a stale `crashed` (INV-3/INV-6).
#[test]
fn reconcile_does_not_clobber_a_result_won_in_the_race() -> anyhow::Result<()> {
    let tmp = tempfile::tempdir()?;
    let journal = Journal::new(tmp.path());
    journal.ensure_dirs().context("ensure journal dirs")?;
    journal
        .write_record(&running_record("job-1", "box-1", 4242))
        .context("write running record")?;

    let backend = FinishesDuringQuery {
        journal: &journal,
        job_id: "job-1".to_string(),
    };

    let reconciled = reconcile_job(&journal, &backend, "job-1").context("reconcile racing job")?;
    assert_eq!(
        reconciled.state,
        JobState::Succeeded,
        "a result won in the race must survive reconcile"
    );
    assert!(reconciled.result.is_some(), "the terminal result must be preserved");
    Ok(())
}
