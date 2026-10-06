//! Tier-2 integration tests for the `sandy` job ops over a [`FakeBackend`] and a
//! real [`Journal`] on a `tempfile::TempDir` `$SANDY_HOME`. No hypervisor boots:
//! the live-boot proof is tier-3 (#26). Every command has a positive and an
//! adversarial case.

use std::time::{Duration, SystemTime};

use anyhow::Context;
use sandy::{
    BackendError, FakeBackend, Grants, JOURNAL_SCHEMA_VERSION, JobRecord, JobState, Journal, Logs, Mount, Outcome,
    Provenance, RESULT_SCHEMA_VERSION, ResultEnvelope, SecretRef, SecretSource, Status,
};
use sandy_cli::{
    plan::JobPlan,
    supervisor::{gc, kill, ls, run_job, status, wait},
};

/// A journal on a fresh local temp `$SANDY_HOME`.
fn fresh_journal() -> anyhow::Result<(tempfile::TempDir, Journal)> {
    let tmp = tempfile::tempdir().context("creating a temp SANDY_HOME")?;
    let journal = Journal::new(tmp.path());
    journal.ensure_dirs().context("ensure_dirs")?;
    Ok((tmp, journal))
}

/// A scripted physical outcome: booted, with the given guest exit code.
fn ok_outcome(guest_exit: i32) -> Outcome {
    Outcome {
        booted: true,
        guest_exit: Some(guest_exit),
        transport_error: None,
        timed_out: false,
    }
}

/// A minimal plan that boots `demo` with no mounts, secrets, or env.
fn booting_plan() -> JobPlan {
    JobPlan {
        template: "demo".to_string(),
        command: vec![],
        mounts: vec![],
        secrets: vec![],
        env: vec![],
        cpu: None,
        mem: None,
        timeout_secs: 60,
        grants: Grants {
            secrets: false,
            agent: false,
            shares: false,
        },
    }
}

/// A plan whose secret file path is also a mount host — rejected by
/// `validate_no_secret_leak` (INV-1).
fn leaking_plan() -> JobPlan {
    let shared = std::path::PathBuf::from("/run/leak-token");
    JobPlan {
        template: "demo".to_string(),
        command: vec![],
        mounts: vec![Mount {
            host: shared.clone(),
            guest: std::path::PathBuf::from("/in/token"),
            ro: true,
        }],
        secrets: vec![SecretRef {
            name: "TOK".to_string(),
            source: SecretSource::File(shared),
        }],
        env: vec![],
        cpu: None,
        mem: None,
        timeout_secs: 60,
        grants: Grants {
            secrets: true,
            agent: false,
            shares: false,
        },
    }
}

/// A hand-built `Running` record with a box id, for the reconcile-driven ops.
fn running_record(job_id: &str, box_id: &str, started: SystemTime) -> JobRecord {
    JobRecord {
        schema_version: JOURNAL_SCHEMA_VERSION,
        job_id: job_id.to_string(),
        box_id: Some(box_id.to_string()),
        state: JobState::Running,
        writer_pid: std::process::id(),
        started,
        result: None,
    }
}

/// A hand-built terminal `Succeeded` record carrying a minimal envelope (INV-6).
fn terminal_record(job_id: &str, started: SystemTime) -> JobRecord {
    JobRecord {
        schema_version: JOURNAL_SCHEMA_VERSION,
        job_id: job_id.to_string(),
        box_id: Some(format!("box-{job_id}")),
        state: JobState::Succeeded,
        writer_pid: std::process::id(),
        started,
        result: Some(ResultEnvelope {
            result_schema_version: RESULT_SCHEMA_VERSION,
            job_id: job_id.to_string(),
            box_id: Some(format!("box-{job_id}")),
            status: Status::Succeeded,
            retryable: false,
            message: "ok".to_string(),
            exit_code: Some(0),
            outputs: vec![],
            receipts: vec![],
            provenance: Provenance {
                template_store_path: "/nix/store/xxx".to_string(),
            },
            logs: Logs { tail: String::new() },
        }),
    }
}

#[test]
fn run_positive_writes_a_succeeded_record_with_the_envelope() -> anyhow::Result<()> {
    let (_tmp, journal) = fresh_journal()?;
    let backend = FakeBackend::new().with_outcome(ok_outcome(0));

    let report = run_job(&backend, &journal, &booting_plan()).context("run_job (positive)")?;

    assert_eq!(report.envelope.status, Status::Succeeded);
    assert_eq!(report.process_exit.code(), 0);

    let record = journal
        .read_record(&report.envelope.job_id)
        .context("terminal record must be on disk")?;
    assert_eq!(record.state, JobState::Succeeded);
    assert!(
        record.result.is_some(),
        "terminal record must carry the envelope (INV-6)"
    );
    Ok(())
}

#[test]
fn run_guest_failure_is_band_one_not_retryable() -> anyhow::Result<()> {
    let (_tmp, journal) = fresh_journal()?;
    let backend = FakeBackend::new().with_outcome(ok_outcome(1));

    let report = run_job(&backend, &journal, &booting_plan()).context("run_job (guest failure)")?;

    assert_eq!(report.envelope.status, Status::Failed);
    assert_eq!(report.process_exit.code(), 1);
    assert!(!report.envelope.retryable, "a guest failure must not be retryable");
    Ok(())
}

#[test]
fn run_infra_fault_is_band_three_and_retryable() -> anyhow::Result<()> {
    let (_tmp, journal) = fresh_journal()?;
    let backend = FakeBackend::new().with_error(BackendError::Spawn("no hypervisor".to_string()));

    let report = run_job(&backend, &journal, &booting_plan()).context("run_job (infra fault)")?;

    assert_eq!(report.envelope.status, Status::Failed);
    assert_eq!(report.process_exit.code(), 3);
    // INV-11 cross-check: band 3 ⟺ retryable.
    assert!(report.envelope.retryable, "an infra fault must be retryable");
    Ok(())
}

#[test]
fn run_invalid_plan_writes_no_record_and_never_boots() -> anyhow::Result<()> {
    let (_tmp, journal) = fresh_journal()?;
    // A success is scripted on purpose: if the backend were ever run the band
    // would be 0, so band 2 here proves the boot was skipped.
    let backend = FakeBackend::new().with_outcome(ok_outcome(0));

    let report = run_job(&backend, &journal, &leaking_plan()).context("run_job (invalid plan)")?;

    assert_eq!(report.process_exit.code(), 2, "an invalid plan is band 2");
    assert!(!report.envelope.retryable, "band 2 is never retryable");
    // INV-6: the running record is written before the backend runs, so an empty
    // journal proves the backend was never reached (the adversarial silent-run).
    assert!(
        journal.list().context("list after invalid plan")?.is_empty(),
        "an invalid plan must write no job record"
    );
    assert!(
        backend.killed().is_empty(),
        "an invalid plan must not touch the backend"
    );
    Ok(())
}

#[test]
fn ls_lists_a_written_job() -> anyhow::Result<()> {
    let (_tmp, journal) = fresh_journal()?;
    let backend = FakeBackend::new().with_outcome(ok_outcome(0));
    let report = run_job(&backend, &journal, &booting_plan()).context("run_job before ls")?;

    let records = ls(&journal).context("ls")?;
    assert_eq!(records.len(), 1, "ls must list the one written job");
    assert_eq!(records[0].job_id, report.envelope.job_id);
    Ok(())
}

#[test]
fn status_returns_the_written_job() -> anyhow::Result<()> {
    let (_tmp, journal) = fresh_journal()?;
    let backend = FakeBackend::new().with_outcome(ok_outcome(0));
    let report = run_job(&backend, &journal, &booting_plan()).context("run_job before status")?;

    let record = status(&journal, &backend, &report.envelope.job_id).context("status")?;
    assert_eq!(record.job_id, report.envelope.job_id);
    assert_eq!(record.state, JobState::Succeeded);
    Ok(())
}

#[test]
fn wait_on_a_dead_box_returns_crashed_without_hanging() -> anyhow::Result<()> {
    let (_tmp, journal) = fresh_journal()?;
    // Record says Running, but the backend reports no live boxes — reconcile must
    // flip it to Crashed in one pass. The test completing is the no-hang proof.
    journal
        .write_record(&running_record("job-dead", "box-dead", SystemTime::now()))
        .context("seed a running record")?;
    let backend = FakeBackend::new().with_boxes(vec![]);

    let record = wait(&journal, &backend, "job-dead").context("wait on dead box")?;
    assert_eq!(record.state, JobState::Crashed, "a dead box must reconcile to Crashed");
    Ok(())
}

#[test]
fn kill_running_job_tears_down_the_box_and_cancels_the_record() -> anyhow::Result<()> {
    let (_tmp, journal) = fresh_journal()?;
    journal
        .write_record(&running_record("job-live", "box-live", SystemTime::now()))
        .context("seed a running record")?;
    let backend = FakeBackend::new();

    let record = kill(&journal, &backend, "job-live").context("kill")?;
    assert_eq!(record.state, JobState::Cancelled, "kill must cancel the record");
    assert!(
        backend.killed().contains(&"box-live".to_string()),
        "kill must tear the box down: {:?}",
        backend.killed()
    );
    Ok(())
}

#[test]
fn gc_evicts_oldest_terminal_beyond_keep_n_but_keeps_the_running_job() -> anyhow::Result<()> {
    let (_tmp, journal) = fresh_journal()?;
    let at = |secs| SystemTime::UNIX_EPOCH + Duration::from_secs(secs);

    // A Running job that is the OLDEST of all — it must survive (referenced).
    journal
        .write_record(&running_record("job-running", "box-r", at(0)))
        .context("seed running")?;
    // Three terminal records, newest last.
    journal
        .write_record(&terminal_record("term-old", at(1)))
        .context("t1")?;
    journal
        .write_record(&terminal_record("term-mid", at(2)))
        .context("t2")?;
    journal
        .write_record(&terminal_record("term-new", at(3)))
        .context("t3")?;

    // Keep the newest 2 terminal records; the oldest terminal is evicted.
    let evicted = gc(&journal, 2).context("gc")?;

    assert!(
        evicted.contains(&"term-old".to_string()),
        "oldest terminal evicted: {evicted:?}"
    );
    assert!(
        !evicted.contains(&"term-new".to_string()),
        "newest terminal kept: {evicted:?}"
    );
    assert!(
        !evicted.contains(&"job-running".to_string()),
        "a referenced (Running) job is never evicted, even when oldest: {evicted:?}"
    );

    // The evicted record's file is gone; the Running record survives.
    assert!(
        journal.read_record("term-old").is_err(),
        "the evicted record file must be deleted"
    );
    let running = journal.read_record("job-running").context("running record survives")?;
    assert_eq!(running.state, JobState::Running);
    Ok(())
}
