//! Tier-2 integration tests for the `sandy` job ops over a [`FakeBackend`] and a
//! real [`Journal`] on a `tempfile::TempDir` `$SANDY_HOME`. No hypervisor boots:
//! the live-boot proof is tier-3 (#26). Every command has a positive and an
//! adversarial case.

use std::time::{Duration, SystemTime};

use anyhow::Context;
use sandy::{
    AllowList, BackendError, CoreError, EgressOs, EgressRule, FakeApplier, FakeBackend, FakeMinter, Grants,
    JOURNAL_SCHEMA_VERSION, JobRecord, JobState, Journal, Logs, Mount, Outcome, Provenance, RESULT_SCHEMA_VERSION,
    ResultEnvelope, SecretRef, SecretSource, Status, TokenScope, to_nftables,
};
use sandy_cli::{
    plan::JobPlan,
    supervisor::{gc, kill, ls, mint_run_token, run_job, status, wait},
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
        allow: AllowList::default(),
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
        allow: AllowList::default(),
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

    let report = run_job(
        &backend,
        &journal,
        &booting_plan(),
        &FakeApplier::new(),
        EgressOs::Linux,
    )
    .context("run_job (positive)")?;

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

    let report = run_job(
        &backend,
        &journal,
        &booting_plan(),
        &FakeApplier::new(),
        EgressOs::Linux,
    )
    .context("run_job (guest failure)")?;

    assert_eq!(report.envelope.status, Status::Failed);
    assert_eq!(report.process_exit.code(), 1);
    assert!(!report.envelope.retryable, "a guest failure must not be retryable");
    Ok(())
}

#[test]
fn run_infra_fault_is_band_three_and_retryable() -> anyhow::Result<()> {
    let (_tmp, journal) = fresh_journal()?;
    let backend = FakeBackend::new().with_error(BackendError::Spawn("no hypervisor".to_string()));

    let report = run_job(
        &backend,
        &journal,
        &booting_plan(),
        &FakeApplier::new(),
        EgressOs::Linux,
    )
    .context("run_job (infra fault)")?;

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

    let report = run_job(
        &backend,
        &journal,
        &leaking_plan(),
        &FakeApplier::new(),
        EgressOs::Linux,
    )
    .context("run_job (invalid plan)")?;

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
    let report = run_job(
        &backend,
        &journal,
        &booting_plan(),
        &FakeApplier::new(),
        EgressOs::Linux,
    )
    .context("run_job before ls")?;

    let records = ls(&journal).context("ls")?;
    assert_eq!(records.len(), 1, "ls must list the one written job");
    assert_eq!(records[0].job_id, report.envelope.job_id);
    Ok(())
}

#[test]
fn status_returns_the_written_job() -> anyhow::Result<()> {
    let (_tmp, journal) = fresh_journal()?;
    let backend = FakeBackend::new().with_outcome(ok_outcome(0));
    let report = run_job(
        &backend,
        &journal,
        &booting_plan(),
        &FakeApplier::new(),
        EgressOs::Linux,
    )
    .context("run_job before status")?;

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

// --- egress bracketing around the boot (#23/#24) ----------------------------

/// A plan that boots `demo` behind a one-rule allow-list (`github.com:443`).
fn allowing_plan() -> JobPlan {
    JobPlan {
        allow: AllowList {
            rules: vec![EgressRule {
                host: "github.com".to_string(),
                port: 443,
            }],
        },
        ..booting_plan()
    }
}

/// #23: a Linux run with a non-empty allow-list applies the `to_nftables`
/// translation of that allow-list as the boundary, and reverts it after the run.
#[test]
fn run_on_linux_applies_the_allow_list_ruleset_and_reverts_it() -> anyhow::Result<()> {
    let (_tmp, journal) = fresh_journal()?;
    let backend = FakeBackend::new().with_outcome(ok_outcome(0));
    let applier = FakeApplier::new();
    let plan = allowing_plan();

    let report = run_job(&backend, &journal, &plan, &applier, EgressOs::Linux).context("run_job (linux egress)")?;

    assert_eq!(report.envelope.status, Status::Succeeded);
    assert_eq!(
        applier.applied_rulesets(),
        vec![to_nftables(&plan.allow)],
        "the enforced boundary must be the allow-list's nftables translation"
    );
    assert!(
        applier.was_reverted(),
        "an enforced boundary must be reverted after the run"
    );
    Ok(())
}

/// An egress applier whose `apply` always fails, to drive the fail-closed path.
struct FailingApplier;
impl sandy::EgressApplier for FailingApplier {
    fn apply(&self, _ruleset: &str) -> Result<(), CoreError> {
        Err(CoreError::Egress("nft apply refused".to_string()))
    }

    fn revert(&self) -> Result<(), CoreError> {
        Ok(())
    }
}

/// If the egress boundary cannot be applied, the run fails CLOSED: a terminal
/// infra-fault (band 3) record is written naming the boundary, the backend is
/// never booted, and no `Running` record is left dangling (INV-6).
#[test]
fn egress_apply_failure_fails_closed_with_a_terminal_record() -> anyhow::Result<()> {
    let (_tmp, journal) = fresh_journal()?;
    // A success is scripted on purpose: band 3 here proves the boot was skipped.
    let backend = FakeBackend::new().with_outcome(ok_outcome(0));

    let report = run_job(&backend, &journal, &allowing_plan(), &FailingApplier, EgressOs::Linux)
        .context("run_job (egress apply fails)")?;

    assert_eq!(
        report.process_exit.code(),
        3,
        "an unestablished boundary is an infra fault"
    );
    assert_eq!(report.envelope.status, Status::Failed);
    assert!(report.envelope.retryable, "band 3 is retryable");
    assert!(
        report.envelope.message.contains("egress boundary"),
        "the message must name the egress failure: {}",
        report.envelope.message
    );
    // No dangling Running: the job's on-disk record is terminal, not Running.
    let record = journal
        .read_record(&report.envelope.job_id)
        .context("terminal record on disk")?;
    assert_eq!(
        record.state,
        JobState::Failed,
        "an egress failure must write a terminal record, not leave Running"
    );
    Ok(())
}

/// #24: a macOS run applies no boundary (vmnet has none), yet the run still
/// succeeds — the honest `NoBoundary` path, not a silent failure.
#[test]
fn run_on_macos_applies_no_boundary_but_still_succeeds() -> anyhow::Result<()> {
    let (_tmp, journal) = fresh_journal()?;
    let backend = FakeBackend::new().with_outcome(ok_outcome(0));
    let applier = FakeApplier::new();

    let report = run_job(&backend, &journal, &allowing_plan(), &applier, EgressOs::MacOs).context("run_job (macos)")?;

    assert_eq!(
        report.envelope.status,
        Status::Succeeded,
        "a NoBoundary run still succeeds"
    );
    assert!(
        applier.applied_rulesets().is_empty(),
        "macOS NoBoundary must apply no ruleset, even with a non-empty allow-list"
    );
    assert!(
        !applier.was_reverted(),
        "nothing was applied, so nothing is reverted on macOS"
    );
    Ok(())
}

/// #23 (adversarial): the boundary is reverted even when the backend run FAILS —
/// a boot failure must never leave egress rules applied on the host.
#[test]
fn egress_boundary_is_reverted_even_when_the_backend_run_fails() -> anyhow::Result<()> {
    let (_tmp, journal) = fresh_journal()?;
    let backend = FakeBackend::new().with_error(BackendError::Spawn("no hypervisor".to_string()));
    let applier = FakeApplier::new();

    let report =
        run_job(&backend, &journal, &allowing_plan(), &applier, EgressOs::Linux).context("run_job (boot failure)")?;

    assert_eq!(report.process_exit.code(), 3, "a boot failure is still band 3");
    assert!(
        applier.was_reverted(),
        "the boundary must be reverted on the backend-error path too"
    );
    Ok(())
}

// --- scoped credential minting (#25) ----------------------------------------

/// A minimal `contents:read` scope on one repo.
fn token_scope() -> TokenScope {
    TokenScope {
        repositories: vec!["acme/widgets".to_string()],
        permissions: vec![("contents".to_string(), "read".to_string())],
    }
}

/// #25: `mint_run_token` stages the token as a `0600` `SecretRef::File`, and the
/// token bytes travel only the secret channel — the staged file holds them, while
/// the plan's argv/env and the `SecretRef` handle never do (INV-1).
#[test]
fn mint_run_token_stages_a_secret_and_the_token_travels_only_the_secret_channel() -> anyhow::Result<()> {
    let (tmp, journal) = fresh_journal()?;
    let token = "ghs_scoped_marker_value";
    let minter = FakeMinter::returning(token);

    let secret =
        mint_run_token(&minter, &token_scope(), "GH_TOKEN", tmp.path(), 1_800).context("mint_run_token (success)")?;

    // The handle is a File source whose 0600 file holds the token bytes. Capture
    // the path and the handle render before the secret is moved into the plan
    // (`SecretRef` is not `Clone`).
    let SecretSource::File(path) = &secret.source else {
        anyhow::bail!("expected a File-sourced secret, got {:?}", secret.source);
    };
    let staged_path = path.clone();
    let rendered = format!("{secret:?}");
    assert_eq!(
        std::fs::read(&staged_path).context("read staged token")?,
        token.as_bytes(),
        "the staged file must hold the token bytes"
    );
    // INV-1 leak plane: the token bytes must not appear in the SecretRef handle.
    assert!(
        !rendered.contains(token),
        "the token must not appear in the SecretRef handle"
    );

    // Thread the secret into a run and prove it still succeeds over the secret channel.
    let plan = JobPlan {
        secrets: vec![secret],
        ..booting_plan()
    };
    let backend = FakeBackend::new().with_outcome(ok_outcome(0));
    let report = run_job(&backend, &journal, &plan, &FakeApplier::new(), EgressOs::Linux).context("run_job (token)")?;
    assert_eq!(report.envelope.status, Status::Succeeded);

    // INV-1: the token bytes are in the file, never in the guest argv or env.
    assert!(
        plan.command.iter().all(|arg| !arg.contains(token)),
        "the token must not appear in the guest argv"
    );
    assert!(
        plan.env.iter().all(|(k, v)| !k.contains(token) && !v.contains(token)),
        "the token must not appear in env (INV-1)"
    );
    Ok(())
}

/// #25 (adversarial): a mint failure surfaces as `CoreError::Cred`, so the caller
/// fails rather than running the job with no token (INV-7).
#[test]
fn mint_run_token_failure_surfaces_as_core_error_not_a_tokenless_run() -> anyhow::Result<()> {
    let (tmp, _journal) = fresh_journal()?;
    let minter = FakeMinter::failing();

    let err = mint_run_token(&minter, &token_scope(), "GH_TOKEN", tmp.path(), 1_800)
        .expect_err("a failing mint must be an error, not a tokenless run");

    assert!(
        matches!(err, CoreError::Cred(_)),
        "expected CoreError::Cred, got {err:?}"
    );
    Ok(())
}
