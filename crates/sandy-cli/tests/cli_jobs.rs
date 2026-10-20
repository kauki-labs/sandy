//! Tier-2 integration tests for the `sandy` job ops over a `FakeBackend` and a
//! real [`Journal`] on a `tempfile::TempDir` `$SANDY_HOME`. No hypervisor boots:
//! the live-boot proof is tier-3 (#26). Every command has a positive and an
//! adversarial case.

use std::{
    os::unix::fs::PermissionsExt,
    time::{Duration, SystemTime},
};

use anyhow::Context;
use sandy::{
    AllowList, BackendError, Capability, CoreError, EgressOs, EgressRule, Grants, JOURNAL_SCHEMA_VERSION, JobRecord,
    JobState, Journal, Logs, Outcome, Provenance, RESULT_SCHEMA_VERSION, ResultEnvelope, Scope, SecretRef,
    SecretSource, Status, Target, to_nftables_forward,
};
use sandy_cli::{
    plan::JobPlan,
    supervisor::{gc, kill, ls, mint_run_token, run_job, run_job_with_credential, status, wait},
};
use sandy_test_support::{FakeApplier, FakeBackend, FakeProvider};

/// A journal on a fresh local temp `$SANDY_HOME`.
fn fresh_journal() -> anyhow::Result<(tempfile::TempDir, Journal)> {
    // 0700 whatever the umask: credentials are staged under it (#174).
    let tmp = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .context("creating a temp SANDY_HOME")?;
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
        console: String::new(),
    }
}

/// A minimal plan that boots `demo` with no secrets or env.
fn booting_plan() -> JobPlan {
    JobPlan {
        template: "demo".to_string(),
        command: vec![],
        inputs: vec![],
        outputs: vec![],
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
        secret_dir: None,
    }
}

/// A plan whose secret name is also set as a plain env var — rejected by
/// `validate_no_secret_leak` (INV-1).
fn leaking_plan() -> JobPlan {
    JobPlan {
        template: "demo".to_string(),
        command: vec![],
        inputs: vec![],
        outputs: vec![],
        secrets: vec![SecretRef {
            name: "TOK".to_string(),
            source: SecretSource::File(std::path::PathBuf::from("/run/leak-token")),
        }],
        env: vec![("TOK".to_string(), "leaked".to_string())],
        allow: AllowList::default(),
        cpu: None,
        mem: None,
        timeout_secs: 60,
        grants: Grants {
            secrets: true,
            agent: false,
            shares: false,
        },
        secret_dir: None,
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
            warnings: Vec::new(),
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
        None,
        &[],
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
fn run_lists_collected_outputs_in_the_envelope() -> anyhow::Result<()> {
    let (tmp, journal) = fresh_journal()?;
    // The backend collects to each declared output's dest; FakeBackend doesn't
    // boot, so seed the dest to stand in for what a real collection writes.
    let dest = tmp.path().join("collected");
    std::fs::create_dir_all(dest.join("sub")).context("mk output dest")?;
    std::fs::write(dest.join("f"), b"x").context("write output")?;
    std::fs::write(dest.join("sub").join("g"), b"y").context("write nested output")?;

    let mut plan = booting_plan();
    plan.outputs = vec![sandy::Output {
        name: Some("result".to_string()),
        dest,
    }];

    let backend = FakeBackend::new().with_outcome(ok_outcome(0));
    let report = run_job(
        &backend,
        &journal,
        &plan,
        &FakeApplier::new(),
        EgressOs::Linux,
        None,
        &[],
    )
    .context("run_job with outputs")?;

    let paths: Vec<&str> = report.envelope.outputs.iter().map(|o| o.path.as_str()).collect();
    assert_eq!(
        paths,
        vec!["result/f", "result/sub/g"],
        "envelope lists the collected outputs, sorted and name-prefixed"
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
        None,
        &[],
    )
    .context("run_job (guest failure)")?;

    assert_eq!(report.envelope.status, Status::Failed);
    assert_eq!(report.process_exit.code(), 1);
    assert!(!report.envelope.retryable, "a guest failure must not be retryable");
    Ok(())
}

#[test]
fn run_timeout_is_band_one_not_retryable() -> anyhow::Result<()> {
    let (_tmp, journal) = fresh_journal()?;
    // A booted guest that hit its wall-clock timeout: no exit code, `timed_out`.
    let timed_out = Outcome {
        booted: true,
        guest_exit: None,
        transport_error: None,
        timed_out: true,
        console: String::new(),
    };
    let backend = FakeBackend::new().with_outcome(timed_out);

    let report = run_job(
        &backend,
        &journal,
        &booting_plan(),
        &FakeApplier::new(),
        EgressOs::Linux,
        None,
        &[],
    )
    .context("run_job (timeout)")?;

    // A timeout is a task/contract fault (band 1), never retryable by the platform.
    assert_eq!(report.envelope.status, Status::Failed);
    assert_eq!(report.process_exit.code(), 1, "timeout is band 1, not an infra fault");
    assert!(!report.envelope.retryable, "a timeout must not be retryable");
    assert_eq!(
        report.envelope.exit_code, None,
        "a timed-out guest produced no exit code"
    );
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
        None,
        &[],
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
        None,
        &[],
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
        None,
        &[],
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
        None,
        &[],
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

    let report = run_job(
        &backend,
        &journal,
        &plan,
        &applier,
        EgressOs::Linux,
        Some("sandytap0"),
        &[],
    )
    .context("run_job (linux egress)")?;

    assert_eq!(report.envelope.status, Status::Succeeded);
    assert_eq!(
        applier.applied_rulesets(),
        vec![to_nftables_forward(&plan.allow, "sandytap0")],
        "the enforced boundary must be the guest-scoped forward ruleset for the tap"
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
    fn apply(&self, _ruleset: &str) -> Result<(), sandy::EgressError> {
        Err(sandy::EgressError::Apply("nft apply refused".to_string()))
    }

    fn revert(&self) -> Result<(), sandy::EgressError> {
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

    let report = run_job(
        &backend,
        &journal,
        &allowing_plan(),
        &FailingApplier,
        EgressOs::Linux,
        Some("sandytap0"),
        &[],
    )
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

    let report = run_job(
        &backend,
        &journal,
        &allowing_plan(),
        &applier,
        EgressOs::MacOs,
        None,
        &[],
    )
    .context("run_job (macos)")?;

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

    let report = run_job(
        &backend,
        &journal,
        &allowing_plan(),
        &applier,
        EgressOs::Linux,
        Some("sandytap0"),
        &[],
    )
    .context("run_job (boot failure)")?;

    assert_eq!(report.process_exit.code(), 3, "a boot failure is still band 3");
    assert!(
        applier.was_reverted(),
        "the boundary must be reverted on the backend-error path too"
    );
    Ok(())
}

// --- scoped credential minting (#25) ----------------------------------------

/// A minimal read-code scope on one repo.
fn token_scope() -> Scope {
    Scope {
        targets: vec![Target("acme/widgets".to_string())],
        capabilities: vec![Capability::ReadCode],
    }
}

/// #25: `mint_run_token` stages the token as a `0600` `SecretRef::File`, and the
/// token bytes travel only the secret channel — the staged file holds them, while
/// the plan's argv/env and the `SecretRef` handle never do (INV-1).
#[test]
fn mint_run_token_stages_a_secret_and_the_token_travels_only_the_secret_channel() -> anyhow::Result<()> {
    let (tmp, journal) = fresh_journal()?;
    let token = "ghs_scoped_marker_value";
    let provider = FakeProvider::returning(token);

    let lease =
        mint_run_token(&provider, &token_scope(), "GH_TOKEN", tmp.path(), 1_800).context("mint_run_token (success)")?;

    // The lease's secret_ref is a File source whose 0600 file holds the token
    // bytes. Capture the path and the handle render before the secret_ref is moved
    // into the plan (`SecretRef` is not `Clone`).
    let SecretSource::File(path) = &lease.secret_ref.source else {
        anyhow::bail!("expected a File-sourced secret, got {:?}", lease.secret_ref.source);
    };
    let staged_path = path.clone();
    let rendered = format!("{lease:?}");
    assert_eq!(
        std::fs::read(&staged_path).context("read staged token")?,
        token.as_bytes(),
        "the staged file must hold the token bytes"
    );
    // INV-1 leak plane: the token bytes must not appear in the Lease handle.
    assert!(
        !rendered.contains(token),
        "the token must not appear in the Lease handle"
    );

    // Thread the secret into a run and prove it still succeeds over the secret channel.
    let plan = JobPlan {
        secrets: vec![lease.secret_ref],
        ..booting_plan()
    };
    let backend = FakeBackend::new().with_outcome(ok_outcome(0));
    let report = run_job(
        &backend,
        &journal,
        &plan,
        &FakeApplier::new(),
        EgressOs::Linux,
        None,
        &[],
    )
    .context("run_job (token)")?;
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
    let provider = FakeProvider::failing();

    let err = mint_run_token(&provider, &token_scope(), "GH_TOKEN", tmp.path(), 1_800)
        .expect_err("a failing mint must be an error, not a tokenless run");

    assert!(
        matches!(err, CoreError::Cred(_)),
        "expected CoreError::Cred, got {err:?}"
    );
    Ok(())
}

/// #49 Block 2: `run_job_with_credential` mints at boot, runs, revokes at teardown
/// on the success path, and removes the staged token file afterwards (INV-1).
#[test]
fn credential_is_minted_run_revoked_and_cleaned() -> anyhow::Result<()> {
    let (tmp, journal) = fresh_journal()?;
    let provider = FakeProvider::returning("ghs_tok");
    let backend = FakeBackend::new().with_outcome(ok_outcome(0));
    let cred_dir = tmp.path().join("cred");
    std::fs::create_dir_all(&cred_dir).context("create cred dir")?;
    // 0700 like the production cred dir, whatever the umask (#192).
    std::fs::set_permissions(&cred_dir, std::fs::Permissions::from_mode(0o700)).context("cred dir 0700")?;

    let report = run_job_with_credential(
        &backend,
        &journal,
        booting_plan(),
        &FakeApplier::new(),
        EgressOs::Linux,
        None,
        &provider,
        &token_scope(),
        "GH_TOKEN",
        &cred_dir,
        1_800,
    )
    .context("run_job_with_credential")?;

    assert_eq!(report.envelope.status, Status::Succeeded);
    assert_eq!(
        provider.revoked().len(),
        1,
        "the credential must be revoked exactly once at teardown"
    );
    assert!(
        !cred_dir.join("GH_TOKEN").exists(),
        "the minted token file must be removed after the run (INV-1)"
    );
    assert!(
        report.envelope.warnings.is_empty(),
        "a clean revoke must leave no warning: {:?}",
        report.envelope.warnings
    );
    Ok(())
}

/// #49 Block 2 (adversarial): the credential is revoked even when the backend run
/// fails, so a failed boot never leaves a live credential behind.
#[test]
fn credential_is_revoked_even_when_the_run_fails() -> anyhow::Result<()> {
    let (tmp, journal) = fresh_journal()?;
    let provider = FakeProvider::returning("ghs_tok");
    let backend = FakeBackend::new().with_error(BackendError::Spawn("no hypervisor".to_string()));
    let cred_dir = tmp.path().join("cred");
    std::fs::create_dir_all(&cred_dir).context("create cred dir")?;
    // 0700 like the production cred dir, whatever the umask (#192).
    std::fs::set_permissions(&cred_dir, std::fs::Permissions::from_mode(0o700)).context("cred dir 0700")?;

    let report = run_job_with_credential(
        &backend,
        &journal,
        booting_plan(),
        &FakeApplier::new(),
        EgressOs::Linux,
        None,
        &provider,
        &token_scope(),
        "GH_TOKEN",
        &cred_dir,
        1_800,
    )
    .context("run_job_with_credential (run fails)")?;

    assert_eq!(report.process_exit.code(), 3, "a boot failure is band 3");
    assert_eq!(
        provider.revoked().len(),
        1,
        "a failed run must still revoke the credential"
    );
    Ok(())
}

/// #49 Block 2 (adversarial): a mint failure fails closed — no backend run, no
/// journal record, and the error surfaces as `CoreError::Cred` (INV-7).
#[test]
fn credential_mint_failure_fails_closed_before_any_run() -> anyhow::Result<()> {
    let (tmp, journal) = fresh_journal()?;
    let provider = FakeProvider::failing();
    // A success is scripted on purpose: if the backend ever ran the band would be 0,
    // so a Cred error here proves the boot was skipped.
    let backend = FakeBackend::new().with_outcome(ok_outcome(0));
    let cred_dir = tmp.path().join("cred");
    std::fs::create_dir_all(&cred_dir).context("create cred dir")?;
    // 0700 like the production cred dir, whatever the umask (#192).
    std::fs::set_permissions(&cred_dir, std::fs::Permissions::from_mode(0o700)).context("cred dir 0700")?;

    let err = run_job_with_credential(
        &backend,
        &journal,
        booting_plan(),
        &FakeApplier::new(),
        EgressOs::Linux,
        None,
        &provider,
        &token_scope(),
        "GH_TOKEN",
        &cred_dir,
        1_800,
    )
    .expect_err("a mint failure must fail closed");

    assert!(
        matches!(err, CoreError::Cred(_)),
        "expected CoreError::Cred, got {err:?}"
    );
    assert!(
        journal.list().context("list after mint failure")?.is_empty(),
        "a mint failure must write no job record"
    );
    assert_eq!(provider.revoked().len(), 0, "nothing to revoke when the mint failed");
    Ok(())
}

// --- console redaction + revoke-failure warnings (M-6 / L-12) ---------------

/// M-6: a console that echoes the minted token never reaches the envelope, or
/// the journaled terminal record, in the clear.
#[test]
fn credentialed_run_redacts_the_token_from_the_console() -> anyhow::Result<()> {
    let (tmp, journal) = fresh_journal()?;
    let token = "ghs_super_secret_marker_value";
    let provider = FakeProvider::returning(token);
    let backend = FakeBackend::new().with_outcome(Outcome {
        booted: true,
        guest_exit: Some(0),
        transport_error: None,
        timed_out: false,
        console: format!("booting...\ngit credential fill -> {token}\ndone"),
    });
    let cred_dir = tmp.path().join("cred");
    std::fs::create_dir_all(&cred_dir).context("create cred dir")?;
    std::fs::set_permissions(&cred_dir, std::fs::Permissions::from_mode(0o700)).context("cred dir 0700")?;

    let report = run_job_with_credential(
        &backend,
        &journal,
        booting_plan(),
        &FakeApplier::new(),
        EgressOs::Linux,
        None,
        &provider,
        &token_scope(),
        "GH_TOKEN",
        &cred_dir,
        1_800,
    )
    .context("run_job_with_credential (console echoes token)")?;

    assert!(
        !report.envelope.logs.tail.contains(token),
        "the returned envelope must not carry the raw token: {:?}",
        report.envelope.logs.tail
    );
    assert!(
        report.envelope.logs.tail.contains("[REDACTED]"),
        "the console must show the redaction marker: {:?}",
        report.envelope.logs.tail
    );

    let record = journal
        .read_record(&report.envelope.job_id)
        .context("terminal record must be on disk")?;
    let persisted = record.result.context("terminal record must carry the envelope")?;
    assert!(
        !persisted.logs.tail.contains(token),
        "the journaled terminal record must not carry the raw token: {:?}",
        persisted.logs.tail
    );
    Ok(())
}

/// A `Vec<u8>`-backed [`tracing_subscriber`] writer shared with the test, so a
/// subscriber installed for just one call can be inspected afterward.
#[derive(Clone, Default)]
struct SharedBuf(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl SharedBuf {
    fn contents(&self) -> anyhow::Result<String> {
        let bytes = self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
        String::from_utf8(bytes).context("captured log is utf8")
    }
}

impl std::io::Write for SharedBuf {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for SharedBuf {
    type Writer = SharedBuf;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// L-12: a revoke failure at teardown never fails the run, is folded into the
/// envelope's `warnings` naming the credential, and the `tracing::warn!` event
/// carries the job id with no token substring anywhere in it.
#[test]
fn credential_revoke_failure_surfaces_as_a_warning_not_a_fault() -> anyhow::Result<()> {
    let (tmp, journal) = fresh_journal()?;
    let token = "ghs_revoke_failure_marker_value";
    let provider = FakeProvider::returning(token).with_failing_revoke();
    let backend = FakeBackend::new().with_outcome(ok_outcome(0));
    let cred_dir = tmp.path().join("cred");
    std::fs::create_dir_all(&cred_dir).context("create cred dir")?;
    std::fs::set_permissions(&cred_dir, std::fs::Permissions::from_mode(0o700)).context("cred dir 0700")?;

    let buf = SharedBuf::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(buf.clone())
        .with_ansi(false)
        .finish();
    let report = tracing::subscriber::with_default(subscriber, || {
        run_job_with_credential(
            &backend,
            &journal,
            booting_plan(),
            &FakeApplier::new(),
            EgressOs::Linux,
            None,
            &provider,
            &token_scope(),
            "GH_TOKEN",
            &cred_dir,
            1_800,
        )
    })
    .context("run_job_with_credential (revoke fails)")?;

    assert_eq!(
        report.envelope.status,
        Status::Succeeded,
        "a revoke failure must not fail an otherwise-successful run"
    );
    assert_eq!(
        report.envelope.warnings.len(),
        1,
        "the envelope must carry exactly one warning: {:?}",
        report.envelope.warnings
    );
    assert!(
        report.envelope.warnings[0].contains("GH_TOKEN"),
        "the warning must name the credential: {:?}",
        report.envelope.warnings
    );

    // The journaled terminal record must carry the same warning (INV-6: the
    // record always carries the envelope) — not just the returned `RunReport`.
    let persisted = journal
        .read_record(&report.envelope.job_id)
        .context("terminal record must be on disk")?
        .result
        .context("terminal record must carry the envelope")?;
    assert_eq!(
        persisted.warnings, report.envelope.warnings,
        "the journaled record's warnings must match the returned envelope's"
    );

    let logged = buf.contents()?;
    let warn_line = logged
        .lines()
        .find(|line| line.contains("credential revoke at teardown failed"))
        .with_context(|| format!("no warn event emitted for the revoke failure: {logged}"))?;
    assert!(
        warn_line.contains(&report.envelope.job_id),
        "the warn event's own line must carry the job id: {warn_line}"
    );
    assert!(
        !logged.contains(token),
        "the warn event must never carry the token value: {logged}"
    );
    Ok(())
}

// `should_refresh` and its refresh sibling now live in `sandy::cred`, unit-tested
// there (cred.rs) with the rest of the refresh-re-delivery logic (#49).
