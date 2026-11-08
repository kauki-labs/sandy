//! Tier-2 integration tests for the `sandy` job ops over a `FakeBackend` and a
//! real [`Journal`] on a `tempfile::TempDir` `$SANDY_HOME`. No hypervisor boots:
//! the live-boot proof is tier-3 (#26). Every command has a positive and an
//! adversarial case.

use std::{
    os::unix::fs::PermissionsExt,
    sync::atomic::{AtomicU32, Ordering},
    time::{Duration, SystemTime},
};

use anyhow::Context;
use sandy::{
    AllowList, BackendError, BoxState, Capability, CoreError, EgressEnforcement, EgressOs, EgressRule, Grants,
    JOURNAL_SCHEMA_VERSION, JobRecord, JobState, Journal, Logs, Outcome, Provenance, RESULT_SCHEMA_VERSION,
    ResultEnvelope, RunSpec, Scope, SecretRef, SecretSource, Status, Target, VmBackend, to_nftables_forward,
};
use sandy_cli::{
    plan::JobPlan,
    supervisor::{gc, kill, ls, mint_run_token, run_job, run_job_with_credential, status, wait},
};
use sandy_test_support::{FakeApplier, FakeBackend, FakeProvider};

/// #358's exact envelope warning: `--allow` entries have no effect on a guest
/// with no network device (macOS, or Linux without a bound tap).
const NO_NETWORK_ALLOW_WARNING: &str =
    "egress unavailable: the guest has no network device, so --allow entries have no effect (see #360)";

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

/// The `(dev, ino)` fingerprint of an already-validated dir, as the production
/// `run_credentialed` captures it from `private_staging_dir` before calling
/// `run_job_with_credential` (#323).
fn fingerprint(dir: &std::path::Path) -> anyhow::Result<sandy::DirFingerprint> {
    let (dev, ino) = sandy_fsutil::OwnedDir::open(dir)
        .context("open dir to fingerprint")?
        .dev_ino()?;
    Ok(sandy::DirFingerprint { dev, ino })
}

/// A scripted physical outcome: booted, with the given guest exit code.
fn ok_outcome(guest_exit: i32) -> Outcome {
    Outcome {
        digests: None,
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
        digests: false,
        template: "demo".to_string(),
        command: vec![],
        inputs: vec![],
        outputs: vec![],
        secrets: vec![],
        env: vec![],
        allow: AllowList::default(),
        egress_proxy: false,
        network: sandy::NetworkMode::None,
        cpu: None,
        mem: None,
        timeout_secs: 60,
        grants: Grants {
            secrets: false,
            agent: false,
            shares: false,
        },
        secret_dir: None,
        control: sandy::RunControl::with_timeout_secs(60),
    }
}

/// `plan` as a `network = nic` run: a bound tap needs the profile (#602), or the plan is invalid.
fn on_tap(plan: JobPlan) -> JobPlan {
    JobPlan {
        network: sandy::NetworkMode::Nic,
        ..plan
    }
}

/// A plan whose secret name is also set as a plain env var — rejected by
/// `validate_no_secret_leak` (INV-1).
fn leaking_plan() -> JobPlan {
    JobPlan {
        digests: false,
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
        egress_proxy: false,
        network: sandy::NetworkMode::None,
        cpu: None,
        mem: None,
        timeout_secs: 60,
        grants: Grants {
            secrets: true,
            agent: false,
            shares: false,
        },
        secret_dir: None,
        control: sandy::RunControl::with_timeout_secs(60),
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
            receipt: None,
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

/// #373: digests the backend reports reach the receipt in the right section:
/// inputs under `host_observed`, outputs under `guest_reported` (on the entry the
/// supervisor listed for that path), and skipped output entries beside them.
/// `FakeBackend` stages and collects nothing, so the hashing itself is covered by
/// the `stage` unit tests over the real `stage_inputs` / `collect_outputs`; this
/// proves only the supervisor's placement of a scripted report.
#[test]
fn run_places_reported_digests_in_the_right_receipt_sections() -> anyhow::Result<()> {
    use sandy::{ContentDigests, FileDigest, RunDigests, SkipReason, SkippedEntry};

    const HELLO: &str = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
    const WORLD: &str = "486ea46224d1bb4fb680f34f7c9ad96a8f24ec88be73ea8e5a6c65260e9cb8a7";
    let (tmp, journal) = fresh_journal()?;
    let dest = tmp.path().join("collected");
    std::fs::create_dir_all(&dest).context("mk output dest")?;
    std::fs::write(dest.join("f"), b"hello").context("write output")?;
    std::fs::write(dest.join("stale"), b"left by someone else").context("write stale file")?;
    let mut plan = booting_plan();
    plan.digests = true;
    plan.outputs = vec![sandy::Output {
        name: Some("result".to_string()),
        dest,
    }];
    let mut outcome = ok_outcome(0);
    outcome.digests = Some(RunDigests {
        inputs: ContentDigests {
            files: vec![FileDigest {
                path: "in/a".to_string(),
                sha256: WORLD.to_string(),
            }],
            skipped: vec![],
        },
        outputs: ContentDigests {
            files: vec![FileDigest {
                path: "result/f".to_string(),
                sha256: HELLO.to_string(),
            }],
            skipped: vec![SkippedEntry {
                path: "result/leak".to_string(),
                reason: SkipReason::Symlink,
            }],
        },
    });

    let backend = FakeBackend::new().with_outcome(outcome);
    let report = run_job(
        &backend,
        &journal,
        &plan,
        &FakeApplier::new(),
        EgressOs::Linux,
        None,
        &[],
    )
    .context("run_job with digests")?;

    let receipt = report.envelope.receipt.context("receipt")?;
    let inputs = receipt
        .host_observed
        .input_digests
        .context("input digests are host-observed")?;
    assert_eq!(inputs.files.len(), 1);
    assert_eq!(
        (inputs.files[0].path.as_str(), inputs.files[0].sha256.as_str()),
        ("in/a", WORLD)
    );
    let outputs: Vec<(&str, Option<&str>)> = receipt
        .guest_reported
        .outputs
        .iter()
        .map(|o| (o.path.as_str(), o.sha256.as_deref()))
        .collect();
    assert_eq!(
        outputs,
        [("result/f", Some(HELLO)), ("result/stale", None)],
        "a file this run did not collect carries no digest"
    );
    assert_eq!(
        receipt.guest_reported.skipped_outputs,
        [SkippedEntry {
            path: "result/leak".to_string(),
            reason: SkipReason::Symlink
        }]
    );
    Ok(())
}

/// A backend that runs the REAL staging and collection code on tempdirs, as qemu, vfkit and the
/// process backend do, and reports what a guest that wrote one output file would. `FakeBackend`
/// cannot do this: it stages nothing, and `sandy-test-support` cannot depend on `sandy`.
struct StagingBackend {
    work: std::path::PathBuf,
}

impl sandy::VmBackend for StagingBackend {
    fn run(&self, spec: &sandy::RunSpec) -> Result<Outcome, BackendError> {
        let (inputs_dir, outputs_dir) = (self.work.join("inputs"), self.work.join("outputs"));
        sandy::stage_inputs(spec.inputs, &inputs_dir)?;
        let input_digests = spec
            .digests
            .then(|| sandy::digest_staged_inputs(spec.inputs, &inputs_dir))
            .transpose()?;
        sandy::prepare_outputs(spec.outputs, &outputs_dir)?;
        // The "guest" writes one output file after boot.
        std::fs::write(outputs_dir.join("result").join("f"), b"hello")
            .map_err(|e| BackendError::Spawn(e.to_string()))?;
        let collected = sandy::collect_outputs(spec.outputs, &outputs_dir, spec.digests);
        sandy::with_digests(Ok(ok_outcome(0)), input_digests, collected)
    }

    fn kill(&self, _box_id: &str) -> Result<(), BackendError> {
        Ok(())
    }

    fn boxes(&self) -> Result<Vec<sandy::BoxState>, BackendError> {
        Ok(vec![])
    }
}

/// #373: known content flows through the real `stage_inputs`, `digest_staged_inputs`, and
/// `collect_outputs`, then through the supervisor, and the receipt carries the known sha256 values in
/// the right sections. This is the end-to-end check the scripted-outcome test above cannot give: it
/// fails if the staged or collected bytes hash differently from what the receipt reports.
#[test]
fn run_digests_known_content_through_the_real_staging_and_collection() -> anyhow::Result<()> {
    const HELLO: &str = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
    const WORLD: &str = "486ea46224d1bb4fb680f34f7c9ad96a8f24ec88be73ea8e5a6c65260e9cb8a7";
    let (tmp, journal) = fresh_journal()?;
    let source = tmp.path().join("source");
    std::fs::create_dir_all(&source).context("mk input source")?;
    std::fs::write(source.join("a"), b"world").context("write input")?;
    let work = tmp.path().join("work");
    std::fs::create_dir_all(&work).context("mk work dir")?;
    let mut plan = booting_plan();
    plan.digests = true;
    plan.inputs = vec![sandy::Input {
        host: source,
        name: "in".to_string(),
        guest_path: None,
    }];
    plan.outputs = vec![sandy::Output {
        name: Some("result".to_string()),
        dest: tmp.path().join("collected"),
    }];

    let report = run_job(
        &StagingBackend { work },
        &journal,
        &plan,
        &FakeApplier::new(),
        EgressOs::Linux,
        None,
        &[],
    )
    .context("run_job over the real staging")?;

    assert_eq!(report.process_exit.code(), 0, "{}", report.envelope.message);
    let receipt = report.envelope.receipt.context("receipt")?;
    let inputs = receipt
        .host_observed
        .input_digests
        .context("input digests are host-observed")?;
    let input_files: Vec<(&str, &str)> = inputs
        .files
        .iter()
        .map(|d| (d.path.as_str(), d.sha256.as_str()))
        .collect();
    assert_eq!(input_files, [("in/a", WORLD)]);
    let outputs: Vec<(&str, Option<&str>)> = receipt
        .guest_reported
        .outputs
        .iter()
        .map(|o| (o.path.as_str(), o.sha256.as_deref()))
        .collect();
    assert_eq!(outputs, [("result/f", Some(HELLO))]);
    assert!(receipt.guest_reported.skipped_outputs.is_empty());
    Ok(())
}

/// #373: with `--digests` off the supervisor asks for no hashing and the serialized
/// envelope has no digest key anywhere.
#[test]
fn run_without_digests_flag_requests_none_and_serializes_no_digest_keys() -> anyhow::Result<()> {
    let (tmp, journal) = fresh_journal()?;
    let dest = tmp.path().join("collected");
    std::fs::create_dir_all(&dest).context("mk output dest")?;
    std::fs::write(dest.join("f"), b"hello").context("write output")?;
    let mut plan = booting_plan();
    plan.outputs = vec![sandy::Output {
        name: Some("result".to_string()),
        dest,
    }];
    assert!(!plan.digests && !plan.as_run_spec().digests, "off by default");

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
    .context("run_job without digests")?;

    let json = serde_json::to_string(&report.envelope)?;
    assert!(json.contains("size_bytes"), "the receipt itself is present: {json}");
    for key in ["sha256", "input_digests", "skipped"] {
        assert!(!json.contains(key), "unexpected `{key}` in {json}");
    }
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
        digests: None,
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
    let report = gc(&journal, 2).context("gc")?;
    let evicted = &report.evicted;

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

/// A plan that boots `demo` behind a one-rule allow-list (`1.1.1.1:443`). An IP
/// entry, not a hostname: these tests exercise the egress-bracketing mechanics
/// (apply/revert, fail-closed), not matching, and a hostname is refused at plan
/// time on Linux (#359).
fn allowing_plan() -> JobPlan {
    JobPlan {
        digests: false,
        allow: AllowList {
            rules: vec![EgressRule {
                host: "1.1.1.1".to_string(),
                port: 443,
            }],
        },
        ..booting_plan()
    }
}

/// A plan behind a one-rule allow-list naming `github.com:443` — a hostname
/// entry. macOS enforces no per-VM boundary, so this stays accepted there (#358);
/// used only by the macOS egress test.
fn allowing_plan_by_hostname() -> JobPlan {
    JobPlan {
        digests: false,
        allow: AllowList {
            rules: vec![EgressRule {
                host: "github.com".to_string(),
                port: 443,
            }],
        },
        ..booting_plan()
    }
}

/// #359: on Linux, a hostname allow-list entry is refused at plan time as an
/// invalid plan (band 2) — no journal record, no boot. nft pins a hostname to
/// one address at load time and the guest can't resolve names through the
/// boundary anyway, so it is refused rather than loaded as a rule that never
/// matches.
#[test]
fn run_hostname_allow_on_linux_is_invalid_plan_writes_no_record_and_never_boots() -> anyhow::Result<()> {
    let (_tmp, journal) = fresh_journal()?;
    // A success is scripted on purpose: if the backend were ever run the band
    // would be 0, so band 2 here proves the boot was skipped.
    let backend = FakeBackend::new().with_outcome(ok_outcome(0));

    let report = run_job(
        &backend,
        &journal,
        &on_tap(allowing_plan_by_hostname()),
        &FakeApplier::new(),
        EgressOs::Linux,
        Some("sandytap0"),
        &[],
    )
    .context("run_job (hostname allow entry, linux)")?;

    assert_eq!(
        report.process_exit.code(),
        2,
        "a hostname allow entry on Linux is band 2"
    );
    assert!(!report.envelope.retryable, "band 2 is never retryable");
    assert!(
        report.envelope.message.contains("github.com"),
        "the error must name the refused entry: {}",
        report.envelope.message
    );
    assert!(
        report.envelope.message.contains("377"),
        "the error must point to #377 (hostname support via the egress proxy): {}",
        report.envelope.message
    );
    assert!(
        journal.list().context("list after hostname allow entry")?.is_empty(),
        "a refused hostname entry must write no job record"
    );
    assert!(
        backend.killed().is_empty(),
        "a refused hostname entry must not touch the backend"
    );
    Ok(())
}

/// A proxy-mode plan (`SANDY_EGRESS=proxy`, #360) behind hostname entries, which
/// the nftables plan refuses on Linux (#359).
fn proxy_plan() -> JobPlan {
    JobPlan {
        digests: false,
        allow: AllowList {
            rules: vec![
                EgressRule {
                    host: "github.com".to_string(),
                    port: 443,
                },
                EgressRule {
                    host: "localhost".to_string(),
                    port: 8080,
                },
            ],
        },
        egress_proxy: true,
        network: sandy::NetworkMode::None,
        ..booting_plan()
    }
}

/// #360: on Linux a bound `$SANDY_TAP` with `SANDY_EGRESS=proxy` would put two
/// boundary models on one guest, so it is an invalid plan (band 2): no journal
/// record, no boot, no ruleset.
#[test]
fn run_proxy_mode_with_a_bound_tap_on_linux_is_invalid_plan_writes_no_record_and_never_boots() -> anyhow::Result<()> {
    let (_tmp, journal) = fresh_journal()?;
    // A success is scripted on purpose: a boot would make the band 0.
    let backend = FakeBackend::new().with_outcome(ok_outcome(0));
    let applier = FakeApplier::new();

    let report = run_job(
        &backend,
        &journal,
        &proxy_plan(),
        &applier,
        EgressOs::Linux,
        Some("sandytap0"),
        &[],
    )
    .context("run_job (proxy mode with a tap, linux)")?;

    assert_eq!(report.process_exit.code(), 2, "proxy mode with a tap is band 2");
    assert!(!report.envelope.retryable, "band 2 is never retryable");
    assert!(
        report.envelope.message.contains("SANDY_TAP"),
        "the error must name the conflicting variable: {}",
        report.envelope.message
    );
    assert!(
        journal.list().context("list after refused proxy plan")?.is_empty(),
        "a refused plan must write no job record"
    );
    assert!(
        backend.run_egress().is_empty(),
        "a refused plan must never reach the backend"
    );
    assert!(
        applier.applied_rulesets().is_empty(),
        "a refused plan applies no ruleset"
    );
    Ok(())
}

/// #602: a profile that disagrees with the tap or the proxy is an invalid plan (band 2): no journal record, no boot,
/// no ruleset. Deleting the `validate_network_mode` call from the supervisor must fail this test.
#[test]
fn run_a_network_profile_that_disagrees_with_the_tap_or_proxy_is_refused_before_anything_runs() -> anyhow::Result<()> {
    let nic = |plan: JobPlan| JobPlan {
        network: sandy::NetworkMode::Nic,
        ..plan
    };
    let cases: Vec<(&str, JobPlan, Option<&str>)> = vec![
        ("nic without a tap", nic(allowing_plan()), None),
        ("a tap without nic", allowing_plan(), Some("sandytap0")),
        ("nic with the proxy", nic(proxy_plan()), None),
        (
            "nic with a malformed tap",
            nic(allowing_plan()),
            Some("sandytap0,vhost=on"),
        ),
    ];
    for (name, plan, tap) in cases {
        let (_tmp, journal) = fresh_journal()?;
        // A success is scripted on purpose: a boot would make the band 0.
        let backend = FakeBackend::new().with_outcome(ok_outcome(0));
        let applier = FakeApplier::new();
        let report = run_job(&backend, &journal, &plan, &applier, EgressOs::Linux, tap, &[])
            .with_context(|| format!("run_job ({name})"))?;
        assert_eq!(report.process_exit.code(), 2, "{name}: band 2");
        assert!(!report.envelope.retryable, "{name}: band 2 is never retryable");
        assert!(journal.list().context(name)?.is_empty(), "{name}: no job record");
        assert!(backend.run_egress().is_empty(), "{name}: the backend never runs");
        assert!(applier.applied_rulesets().is_empty(), "{name}: no ruleset");
    }
    Ok(())
}

/// #360: in proxy mode the backend receives the allow-list in `RunSpec`, the
/// applier sees no apply and no revert, and hostname entries pass plan
/// validation (#359's refusal is scoped to the nftables plan).
#[test]
fn run_proxy_mode_hands_the_allow_list_to_the_backend_and_applies_no_ruleset() -> anyhow::Result<()> {
    let (_tmp, journal) = fresh_journal()?;
    let backend = FakeBackend::new().with_outcome(ok_outcome(0));
    let applier = FakeApplier::new();
    let plan = proxy_plan();

    let report = run_job(&backend, &journal, &plan, &applier, EgressOs::Linux, None, &[])
        .context("run_job (proxy mode, linux, no tap)")?;

    assert_eq!(
        report.process_exit.code(),
        0,
        "hostname entries are valid in proxy mode: {}",
        report.envelope.message
    );
    assert_eq!(
        backend.run_egress(),
        vec![Some(plan.allow.clone())],
        "the backend must receive exactly the plan's allow-list"
    );
    assert!(
        applier.applied_rulesets().is_empty(),
        "proxy mode applies no nftables ruleset"
    );
    assert!(!applier.was_reverted(), "proxy mode reverts nothing");
    assert!(
        report.envelope.warnings.is_empty(),
        "the no-NIC `--allow has no effect` warning would be false in proxy mode: {:?}",
        report.envelope.warnings
    );
    let egress = report.envelope.receipt.context("receipt")?.host_observed.egress;
    assert_eq!(egress.status, EgressEnforcement::Enforced);
    assert_eq!(egress.allow_list.as_ref(), Some(&plan.allow));
    Ok(())
}

/// A plan with no proxy mode hands the backend no policy: the nftables path is unchanged.
#[test]
fn run_without_proxy_mode_hands_the_backend_no_policy() -> anyhow::Result<()> {
    let (_tmp, journal) = fresh_journal()?;
    let backend = FakeBackend::new().with_outcome(ok_outcome(0));

    run_job(
        &backend,
        &journal,
        &on_tap(allowing_plan()),
        &FakeApplier::new(),
        EgressOs::Linux,
        Some("sandytap0"),
        &[],
    )
    .context("run_job (nftables path)")?;

    assert_eq!(backend.run_egress(), vec![None]);
    Ok(())
}

/// #360: the receipt records the proxy as enforcing only if the run reached it. A
/// backend that refuses the policy before boot (`Spawn`) left it unapplied, and the
/// receipt says so, with the reason and no allow-list.
#[test]
fn receipt_reports_a_proxy_refused_before_boot_as_unenforced() -> anyhow::Result<()> {
    let (_tmp, journal) = fresh_journal()?;
    let backend = FakeBackend::new().with_error(BackendError::Spawn(
        "the vfkit backend does not support the egress proxy yet".to_string(),
    ));

    let report = run_job(
        &backend,
        &journal,
        &proxy_plan(),
        &FakeApplier::new(),
        EgressOs::Linux,
        None,
        &[],
    )
    .context("run_job (proxy refused before boot)")?;

    assert_eq!(report.process_exit.code(), 3, "a refusal before boot is an infra fault");
    let egress = report.envelope.receipt.context("receipt")?.host_observed.egress;
    assert_eq!(egress.status, EgressEnforcement::Unenforced);
    assert!(
        egress.allow_list.is_none(),
        "an allow-list that was never applied must not be recorded"
    );
    let reason = egress.reason.context("an unenforced receipt names why")?;
    assert!(reason.contains("does not support the egress proxy"), "{reason}");
    Ok(())
}

/// #360: a guest that never booted ran behind no proxy, so its receipt is not `enforced` either.
#[test]
fn receipt_reports_a_proxy_run_that_never_booted_as_unenforced() -> anyhow::Result<()> {
    let (_tmp, journal) = fresh_journal()?;
    let backend = FakeBackend::new().with_outcome(Outcome {
        digests: None,
        booted: false,
        guest_exit: None,
        transport_error: None,
        timed_out: false,
        console: String::new(),
    });

    let report = run_job(
        &backend,
        &journal,
        &proxy_plan(),
        &FakeApplier::new(),
        EgressOs::Linux,
        None,
        &[],
    )
    .context("run_job (proxy, never booted)")?;

    let egress = report.envelope.receipt.context("receipt")?.host_observed.egress;
    assert_eq!(egress.status, EgressEnforcement::Unenforced);
    assert!(egress.allow_list.is_none());
    Ok(())
}

/// #360: a proxy found dead before the guest booted served no run, so its receipt is not
/// `enforced` either: `guest_exit: None` alone could not tell this from a mid-run death.
#[test]
fn receipt_reports_a_proxy_that_died_before_the_guest_booted_as_unenforced() -> anyhow::Result<()> {
    let (_tmp, journal) = fresh_journal()?;
    let backend = FakeBackend::new().with_error(BackendError::EgressProxyDied {
        status: Some(1),
        booted: false,
        guest_exit: None,
    });

    let report = run_job(
        &backend,
        &journal,
        &proxy_plan(),
        &FakeApplier::new(),
        EgressOs::Linux,
        None,
        &[],
    )
    .context("run_job (proxy died before boot)")?;

    assert_eq!(report.process_exit.code(), 3, "a dead proxy is an infra fault");
    let egress = report.envelope.receipt.context("receipt")?.host_observed.egress;
    assert_eq!(egress.status, EgressEnforcement::Unenforced);
    assert!(egress.allow_list.is_none());
    Ok(())
}

/// #360: a proxy that died after it served the run stays recorded as enforced: the
/// boundary held, and the death is its own band-3 fault.
#[test]
fn receipt_keeps_a_proxy_that_died_mid_run_as_enforced() -> anyhow::Result<()> {
    let (_tmp, journal) = fresh_journal()?;
    let backend = FakeBackend::new().with_error(BackendError::EgressProxyDied {
        status: Some(2),
        booted: true,
        guest_exit: Some(0),
    });
    let plan = proxy_plan();

    let report = run_job(
        &backend,
        &journal,
        &plan,
        &FakeApplier::new(),
        EgressOs::Linux,
        None,
        &[],
    )
    .context("run_job (proxy died)")?;

    let egress = report.envelope.receipt.context("receipt")?.host_observed.egress;
    assert_eq!(egress.status, EgressEnforcement::Enforced);
    assert_eq!(egress.allow_list.as_ref(), Some(&plan.allow));
    Ok(())
}

/// #360: a proxy that died mid-run makes the run band 3 and retryable even though
/// the guest exited 0, and the envelope names both exits.
#[test]
fn run_a_dead_egress_proxy_is_band_three_whatever_the_guest_exit() -> anyhow::Result<()> {
    let (_tmp, journal) = fresh_journal()?;
    let backend = FakeBackend::new().with_error(BackendError::EgressProxyDied {
        status: Some(2),
        booted: true,
        guest_exit: Some(0),
    });

    let report = run_job(
        &backend,
        &journal,
        &proxy_plan(),
        &FakeApplier::new(),
        EgressOs::Linux,
        None,
        &[],
    )
    .context("run_job (proxy died)")?;

    assert_eq!(report.process_exit.code(), 3, "a dead proxy is an infra fault");
    assert!(report.envelope.retryable);
    assert_ne!(report.envelope.status, Status::Succeeded);
    assert!(
        report.envelope.message.contains("exit status 2") && report.envelope.message.contains("guest exit 0"),
        "the envelope must name the proxy status and the guest exit: {}",
        report.envelope.message
    );
    Ok(())
}

/// #359 + credentialed path (review finding on #418): a hostname allow-list
/// entry on Linux must be refused BEFORE the credential mint, not after. Minting
/// first would mint-and-immediately-revoke a credential for a plan that was
/// always going to be refused, and a mint failure would mask the clean band-2
/// invalid-plan report behind `CoreError::Cred`.
#[test]
fn run_with_credential_hostname_allow_on_linux_is_invalid_plan_never_mints() -> anyhow::Result<()> {
    let (tmp, journal) = fresh_journal()?;
    let provider = FakeProvider::returning("ghs_should_never_be_minted");
    let backend = FakeBackend::new().with_outcome(ok_outcome(0));
    let cred_dir = tmp.path().join("cred");
    std::fs::create_dir_all(&cred_dir).context("create cred dir")?;
    std::fs::set_permissions(&cred_dir, std::fs::Permissions::from_mode(0o700)).context("cred dir 0700")?;

    let report = run_job_with_credential(
        &backend,
        &journal,
        on_tap(allowing_plan_by_hostname()),
        &FakeApplier::new(),
        EgressOs::Linux,
        Some("sandytap0"),
        &provider,
        &token_scope(),
        "GH_TOKEN",
        &cred_dir,
        fingerprint(&cred_dir)?,
        1_800,
    )
    .context("run_job_with_credential (hostname allow entry, linux)")?;

    assert_eq!(
        report.process_exit.code(),
        2,
        "a hostname allow entry on Linux is band 2, even on the credentialed path"
    );
    assert!(
        report.envelope.message.contains("github.com"),
        "the error must name the refused entry: {}",
        report.envelope.message
    );
    assert!(
        provider.mints().is_empty(),
        "the plan must be rejected before any credential is minted"
    );
    assert!(
        journal.list().context("list after hostname allow entry")?.is_empty(),
        "a refused hostname entry must write no job record"
    );
    Ok(())
}

/// #23: a Linux run with a non-empty allow-list applies the `to_nftables`
/// translation of that allow-list as the boundary, and reverts it after the run.
#[test]
fn run_on_linux_applies_the_allow_list_ruleset_and_reverts_it() -> anyhow::Result<()> {
    let (_tmp, journal) = fresh_journal()?;
    let backend = FakeBackend::new().with_outcome(ok_outcome(0));
    let applier = FakeApplier::new();
    let plan = on_tap(allowing_plan());

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
    assert!(
        report.envelope.warnings.is_empty(),
        "a Linux guest with a bound tap has a real boundary, so --allow has effect: no #358 warning: {:?}",
        report.envelope.warnings
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
        &on_tap(allowing_plan()),
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

/// #24: a macOS run applies no boundary (`vfkit_args` emits no network device),
/// yet the run still succeeds — the honest `NoBoundary` path, not a silent
/// failure. #358: a non-empty `--allow` list has no effect with no NIC to grant
/// it on, so the envelope warns.
#[test]
fn run_on_macos_applies_no_boundary_but_still_succeeds() -> anyhow::Result<()> {
    let (_tmp, journal) = fresh_journal()?;
    let backend = FakeBackend::new().with_outcome(ok_outcome(0));
    let applier = FakeApplier::new();

    // A hostname entry on purpose: macOS enforces no per-VM boundary, so it
    // stays accepted there (#358) even though the same entry is refused on
    // Linux (#359).
    let report = run_job(
        &backend,
        &journal,
        &allowing_plan_by_hostname(),
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
    assert_eq!(
        report.envelope.warnings,
        vec![NO_NETWORK_ALLOW_WARNING],
        "a non-empty --allow list has no effect on a NIC-less macOS guest"
    );
    Ok(())
}

/// #358 (adversarial): an empty `--allow` list grants nothing on macOS either
/// way, so there is nothing for the missing NIC to defeat: no warning.
#[test]
fn run_on_macos_with_an_empty_allow_list_carries_no_warning() -> anyhow::Result<()> {
    let (_tmp, journal) = fresh_journal()?;
    let backend = FakeBackend::new().with_outcome(ok_outcome(0));
    let applier = FakeApplier::new();

    let report = run_job(
        &backend,
        &journal,
        &booting_plan(),
        &applier,
        EgressOs::MacOs,
        None,
        &[],
    )
    .context("run_job (macos, empty allow-list)")?;

    assert!(
        report.envelope.warnings.is_empty(),
        "an empty --allow list has no effect to warn about, NIC or not: {:?}",
        report.envelope.warnings
    );
    Ok(())
}

/// #358: a Linux guest with no bound tap has no NIC either, so a non-empty
/// `--allow` list has no effect there too: same warning as macOS.
#[test]
fn run_on_linux_with_no_tap_and_a_nonempty_allow_list_warns() -> anyhow::Result<()> {
    let (_tmp, journal) = fresh_journal()?;
    let backend = FakeBackend::new().with_outcome(ok_outcome(0));
    let applier = FakeApplier::new();

    let report = run_job(
        &backend,
        &journal,
        &allowing_plan(),
        &applier,
        EgressOs::Linux,
        None,
        &[],
    )
    .context("run_job (linux, no tap)")?;

    assert_eq!(
        report.envelope.warnings,
        vec![NO_NETWORK_ALLOW_WARNING],
        "a non-empty --allow list has no effect on a tap-less Linux guest"
    );
    Ok(())
}

/// #358 (adversarial): a Linux guest with no bound tap and an empty allow-list
/// already denies everything, NIC or not: no warning.
#[test]
fn run_on_linux_with_no_tap_and_an_empty_allow_list_carries_no_warning() -> anyhow::Result<()> {
    let (_tmp, journal) = fresh_journal()?;
    let backend = FakeBackend::new().with_outcome(ok_outcome(0));
    let applier = FakeApplier::new();

    let report = run_job(
        &backend,
        &journal,
        &booting_plan(),
        &applier,
        EgressOs::Linux,
        None,
        &[],
    )
    .context("run_job (linux, no tap, empty allow-list)")?;

    assert!(
        report.envelope.warnings.is_empty(),
        "an empty --allow list has no effect to warn about, NIC or not: {:?}",
        report.envelope.warnings
    );
    Ok(())
}

/// #358 (review finding): the process backend shares the host network with no
/// isolation boundary at all — it has no guest and no NIC to lack. A non-empty
/// `--allow` list is just as unenforced there, but the warning must name the
/// real cause instead of claiming "the guest has no network device", which
/// does not describe a process run.
#[test]
fn run_on_the_process_backend_with_a_nonempty_allow_list_warns_with_the_right_cause() -> anyhow::Result<()> {
    let (_tmp, journal) = fresh_journal()?;
    let backend = FakeBackend::new()
        .with_outcome(ok_outcome(0))
        .with_kind(sandy::SandboxKind::Process);
    let applier = FakeApplier::new();

    let report = run_job(
        &backend,
        &journal,
        &allowing_plan(),
        &applier,
        EgressOs::Linux,
        None,
        &[],
    )
    .context("run_job (process backend)")?;

    assert_eq!(
        report.envelope.warnings,
        vec![
            "egress unavailable: the process backend shares the host network with no isolation boundary, so --allow \
             entries have no effect"
        ],
        "the process backend's warning must name the real cause, not the no-NIC VM reason"
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
        &on_tap(allowing_plan()),
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
        digests: false,
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
        fingerprint(&cred_dir)?,
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
        fingerprint(&cred_dir)?,
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
        fingerprint(&cred_dir)?,
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
        digests: None,
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
        fingerprint(&cred_dir)?,
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
    let cred_fingerprint = fingerprint(&cred_dir)?;

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
            cred_fingerprint,
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

// --- envelope receipts v1 (#361) ---------------------------------------------

/// The receipt is populated for a direct (non-sandyd) run, and `who` is the
/// local-uid fallback, `authenticated: false` — there is no submitter cap on
/// this path.
#[test]
fn run_job_populates_the_receipt_for_a_direct_run() -> anyhow::Result<()> {
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
    .context("run_job (receipt, direct)")?;

    let receipt = report
        .envelope
        .receipt
        .clone()
        .context("a run that reached the backend must carry a receipt")?;
    assert!(
        !receipt.host_observed.who.authenticated,
        "a direct run has no submitter cap; who.authenticated must be false"
    );
    assert!(
        !receipt.host_observed.who.identity.is_empty(),
        "who.identity must name the local uid"
    );
    assert_eq!(receipt.host_observed.what.job_id, report.envelope.job_id);
    assert_eq!(receipt.host_observed.what.template, "demo");
    assert_eq!(
        receipt.host_observed.location.backend, "qemu",
        "FakeBackend defaults to SandboxKind::Vm, paired with Linux"
    );
    assert!(
        receipt.host_observed.credential.is_none(),
        "a non-credentialed run must carry no credential receipt"
    );
    assert_eq!(receipt.guest_reported.exit_code, Some(0));
    assert!(receipt.guest_reported.outputs.is_empty(), "no outputs were declared");

    // The journaled copy must carry the same receipt (INV-6).
    let persisted = journal
        .read_record(&report.envelope.job_id)
        .context("terminal record must be on disk")?
        .result
        .context("terminal record must carry the envelope")?;
    assert_eq!(persisted.receipt, report.envelope.receipt);
    Ok(())
}

/// `booting_plan`'s run has no guest tap, so `plan_egress_scoped` yields
/// `NoBoundary` (macOS-style honesty even on the Linux egress_os used in these
/// tests) — the receipt's egress half must report `unenforced` with a reason
/// and no applied allow-list.
#[test]
fn receipt_reports_unenforced_egress_with_a_reason_and_no_allow_list() -> anyhow::Result<()> {
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
    .context("run_job (receipt, unenforced egress)")?;

    let egress = report.envelope.receipt.context("receipt")?.host_observed.egress;
    assert_eq!(egress.status, EgressEnforcement::Unenforced);
    assert!(egress.reason.is_some(), "an unenforced boundary must name why");
    assert!(
        egress.allow_list.is_none(),
        "nothing was applied; the allow-list field must not claim otherwise"
    );
    assert!(egress.attempts.is_empty(), "attempts is reserved and empty until #375");
    Ok(())
}

/// A Linux run with a bound tap enforces the guest-scoped ruleset — the
/// receipt's egress half must report `enforced` with the allow-list that was
/// actually applied, and no reason (there is nothing to explain).
#[test]
fn receipt_reports_enforced_egress_with_the_applied_allow_list() -> anyhow::Result<()> {
    let (_tmp, journal) = fresh_journal()?;
    let backend = FakeBackend::new().with_outcome(ok_outcome(0));
    let plan = on_tap(allowing_plan());

    let report = run_job(
        &backend,
        &journal,
        &plan,
        &FakeApplier::new(),
        EgressOs::Linux,
        Some("sandytap0"),
        &[],
    )
    .context("run_job (receipt, enforced egress)")?;

    let egress = report.envelope.receipt.context("receipt")?.host_observed.egress;
    assert_eq!(egress.status, EgressEnforcement::Enforced);
    assert!(egress.reason.is_none(), "an enforced boundary needs no explanation");
    assert_eq!(
        egress.allow_list.as_ref(),
        Some(&plan.allow),
        "the receipt must carry the SAME allow-list that was actually applied"
    );
    Ok(())
}

/// An egress apply failure (fail-closed, band 3) still must not be reported as
/// "enforced": the receipt's egress half names it `unenforced`, with a reason.
#[test]
fn receipt_reports_a_failed_egress_apply_as_unenforced() -> anyhow::Result<()> {
    let (_tmp, journal) = fresh_journal()?;
    let backend = FakeBackend::new().with_outcome(ok_outcome(0));

    let report = run_job(
        &backend,
        &journal,
        &on_tap(allowing_plan()),
        &FailingApplier,
        EgressOs::Linux,
        Some("sandytap0"),
        &[],
    )
    .context("run_job (receipt, egress apply failed)")?;

    let egress = report.envelope.receipt.context("receipt")?.host_observed.egress;
    assert_eq!(egress.status, EgressEnforcement::Unenforced);
    assert!(
        egress.reason.as_deref().is_some_and(|r| r.contains("egress boundary")),
        "the reason must name the apply failure: {:?}",
        egress.reason
    );
    assert!(egress.allow_list.is_none());
    Ok(())
}

/// The receipt is populated for a credentialed run too, with the credential
/// lease's lifecycle (mint/revoke) filled in — never the token itself (INV-1).
#[test]
fn credentialed_run_populates_the_receipts_credential_lease() -> anyhow::Result<()> {
    let (tmp, journal) = fresh_journal()?;
    let provider = FakeProvider::returning("ghs_receipt_cred_marker");
    let backend = FakeBackend::new().with_outcome(ok_outcome(0));
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
        fingerprint(&cred_dir)?,
        1_800,
    )
    .context("run_job_with_credential (receipt)")?;

    let receipt = report
        .envelope
        .receipt
        .clone()
        .context("a credentialed run must carry a receipt")?;
    let credential = receipt
        .host_observed
        .credential
        .context("a credentialed run's receipt must carry a credential lease")?;
    assert_eq!(credential.provider, "github");
    assert_eq!(credential.scope, token_scope());
    assert!(credential.revoke_succeeded, "the fake provider's revoke must succeed");
    assert!(
        credential.revoked_at >= credential.minted_at,
        "revoke must be observed no earlier than mint"
    );
    assert!(
        !receipt.host_observed.who.authenticated,
        "no submitter cap on this path either"
    );

    // The journaled copy must carry the same credential receipt (INV-6).
    let persisted = journal
        .read_record(&report.envelope.job_id)
        .context("terminal record must be on disk")?
        .result
        .context("terminal record must carry the envelope")?;
    assert_eq!(persisted.receipt, report.envelope.receipt);
    Ok(())
}

/// Adversarial (INV-1): no token or secret bytes appear anywhere in the
/// serialized envelope — not in `logs.tail` (M-6, already covered), and not in
/// any receipt field either. Driven as a real mutation test: the assertion is
/// first proven capable of failing by temporarily smuggling the token into a
/// receipt field, then the real (non-smuggled) code is asserted clean.
#[test]
fn no_token_or_secret_bytes_anywhere_in_the_serialized_envelope() -> anyhow::Result<()> {
    let (tmp, journal) = fresh_journal()?;
    let token = "ghs_marker_never_in_receipt_or_envelope";
    let provider = FakeProvider::returning(token);
    // The guest console also echoes the token (as `credentialed_run_redacts_...`
    // already does), so this test's marker is genuinely "in flight" during the
    // run, not merely absent because nothing ever touched it.
    let backend = FakeBackend::new().with_outcome(Outcome {
        digests: None,
        booted: true,
        guest_exit: Some(0),
        transport_error: None,
        timed_out: false,
        console: format!("git credential fill -> {token}"),
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
        fingerprint(&cred_dir)?,
        1_800,
    )
    .context("run_job_with_credential (no-leak)")?;

    // Prove this assertion can actually fail (mutation): a receipt carrying the
    // token directly would be caught by the same check below.
    let mut smuggled = report.envelope.clone();
    if let Some(receipt) = &mut smuggled.receipt {
        receipt.host_observed.what.template = token.to_string();
    }
    let smuggled_json = serde_json::to_string(&smuggled).context("serialize smuggled envelope")?;
    assert!(
        smuggled_json.contains(token),
        "sanity: the mutation must actually be observable, or this test proves nothing"
    );

    let json = serde_json::to_string(&report.envelope).context("serialize envelope")?;
    assert!(
        !json.contains(token),
        "the token must never appear anywhere in the serialized envelope: {json}"
    );

    let persisted = journal
        .read_record(&report.envelope.job_id)
        .context("terminal record must be on disk")?;
    let persisted_json = serde_json::to_string(&persisted).context("serialize journaled record")?;
    assert!(
        !persisted_json.contains(token),
        "the token must never appear in the journaled record either: {persisted_json}"
    );
    Ok(())
}

/// A backend that holds the run until its control is cancelled, then returns what the real backends return for a
/// cancel (they treat it like a timeout), and counts the runs it was asked for.
struct HoldsUntilCancelled {
    runs: AtomicU32,
}

impl HoldsUntilCancelled {
    fn new() -> Self {
        Self {
            runs: AtomicU32::new(0),
        }
    }
}

impl VmBackend for HoldsUntilCancelled {
    fn run(&self, spec: &RunSpec) -> Result<Outcome, BackendError> {
        self.runs.fetch_add(1, Ordering::SeqCst);
        while !spec.control.is_cancelled() {
            std::thread::sleep(Duration::from_millis(10));
        }
        Ok(Outcome {
            digests: None,
            booted: true,
            guest_exit: None,
            transport_error: None,
            timed_out: true,
            console: String::new(),
        })
    }

    fn kill(&self, _box_id: &str) -> Result<(), BackendError> {
        Ok(())
    }

    fn boxes(&self) -> Result<Vec<BoxState>, BackendError> {
        Ok(vec![])
    }
}

/// #687: a cancel while the guest runs (what `sandy run` does on SIGTERM) ends the run `cancelled`, band 1, and the
/// journal record reaches that terminal state instead of staying `running`.
#[test]
fn a_run_cancelled_while_the_guest_runs_ends_cancelled_in_band_one() -> anyhow::Result<()> {
    let (_tmp, journal) = fresh_journal()?;
    let backend = HoldsUntilCancelled::new();
    let plan = booting_plan();
    let control = plan.control.clone();
    let canceller = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(200));
        control.cancel();
    });

    let report = run_job(
        &backend,
        &journal,
        &plan,
        &FakeApplier::new(),
        EgressOs::Linux,
        None,
        &[],
    )
    .context("run_job (cancelled mid-run)")?;
    canceller.join().map_err(|_| anyhow::anyhow!("canceller panicked"))?;

    assert_eq!(report.envelope.status, Status::Cancelled);
    assert_eq!(report.process_exit.code(), 1, "a cancel is band 1, not an infra fault");
    assert!(!report.envelope.retryable);
    let records = ls(&journal)?;
    assert_eq!(records.len(), 1);
    assert_eq!(
        records[0].state,
        JobState::Cancelled,
        "the record must not stay running"
    );
    Ok(())
}

/// #687: a cancel that lands before the boot (during mint or setup) starts no guest at all, and still ends
/// `cancelled` with a terminal record.
#[test]
fn a_run_cancelled_before_boot_starts_no_guest() -> anyhow::Result<()> {
    let (_tmp, journal) = fresh_journal()?;
    let backend = HoldsUntilCancelled::new();
    // An allow-list on a bound tap would load nft rules: none may be loaded, or left behind, for a run that never
    // boots.
    let plan = on_tap(allowing_plan());
    plan.control.cancel();
    let applier = FakeApplier::new();

    let report = run_job(
        &backend,
        &journal,
        &plan,
        &applier,
        EgressOs::Linux,
        Some("sandytap0"),
        &[],
    )
    .context("run_job (cancelled before boot)")?;

    assert_eq!(
        backend.runs.load(Ordering::SeqCst),
        0,
        "no guest may start after a cancel"
    );
    assert!(
        applier.applied_rulesets().is_empty(),
        "no egress rules may load for a run that never boots"
    );
    assert_eq!(report.envelope.status, Status::Cancelled);
    assert_eq!(report.process_exit.code(), 1);
    assert_eq!(ls(&journal)?[0].state, JobState::Cancelled);
    Ok(())
}

/// #687, INV-7: the credential bracket still revokes when the run is cancelled, and the record says so.
#[test]
fn a_cancelled_credentialed_run_revokes_the_token_and_records_it() -> anyhow::Result<()> {
    let (tmp, journal) = fresh_journal()?;
    let provider = FakeProvider::returning("ghs_cancelled");
    let backend = HoldsUntilCancelled::new();
    let cred_dir = tmp.path().join("cred");
    std::fs::create_dir_all(&cred_dir).context("create cred dir")?;
    std::fs::set_permissions(&cred_dir, std::fs::Permissions::from_mode(0o700)).context("cred dir 0700")?;
    let plan = booting_plan();
    let control = plan.control.clone();
    let canceller = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(300));
        control.cancel();
    });

    let report = run_job_with_credential(
        &backend,
        &journal,
        plan,
        &FakeApplier::new(),
        EgressOs::Linux,
        None,
        &provider,
        &token_scope(),
        "GH_TOKEN",
        &cred_dir,
        fingerprint(&cred_dir)?,
        1_800,
    )
    .context("run_job_with_credential (cancelled)")?;
    canceller.join().map_err(|_| anyhow::anyhow!("canceller panicked"))?;

    assert_eq!(report.envelope.status, Status::Cancelled);
    assert_eq!(provider.revoked().len(), 1, "the minted token must be revoked");
    let record = &ls(&journal)?[0];
    assert_eq!(record.state, JobState::Cancelled);
    assert!(
        record
            .result
            .as_ref()
            .and_then(|r| r.receipt.as_ref())
            .and_then(|r| r.host_observed.credential.as_ref())
            .is_some_and(|c| c.revoke_succeeded),
        "the record must say the revoke succeeded"
    );
    Ok(())
}

/// A backend that cancels the run itself while the guest is up, then returns `outcome` (a signal that lands as
/// the guest finishes).
struct CancelsThenReturns {
    outcome: Outcome,
}

impl VmBackend for CancelsThenReturns {
    fn run(&self, spec: &RunSpec) -> Result<Outcome, BackendError> {
        spec.control.cancel();
        Ok(self.outcome.clone())
    }

    fn kill(&self, _box_id: &str) -> Result<(), BackendError> {
        Ok(())
    }

    fn boxes(&self) -> Result<Vec<BoxState>, BackendError> {
        Ok(vec![])
    }
}

/// #687: a guest that finished clean before the cancel took effect keeps its result.
#[test]
fn a_clean_run_that_a_signal_lands_on_keeps_its_result() -> anyhow::Result<()> {
    let (_tmp, journal) = fresh_journal()?;
    let backend = CancelsThenReturns { outcome: ok_outcome(0) };

    let report = run_job(
        &backend,
        &journal,
        &booting_plan(),
        &FakeApplier::new(),
        EgressOs::Linux,
        None,
        &[],
    )
    .context("run_job (clean, then cancelled)")?;

    assert_eq!(report.envelope.status, Status::Succeeded);
    assert_eq!(report.process_exit.code(), 0);
    Ok(())
}

/// #687: the override to `cancelled` keeps what the run said, so a real fault is not lost behind the signal.
#[test]
fn a_cancel_keeps_the_original_failure_in_the_message() -> anyhow::Result<()> {
    let (_tmp, journal) = fresh_journal()?;
    let backend = CancelsThenReturns { outcome: ok_outcome(7) };

    let report = run_job(
        &backend,
        &journal,
        &booting_plan(),
        &FakeApplier::new(),
        EgressOs::Linux,
        None,
        &[],
    )
    .context("run_job (failed, then cancelled)")?;

    assert_eq!(report.envelope.status, Status::Cancelled);
    assert!(
        report.envelope.message.contains("Failed"),
        "the message must keep the original classification: {}",
        report.envelope.message
    );
    assert_eq!(report.envelope.exit_code, Some(7), "the guest's exit code is kept");
    Ok(())
}
