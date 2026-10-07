//! The foreground supervisor and job operations (generic over [`VmBackend`]).
//!
//! `run_job` is the foreground path: it validates the plan, writes a `Running`
//! record *before* the backend runs (INV-6), classifies the physical outcome into
//! the LOCKED [`ResultEnvelope`] plus a process band, and writes the terminal
//! record carrying the envelope. `ls` / `status` / `wait` / `kill` / `gc` are the
//! management ops; all liveness goes through [`reconcile_job`], never a direct
//! registry read (INV-3).

use std::{collections::HashSet, path::Path, time::SystemTime};

use sandy::{
    BackendError, Classification, CoreError, EgressApplier, EgressOs, EgressOutcome, InstallationTokenMinter,
    JOURNAL_SCHEMA_VERSION, JobRecord, JobState, Journal, Logs, Outcome, OutputStatus, ProcessExit, Provenance,
    RESULT_SCHEMA_VERSION, ResultEnvelope, SecretRef, StagedImage, Status, TokenScope, VmBackend,
    classify_backend_error, classify_invalid_plan, classify_outcome, enforce, mint_token, new_job_id, plan_egress,
    plan_eviction, reconcile_job, validate_no_secret_leak,
};

use crate::plan::JobPlan;

/// Build the LOCKED [`ResultEnvelope`] from a terminal [`Classification`].
///
/// Outputs, receipts, provenance, and logs are placeholders: output collection
/// and provenance capture are out of #22 scope (they land with the host boot,
/// #26). The envelope still carries the authoritative `status` / `retryable` /
/// `exit_code` triple so the on-disk terminal record is complete (INV-6/INV-11).
fn build_envelope(
    job_id: &str,
    box_id: Option<String>,
    classification: Classification,
    guest_exit: Option<i32>,
    message: String,
) -> ResultEnvelope {
    ResultEnvelope {
        result_schema_version: RESULT_SCHEMA_VERSION,
        job_id: job_id.to_string(),
        box_id,
        status: classification.status,
        retryable: classification.retryable,
        message,
        exit_code: guest_exit,
        outputs: vec![],
        receipts: vec![],
        provenance: Provenance {
            template_store_path: String::new(),
        },
        logs: Logs { tail: String::new() },
    }
}

/// Map a terminal envelope [`Status`] to the journal [`JobState`] it persists as.
fn terminal_state(status: Status) -> JobState {
    match status {
        Status::Succeeded => JobState::Succeeded,
        Status::Failed => JobState::Failed,
        Status::Cancelled => JobState::Cancelled,
    }
}

/// The result of a foreground `run`: the LOCKED envelope plus sandy's own process
/// exit band (INV-11). `main` prints the envelope as JSON and exits with
/// `process_exit.code()`.
#[derive(Debug, Clone)]
pub struct RunReport {
    /// The terminal result envelope (also persisted to the journal, INV-6).
    pub envelope: ResultEnvelope,
    /// sandy's process exit band — distinct from the guest's `exit_code`.
    pub process_exit: ProcessExit,
}

/// Run one job to completion in the foreground, bracketing the boot with the
/// egress boundary.
///
/// Order (INV-6): validate the plan (an invalid plan returns band 2 with **no**
/// journal record and **no** backend run); else write a `Running` record, apply
/// the egress boundary (`plan_egress` + `enforce`), run the backend, revert the
/// boundary if it was enforced (on both the ok and error paths, so a boot failure
/// never leaves rules applied), classify the outcome, then write the terminal
/// record carrying the envelope and return the band. A `NoBoundary`/`Unenforced`
/// run (macOS) applies and reverts nothing.
///
/// # Errors
///
/// Returns [`CoreError`] only on genuine journal I/O failure. Every run-outcome,
/// plan, and egress-apply error is folded into the envelope and band — a failed
/// egress boundary fails closed as a band-3 infra fault — not the `Err` arm.
pub fn run_job<B: VmBackend, E: EgressApplier>(
    backend: &B,
    journal: &Journal,
    plan: &JobPlan,
    egress: &E,
    egress_os: EgressOs,
) -> Result<RunReport, CoreError> {
    let spec = plan.as_run_spec();

    // 1. Validate the plan. An invalid plan is band 2 with NO journal record and NO backend run — the running record is
    //    the first thing written, so an empty journal proves the backend was never reached (the silent-run guard).
    if let Err(plan_error) = validate_no_secret_leak(&spec) {
        let classification = classify_invalid_plan(&plan_error);
        let envelope = build_envelope(&new_job_id(), None, classification, None, plan_error.to_string());
        return Ok(RunReport {
            envelope,
            process_exit: classification.process_exit,
        });
    }

    // 2. Write the `Running` record BEFORE the backend runs (INV-6).
    let job_id = new_job_id();
    let started = SystemTime::now();
    let running = JobRecord {
        schema_version: JOURNAL_SCHEMA_VERSION,
        job_id: job_id.clone(),
        box_id: None,
        state: JobState::Running,
        writer_pid: std::process::id(),
        started,
        result: None,
    };
    journal.write_record(&running)?;

    // 3. Apply the egress boundary around the boot. On Linux this loads the default-deny ruleset; on macOS
    //    `plan_egress` yields `NoBoundary`, so `enforce` applies nothing and warns. If the boundary can't be applied we
    //    fail CLOSED: do not boot, and treat it as an infra fault that lands a terminal record (band 3) rather than
    //    leaving a dangling `Running` record.
    // 4. On a successful apply, run the backend, then ALWAYS revert when the boundary was enforced — on both the ok and
    //    error paths, so a boot failure never leaves nftables rules up.
    let eplan = plan_egress(&plan.allow, egress_os);
    let run_result: Result<Outcome, BackendError> = match enforce(&eplan, egress) {
        Ok(eoutcome) => {
            let outcome = backend.run(&spec);
            if matches!(eoutcome, EgressOutcome::Enforced) {
                if let Err(e) = egress.revert() {
                    tracing::warn!(%e, "egress revert failed");
                }
            }
            outcome
        }
        Err(egress_error) => {
            tracing::warn!(%job_id, %egress_error, "egress apply failed; refusing to boot (fail-closed)");
            Err(BackendError::Spawn(format!(
                "egress boundary not established: {egress_error}"
            )))
        }
    };

    // 5. Classify the physical outcome.
    let (classification, guest_exit, message) = match run_result {
        Err(backend_error) => {
            tracing::warn!(%job_id, error = %backend_error, "backend run failed (infra fault)");
            (
                classify_backend_error(&backend_error),
                None,
                format!("infra fault: {backend_error}"),
            )
        }
        Ok(outcome) => {
            // Output collection is out of #22 scope; treat outputs as Complete.
            let classification = classify_outcome(&outcome, OutputStatus::Complete);
            (
                classification,
                outcome.guest_exit,
                format!("run {:?}", classification.status),
            )
        }
    };

    // 6. Write the terminal record carrying the envelope (INV-6).
    let envelope = build_envelope(&job_id, None, classification, guest_exit, message);
    let terminal = JobRecord {
        schema_version: JOURNAL_SCHEMA_VERSION,
        job_id,
        box_id: None,
        state: terminal_state(classification.status),
        writer_pid: std::process::id(),
        started,
        result: Some(envelope.clone()),
    };
    journal.write_record(&terminal)?;

    Ok(RunReport {
        envelope,
        process_exit: classification.process_exit,
    })
}

/// Mint a scoped installation token and stage it as a `0600` [`SecretRef`] for a
/// run — a host/pre-run step, kept separate from [`run_job`] (the token is minted
/// before the plan is assembled, then threaded in as a secret).
///
/// Wraps [`sandy::mint_token`], mapping a [`sandy::CredError`] into
/// [`CoreError::Cred`]: a mint failure is an infra fault the caller must fail on,
/// never a run with no token (INV-7).
///
/// # Errors
///
/// Returns [`CoreError::Cred`] when minting or staging the token fails.
pub fn mint_run_token<M: InstallationTokenMinter>(
    minter: &M,
    scope: &TokenScope,
    secret_name: &str,
    out_dir: &Path,
    requested_ttl_secs: u32,
) -> Result<SecretRef, CoreError> {
    mint_token(minter, scope, requested_ttl_secs, secret_name, out_dir).map_err(|e| CoreError::Cred(e.to_string()))
}

/// List every job record (`journal.list()`).
///
/// # Errors
///
/// Returns [`CoreError`] on journal I/O failure.
pub fn ls(journal: &Journal) -> Result<Vec<JobRecord>, CoreError> {
    journal.list()
}

/// Reconcile a job against live backend state (INV-3) and return its record.
///
/// # Errors
///
/// Returns [`CoreError`] when the job is unknown or liveness cannot be determined.
pub fn status<B: VmBackend>(journal: &Journal, backend: &B, job_id: &str) -> Result<JobRecord, CoreError> {
    reconcile_job(journal, backend, job_id)
}

/// Wait for a job to reach a terminal state. Reconcile-on-read makes a dead box
/// terminal (`Crashed`) in one pass, so this never loops on an absent box.
///
/// # Errors
///
/// Returns [`CoreError`] when the job is unknown or liveness cannot be determined.
pub fn wait<B: VmBackend>(journal: &Journal, backend: &B, job_id: &str) -> Result<JobRecord, CoreError> {
    // One reconcile pass is enough for every state the sandbox gate exercises: a
    // terminal record returns unchanged, and a `Running` record whose box is gone
    // is flipped to `Crashed` in that single pass — so a dead box never loops. A
    // true blocking poll over a still-live box lands with the host boot (#26).
    reconcile_job(journal, backend, job_id)
}

/// Cancel a running job: tear its box down and flip the record to `Cancelled`.
/// Idempotent on an already-terminal record.
///
/// # Errors
///
/// Returns [`CoreError`] on journal I/O failure.
pub fn kill<B: VmBackend>(journal: &Journal, backend: &B, job_id: &str) -> Result<JobRecord, CoreError> {
    // Idempotent on an already-terminal record: nothing to tear down.
    let record = journal.read_record(job_id)?;
    if record.state != JobState::Running {
        return Ok(record);
    }

    // Flip under the job flock so a concurrent reconcile/writer can't race us.
    let _lock = journal.lock_job(job_id)?;
    // Re-read under the lock: the owner may have reached a terminal state in the
    // window before we acquired it — never clobber a real result (INV-3/INV-6).
    let record = journal.read_record(job_id)?;
    if record.state != JobState::Running {
        return Ok(record);
    }

    if let Some(box_id) = &record.box_id {
        backend
            .kill(box_id)
            .map_err(|e| CoreError::State(format!("teardown of box {box_id} failed: {e}")))?;
    }

    let envelope = build_envelope(
        job_id,
        record.box_id.clone(),
        Classification {
            status: Status::Cancelled,
            retryable: false,
            process_exit: ProcessExit::TaskFailure,
        },
        None,
        "cancelled by kill".to_string(),
    );
    let cancelled = JobRecord {
        state: JobState::Cancelled,
        writer_pid: std::process::id(),
        result: Some(envelope),
        ..record
    };
    journal.write_record(&cancelled)?;
    Ok(cancelled)
}

/// Garbage-collect terminal job records under the keep-last-N + referenced policy.
/// A still-`Running` job is referenced and never evicted, even when it is oldest.
/// Returns the evicted job ids.
///
/// # Errors
///
/// Returns [`CoreError`] on journal I/O failure.
pub fn gc(journal: &Journal, keep_last_n: usize) -> Result<Vec<String>, CoreError> {
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

#[cfg(test)]
mod tests {
    use anyhow::Context;
    use sandy::{AllowList, BackendError, EgressOs, FakeApplier, FakeBackend, Grants, Journal, Outcome, ProcessExit};

    use super::run_job;
    use crate::plan::JobPlan;

    /// A journal on a fresh local temp `$SANDY_HOME`.
    fn fresh_journal() -> anyhow::Result<(tempfile::TempDir, Journal)> {
        let tmp = tempfile::tempdir().context("creating a temp SANDY_HOME")?;
        let journal = Journal::new(tmp.path());
        journal.ensure_dirs().context("ensure_dirs")?;
        Ok((tmp, journal))
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

    /// A plan whose secret file path is also a mount host — `validate_no_secret_leak`
    /// must reject it (INV-1), driving the invalid-plan band.
    fn leaking_plan() -> JobPlan {
        use sandy::{Mount, SecretRef, SecretSource};
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

    /// INV-11 exit-band map + cross-check: every band `run_job` produces has code
    /// 0/1/2/3, and band 3 (infra fault) holds **iff** the envelope is retryable
    /// — bands 0/1/2 are never retryable. Asserted over the four scripted
    /// outcomes `run_job` can classify.
    #[test]
    fn run_job_band_three_iff_retryable_over_scripted_outcomes() -> anyhow::Result<()> {
        // (scripted backend, plan, expected code, expected retryable)
        // Band 0 — clean guest success.
        {
            let (_tmp, journal) = fresh_journal()?;
            let backend = FakeBackend::new().with_outcome(Outcome {
                booted: true,
                guest_exit: Some(0),
                transport_error: None,
                timed_out: false,
            });
            let report = run_job(
                &backend,
                &journal,
                &booting_plan(),
                &FakeApplier::new(),
                EgressOs::Linux,
            )
            .context("run_job (succeeded)")?;
            assert_eq!(report.process_exit.code(), ProcessExit::Succeeded.code());
            assert!(!report.envelope.retryable, "band 0 must not be retryable");
        }
        // Band 1 — guest nonzero exit is a task failure, not retryable.
        {
            let (_tmp, journal) = fresh_journal()?;
            let backend = FakeBackend::new().with_outcome(Outcome {
                booted: true,
                guest_exit: Some(1),
                transport_error: None,
                timed_out: false,
            });
            let report = run_job(
                &backend,
                &journal,
                &booting_plan(),
                &FakeApplier::new(),
                EgressOs::Linux,
            )
            .context("run_job (task failure)")?;
            assert_eq!(report.process_exit.code(), ProcessExit::TaskFailure.code());
            assert!(!report.envelope.retryable, "band 1 must not be retryable");
        }
        // Band 3 — a backend spawn error is an infra fault, retryable.
        {
            let (_tmp, journal) = fresh_journal()?;
            let backend = FakeBackend::new().with_error(BackendError::Spawn("boom".to_string()));
            let report = run_job(
                &backend,
                &journal,
                &booting_plan(),
                &FakeApplier::new(),
                EgressOs::Linux,
            )
            .context("run_job (infra fault)")?;
            assert_eq!(report.process_exit.code(), ProcessExit::InfraFault.code());
            assert!(report.envelope.retryable, "band 3 must be retryable");
        }
        // Band 2 — an invalid plan is never retryable (and never boots).
        {
            let (_tmp, journal) = fresh_journal()?;
            let backend = FakeBackend::new().with_outcome(Outcome {
                booted: true,
                guest_exit: Some(0),
                transport_error: None,
                timed_out: false,
            });
            let report = run_job(
                &backend,
                &journal,
                &leaking_plan(),
                &FakeApplier::new(),
                EgressOs::Linux,
            )
            .context("run_job (invalid plan)")?;
            assert_eq!(report.process_exit.code(), ProcessExit::InvalidPlan.code());
            assert!(!report.envelope.retryable, "band 2 must not be retryable");
        }
        Ok(())
    }
}
