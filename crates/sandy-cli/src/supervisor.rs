//! The foreground supervisor and job operations (generic over [`VmBackend`]).
//!
//! `run_job` is the foreground path: it validates the plan, writes a `Running`
//! record *before* the backend runs (INV-6), classifies the physical outcome into
//! the LOCKED [`ResultEnvelope`] plus a process band, and writes the terminal
//! record carrying the envelope. `ls` / `status` / `wait` / `kill` / `gc` are the
//! management ops; all liveness goes through [`reconcile_job`], never a direct
//! registry read (INV-3).

use std::{
    collections::HashSet,
    path::Path,
    sync::{Mutex, PoisonError, mpsc},
    time::{Duration, SystemTime},
};

use sandy::{
    BackendError, Classification, CoreError, CredentialProvider, EgressApplier, EgressOs, EgressOutcome,
    JOURNAL_SCHEMA_VERSION, JobRecord, JobState, Journal, Lease, Logs, Outcome, OutputRef, OutputStatus, ProcessExit,
    Provenance, RESULT_SCHEMA_VERSION, ResultEnvelope, Scope, SecretSource, StagedImage, Status, VmBackend,
    classify_backend_error, classify_invalid_plan, classify_outcome, enforce, mint_lease, new_job_id,
    plan_egress_scoped, plan_eviction, reconcile_job, refresh_once, validate_no_secret_leak,
};

use crate::plan::JobPlan;

/// Build the LOCKED [`ResultEnvelope`] from a terminal [`Classification`].
///
/// `outputs` are the files the backend collected to the job's declared
/// destinations (empty when the run never collected, e.g. an invalid plan or an
/// infra fault). Receipts and provenance remain placeholders (provenance capture
/// lands with #26).
fn build_envelope(
    job_id: &str,
    box_id: Option<String>,
    classification: Classification,
    guest_exit: Option<i32>,
    message: String,
    console: String,
    outputs: Vec<OutputRef>,
) -> ResultEnvelope {
    ResultEnvelope {
        result_schema_version: RESULT_SCHEMA_VERSION,
        job_id: job_id.to_string(),
        box_id,
        status: classification.status,
        retryable: classification.retryable,
        message,
        exit_code: guest_exit,
        outputs,
        receipts: vec![],
        provenance: Provenance {
            template_store_path: String::new(),
        },
        // The captured guest console tail (boot log + command output), so a boot
        // that never reached the command is diagnosable from the envelope alone.
        logs: Logs { tail: console },
    }
}

/// List the files the backend collected to each declared output's destination as
/// [`OutputRef`]s. The path is logical, not a host path: `<name>/<relpath>` for a
/// named output (`--out NAME:DEST`) and `<relpath>` for a catch-all (`--out DEST`),
/// so it identifies what the job produced independent of where on the host the
/// caller sent it. Sorted for a deterministic envelope. Best-effort: an unreadable
/// destination contributes no refs.
fn collect_output_refs(plan: &JobPlan) -> Vec<OutputRef> {
    let mut refs = Vec::new();
    for output in &plan.outputs {
        walk_outputs(&output.dest, output.name.as_deref().unwrap_or(""), &mut refs);
    }
    refs.sort_by(|a, b| a.path.cmp(&b.path));
    refs
}

/// Recurse `dir`, pushing one [`OutputRef`] per regular file with a
/// `<prefix>/<name>` logical path (an empty `prefix` yields the bare relative
/// path). Symlinks and special files are skipped — collection already dropped
/// escaping symlinks, so none should remain, and a stray one is not an output.
fn walk_outputs(dir: &Path, prefix: &str, refs: &mut Vec<OutputRef>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let rel = if prefix.is_empty() {
            name.into_owned()
        } else {
            format!("{prefix}/{name}")
        };
        match entry.file_type() {
            Ok(ft) if ft.is_dir() => walk_outputs(&entry.path(), &rel, refs),
            Ok(ft) if ft.is_file() => refs.push(OutputRef { path: rel }),
            _ => {}
        }
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
/// the egress boundary (`plan_egress_scoped` + `enforce`), run the backend, revert
/// the boundary if it was enforced (on both the ok and error paths, so a boot
/// failure never leaves rules applied), classify the outcome, then write the
/// terminal record carrying the envelope and return the band. A
/// `NoBoundary`/`Unenforced` run (macOS) applies and reverts nothing.
///
/// `tap` names the guest's host tap interface when networking is bound (the same
/// `$SANDY_TAP` the backend attaches the NIC to). On Linux a bound tap selects the
/// **guest-scoped** forward ruleset — the safe model that filters only the guest
/// and can never lock the host off the network (#29); with no tap the Linux and
/// macOS behaviour is unchanged.
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
    tap: Option<&str>,
) -> Result<RunReport, CoreError> {
    let spec = plan.as_run_spec();

    // 1. Validate the plan. An invalid plan is band 2 with NO journal record and NO backend run — the running record is
    //    the first thing written, so an empty journal proves the backend was never reached (the silent-run guard).
    if let Err(plan_error) = validate_no_secret_leak(&spec) {
        let classification = classify_invalid_plan(&plan_error);
        let envelope = build_envelope(
            &new_job_id(),
            None,
            classification,
            None,
            plan_error.to_string(),
            String::new(),
            vec![],
        );
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

    // 3. Apply the egress boundary around the boot. On Linux with a tap this loads the guest-scoped forward ruleset
    //    (the safe model, #29); on macOS `plan_egress_scoped` yields `NoBoundary`, so `enforce` applies nothing and
    //    warns. If the boundary can't be applied we fail CLOSED: do not boot, and treat it as an infra fault that lands
    //    a terminal record (band 3) rather than leaving a dangling `Running` record.
    // 4. On a successful apply, run the backend, then ALWAYS revert when the boundary was enforced — on both the ok and
    //    error paths, so a boot failure never leaves nftables rules up.
    let eplan = plan_egress_scoped(&plan.allow, egress_os, tap);
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

    // 5. Classify the physical outcome. The console tail is carried through to the envelope so a boot fault (which
    //    never produced a guest exit) is still diagnosable from the record alone.
    let (classification, guest_exit, message, console, outputs) = match run_result {
        Err(backend_error) => {
            tracing::warn!(%job_id, error = %backend_error, "backend run failed (infra fault)");
            (
                classify_backend_error(&backend_error),
                None,
                format!("infra fault: {backend_error}"),
                String::new(),
                vec![],
            )
        }
        Ok(outcome) => {
            // The backend ran and collected to the declared destinations; list what
            // landed. Classification still treats outputs as Complete — the
            // required-missing/over-quota resolution is a follow-up (the hooks exist
            // in `OutputStatus`), so an empty output does not fail a run today.
            let classification = classify_outcome(&outcome, OutputStatus::Complete);
            (
                classification,
                outcome.guest_exit,
                format!("run {:?}", classification.status),
                outcome.console,
                collect_output_refs(plan),
            )
        }
    };

    // 6. Write the terminal record carrying the envelope (INV-6).
    let envelope = build_envelope(&job_id, None, classification, guest_exit, message, console, outputs);
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
/// Wraps [`sandy::mint_lease`], mapping a [`sandy::CredError`] into
/// [`CoreError::Cred`]: a mint failure is an infra fault the caller must fail on,
/// never a run with no credential (INV-7). Returns the whole [`Lease`] so the
/// caller can revoke it at teardown (the Block-2 bracket); today only its
/// `secret_ref` is threaded into the plan.
///
/// # Errors
///
/// Returns [`CoreError::Cred`] when minting or staging the credential fails.
pub fn mint_run_token<P: CredentialProvider>(
    provider: &P,
    scope: &Scope,
    secret_name: &str,
    out_dir: &Path,
    requested_ttl_secs: u32,
) -> Result<Lease, CoreError> {
    mint_lease(provider, scope, requested_ttl_secs, secret_name, out_dir).map_err(|e| CoreError::Cred(e.to_string()))
}

/// Run a job with a forge credential bracketed around it: mint at boot, inject the
/// staged secret into the plan, run, then **revoke on every path** (success,
/// failure, fault) so the credential never outlives the job.
///
/// This is the credential sibling of [`run_job`]'s egress bracket, written as a
/// wrapper rather than a parameter on `run_job` because a forge credential is
/// opt-in while the egress boundary is universal. `requested_ttl_secs` is clamped to
/// `MAX_TTL_SECS` by [`sandy::mint_lease`]; revoke-at-teardown is the real lifetime
/// bound (the provider's native token TTL is too coarse, #49), so the token file is
/// kept until after `revoke` (a GitHub revoke reads it) and then removed.
///
/// `cred_dir` is the caller-owned secret share: the token is staged there as its
/// env name and the dir is shared read-only into the guest ([`RunSpec::secret_dir`]),
/// so a refresh can rewrite the live file in place. While the job runs, a background
/// thread drives [`sandy::refresh_once`] (gated by [`sandy::should_refresh`]) to
/// re-mint and re-stage the token before it lapses, revoking each superseded one, so
/// a job that outlives the provider's native token cap (GitHub ~1h) keeps a valid
/// scoped token the whole run. The refresh margin and poll interval default to
/// [`DEFAULT_REFRESH_MARGIN_SECS`] / [`DEFAULT_REFRESH_TICK_SECS`], overridable via
/// `SANDY_REFRESH_MARGIN_SECS` / `SANDY_REFRESH_TICK_SECS`. Teardown revokes the
/// live token (the latest handle after any refresh) on every path and removes the
/// staged file (INV-1); `cred_dir` itself is the caller's to clean up.
///
/// # Errors
///
/// Returns [`CoreError::Cred`] when the mint fails, before the backend runs, so the
/// caller fails rather than booting with no credential (INV-7); otherwise the run
/// outcome is folded into the returned [`RunReport`] exactly as [`run_job`] does.
#[allow(
    clippy::too_many_arguments,
    reason = "the bracket threads both the run and the credential inputs"
)]
pub fn run_job_with_credential<B: VmBackend, E: EgressApplier, P: CredentialProvider + Sync>(
    backend: &B,
    journal: &Journal,
    plan: JobPlan,
    egress: &E,
    egress_os: EgressOs,
    tap: Option<&str>,
    provider: &P,
    scope: &Scope,
    secret_name: &str,
    cred_dir: &Path,
    requested_ttl_secs: u32,
) -> Result<RunReport, CoreError> {
    // Mint and stage the token before the guest boots, into the share dir itself so
    // the staged file IS the live guest file (refresh rewrites it). A mint failure is
    // a fail-closed infra fault: return before any backend run (INV-7).
    let lease = mint_lease(provider, scope, requested_ttl_secs, secret_name, cred_dir)
        .map_err(|e| CoreError::Cred(e.to_string()))?;
    let SecretSource::File(token_path) = &lease.secret_ref.source else {
        // mint_lease always stages a File-sourced secret; a non-File source is a
        // contract violation, not a run-with-no-credential.
        return Err(CoreError::Cred(
            "minted credential is not a file-sourced secret".to_string(),
        ));
    };
    let token_path = token_path.clone();

    // Share cred_dir directly instead of pushing a plan secret the backend copies:
    // the caller owns the dir and the refresh thread rewrites the token in it live.
    let mut plan = plan;
    plan.secret_dir = Some(cred_dir.to_path_buf());

    let margin = refresh_interval("SANDY_REFRESH_MARGIN_SECS", DEFAULT_REFRESH_MARGIN_SECS);
    let tick = refresh_interval("SANDY_REFRESH_TICK_SECS", DEFAULT_REFRESH_TICK_SECS);
    let lease = Mutex::new(lease);
    let (stop_tx, stop_rx) = mpsc::channel::<()>();

    // Run the job on this thread; refresh the credential on a second thread until the
    // run returns, then signal it to stop by dropping the sender. The refresh thread
    // borrows the lease (a copied `&Mutex`, so the Mutex isn't moved) and owns the
    // receiver; the scope joins it before we take the lease back.
    let shared_lease = &lease;
    let report = std::thread::scope(|s| {
        s.spawn(move || refresh_loop(provider, shared_lease, margin, tick, &stop_rx));
        let report = run_job(backend, journal, &plan, egress, egress_os, tap);
        drop(stop_tx);
        report
    });

    // The refresh thread has joined; take back the lease, now naming the live token.
    let lease = lease.into_inner().unwrap_or_else(PoisonError::into_inner);

    // Revoke the live token on EVERY path (before removing the file a GitHub revoke
    // reads) so it is invalid the moment the job ends, not at its native expiry (#49).
    // A revoke failure is logged, not fatal: the native TTL is the backstop.
    if let Err(e) = provider.revoke(&lease) {
        tracing::warn!(%e, "credential revoke at teardown failed; relying on native expiry");
    }
    // Remove the staged token so the secret never outlives the run (INV-1).
    if let Err(e) = std::fs::remove_file(&token_path) {
        tracing::warn!(path = %token_path.display(), %e, "failed to remove staged credential on teardown");
    }

    report
}

/// Default margin before token expiry at which a mid-run refresh fires (5 min): it
/// must exceed one refresh's latency so the token never lapses between polls.
pub const DEFAULT_REFRESH_MARGIN_SECS: u64 = 300;
/// Default interval between refresh checks while a credentialed job runs (60s).
pub const DEFAULT_REFRESH_TICK_SECS: u64 = 60;

/// Read a refresh interval (seconds) from `env_key`, falling back to `default`. The
/// tick is floored at 1s so a misconfigured `0` can't spin the poll loop.
fn refresh_interval(env_key: &str, default: u64) -> Duration {
    let secs = std::env::var(env_key)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(default)
        .max(1);
    Duration::from_secs(secs)
}

/// Poll `lease` every `tick` and refresh it when within `margin` of expiry, until
/// the sender half of `stop` is dropped (the run finished). Each refresh re-stages
/// the live token file and revokes the superseded token via [`refresh_once`]; a
/// refresh error is logged and retried on the next tick, never fatal to the run.
fn refresh_loop<P: CredentialProvider + Sync>(
    provider: &P,
    lease: &Mutex<Lease>,
    margin: Duration,
    tick: Duration,
    stop: &mpsc::Receiver<()>,
) {
    loop {
        match stop.recv_timeout(tick) {
            // Sender dropped (run finished) or an explicit stop: leave.
            Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
        let mut guard = lease.lock().unwrap_or_else(PoisonError::into_inner);
        if let Err(e) = refresh_once(provider, &mut guard, SystemTime::now(), margin) {
            tracing::warn!(%e, "mid-run credential refresh failed; keeping the current token");
        }
    }
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
        String::new(),
        vec![],
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

    /// A plan whose secret name is also set as a plain env var —
    /// `validate_no_secret_leak` must reject it (INV-1), driving the invalid-plan
    /// band.
    fn leaking_plan() -> JobPlan {
        use sandy::{SecretRef, SecretSource};
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
                console: String::new(),
            });
            let report = run_job(
                &backend,
                &journal,
                &booting_plan(),
                &FakeApplier::new(),
                EgressOs::Linux,
                None,
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
                console: String::new(),
            });
            let report = run_job(
                &backend,
                &journal,
                &booting_plan(),
                &FakeApplier::new(),
                EgressOs::Linux,
                None,
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
                None,
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
                console: String::new(),
            });
            let report = run_job(
                &backend,
                &journal,
                &leaking_plan(),
                &FakeApplier::new(),
                EgressOs::Linux,
                None,
            )
            .context("run_job (invalid plan)")?;
            assert_eq!(report.process_exit.code(), ProcessExit::InvalidPlan.code());
            assert!(!report.envelope.retryable, "band 2 must not be retryable");
        }
        Ok(())
    }

    /// `refresh_loop` refreshes the credential on each tick while the job runs and
    /// stops promptly when the sender is dropped. A margin past the token TTL makes
    /// `should_refresh` fire every tick, so a superseded token is revoked each time.
    #[test]
    fn refresh_loop_refreshes_until_the_sender_drops() -> anyhow::Result<()> {
        use std::{
            sync::{Mutex, mpsc},
            time::Duration,
        };

        use sandy::{FakeProvider, Scope, mint_lease};

        let tmp = tempfile::tempdir().context("tmp")?;
        let provider = FakeProvider::returning("tok");
        let lease = mint_lease(&provider, &Scope::default(), 1_800, "GITHUB_TOKEN", tmp.path())
            .map_err(|e| anyhow::anyhow!("{e}"))
            .context("mint")?;
        let lease = Mutex::new(lease);
        let (tx, rx) = mpsc::channel::<()>();
        let margin = Duration::from_secs(1_000_000);
        let tick = Duration::from_millis(5);

        std::thread::scope(|s| {
            let pref = &provider;
            let shared = &lease;
            s.spawn(move || super::refresh_loop(pref, shared, margin, tick, &rx));
            std::thread::sleep(Duration::from_millis(50));
            drop(tx);
        });

        assert!(
            !provider.revoked().is_empty(),
            "refresh_loop must refresh and revoke a superseded token while the job runs"
        );
        Ok(())
    }
}
