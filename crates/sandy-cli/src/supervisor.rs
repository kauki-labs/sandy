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
    path::{Path, PathBuf},
    sync::{Mutex, PoisonError, mpsc},
    time::{Duration, SystemTime},
};

use sandy::{
    BackendError, Classification, CoreError, CredentialProvider, EgressApplier, EgressOs, EgressOutcome,
    JOURNAL_SCHEMA_VERSION, JobRecord, JobState, Journal, Lease, Logs, MAX_TTL_SECS, Outcome, OutputRef, OutputStatus,
    ProcessExit, Profile, Provenance, RESULT_SCHEMA_VERSION, ResultEnvelope, Scope, SecretSource, StagedImage, Status,
    VmBackend, classify_backend_error, classify_invalid_plan, classify_outcome, enforce, mint_lease, new_job_id,
    plan_egress_scoped, plan_eviction, reconcile_job, refresh_once, validate_no_secret_leak,
};
use zeroize::Zeroizing;

use crate::plan::JobPlan;

/// Redact every exact occurrence of a `secrets` entry in `console` with
/// `[REDACTED]` (M-6). A secret under 8 bytes is skipped rather than replaced: a
/// short value risks consuming unrelated text (a secret `"ab"` must never redact
/// unrelated `"abc"`), and a real forge token is never that short.
fn redact_console<S: AsRef<str>>(mut console: String, secrets: &[S]) -> String {
    for secret in secrets {
        let secret = secret.as_ref();
        if secret.len() < 8 {
            continue;
        }
        console = console.replace(secret, "[REDACTED]");
    }
    console
}

/// Re-redact `console` against `initial` plus every token `refresh_loop` queued
/// onto `redact_log` as it staged one (M-6 follow-up): `run_job`'s own redaction
/// pass only ever sees `initial`, so a mid-run refresh needs this second pass to
/// catch its own token too. Both passes borrow their secrets rather than
/// cloning them into a plain, unzeroized `String` first — `redact_console` is
/// generic over `AsRef<str>` precisely so `initial` (a `&str`) and `refreshed`
/// (`Zeroizing<String>`, which forwards `AsRef<str>`) can go straight through.
/// A no-op when `refreshed` is empty: re-running `redact_console` against
/// `initial` alone finds nothing new, since the first pass already turned
/// every occurrence of it into `[REDACTED]`.
fn redact_with_refreshes(console: String, initial: &str, refreshed: &[Zeroizing<String>]) -> String {
    redact_console(redact_console(console, &[initial]), refreshed)
}

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
        // Redaction (M-6) happens in the caller, right before this console is
        // passed in — there's no seam after `build_envelope` returns.
        logs: Logs { tail: console },
        // A credentialed run folds a non-fatal teardown fault in here after this
        // envelope is built (L-12); every other path leaves it empty.
        warnings: vec![],
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
/// `redact` lists secrets to strip from the captured console before it reaches
/// the envelope (M-6): the non-credentialed path passes `&[]`, and
/// [`run_job_with_credential`] passes the minted token.
///
/// # Errors
///
/// Returns [`CoreError`] only on genuine journal I/O failure. Every run-outcome,
/// plan, and egress-apply error is folded into the envelope and band — a failed
/// egress boundary fails closed as a band-3 infra fault — not the `Err` arm.
pub fn run_job<B: VmBackend + ?Sized, E: EgressApplier + ?Sized>(
    backend: &B,
    journal: &Journal,
    plan: &JobPlan,
    egress: &E,
    egress_os: EgressOs,
    tap: Option<&str>,
    redact: &[String],
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
            redact_console(String::new(), redact),
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
            if matches!(eoutcome, EgressOutcome::Enforced)
                && let Err(e) = egress.revert()
            {
                tracing::warn!(%e, "egress revert failed");
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

    // 6. Write the terminal record carrying the envelope (INV-6). Redact right before the envelope is built: this is
    //    the last point before the journal write, and there's no seam after `run_job` returns (M-6).
    let console = redact_console(console, redact);
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

/// Run one job to completion from a composition [`Profile`]: the profile selects
/// the sandbox backend and the egress applier (and the OS egress model), and this
/// threads them into [`run_job`]. It is the injectable entry the composition root
/// (`dispatch_run`) calls, so which backend/egress impl runs is a profile choice,
/// not hardcoded in dispatch. The non-credentialed path; the credentialed bracket
/// stays [`run_job_with_credential`].
///
/// # Errors
///
/// Returns [`CoreError`] exactly as [`run_job`] does — only on genuine journal I/O
/// failure; every run-outcome is folded into the returned [`RunReport`].
pub fn run_with_profile(
    profile: &Profile,
    journal: &Journal,
    plan: &JobPlan,
    tap: Option<&str>,
) -> Result<RunReport, CoreError> {
    run_job(
        profile.backend(),
        journal,
        plan,
        profile.egress(),
        profile.egress_os(),
        tap,
        &[],
    )
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
pub fn mint_run_token<P: CredentialProvider + ?Sized>(
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
/// `SANDY_REFRESH_MARGIN_SECS` / `SANDY_REFRESH_TICK_SECS`. Every tick also
/// heartbeats `cred_dir`'s mtime (#195), so [`gc`]'s stale-staging-dir sweep
/// never mistakes a live long-running job for one SIGKILL or a crash left
/// behind. Teardown revokes the live token (the latest handle after any
/// refresh) on every path and removes the staged file (INV-1); `cred_dir`
/// itself is the caller's to clean up.
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
pub fn run_job_with_credential<
    B: VmBackend + ?Sized,
    E: EgressApplier + ?Sized,
    P: CredentialProvider + Sync + ?Sized,
>(
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

    // Read the staged plaintext back once, for console redaction only (M-6): the
    // `Lease` itself still never carries it past staging (INV-1 unchanged). Held
    // as long as the lease and zeroized at the same teardown point. A read
    // failure here is after the credential was minted and staged, so it must
    // still be revoked before this returns (INV-1) — there's no `CredTeardown`
    // guard yet to do that for us.
    let secret = match std::fs::read_to_string(&token_path) {
        Ok(s) => Zeroizing::new(s),
        Err(e) => {
            if let Err(revoke_err) = provider.revoke(&lease) {
                tracing::warn!(%revoke_err, "credential revoke failed after a staged-token read error; relying on native expiry");
            }
            let _ = std::fs::remove_file(&token_path);
            return Err(e.into());
        }
    };
    // Share cred_dir directly instead of pushing a plan secret the backend copies:
    // the caller owns the dir and the refresh thread rewrites the token in it live.
    let mut plan = plan;
    plan.secret_dir = Some(cred_dir.to_path_buf());

    let margin = refresh_interval("SANDY_REFRESH_MARGIN_SECS", DEFAULT_REFRESH_MARGIN_SECS);
    let tick = safe_heartbeat_tick(
        refresh_interval("SANDY_REFRESH_TICK_SECS", DEFAULT_REFRESH_TICK_SECS),
        MAX_TTL_SECS,
    );
    let (stop_tx, stop_rx) = mpsc::channel::<()>();

    // Teardown also runs as a Drop guard, not only as the explicit call below: it
    // revokes the live token and removes the staged file on EVERY exit from here,
    // including a panic unwinding out of `run_job` through `thread::scope`, where
    // the explicit call below is never reached. Skipping it on a panic would leave
    // a valid forge token and the 0600 secret on disk past the run (INV-1).
    let mut teardown = CredTeardown {
        provider,
        lease: Mutex::new(lease),
        token_path,
        secret,
        secret_name: secret_name.to_string(),
        scope: scope.clone(),
        job_id: String::new(),
        done: false,
    };
    // Borrow the zeroizing holder directly: no unzeroized plaintext clone.
    // `run_job`'s own redaction only ever sees this initial token; `redact_log`
    // (M-6 follow-up) catches whatever a mid-run refresh adds after that.
    let redact = std::slice::from_ref(&*teardown.secret);
    let redact_log: Mutex<Vec<Zeroizing<String>>> = Mutex::new(Vec::new());

    // Run the job on this thread; refresh the credential on a second thread until the
    // run returns, then signal it to stop by dropping the sender. The refresh thread
    // borrows the guard's lease (a `&Mutex`, so the guard isn't moved) and owns the
    // receiver; the scope joins it before the guard's teardown can run.
    let shared_lease = &teardown.lease;
    let shared_redact_log = &redact_log;
    let mut report = std::thread::scope(|s| {
        s.spawn(move || refresh_loop(provider, shared_lease, margin, tick, &stop_rx, shared_redact_log));
        let report = run_job(backend, journal, &plan, egress, egress_os, tap, redact);
        drop(stop_tx);
        report
    });

    // Explicit teardown on the normal return path (the borrow of `teardown.lease`
    // above ended with `thread::scope`, so this is the first point it can be
    // touched again): name the job in the revoke-failure log, then fold a
    // failure into both the returned envelope and the already-journaled terminal
    // record (L-12) — INV-6 says the record always carries the envelope, so the
    // two must not drift apart. On a panic, `Drop` runs the same teardown
    // instead, with no envelope to fold into and no job id yet known.
    if let Ok(run_report) = &report {
        teardown.job_id = run_report.envelope.job_id.clone();
    }
    let warning = teardown.teardown();
    let refreshed_tokens = redact_log.into_inner().unwrap_or_else(PoisonError::into_inner);
    if let Ok(run_report) = &mut report {
        let mut amended = false;

        // M-6 follow-up: re-redact against every token this run ever had live,
        // not just the one `run_job` saw at its own redaction pass.
        if !refreshed_tokens.is_empty() {
            run_report.envelope.logs.tail = redact_with_refreshes(
                std::mem::take(&mut run_report.envelope.logs.tail),
                &teardown.secret,
                &refreshed_tokens,
            );
            amended = true;
        }
        if let Some(warning) = warning {
            run_report.envelope.warnings.push(warning);
            amended = true;
        }

        // The run already succeeded or failed on its own terms; an amend
        // failure here (lock contention, a disk write error) must not
        // overwrite that outcome with one about the journal instead. The
        // caller still gets the corrected envelope above — only the
        // journaled copy risks staying stale.
        if amended && let Err(e) = amend_terminal_envelope(journal, &run_report.envelope.job_id, &run_report.envelope) {
            tracing::warn!(job_id = %run_report.envelope.job_id, error = %e, "failed to amend the journaled terminal record");
        }
    }
    report
}

/// Overwrite the terminal record's envelope already written by `run_job` with
/// `envelope`, under the job flock, so the journal stays in lock-step with what
/// `run_job_with_credential` returns (INV-6; L-12 and its M-6 follow-up:
/// a teardown warning or a post-run console re-redaction, or both). Re-reads
/// the record under the lock rather than touching a cached copy: a concurrent
/// reconcile could have touched it since `run_job` wrote it.
fn amend_terminal_envelope(journal: &Journal, job_id: &str, envelope: &ResultEnvelope) -> Result<(), CoreError> {
    let _lock = journal.lock_job(job_id)?;
    let mut record = journal.read_record(job_id)?;
    record.result = Some(envelope.clone());
    journal.write_record(&record)
}

/// Revokes the live credential and removes its staged `0600` file, exactly once
/// ([`CredTeardown::teardown`]): explicitly, right after [`run_job_with_credential`]
/// gets its result, or — if a panic unwinds out of `run_job` first — via `Drop`
/// instead, skipping the explicit call. Either way the credential never outlives
/// the run (INV-1); the explicit path additionally gets a warning string back to
/// fold into the envelope (L-12), which `Drop` has nowhere to return it to.
struct CredTeardown<'a, P: CredentialProvider + ?Sized> {
    provider: &'a P,
    /// The live lease; the refresh thread advances it to the latest minted token,
    /// so teardown revokes whatever token is current when the run ends.
    lease: Mutex<Lease>,
    token_path: PathBuf,
    /// The raw secret, read back once after staging, purely for this run's
    /// console redaction (M-6): `run_job` is handed a clone of it (as `redact`)
    /// before this guard is built. Held here only so it zeroizes alongside the
    /// lease revoke, never read back out — the `Lease` it sits beside still
    /// never carries it.
    /// Borrowed by `redact` for the run's duration and zeroized on drop (M-6).
    secret: Zeroizing<String>,
    /// The credential's declared name (e.g. `"GH_TOKEN"`), naming it in a
    /// revoke-failure warning without naming the token value (L-12).
    secret_name: String,
    /// The credential's scope, logged alongside a revoke failure (L-12).
    scope: Scope,
    /// The job id, filled in once `run_job` returns it; empty if teardown runs
    /// from `Drop` during a panic, before the job id is known.
    job_id: String,
    /// Set once [`CredTeardown::teardown`] has run, so a later call — including
    /// the implicit one from `Drop` after an explicit call already handled it —
    /// is a no-op.
    done: bool,
}

impl<P: CredentialProvider + ?Sized> CredTeardown<'_, P> {
    /// Revoke the live credential and remove its staged file. A revoke failure is
    /// never fatal to the run; it is logged (job id, scope, TTL remaining — never
    /// the token value, L-12) and returned as a warning string naming the
    /// credential, for the caller to fold into the envelope.
    fn teardown(&mut self) -> Option<String> {
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
        let warning = self.provider.revoke(lease).err().map(|e| {
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

/// Bump `dir`'s mtime to now: proves to [`gc`]'s mtime-based stale-dir sweep
/// (#195) that a credential staging dir is still in active use.
fn touch_dir_mtime(dir: &Path) -> std::io::Result<()> {
    std::fs::File::open(dir)?.set_modified(SystemTime::now())
}

/// Clamp `tick` so the mid-run heartbeat can never tick slower than [`gc`]'s
/// stale-dir sweep threshold (#195, flagged in review): a
/// `SANDY_REFRESH_TICK_SECS` at or above `max_ttl_secs` would let a live
/// job's cred dir go stale between heartbeats and get swept out from under
/// it, so a tick that reaches the threshold is never honored — it falls back
/// to [`DEFAULT_REFRESH_TICK_SECS`], which is safe by construction (well
/// below any reasonable `MAX_TTL_SECS`).
fn safe_heartbeat_tick(tick: Duration, max_ttl_secs: u32) -> Duration {
    if tick.as_secs() >= u64::from(max_ttl_secs) {
        tracing::warn!(
            configured_secs = tick.as_secs(),
            max_ttl_secs,
            "SANDY_REFRESH_TICK_SECS reaches MAX_TTL_SECS; falling back to the default tick so gc's stale-dir sweep \
             can never outrun the heartbeat"
        );
        Duration::from_secs(DEFAULT_REFRESH_TICK_SECS)
    } else {
        tick
    }
}

/// Poll `lease` every `tick` and refresh it when within `margin` of expiry, until
/// the sender half of `stop` is dropped (the run finished). Each refresh re-stages
/// the live token file and revokes the superseded token via [`refresh_once`]; a
/// refresh error is logged and retried on the next tick, never fatal to the run.
///
/// A successful refresh's new token is read back and queued onto `redact_log`
/// (M-6 follow-up): `run_job`'s own redaction pass only ever saw the token staged
/// before it started, so a refreshed token needs its own entry for the
/// post-run re-redaction pass in [`run_job_with_credential`] to catch it too.
///
/// Every tick also heartbeats the cred dir's mtime (#195), regardless of
/// whether a refresh actually fires: [`gc`] sweeps a `cred-*` staging dir whose
/// mtime is older than `MAX_TTL_SECS` to reclaim one a crash or SIGKILL left
/// behind, but a provider's native token TTL can exceed `MAX_TTL_SECS`, so a
/// genuinely running job can otherwise go longer than that between refreshes.
/// A `kill -9`'d process stops ticking, so an actually abandoned dir still
/// ages out.
fn refresh_loop<P: CredentialProvider + Sync + ?Sized>(
    provider: &P,
    lease: &Mutex<Lease>,
    margin: Duration,
    tick: Duration,
    stop: &mpsc::Receiver<()>,
    redact_log: &Mutex<Vec<Zeroizing<String>>>,
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
        match refresh_once(provider, &mut guard, SystemTime::now(), margin) {
            Ok(true) => {
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

/// Garbage-collect terminal job records under the keep-last-N + referenced
/// policy, then best-effort sweep any `cred-*`/`verify-*` credential staging
/// dir left behind under the sandy staging base past its mint TTL (#195: a
/// drop guard normally removes one on every exit path, but SIGKILL or a crash
/// before it runs can leave one behind holding a live token). A still-
/// `Running` job is referenced and never evicted, even when it is oldest.
/// Returns the evicted job ids followed by the names of any swept staging
/// dirs.
///
/// The staging sweep is independent of record eviction and never fails this
/// call: an unreadable or unsafe staging base is logged and skipped rather
/// than blocking `gc`'s primary duty of reclaiming journal records.
///
/// # Errors
///
/// Returns [`CoreError`] on journal I/O failure.
pub fn gc(journal: &Journal, keep_last_n: usize) -> Result<Vec<String>, CoreError> {
    match sandy_fsutil::ensure_sandy_staging_base() {
        Ok(base) => gc_against(journal, keep_last_n, &base),
        Err(e) => {
            tracing::warn!(%e, "gc: could not validate the sandy staging base; skipping the stale credential dir sweep");
            gc_records(journal, keep_last_n)
        }
    }
}

/// [`gc`]'s implementation against an already-resolved `staging_base`: evict
/// terminal records, then sweep stale staging dirs under it. [`gc`] calls this
/// with the real sandy-owned staging base; tests call it with an injected temp
/// dir instead.
fn gc_against(journal: &Journal, keep_last_n: usize, staging_base: &Path) -> Result<Vec<String>, CoreError> {
    let mut evicted = gc_records(journal, keep_last_n)?;
    evicted.extend(sweep_stale_cred_dirs(staging_base));
    Ok(evicted)
}

/// Evict terminal job records under the keep-last-N + referenced policy (the
/// policy half of [`gc`], split out so it runs — and can be tested —
/// independently of the staging-dir sweep).
fn gc_records(journal: &Journal, keep_last_n: usize) -> Result<Vec<String>, CoreError> {
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
/// swept" rather than propagated, consistent with [`gc`]'s contract that the
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
    use std::{
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        time::{Duration, SystemTime},
    };

    use anyhow::Context;
    use sandy::{
        AllowList, BackendError, CredentialProvider, CredentialSource, EgressApplier, EgressError, EgressOs, Grants,
        Journal, Outcome, ProcessExit, Profile, Scope,
    };
    use sandy_test_support::{FakeApplier, FakeBackend};
    use zeroize::Zeroizing;

    use super::{gc_against, redact_console, redact_with_refreshes, run_job};
    use crate::plan::JobPlan;

    // --- console redaction (M-6) -------------------------------------------------

    #[test]
    fn redact_console_replaces_every_exact_occurrence() {
        let console = "login ok\ntoken=ghs_abcdef12 used\nghs_abcdef12 again".to_string();
        let redacted = redact_console(console, &["ghs_abcdef12".to_string()]);
        assert_eq!(redacted, "login ok\ntoken=[REDACTED] used\n[REDACTED] again");
    }

    /// A secret under the 8-byte floor is skipped rather than redacted: a short
    /// value like `"ab"` must never consume unrelated text like `"abc"`.
    #[test]
    fn redact_console_skips_secrets_under_eight_bytes() {
        let redacted = redact_console("abc".to_string(), &["ab".to_string()]);
        assert_eq!(redacted, "abc", "a short secret must not redact unrelated text");
    }

    #[test]
    fn redact_console_applies_every_secret_in_the_list() {
        let console = "first=sec-one-xx second=sec-two-yy".to_string();
        let redacted = redact_console(console, &["sec-one-xx".to_string(), "sec-two-yy".to_string()]);
        assert_eq!(redacted, "first=[REDACTED] second=[REDACTED]");
    }

    #[test]
    fn redact_with_refreshes_catches_a_refreshed_token_the_first_pass_never_saw() {
        let console = "initial=ghs_initial_marker refreshed=ghs_refreshed_marker".to_string();
        let redacted = redact_with_refreshes(
            console,
            "ghs_initial_marker",
            &[Zeroizing::new("ghs_refreshed_marker".to_string())],
        );
        assert_eq!(redacted, "initial=[REDACTED] refreshed=[REDACTED]");
    }

    #[test]
    fn redact_with_refreshes_is_a_no_op_shaped_call_when_nothing_refreshed() {
        let console = "initial=ghs_initial_marker only".to_string();
        let redacted = redact_with_refreshes(console, "ghs_initial_marker", &[]);
        assert_eq!(redacted, "initial=[REDACTED] only");
    }

    /// A credential source that panics if asked for a provider — the non-credentialed
    /// run path never builds one, so a [`Profile`] in these tests carries this to
    /// satisfy the seam without a live cred backend.
    struct UnusedCred;
    impl CredentialSource for UnusedCred {
        fn provider(
            &self,
            _dir: &std::path::Path,
            _name: &str,
            _capabilities: &[String],
        ) -> Result<(Box<dyn CredentialProvider + Sync>, Scope), String> {
            unreachable!("the non-credentialed run path never builds a credential provider")
        }
    }

    /// An egress applier that records apply/revert through shared handles, so a test
    /// can observe the applier a [`Profile`] has taken ownership of (by value behind a
    /// `Box<dyn>`), proving the injected egress seam was exercised.
    struct SpyApplier {
        applied: Arc<AtomicUsize>,
        reverted: Arc<AtomicBool>,
    }
    impl EgressApplier for SpyApplier {
        fn apply(&self, _ruleset: &str) -> Result<(), EgressError> {
            self.applied.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn revert(&self) -> Result<(), EgressError> {
            self.reverted.store(true, Ordering::SeqCst);
            Ok(())
        }
    }

    /// The injection contract (T1): a run driven from a [`Profile`] uses the
    /// profile's injected backend AND egress applier, not hardcoded ones. A
    /// `FakeBackend` scripted to a clean success and a shared-handle [`SpyApplier`]
    /// are bundled into the profile; with a bound tap on Linux the boot is bracketed
    /// by an enforced ruleset, so `run_with_profile` must surface band 0 AND the spy
    /// must have applied then reverted — proving both seams routed through the
    /// injected profile rather than reaching for `host_backend()`/`egress_applier()`.
    #[test]
    fn run_with_profile_uses_the_injected_backend_and_egress() -> anyhow::Result<()> {
        let (_tmp, journal) = fresh_journal()?;
        let backend = FakeBackend::new().with_outcome(Outcome {
            booted: true,
            guest_exit: Some(0),
            transport_error: None,
            timed_out: false,
            console: String::new(),
        });
        let applied = Arc::new(AtomicUsize::new(0));
        let reverted = Arc::new(AtomicBool::new(false));
        let egress = SpyApplier {
            applied: Arc::clone(&applied),
            reverted: Arc::clone(&reverted),
        };
        let profile = Profile::new(
            Box::new(backend),
            Box::new(egress),
            EgressOs::Linux,
            Box::new(UnusedCred),
        );
        // A bound tap on Linux selects an enforced guest-scoped forward ruleset, so the
        // boot is bracketed by the injected egress applier (apply then revert).
        let report =
            super::run_with_profile(&profile, &journal, &booting_plan(), Some("tap0")).context("run_with_profile")?;
        assert_eq!(
            report.process_exit.code(),
            ProcessExit::Succeeded.code(),
            "the injected FakeBackend's clean-success outcome must surface (band 0)"
        );
        assert!(!report.envelope.retryable, "a clean success is not retryable");
        assert!(
            applied.load(Ordering::SeqCst) >= 1,
            "the injected egress applier must have applied the enforced ruleset"
        );
        assert!(
            reverted.load(Ordering::SeqCst),
            "the injected egress applier must have reverted the boundary after the boot"
        );
        Ok(())
    }

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
            control: sandy::RunControl::with_timeout_secs(60),
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
            control: sandy::RunControl::with_timeout_secs(60),
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
                &[],
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
                &[],
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
                &[],
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
                &[],
            )
            .context("run_job (invalid plan)")?;
            assert_eq!(report.process_exit.code(), ProcessExit::InvalidPlan.code());
            assert!(!report.envelope.retryable, "band 2 must not be retryable");
        }
        Ok(())
    }

    /// A tick safely below `MAX_TTL_SECS` passes through unchanged.
    #[test]
    fn safe_heartbeat_tick_passes_through_a_safe_tick() {
        let tick = super::safe_heartbeat_tick(Duration::from_secs(60), 3000);
        assert_eq!(tick, Duration::from_secs(60));
    }

    /// #195 (flagged in review): a tick that reaches `MAX_TTL_SECS` would let a
    /// live job's cred dir go stale between heartbeats and get swept out from
    /// under it, so it must never be honored as-is.
    #[test]
    fn safe_heartbeat_tick_falls_back_when_the_tick_reaches_max_ttl_secs() {
        let tick = super::safe_heartbeat_tick(Duration::from_secs(3000), 3000);
        assert_eq!(tick, Duration::from_secs(super::DEFAULT_REFRESH_TICK_SECS));
    }

    /// As above, for a tick that exceeds (not just reaches) the threshold.
    #[test]
    fn safe_heartbeat_tick_falls_back_when_the_tick_exceeds_max_ttl_secs() {
        let tick = super::safe_heartbeat_tick(Duration::from_secs(3_600_000), 3000);
        assert_eq!(tick, Duration::from_secs(super::DEFAULT_REFRESH_TICK_SECS));
    }

    /// `refresh_loop` refreshes the credential on each tick while the job runs and
    /// stops promptly when the sender is dropped. A margin past the token TTL makes
    /// `should_refresh` fire every tick, so a superseded token is revoked each time.
    /// Also covers the M-6 follow-up: each refresh's new token must land in
    /// `redact_log` so a post-run re-redaction pass can catch it.
    #[test]
    fn refresh_loop_refreshes_until_the_sender_drops() -> anyhow::Result<()> {
        use std::{
            sync::{Mutex, mpsc},
            time::Duration,
        };

        use sandy::{Scope, mint_lease};
        use sandy_test_support::FakeProvider;
        use zeroize::Zeroizing;

        let tmp = tempfile::tempdir().context("tmp")?;
        std::fs::set_permissions(tmp.path(), std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .context("tmp 0700")?;
        let provider = FakeProvider::returning("tok");
        let lease = mint_lease(&provider, &Scope::default(), 1_800, "GITHUB_TOKEN", tmp.path())
            .map_err(|e| anyhow::anyhow!("{e}"))
            .context("mint")?;
        let lease = Mutex::new(lease);
        let (tx, rx) = mpsc::channel::<()>();
        let margin = Duration::from_secs(1_000_000);
        let tick = Duration::from_millis(5);
        let redact_log: Mutex<Vec<Zeroizing<String>>> = Mutex::new(Vec::new());

        std::thread::scope(|s| {
            let pref = &provider;
            let shared = &lease;
            let shared_log = &redact_log;
            s.spawn(move || super::refresh_loop(pref, shared, margin, tick, &rx, shared_log));
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
        Ok(())
    }

    /// #195: `refresh_loop` must heartbeat the cred dir's mtime every tick even
    /// when no refresh actually fires (the margin is far smaller than the
    /// lease's TTL, so `should_refresh` never trips here — proven by asserting
    /// nothing was revoked). Without the heartbeat, a long-running job whose
    /// provider TTL outlasts `gc`'s `MAX_TTL_SECS` sweep window would have its
    /// live credential dir deleted out from under it.
    #[test]
    fn refresh_loop_heartbeats_the_cred_dir_mtime_every_tick() -> anyhow::Result<()> {
        use std::sync::{Mutex, mpsc};

        use sandy::{Scope, mint_lease};
        use sandy_test_support::FakeProvider;
        use zeroize::Zeroizing;

        let tmp = tempfile::tempdir().context("tmp")?;
        std::fs::set_permissions(tmp.path(), std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .context("tmp 0700")?;
        let provider = FakeProvider::returning("tok");
        let lease = mint_lease(&provider, &Scope::default(), 1_800, "GITHUB_TOKEN", tmp.path())
            .map_err(|e| anyhow::anyhow!("{e}"))
            .context("mint")?;
        // Back-date the dir well past gc's MAX_TTL_SECS window before the loop
        // starts ticking, so a surviving fresh mtime can only be the heartbeat.
        set_mtime_age(tmp.path(), Duration::from_secs(u64::from(sandy::MAX_TTL_SECS) + 600))?;
        let lease = Mutex::new(lease);
        let (tx, rx) = mpsc::channel::<()>();
        // Far smaller than the lease's 1_800s TTL, so `should_refresh` never
        // trips in this short test: isolates the heartbeat from the
        // already-covered refresh-rewrite path.
        let margin = Duration::from_secs(1);
        let tick = Duration::from_millis(5);
        let redact_log: Mutex<Vec<Zeroizing<String>>> = Mutex::new(Vec::new());

        std::thread::scope(|s| {
            let pref = &provider;
            let shared = &lease;
            let shared_log = &redact_log;
            s.spawn(move || super::refresh_loop(pref, shared, margin, tick, &rx, shared_log));
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

    /// A backend that panics inside `run`, to drive the teardown Drop guard down the
    /// unwind path.
    struct PanicBackend;
    impl sandy::VmBackend for PanicBackend {
        fn run(&self, _spec: &sandy::RunSpec) -> Result<Outcome, BackendError> {
            panic!("backend panic during run")
        }

        fn kill(&self, _box_id: &str) -> Result<(), BackendError> {
            Ok(())
        }

        fn boxes(&self) -> Result<Vec<sandy::BoxState>, BackendError> {
            Ok(Vec::new())
        }
    }

    /// Adversarial (teardown runs on unwind): when the backend panics mid-run, the
    /// credential is still revoked and the staged `0600` secret is still removed. The
    /// Drop guard runs during unwind, where the old straight-line teardown after the
    /// refresh scope was skipped, leaving a live token and the secret on disk (INV-1).
    #[test]
    fn a_panic_during_the_run_still_revokes_and_removes_the_token() -> anyhow::Result<()> {
        use std::panic::{AssertUnwindSafe, catch_unwind};

        use sandy::{MAX_TTL_SECS, Scope};
        use sandy_test_support::FakeProvider;

        use super::run_job_with_credential;

        let (_home, journal) = fresh_journal()?;
        let cred_dir = tempfile::tempdir().context("cred dir")?;
        std::fs::set_permissions(cred_dir.path(), std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .context("cred dir 0700")?;
        let provider = FakeProvider::returning("tok");

        // Suppress the deliberate panic's default backtrace print.
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let result = catch_unwind(AssertUnwindSafe(|| {
            run_job_with_credential(
                &PanicBackend,
                &journal,
                booting_plan(),
                &FakeApplier::new(),
                EgressOs::Linux,
                None,
                &provider,
                &Scope::default(),
                "GITHUB_TOKEN",
                cred_dir.path(),
                MAX_TTL_SECS,
            )
        }));
        std::panic::set_hook(prev);

        assert!(result.is_err(), "the backend panic must propagate");
        assert!(
            !provider.revoked().is_empty(),
            "the credential must be revoked even when the run panics"
        );
        assert!(
            !cred_dir.path().join("GITHUB_TOKEN").exists(),
            "the staged token must be removed even when the run panics"
        );
        Ok(())
    }

    // --- gc sweeps stale credential staging dirs (#195) -------------------------

    /// Back-date `dir`'s mtime by `age` so gc's sweep sees it as that old.
    fn set_mtime_age(dir: &std::path::Path, age: Duration) -> anyhow::Result<()> {
        let past = SystemTime::now() - age;
        std::fs::File::open(dir)
            .context("open dir to back-date mtime")?
            .set_modified(past)
            .context("set_modified")?;
        Ok(())
    }

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

        let evicted = gc_against(&journal, 20, &staging_base).context("gc")?;

        assert!(
            evicted.contains(&"cred-deadbeef".to_string()),
            "a stale cred dir past MAX_TTL_SECS must be swept: {evicted:?}"
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

        let evicted = gc_against(&journal, 20, &staging_base).context("gc")?;

        assert!(
            !evicted.contains(&"verify-cafef00d".to_string()),
            "a fresh verify dir must not be swept: {evicted:?}"
        );
        assert!(fresh.exists(), "the fresh verify dir must survive");
        Ok(())
    }
}
