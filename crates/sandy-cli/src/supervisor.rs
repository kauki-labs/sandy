//! The foreground supervisor and job operations (generic over [`VmBackend`]).
//!
//! `run_job` is the foreground path: it validates the plan, writes a `Running`
//! record *before* the backend runs (INV-6), classifies the physical outcome into
//! the LOCKED [`ResultEnvelope`] plus a process band, and writes the terminal
//! record carrying the envelope. [`run_job_with_credential`] shares that core
//! ([`run_job_core`]) but defers the terminal write until its refresh thread has
//! joined and the console's final redaction is known (#322), so the write and the
//! redaction are atomic rather than a write followed by an amend. `ls` / `status`
//! / `wait` / `kill` / `gc` are the management ops; all liveness goes through
//! [`reconcile_job`], never a direct registry read (INV-3).
//!
//! Five independent concerns live in sibling modules, each hiding its own
//! implementation: [`envelope`] (redaction + the result envelope),
//! [`outputs`] (collecting a job's declared output files), [`journal`]
//! (persisting the terminal record), [`cred_refresh`] (the mid-run credential
//! refresh loop) and [`lifecycle`] (`gc`'s record eviction + staging-dir
//! sweep). This file is the thin orchestration layer that calls into them.

use std::{
    path::Path,
    sync::{Mutex, PoisonError, mpsc},
    time::{Duration, Instant, SystemTime},
};

use sandy::{
    AuditReceipt, BackendError, CALL_DEADLINE, Classification, CoreError, CredentialProvider, CredentialReceipt,
    DirFingerprint, EgressApplier, EgressOs, EgressOutcome, EgressPlan, GuestReported, JOURNAL_SCHEMA_VERSION,
    JobRecord, JobState, Journal, Lease, MAX_TTL_SECS, Outcome, OutputStatus, PlanError, ProcessExit, Profile,
    ResultEnvelope, Scope, SecretSource, Status, VmBackend, classify_backend_error, classify_invalid_plan,
    classify_outcome, enforce, mint_lease, mint_lease_checked, new_job_id, plan_egress_scoped, reconcile_job,
    validate_egress_hosts, validate_network_mode, validate_no_secret_leak, validate_proxy_egress,
};
use zeroize::Zeroizing;

use crate::plan::JobPlan;

mod cred_refresh;
mod envelope;
mod journal;
mod lifecycle;
mod outputs;

use cred_refresh::{CredTeardown, refresh_interval, refresh_loop, safe_heartbeat_tick};
pub use cred_refresh::{DEFAULT_REFRESH_MARGIN_SECS, DEFAULT_REFRESH_TICK_SECS};
use envelope::{build_envelope, build_host_observed, no_network_allow_warning, redact_console, redact_with_refreshes};
pub use journal::JournalWriter;
use journal::{JobOutcome, write_terminal_record};
use lifecycle::{gc_against, gc_records};
use outputs::{collect_output_refs, collect_output_size_refs};

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
    let mut outcome = run_job_core(backend, journal, plan, egress, egress_os, tap, redact)?;
    if let Some(started) = outcome.started {
        match write_terminal_record(journal, started, &outcome.report) {
            Ok(true) => {}
            Ok(false) => {
                // A concurrent kill/reconcile already landed this job's terminal
                // record; reporting our own result here would drift from the
                // journal (the review finding behind this match). Fail rather
                // than hand back a result nobody else will see.
                return Err(CoreError::State(format!(
                    "job {} was already finalized by a concurrent kill/reconcile; refusing to report a result that \
                     would drift from the journal",
                    outcome.report.envelope.job_id
                )));
            }
            Err(e) => {
                // L-12: fold into the envelope too, not just the log — see
                // run_job_with_credential_timed's matching comment.
                tracing::warn!(job_id = %outcome.report.envelope.job_id, error = %e, "failed to write the terminal journal record");
                outcome
                    .report
                    .envelope
                    .warnings
                    .push(format!("terminal journal record could not be written: {e}"));
            }
        }
    }
    Ok(outcome.report)
}

/// The plan-time egress check for the run's boundary model: the nftables path
/// refuses hostname entries (#359); a proxy-mode run (`SANDY_EGRESS=proxy`, #360)
/// resolves names host-side, so it refuses a guest NIC on Linux instead.
fn validate_run_egress(plan: &JobPlan, egress_os: EgressOs, tap: Option<&str>) -> Result<(), PlanError> {
    if plan.egress_proxy {
        validate_proxy_egress(egress_os, tap)?;
    } else {
        validate_egress_hosts(&plan.allow, egress_os)?;
    }
    validate_network_mode(egress_os, plan.network, tap, plan.egress_proxy)
}

/// The receipt's egress outcome for a proxy-mode run, read from what the backend did.
///
/// The host applies nothing in proxy mode: the backend starts the proxy and boots the
/// guest behind it, so "enforced" is true only once a guest ran. `Spawn` means the
/// backend refused the policy or could not start the proxy, before any boot. A guest that never
/// booted ran behind nothing. Anything later, a proxy that died mid-run included, means the
/// proxy served the run, so it stays enforced: that fault is already a band-3 result of its own.
/// A proxy found dead before the guest booted (`booted: false`) counts as a guest that never booted.
fn proxy_receipt_result(run: &Result<Outcome, BackendError>) -> Result<EgressOutcome, String> {
    match run {
        Err(BackendError::Spawn(why)) => Err(why.clone()),
        Err(BackendError::EgressProxyDied { booted: false, .. }) => {
            Err("the egress proxy died before the guest booted, so it served no run".to_string())
        }
        Ok(outcome) if !outcome.booted => Err("the guest never booted, so the egress proxy served no run".to_string()),
        _ => Ok(EgressOutcome::Proxied),
    }
}

/// The shared core of [`run_job`] and [`run_job_with_credential`]: validates the
/// plan, writes the `Running` record, runs the backend, classifies the outcome,
/// and builds the envelope — everything through step 5 of [`run_job`]'s
/// documented order, but WITHOUT writing the terminal record (step 6). [`run_job`]
/// persists it immediately after this returns; [`run_job_with_credential`] defers
/// it until the refresh thread has joined and `redact_with_refreshes` is final, so
/// the credentialed path's terminal write and its token redaction are one atomic
/// write, not a write followed by an amend (#322).
fn run_job_core<B: VmBackend + ?Sized, E: EgressApplier + ?Sized, J: JournalWriter + ?Sized>(
    backend: &B,
    journal: &J,
    plan: &JobPlan,
    egress: &E,
    egress_os: EgressOs,
    tap: Option<&str>,
    redact: &[String],
) -> Result<JobOutcome, CoreError> {
    let spec = plan.as_run_spec();

    // 1. Validate the plan. An invalid plan is band 2 with NO journal record and NO backend run — the running record is
    //    the first thing written, so an empty journal proves the backend was never reached (the silent-run guard). A
    //    hostname allow-list entry is invalid on Linux only (#359): nft pins one address at load time and the guest
    //    can't resolve names through the boundary anyway, so it is refused here rather than loaded as a rule that never
    //    matches. macOS enforces no boundary, so a hostname entry there stays accepted. A proxy-mode run
    //    (`SANDY_EGRESS=proxy`, #360) swaps that check: the proxy resolves names host-side, so hostnames are valid, and
    //    what is refused instead is a guest NIC (`$SANDY_TAP`) on Linux. The guest network profile must agree with the
    //    tap and the proxy (#602).
    if let Err(plan_error) = validate_no_secret_leak(&spec).and_then(|()| validate_run_egress(plan, egress_os, tap)) {
        let classification = classify_invalid_plan(&plan_error);
        let envelope = build_envelope(
            &new_job_id(),
            None,
            classification,
            None,
            plan_error.to_string(),
            redact_console(String::new(), redact),
            vec![],
            None,
        );
        return Ok(JobOutcome {
            report: RunReport {
                envelope,
                process_exit: classification.process_exit,
            },
            started: None,
            live: None,
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
    // Before the `Running` record exists, so no reader can see the job running without seeing its owner live (#699).
    let live = journal.hold_liveness(&job_id)?;
    journal.persist(&running)?;

    // 3. Apply the egress boundary around the boot. On Linux with a tap this loads the guest-scoped forward ruleset
    //    (the safe model, #29); on macOS `plan_egress_scoped` yields `NoBoundary`, so `enforce` applies nothing and
    //    warns. If the boundary can't be applied we fail CLOSED: do not boot, and treat it as an infra fault that lands
    //    a terminal record (band 3) rather than leaving a dangling `Running` record.
    // 4. On a successful apply, run the backend, then ALWAYS revert when the boundary was enforced — on both the ok and
    //    error paths, so a boot failure never leaves nftables rules up.
    let eplan = if plan.egress_proxy {
        EgressPlan::Proxy
    } else {
        plan_egress_scoped(&plan.allow, egress_os, tap)
    };
    // Captured alongside `run_result` so the receipt's egress half (#361) reads
    // the SAME platform-keyed outcome that drove the enforce/revert bracket below,
    // never a second, independently derived copy.
    let egress_receipt_result: Result<EgressOutcome, String>;
    // A cancel that landed before the boot (a signal during mint or setup, #687) starts no guest and loads no egress
    // rules: the run is cancelled and the caller's teardown still runs.
    let enforced = if plan.control.is_cancelled() {
        None
    } else {
        Some(enforce(&eplan, egress))
    };
    let (run_result, egress_warning): (Result<Outcome, BackendError>, Option<String>) = match enforced {
        None => {
            egress_receipt_result = Err("run cancelled before boot".to_owned());
            (Err(BackendError::Spawn("run cancelled before boot".to_owned())), None)
        }
        Some(Ok(eoutcome)) => {
            let outcome = backend.run(&spec);
            // The proxy is the boundary, and the backend establishes it, so the receipt reads the run's result
            // rather than the plan's intent: a refusal before boot must not be recorded as enforced.
            egress_receipt_result = if matches!(eoutcome, EgressOutcome::Proxied) {
                proxy_receipt_result(&outcome)
            } else {
                Ok(eoutcome.clone())
            };
            if matches!(eoutcome, EgressOutcome::Enforced)
                && let Err(e) = egress.revert()
            {
                tracing::warn!(%e, "egress revert failed");
            }
            // In proxy mode the guest has no NIC by design and the proxy enforces the allow-list, so the
            // "allow-list has no effect" warning would be false.
            let warning = if plan.egress_proxy {
                None
            } else {
                no_network_allow_warning(&plan.allow, backend.kind(), egress_os, tap, plan.network)
            };
            (outcome, warning)
        }
        Some(Err(egress_error)) => {
            egress_receipt_result = Err(egress_error.to_string());
            tracing::warn!(%job_id, %egress_error, "egress apply failed; refusing to boot (fail-closed)");
            (
                Err(BackendError::Spawn(format!(
                    "egress boundary not established: {egress_error}"
                ))),
                None,
            )
        }
    };

    // 5. Classify the physical outcome. The console tail is carried through to the envelope so a boot fault (which
    //    never produced a guest exit) is still diagnosable from the record alone.
    let (classification, guest_exit, message, console, outputs, output_sizes, digests) = match run_result {
        Err(backend_error) => {
            tracing::warn!(%job_id, error = %backend_error, "backend run failed (infra fault)");
            (
                classify_backend_error(&backend_error),
                None,
                format!("infra fault: {backend_error}"),
                String::new(),
                vec![],
                vec![],
                None,
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
                collect_output_size_refs(plan, outcome.digests.as_ref().map(|d| &d.outputs)),
                outcome.digests,
            )
        }
    };
    // A cancel (SIGTERM, SIGHUP or SIGINT to `sandy run`, #687) ends the run `cancelled`, band 1, whatever the
    // backend made of it: the real backends treat it like a timeout or a refusal. A guest that already exited
    // (clean or not) keeps its result: the signal only found the teardown.
    let (classification, message) =
        if plan.control.is_cancelled() && classification.status != Status::Succeeded && guest_exit.is_none() {
            (
                Classification {
                    status: Status::Cancelled,
                    retryable: false,
                    process_exit: ProcessExit::TaskFailure,
                },
                format!("run cancelled ({message})"),
            )
        } else {
            (classification, message)
        };
    // Teardown completed the moment the backend returned and the egress boundary
    // (if enforced) was reverted, just above — captured here, before the console
    // redaction pass or the journal write, neither of which are part of the run
    // itself (#361's `timing.teardown_at`).
    let teardown_at = SystemTime::now();

    // 6. Build the envelope carrying the redacted console (INV-6). Redact right before the envelope is built: for
    //    `run_job` this is the last point before the journal write; `run_job_with_credential` re-redacts against any
    //    mid-run refresh before persisting (M-6). The caller (`run_job` or `run_job_with_credential`) writes the
    //    terminal record.
    let console = redact_console(console, redact);
    let mut host_observed = build_host_observed(
        &job_id,
        plan,
        backend.kind(),
        egress_os,
        &egress_receipt_result,
        started,
        teardown_at,
    );
    // #373: the backend hashed the staged inputs before boot (host-observed) and the
    // collected outputs (guest-reported). Both are `None` unless `--digests` was given.
    let skipped_outputs = digests.as_ref().map(|d| d.outputs.skipped.clone()).unwrap_or_default();
    host_observed.input_digests = digests.map(|d| d.inputs);
    let receipt = Some(AuditReceipt {
        host_observed,
        guest_reported: GuestReported {
            exit_code: guest_exit,
            outputs: output_sizes,
            skipped_outputs,
        },
    });
    let mut envelope = build_envelope(
        &job_id,
        None,
        classification,
        guest_exit,
        message,
        console,
        outputs,
        receipt,
    );
    if let Some(warning) = egress_warning {
        envelope.warnings.push(warning);
    }

    Ok(JobOutcome {
        report: RunReport {
            envelope,
            process_exit: classification.process_exit,
        },
        started: Some(started),
        live,
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
/// `MAX_TTL_SECS` by [`sandy::mint_lease_checked`]; revoke-at-teardown is the real
/// lifetime bound (the provider's native token TTL is too coarse, #49), so the token
/// file is kept until after `revoke` (a GitHub revoke reads it) and then removed.
///
/// `cred_dir` is the caller-owned secret share: the token is staged there as its
/// env name and the dir is shared read-only into the guest ([`RunSpec::secret_dir`]),
/// so a refresh can rewrite the live file in place. `cred_dir_fingerprint` is the
/// `(dev, ino)` the caller's own validation of `cred_dir` (e.g.
/// [`sandy_fsutil::private_staging_dir`]) captured before this call: every re-open of
/// `cred_dir` by path from here on (the initial mint, each refresh, and the
/// backend's own guest-share staging) is checked against it, refusing a same-uid,
/// same-mode directory swapped in at `cred_dir`'s path in between (#323) instead of
/// trusting the path alone. While the job runs, a background thread drives
/// [`sandy::refresh_once_checked`] (gated by [`sandy::should_refresh`]) to
/// re-mint and re-stage the token before it lapses, revoking each superseded one, so
/// a job that outlives the provider's native token cap (GitHub ~1h) keeps a valid
/// scoped token the whole run. The refresh margin and poll interval default to
/// [`DEFAULT_REFRESH_MARGIN_SECS`] / [`DEFAULT_REFRESH_TICK_SECS`], overridable via
/// `SANDY_REFRESH_MARGIN_SECS` / `SANDY_REFRESH_TICK_SECS` (the latter capped by
/// [`safe_heartbeat_tick`]). Every tick also heartbeats `cred_dir`'s mtime
/// (#195), so [`gc`]'s stale-staging-dir sweep never mistakes a live
/// long-running job for one SIGKILL or a crash left behind. Teardown revokes
/// the live token (the latest handle after any refresh) on every path and
/// removes the staged file (INV-1); `cred_dir` itself is the caller's to
/// clean up.
///
/// Unlike [`run_job`], this runs the shared core ([`run_job_core`]) WITHOUT
/// writing the terminal record: that write happens once, here, after the refresh
/// thread has joined and `redact_with_refreshes` has produced the final console
/// (#322) — never a first write against only the initial token followed by an
/// amend. A revoke-failure warning is folded into the same envelope before that
/// one write, so the journaled record and the returned [`RunReport`] never drift
/// apart (L-12).
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
    J: JournalWriter + ?Sized,
>(
    backend: &B,
    journal: &J,
    plan: JobPlan,
    egress: &E,
    egress_os: EgressOs,
    tap: Option<&str>,
    provider: &P,
    scope: &Scope,
    secret_name: &str,
    cred_dir: &Path,
    cred_dir_fingerprint: DirFingerprint,
    requested_ttl_secs: u32,
) -> Result<RunReport, CoreError> {
    // Validate the plan before minting: a hostname allow-list entry is invalid on
    // Linux (#359, same check `run_job` runs). Checking it here, before the mint,
    // means a bad plan never mints-and-immediately-revokes a credential for a run
    // that was always going to be refused, and a mint failure (CoreError::Cred)
    // never masks what should be a clean band-2 invalid-plan report.
    if let Err(plan_error) = validate_run_egress(&plan, egress_os, tap) {
        let classification = classify_invalid_plan(&plan_error);
        let envelope = build_envelope(
            &new_job_id(),
            None,
            classification,
            None,
            plan_error.to_string(),
            String::new(),
            vec![],
            None,
        );
        return Ok(RunReport {
            envelope,
            process_exit: classification.process_exit,
        });
    }

    let margin = refresh_interval("SANDY_REFRESH_MARGIN_SECS", DEFAULT_REFRESH_MARGIN_SECS);
    let tick = safe_heartbeat_tick(
        refresh_interval("SANDY_REFRESH_TICK_SECS", DEFAULT_REFRESH_TICK_SECS),
        MAX_TTL_SECS,
        CALL_DEADLINE,
    );
    run_job_with_credential_timed(
        backend,
        journal,
        plan,
        egress,
        egress_os,
        tap,
        provider,
        scope,
        secret_name,
        cred_dir,
        cred_dir_fingerprint,
        requested_ttl_secs,
        margin,
        tick,
    )
}

/// [`run_job_with_credential`]'s body, with the refresh margin/tick taken as
/// parameters instead of read from the environment: `std::env::set_var` is
/// `unsafe` (edition 2024) and forbidden by this workspace's lints, so a test
/// that needs a short tick to force a mid-run refresh calls this directly
/// rather than mutating process environment state.
#[allow(
    clippy::too_many_arguments,
    reason = "the bracket threads both the run and the credential inputs, plus the injectable timing"
)]
fn run_job_with_credential_timed<
    B: VmBackend + ?Sized,
    E: EgressApplier + ?Sized,
    P: CredentialProvider + Sync + ?Sized,
    J: JournalWriter + ?Sized,
>(
    backend: &B,
    journal: &J,
    plan: JobPlan,
    egress: &E,
    egress_os: EgressOs,
    tap: Option<&str>,
    provider: &P,
    scope: &Scope,
    secret_name: &str,
    cred_dir: &Path,
    cred_dir_fingerprint: DirFingerprint,
    requested_ttl_secs: u32,
    margin: Duration,
    tick: Duration,
) -> Result<RunReport, CoreError> {
    // Mint and stage the token before the guest boots, into the share dir itself so
    // the staged file IS the live guest file (refresh rewrites it). A mint failure is
    // a fail-closed infra fault: return before any backend run (INV-7).
    // `mint_lease_checked` refuses the stage if `cred_dir` no longer matches
    // `cred_dir_fingerprint` — the caller's own validation of it, captured before
    // this call (#323) — rather than trusting a same-uid, same-mode directory
    // swapped in at `cred_dir`'s path since.
    let lease = mint_lease_checked(
        provider,
        scope,
        requested_ttl_secs,
        secret_name,
        cred_dir,
        cred_dir_fingerprint,
    )
    .map_err(|e| CoreError::Cred(e.to_string()))?;
    // Captured for the receipt's `credential.minted_at` (#361): right after the
    // mint that just succeeded, before the boot it's staged for.
    let minted_at = SystemTime::now();
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
    // The fingerprint rides along so the backend's own reopen-by-path (it only ever
    // gets `RunSpec::secret_dir`'s path, never this live handle) is checked the same
    // way (#323).
    let mut plan = plan;
    plan.secret_dir = Some((cred_dir.to_path_buf(), cred_dir_fingerprint));

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
        revoked_at: None,
        revoke_succeeded: None,
    };
    // Borrow the zeroizing holder directly: no unzeroized plaintext clone.
    // `run_job`'s own redaction only ever sees this initial token; `redact_log`
    // (M-6 follow-up) catches whatever a mid-run refresh adds after that.
    let redact = std::slice::from_ref(&*teardown.secret);
    let redact_log: Mutex<Vec<Zeroizing<String>>> = Mutex::new(Vec::new());
    // Parallel to `redact_log`: when each mid-run refresh fired, for the
    // receipt's `credential.refreshed_at` (#361).
    let refresh_times_log: Mutex<Vec<SystemTime>> = Mutex::new(Vec::new());

    // Run the job on this thread; refresh the credential on a second thread until the
    // run returns, then signal it to stop by dropping the sender. The refresh thread
    // borrows the guard's lease (a `&Mutex`, so the guard isn't moved) and owns the
    // receiver; the scope joins it before the guard's teardown can run.
    let shared_lease = &teardown.lease;
    let shared_redact_log = &redact_log;
    let shared_refresh_times_log = &refresh_times_log;
    let mut outcome = std::thread::scope(|s| {
        s.spawn(move || {
            refresh_loop(
                provider,
                shared_lease,
                margin,
                tick,
                &stop_rx,
                shared_redact_log,
                shared_refresh_times_log,
                cred_dir_fingerprint,
            )
        });
        let outcome = run_job_core(backend, journal, &plan, egress, egress_os, tap, redact);
        drop(stop_tx);
        outcome
    });

    // Explicit teardown on the normal return path (the borrow of `teardown.lease`
    // above ended with `thread::scope`, so this is the first point it can be
    // touched again): name the job in the revoke-failure log. On a panic, `Drop`
    // runs the same teardown instead, with no job id yet known.
    if let Ok(job_outcome) = &outcome {
        teardown.job_id = job_outcome.report.envelope.job_id.clone();
    }
    let warning = teardown.teardown();
    let refreshed_tokens = redact_log.into_inner().unwrap_or_else(PoisonError::into_inner);
    let refreshed_at = refresh_times_log.into_inner().unwrap_or_else(PoisonError::into_inner);
    // #361: the only credential provider implemented today (`GithubAdapter`);
    // becomes a caller-supplied parameter once a second provider (e.g. GitLab)
    // ships — `CredentialProvider` itself exposes no name to read back.
    const CREDENTIAL_PROVIDER: &str = "github";
    let credential_receipt = CredentialReceipt {
        provider: CREDENTIAL_PROVIDER.to_string(),
        scope: scope.clone(),
        minted_at,
        refreshed_at,
        // `teardown.teardown()` above always sets both on its one real run
        // (the `done` guard makes every later call, including `Drop`'s, a
        // no-op); these fallbacks are unreachable in practice, not a silent
        // default standing in for a real observation.
        revoked_at: teardown.revoked_at.unwrap_or(minted_at),
        revoke_succeeded: teardown.revoke_succeeded.unwrap_or(false),
    };
    if let Ok(job_outcome) = &mut outcome {
        let report = &mut job_outcome.report;

        // M-6 follow-up: re-redact against every token this run ever had live,
        // not just the one `run_job_core` saw at its own redaction pass.
        if !refreshed_tokens.is_empty() {
            report.envelope.logs.tail = redact_with_refreshes(
                std::mem::take(&mut report.envelope.logs.tail),
                &teardown.secret,
                &refreshed_tokens,
            );
        }
        if let Some(warning) = warning {
            report.envelope.warnings.push(warning);
        }
        // `run_job_core` always sets `credential: None` (it knows nothing of
        // the bracket wrapping it); fill it in here, before the single
        // terminal write below, the first point the credential's own
        // lifecycle is known. `None` only when the run itself never reached a
        // Running record (an invalid plan) — nothing to fill in on that path.
        if let Some(receipt) = &mut report.envelope.receipt {
            receipt.host_observed.credential = Some(credential_receipt);
        }

        // Persist the terminal record exactly once, now that redaction is final
        // (#322): no separate first write to amend. `started` is `None` only for
        // the invalid-plan early return, which never wrote a `Running` record
        // either — the silent-run guard stays intact.
        if let Some(started) = job_outcome.started {
            match write_terminal_record(journal, started, report) {
                Ok(true) => {}
                Ok(false) => {
                    // A concurrent kill/reconcile already landed this job's
                    // terminal record; reporting our own result here would drift
                    // from the journal. Fail rather than hand back a result
                    // nobody else will see.
                    let job_id = report.envelope.job_id.clone();
                    return Err(CoreError::State(format!(
                        "job {job_id} was already finalized by a concurrent kill/reconcile; refusing to report a \
                         result that would drift from the journal"
                    )));
                }
                Err(e) => {
                    // L-12: fold into the returned envelope too, not just the log.
                    // The caller otherwise sees an ordinary successful exit band
                    // with no sign that the journal record (INV-6) is missing or
                    // stale; a later `status`/`wait` then disagrees with the
                    // result this call already returned. Teardown has already
                    // run, so there is nothing left to undo by failing this call
                    // outright.
                    tracing::warn!(job_id = %report.envelope.job_id, error = %e, "failed to write the credentialed run's terminal journal record");
                    report
                        .envelope
                        .warnings
                        .push(format!("terminal journal record could not be written: {e}"));
                }
            }
        }
    }
    outcome.map(|o| o.report)
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

/// How long [`kill`] waits for the owner of a live run to finish its own teardown after a `SIGTERM`.
pub const KILL_BUDGET: Duration = Duration::from_secs(60);

/// What [`kill`] sends the owner of a live run. A trait only so a test can observe the signal without sending one to a
/// real process.
pub trait OwnerSignal {
    /// Ask process `pid` to stop (`SIGTERM`). The error is the kernel's: [`std::io::ErrorKind::PermissionDenied`] when
    /// the process belongs to another user.
    ///
    /// # Errors
    ///
    /// The `kill(2)` failure.
    fn terminate(&self, pid: u32) -> std::io::Result<()>;
}

/// The real `SIGTERM`, which `sandy run` answers by cancelling the run (#687).
#[derive(Debug, Clone, Copy)]
pub struct SigTerm;

impl OwnerSignal for SigTerm {
    fn terminate(&self, pid: u32) -> std::io::Result<()> {
        let pid = i32::try_from(pid)
            .ok()
            .and_then(rustix::process::Pid::from_raw)
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
        rustix::process::kill_process(pid, rustix::process::Signal::TERM).map_err(errno_to_io)
    }
}

/// `kill(2)`'s errno as the error [`stop_live_owner`] matches on. `std` has no [`std::io::ErrorKind`] for `ESRCH` (it
/// reads as `Uncategorized`), so a process that exited since the lock was checked is named `NotFound` here.
fn errno_to_io(errno: rustix::io::Errno) -> std::io::Error {
    if errno == rustix::io::Errno::SRCH {
        std::io::Error::from(std::io::ErrorKind::NotFound)
    } else {
        std::io::Error::from(errno)
    }
}

/// Cancel a running job.
///
/// A live owner (its liveness lock is held, INV-3) is sent `SIGTERM` and given [`KILL_BUDGET`] to tear the guest down,
/// revoke the credential and write its own terminal record; that record is returned. Nothing is written here for a
/// live job, so the owner's receipt stands. A dead owner's record is flipped to `Cancelled` after its box is torn down.
/// Idempotent on an already-terminal record.
///
/// # Errors
///
/// Returns [`CoreError`] on journal I/O failure, when the owner cannot be signalled (another user's process), or when
/// it does not finish within the budget. The record stays `running` in both of the last two cases.
pub fn kill<B: VmBackend>(journal: &Journal, backend: &B, job_id: &str) -> Result<JobRecord, CoreError> {
    kill_with(journal, backend, &SigTerm, job_id, KILL_BUDGET)
}

/// [`kill`] with the signal and the budget supplied.
///
/// # Errors
///
/// As [`kill`].
pub fn kill_with<B: VmBackend, S: OwnerSignal + ?Sized>(
    journal: &Journal,
    backend: &B,
    signal: &S,
    job_id: &str,
    budget: Duration,
) -> Result<JobRecord, CoreError> {
    // Idempotent on an already-terminal record: nothing to tear down.
    let record = journal.read_record(job_id)?;
    if record.state != JobState::Running {
        return Ok(record);
    }
    if journal.owner_live(job_id)? {
        return stop_live_owner(journal, backend, signal, &record, budget);
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
        // No backend run to observe (kill tears a Running job down, it never
        // itself runs one) — same reasoning as the invalid-plan path (#361).
        None,
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

/// Signal the live owner of `record` and wait for it to finish (#695). The liveness lock is held, so `writer_pid` is
/// that owner and cannot have been reused. No job lock is held while waiting: the owner's terminal write takes it.
fn stop_live_owner<B: VmBackend, S: OwnerSignal + ?Sized>(
    journal: &Journal,
    backend: &B,
    signal: &S,
    record: &JobRecord,
    budget: Duration,
) -> Result<JobRecord, CoreError> {
    let job_id = &record.job_id;
    let pid = record.writer_pid;
    // `kill(0)` is the caller's whole process group and pid 1 is init: never what a record should name.
    if pid <= 1 {
        return Err(CoreError::State(format!(
            "job {job_id} names pid {pid} as its owner; refusing to signal it"
        )));
    }
    match signal.terminate(pid) {
        Ok(()) => {}
        // The owner exited since the lock was checked: the wait below sees it go.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            return Err(CoreError::State(format!(
                "job {job_id} is run by pid {pid}, which this user may not signal ({e}); run `sandy kill {job_id}` as \
                 that user or as root"
            )));
        }
        Err(e) => {
            return Err(CoreError::State(format!(
                "could not signal pid {pid}, the owner of job {job_id}: {e}"
            )));
        }
    }
    let deadline = Instant::now() + budget;
    while journal.owner_live(job_id)? {
        if Instant::now() >= deadline {
            return Err(CoreError::State(format!(
                "job {job_id} (pid {pid}) did not finish within {budget:?} of SIGTERM; not escalating to SIGKILL, \
                 which would skip the credential revoke"
            )));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let finished = journal.read_record(job_id)?;
    if finished.state != JobState::Running {
        return Ok(finished);
    }
    // The owner went without writing its result: the reconcile path settles it (`crashed`).
    reconcile_job(journal, backend, job_id)
}

/// [`gc`]'s result: evicted job ids and swept staging-dir names, kept apart
/// (#195). `evicted` holds job ids only, so a consumer passing its entries to
/// `status`/`wait` never receives a staging-dir name, and the plain-text
/// "evicted N record(s)" count never counts a directory as a record.
#[derive(Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct GcReport {
    /// Job ids evicted under the keep-last-N + referenced policy.
    pub evicted: Vec<String>,
    /// Names of any `cred-*`/`verify-*` staging dirs swept past `MAX_TTL_SECS`.
    pub swept_staging_dirs: Vec<String>,
}

/// Garbage-collect terminal job records under the keep-last-N + referenced
/// policy, then best-effort sweep any `cred-*`/`verify-*` credential staging
/// dir left behind under the sandy staging base past its mint TTL (#195: a
/// drop guard normally removes one on every exit path, but SIGKILL or a crash
/// before it runs can leave one behind holding a live token). A still-
/// `Running` job is referenced and never evicted, even when it is oldest.
///
/// The staging sweep is independent of record eviction and never fails this
/// call: an unreadable or unsafe staging base is logged and skipped rather
/// than blocking `gc`'s primary duty of reclaiming journal records.
///
/// # Errors
///
/// Returns [`CoreError`] on journal I/O failure.
pub fn gc(journal: &Journal, keep_last_n: usize) -> Result<GcReport, CoreError> {
    match sandy_fsutil::ensure_sandy_staging_base() {
        Ok(base) => gc_against(journal, keep_last_n, &base),
        Err(e) => {
            tracing::warn!(%e, "gc: could not validate the sandy staging base; skipping the stale credential dir sweep");
            Ok(GcReport {
                evicted: gc_records(journal, keep_last_n)?,
                swept_staging_dirs: Vec::new(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    /// `kill(2)` on an exited process fails with `ESRCH`, which `std` does not categorise: `kill` must see `NotFound`
    /// to tell "the owner just finished" from a real failure (#695).
    #[test]
    fn a_missing_process_is_not_found_and_a_refusal_stays_permission_denied() {
        assert_eq!(
            super::errno_to_io(rustix::io::Errno::SRCH).kind(),
            std::io::ErrorKind::NotFound
        );
        assert_eq!(
            super::errno_to_io(rustix::io::Errno::PERM).kind(),
            std::io::ErrorKind::PermissionDenied
        );
    }

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

    use super::run_job;
    use crate::plan::JobPlan;

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
            digests: None,
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
        let plan = JobPlan {
            network: sandy::NetworkMode::Nic,
            ..booting_plan()
        };
        let report = super::run_with_profile(&profile, &journal, &plan, Some("tap0")).context("run_with_profile")?;
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
            digests: false,
            egress_proxy: false,
            network: sandy::NetworkMode::None,
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
            digests: false,
            egress_proxy: false,
            network: sandy::NetworkMode::None,
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
                digests: None,
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
                digests: None,
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
                digests: None,
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
        let (dev, ino) = sandy_fsutil::OwnedDir::open(cred_dir.path())?.dev_ino()?;
        let fingerprint = sandy::DirFingerprint { dev, ino };
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
                fingerprint,
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

    // --- terminal journal write ordering (#322) ----------------------------------

    use std::sync::{Mutex, PoisonError};

    /// A [`super::JournalWriter`] test double that delegates every write through to
    /// a real [`Journal`] (so `Journal::read_record` still sees genuine persisted
    /// state) while also recording each record passed to `persist`, in call order.
    /// Lets a test assert how many times, and in what shape, a write happened — not
    /// just the final content left on disk.
    struct CountingJournal<'a> {
        inner: &'a Journal,
        writes: Mutex<Vec<sandy::JobRecord>>,
    }

    impl<'a> CountingJournal<'a> {
        fn new(inner: &'a Journal) -> Self {
            Self {
                inner,
                writes: Mutex::new(Vec::new()),
            }
        }

        fn writes_for(&self, job_id: &str) -> Vec<sandy::JobRecord> {
            self.writes
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .iter()
                .filter(|r| r.job_id == job_id)
                .cloned()
                .collect()
        }
    }

    impl super::JournalWriter for CountingJournal<'_> {
        fn persist(&self, record: &sandy::JobRecord) -> Result<(), sandy::CoreError> {
            self.writes
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(record.clone());
            self.inner.write_record(record)
        }

        fn persist_if_still_running(&self, record: &sandy::JobRecord) -> Result<bool, sandy::CoreError> {
            self.writes
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(record.clone());
            super::JournalWriter::persist_if_still_running(self.inner, record)
        }
    }

    /// A [`CredentialProvider`] whose mint and refresh return distinct tokens, so a
    /// test can tell the initial-token redaction pass apart from the mid-run-refresh
    /// redaction pass (M-6 follow-up) — `FakeProvider` returns the same token for
    /// both, which can't exercise that distinction.
    struct TwoTokenProvider {
        initial: &'static str,
        refreshed: &'static str,
    }

    impl CredentialProvider for TwoTokenProvider {
        fn mint(&self, _scope: &Scope, ttl_hint: Duration) -> Result<sandy::Minted, sandy::CredError> {
            Ok(sandy::Minted::new(
                self.initial.to_string(),
                SystemTime::now() + ttl_hint,
                sandy::CredentialHandle {
                    id: "two-token-initial".to_string(),
                },
            ))
        }

        fn revoke(&self, _lease: &sandy::Lease) -> Result<(), sandy::CredError> {
            Ok(())
        }

        fn refresh(&self, lease: &sandy::Lease) -> Result<sandy::Minted, sandy::CredError> {
            Ok(sandy::Minted::new(
                self.refreshed.to_string(),
                SystemTime::now() + Duration::from_secs(u64::from(sandy::MAX_TTL_SECS)),
                lease.handle.clone(),
            ))
        }
    }

    /// A backend that sleeps past `delay` before returning its scripted outcome,
    /// giving a background refresh tick time to fire before the run itself returns.
    struct SlowBackend {
        inner: FakeBackend,
        delay: Duration,
    }

    impl sandy::VmBackend for SlowBackend {
        fn run(&self, spec: &sandy::RunSpec) -> Result<Outcome, BackendError> {
            std::thread::sleep(self.delay);
            self.inner.run(spec)
        }

        fn kill(&self, box_id: &str) -> Result<(), BackendError> {
            self.inner.kill(box_id)
        }

        fn boxes(&self) -> Result<Vec<sandy::BoxState>, BackendError> {
            self.inner.boxes()
        }
    }

    /// #322: the credentialed path must write the terminal journal record exactly
    /// once, after the refresh thread has joined and `redact_with_refreshes` has
    /// run — never a first write against only the initial token, amended after a
    /// mid-run refresh. A huge margin plus a 1ms tick forces a refresh on the
    /// loop's very first tick; the backend sleeps past that tick so the refresh
    /// has already happened by the time the run itself returns. Goes through
    /// `run_job_with_credential_timed` directly rather than the env-var-driven
    /// public entry point: `std::env::set_var` is `unsafe` (edition 2024) and
    /// forbidden by this workspace's lints.
    #[test]
    fn credentialed_run_writes_the_terminal_record_once_after_refresh_redaction() -> anyhow::Result<()> {
        use sandy::Scope;

        let (_home, real_journal) = fresh_journal()?;
        let journal = CountingJournal::new(&real_journal);
        let cred_dir = tempfile::tempdir().context("cred dir")?;
        std::fs::set_permissions(cred_dir.path(), std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .context("cred dir 0700")?;

        let initial = "ghs_initial_marker_value";
        let refreshed = "ghs_refreshed_marker_value";
        let provider = TwoTokenProvider { initial, refreshed };
        let backend = SlowBackend {
            inner: FakeBackend::new().with_outcome(Outcome {
                digests: None,
                booted: true,
                guest_exit: Some(0),
                transport_error: None,
                timed_out: false,
                console: format!("boot: {initial}\nmid-run leak: {refreshed}\ndone"),
            }),
            delay: Duration::from_millis(2_500),
        };

        let (dev, ino) = sandy_fsutil::OwnedDir::open(cred_dir.path())?.dev_ino()?;
        let fingerprint = sandy::DirFingerprint { dev, ino };

        let report = super::run_job_with_credential_timed(
            &backend,
            &journal,
            booting_plan(),
            &FakeApplier::new(),
            EgressOs::Linux,
            None,
            &provider,
            &Scope::default(),
            "GH_TOKEN",
            cred_dir.path(),
            fingerprint,
            1_800,
            Duration::from_secs(1_000_000),
            Duration::from_millis(1),
        )
        .context("run_job_with_credential (mid-run refresh)")?;

        assert!(
            !report.envelope.logs.tail.contains(refreshed),
            "the returned envelope must not carry the refreshed token: {:?}",
            report.envelope.logs.tail
        );
        assert!(
            !report.envelope.logs.tail.contains(initial),
            "the returned envelope must not carry the initial token either: {:?}",
            report.envelope.logs.tail
        );

        let writes = journal.writes_for(&report.envelope.job_id);
        let terminal_writes: Vec<_> = writes.iter().filter(|r| r.state != sandy::JobState::Running).collect();
        assert_eq!(
            terminal_writes.len(),
            1,
            "the terminal record must be written exactly once, not written-then-amended: {writes:?}"
        );
        let persisted = terminal_writes[0]
            .result
            .as_ref()
            .context("the terminal record must carry the envelope")?;
        assert!(
            !persisted.logs.tail.contains(refreshed),
            "the single journaled write must already be redacted against the refreshed token: {:?}",
            persisted.logs.tail
        );
        assert!(
            !persisted.logs.tail.contains(initial),
            "the single journaled write must already be redacted against the initial token: {:?}",
            persisted.logs.tail
        );
        Ok(())
    }

    /// A [`super::JournalWriter`] whose `persist_if_still_running` always reports
    /// the write skipped, as if a concurrent `kill`/`reconcile_job` had already
    /// landed a terminal record, regardless of the real journal state. Isolates
    /// `run_job_with_credential_timed`'s response to that signal from
    /// `persist_if_still_running`'s own race detection, which is covered by
    /// `persist_if_still_running_never_overwrites_an_already_terminal_record`.
    struct AlwaysSkipJournal<'a> {
        inner: &'a Journal,
    }

    impl super::JournalWriter for AlwaysSkipJournal<'_> {
        fn persist(&self, record: &sandy::JobRecord) -> Result<(), sandy::CoreError> {
            self.inner.write_record(record)
        }

        fn persist_if_still_running(&self, _record: &sandy::JobRecord) -> Result<bool, sandy::CoreError> {
            Ok(false)
        }
    }

    /// When the terminal write is skipped because another writer already landed a
    /// terminal record, the credentialed path must not hand back its own result:
    /// that would drift from the journal a `status`/`wait` reads next (review
    /// finding on #415). Before this fix, `write_terminal_record` returned `()`
    /// and the skip case was indistinguishable from a successful write, so this
    /// call returned `Ok(report)` with a result nothing else will ever see.
    #[test]
    fn credentialed_run_refuses_to_report_a_result_the_journal_never_recorded() -> anyhow::Result<()> {
        use sandy::Scope;

        let (_home, real_journal) = fresh_journal()?;
        let journal = AlwaysSkipJournal { inner: &real_journal };
        let cred_dir = tempfile::tempdir().context("cred dir")?;
        std::fs::set_permissions(cred_dir.path(), std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .context("cred dir 0700")?;
        let provider = sandy_test_support::FakeProvider::returning("tok");
        let backend = FakeBackend::new().with_outcome(Outcome {
            digests: None,
            booted: true,
            guest_exit: Some(0),
            transport_error: None,
            timed_out: false,
            console: String::new(),
        });
        let (dev, ino) = sandy_fsutil::OwnedDir::open(cred_dir.path())?.dev_ino()?;
        let fingerprint = sandy::DirFingerprint { dev, ino };

        let result = super::run_job_with_credential_timed(
            &backend,
            &journal,
            booting_plan(),
            &FakeApplier::new(),
            EgressOs::Linux,
            None,
            &provider,
            &Scope::default(),
            "GH_TOKEN",
            cred_dir.path(),
            fingerprint,
            1_800,
            Duration::from_secs(1_000_000),
            Duration::from_millis(1),
        );

        assert!(
            result.is_err(),
            "a skipped terminal write must refuse to report a result, not return the local one: {result:?}"
        );
        assert!(
            !cred_dir.path().join("GH_TOKEN").exists(),
            "teardown must still have run (credential revoked/removed) even though the report was refused"
        );
        Ok(())
    }
}
