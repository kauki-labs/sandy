//! Build the LOCKED [`ResultEnvelope`] and its supporting pieces: console
//! redaction (M-6), the audit receipt's host-observed half (#361), and the
//! no-network-allow warning (#358). Consumed by
//! [`super::run_job_core`]/[`super::run_job_with_credential_timed`].

use std::time::SystemTime;

use sandy::{
    AllowList, AuditReceipt, Classification, EgressEnforcement, EgressOs, EgressOutcome, EgressReceipt, HostObserved,
    Location, Logs, OutputRef, Provenance, RESULT_SCHEMA_VERSION, ResultEnvelope, SandboxKind, Timing, What, Who,
};
use zeroize::Zeroizing;

use crate::plan::JobPlan;

/// Redact every exact occurrence of a `secrets` entry in `console` with
/// `[REDACTED]` (M-6). A secret under 8 bytes is skipped rather than replaced: a
/// short value risks consuming unrelated text (a secret `"ab"` must never redact
/// unrelated `"abc"`), and a real forge token is never that short.
pub(super) fn redact_console<S: AsRef<str>>(mut console: String, secrets: &[S]) -> String {
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
pub(super) fn redact_with_refreshes(console: String, initial: &str, refreshed: &[Zeroizing<String>]) -> String {
    redact_console(redact_console(console, &[initial]), refreshed)
}

/// Build the LOCKED [`ResultEnvelope`] from a terminal [`Classification`].
///
/// `outputs` are the files the backend collected to the job's declared
/// destinations (empty when the run never collected, e.g. an invalid plan or an
/// infra fault). `receipt` is the audit receipt (#361): `None` for a run that
/// never reached the backend (invalid plan) or never ran one (`kill`'s synthetic
/// cancellation). Provenance remains a placeholder (provenance capture lands
/// with #26).
#[allow(
    clippy::too_many_arguments,
    reason = "every field of the LOCKED envelope this helper assembles; a bundling struct would just move the fields, \
              not reduce them"
)]
pub(super) fn build_envelope(
    job_id: &str,
    box_id: Option<String>,
    classification: Classification,
    guest_exit: Option<i32>,
    message: String,
    console: String,
    outputs: Vec<OutputRef>,
    receipt: Option<AuditReceipt>,
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
        receipt,
    }
}

/// The backend kind name for [`Location::backend`] (#361): `"process"` for the
/// process backend, else `"qemu"`/`"vfkit"` by host OS — [`SandboxKind`] alone
/// only distinguishes process from VM, and this codebase pairs exactly one VM
/// backend with each OS (`QemuBackend` on Linux, `VfkitBackend` on macOS), so
/// the pairing is accurate without a new seam method.
fn backend_kind_name(kind: SandboxKind, os: EgressOs) -> &'static str {
    match (kind, os) {
        (SandboxKind::Process, _) => "process",
        (SandboxKind::Vm, EgressOs::Linux) => "qemu",
        (SandboxKind::Vm, EgressOs::MacOs) => "vfkit",
    }
}

/// Build the egress half of the receipt (#361) from the same [`EgressOutcome`]
/// (or apply failure) that already drove `run_job`'s enforce/revert bracket —
/// the one platform-keyed signal, not a second copy of the logic (shared with
/// #358's warning).
fn build_egress_receipt(result: &Result<EgressOutcome, String>, allow: &AllowList) -> EgressReceipt {
    match result {
        Ok(EgressOutcome::Enforced) => EgressReceipt {
            status: EgressEnforcement::Enforced,
            reason: None,
            allow_list: Some(allow.clone()),
            attempts: vec![],
        },
        // The proxy is the boundary and it enforces `allow`; a backend that cannot run it refuses before boot.
        Ok(EgressOutcome::Proxied) => EgressReceipt {
            status: EgressEnforcement::Enforced,
            reason: None,
            allow_list: Some(allow.clone()),
            attempts: vec![],
        },
        Ok(EgressOutcome::Unenforced { reason }) => EgressReceipt {
            status: EgressEnforcement::Unenforced,
            reason: Some(reason.clone()),
            // Nothing was applied: never label an allow-list "applied" when it wasn't.
            allow_list: None,
            attempts: vec![],
        },
        Err(apply_error) => EgressReceipt {
            status: EgressEnforcement::Unenforced,
            reason: Some(format!("egress boundary not established: {apply_error}")),
            allow_list: None,
            attempts: vec![],
        },
    }
}

/// Build the receipt for a run that reached backend execution (#361). `who` is
/// always the local uid today (`authenticated: false`): no run path yet derives
/// it from a verified submitter cap — sandyd's dispatch core does not persist a
/// receipt at all yet (#413). `credential` starts
/// `None`; [`super::run_job_with_credential`] fills it in after teardown.
pub(super) fn build_host_observed(
    job_id: &str,
    plan: &JobPlan,
    backend_kind: SandboxKind,
    egress_os: EgressOs,
    egress_result: &Result<EgressOutcome, String>,
    started: SystemTime,
    teardown_at: SystemTime,
) -> HostObserved {
    HostObserved {
        who: Who {
            identity: sandy_fsutil::current_uid().to_string(),
            authenticated: false,
        },
        what: What {
            job_id: job_id.to_string(),
            template: plan.template.clone(),
            template_store_path: None,
            manifest_digest: None,
        },
        location: Location {
            backend: backend_kind_name(backend_kind, egress_os).to_string(),
            executor_host_id: None,
            executor_mesh_ip: None,
        },
        credential: None,
        egress: build_egress_receipt(egress_result, &plan.allow),
        timing: Timing {
            boot_started_at: started,
            job_started_at: None,
            teardown_at,
        },
        // Filled by `run_job_core` from the backend's `Outcome` when `--digests` was given (#373).
        input_digests: None,
    }
}

/// The envelope warning for a non-empty `--allow` list that has no effect
/// (#358).
///
/// On a VM backend, `vfkit_args` (`impls/vm/src/vfkit.rs`) emits no
/// `virtio-net` device, so a macOS guest has no NIC at all; a Linux guest with
/// no bound tap has none either (`plan_egress_scoped`). `--allow` entries are
/// not merely unfiltered there, they are inert: there is nothing to grant them
/// onto. On the process backend there is no guest at all — the job runs
/// directly on the host network, sharing it rather than lacking a NIC — but
/// the allow-list is just as unenforced, so the warning still fires, with a
/// cause that matches what's actually true for that backend. Keys on
/// structure (`backend_kind`, `EgressOs::MacOs`, or no `tap`), never on the
/// `EgressOutcome`'s reason string, so a reason that happens not to match a
/// pattern can't defeat it. An empty allow-list never warns: deny-all already
/// holds regardless of the reason.
pub(super) fn no_network_allow_warning(
    allow: &AllowList,
    backend_kind: SandboxKind,
    egress_os: EgressOs,
    tap: Option<&str>,
) -> Option<String> {
    if allow.rules.is_empty() {
        return None;
    }
    match backend_kind {
        SandboxKind::Process => Some(
            "egress unavailable: the process backend shares the host network with no isolation boundary, so --allow \
             entries have no effect"
                .to_string(),
        ),
        SandboxKind::Vm if matches!(egress_os, EgressOs::MacOs) || tap.is_none() => Some(
            "egress unavailable: the guest has no network device, so --allow entries have no effect (see #360)"
                .to_string(),
        ),
        SandboxKind::Vm => None,
    }
}

#[cfg(test)]
mod tests {
    use zeroize::Zeroizing;

    use super::{redact_console, redact_with_refreshes};

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
}
