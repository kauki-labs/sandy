//! The supporting pieces of the LOCKED result envelope (built by `sandy::build_envelope`): console
//! redaction (M-6), the audit receipt's host-observed half (#361), and the
//! no-network-allow warning (#358). Consumed by
//! [`super::run_job_core`]/[`super::run_job_with_credential_timed`].

use std::time::SystemTime;

use sandy::{
    AllowList, EgressEnforcement, EgressOs, EgressOutcome, EgressReceipt, HostObserved, Location, NetworkMode,
    SandboxKind, Timing, What, Who,
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
    network: NetworkMode,
) -> Option<String> {
    // An empty list means deny-all except on a macOS `nic` guest, whose NAT NIC has no boundary to enforce it (#603).
    let unenforced_nic = matches!(egress_os, EgressOs::MacOs) && network == NetworkMode::Nic;
    if allow.rules.is_empty() && !unenforced_nic {
        return None;
    }
    match backend_kind {
        SandboxKind::Process => Some(
            "egress unavailable: the process backend shares the host network with no isolation boundary, so --allow \
             entries have no effect"
                .to_string(),
        ),
        // A macOS `nic` guest has a NAT NIC and no boundary (#603): the entries are not inert, they are unenforced.
        SandboxKind::Vm if matches!(egress_os, EgressOs::MacOs) && network == NetworkMode::Nic => Some(
            "egress unenforced: the guest has a NAT NIC and macOS has no per-VM boundary, so --allow entries are not \
             enforced (see #603)"
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
    use sandy::{AllowList, EgressOs, EgressRule, NetworkMode, SandboxKind};
    use zeroize::Zeroizing;

    use super::{no_network_allow_warning, redact_console, redact_with_refreshes};

    /// #602: a macOS `nic` guest has a NAT NIC, so `--allow` is unenforced, not "no network device".
    #[test]
    fn a_macos_nic_guest_is_not_reported_as_having_no_network_device() {
        let allow = AllowList {
            rules: vec![EgressRule {
                host: "10.0.0.1".to_string(),
                port: 443,
            }],
        };
        let warn = |mode, os, tap| no_network_allow_warning(&allow, SandboxKind::Vm, os, tap, mode);
        let none_listed = AllowList::default();
        let empty = no_network_allow_warning(&none_listed, SandboxKind::Vm, EgressOs::MacOs, None, NetworkMode::Nic);
        assert!(
            empty.is_some_and(|w| w.contains("NAT NIC")),
            "an empty list must still warn on a macOS nic guest"
        );
        assert_eq!(
            no_network_allow_warning(&none_listed, SandboxKind::Vm, EgressOs::MacOs, None, NetworkMode::None),
            None
        );
        let none = warn(NetworkMode::None, EgressOs::MacOs, None).unwrap_or_default();
        assert!(none.contains("no network device"), "{none}");
        let nic = warn(NetworkMode::Nic, EgressOs::MacOs, None).unwrap_or_default();
        assert!(nic.contains("NAT NIC") && !nic.contains("no network device"), "{nic}");
        assert_eq!(warn(NetworkMode::Nic, EgressOs::Linux, Some("sandytap0")), None);
    }

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
