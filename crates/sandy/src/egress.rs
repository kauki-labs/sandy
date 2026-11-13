//! `sandy-egress` — egress allow-list → nftables translation and macOS honesty
//! (Phase D, D.3 / D-REQ-3).
//!
//! On Linux the allow-list compiles to a default-deny nftables ruleset permitting
//! exactly the listed `host:port` pairs; the real kernel enforcement is host-tier
//! (tier-3). On macOS (vmnet) there is no per-VM egress boundary, so
//! [`macos_egress_statement`] says so honestly instead of pretending to filter.
//!
//! [`plan_egress`] turns an [`AllowList`] plus a target [`EgressOs`] into a typed
//! [`EgressPlan`] (pure, OS injected, so it unit-tests without a real OS), and
//! [`enforce`] drives that plan over the [`EgressApplier`] seam — `FakeApplier`
//! (now in `sandy-test-support`) in tests. No production applier remains: a guest has no NIC (#483), and the egress
//! proxy is its only network path.

pub use sandy_api::egress::{AllowList, EgressApplier, EgressError, EgressOs, EgressOutcome, EgressPlan, EgressRule};

use crate::backend::PlanError;

/// Translate an [`AllowList`] into a **default-deny** nftables ruleset that
/// permits exactly the listed `host:port` pairs (D-REQ-3 translation).
///
/// The ruleset is deterministic: a base chain with a `drop` policy, one accept
/// rule per [`EgressRule`] naming its host and port, and no rule for any host not
/// in the list.
#[must_use]
pub fn to_nftables(allow: &AllowList) -> String {
    // A base chain with a `drop` policy is the default-deny floor; one accept per
    // rule, in the allow-list's own order, keeps the output deterministic. Host
    // names are emitted verbatim — the real resolution to addresses is host-tier.
    let mut ruleset = format!("table inet {EGRESS_TABLE} {{\n\tchain output {{\n");
    ruleset.push_str("\t\ttype filter hook output priority filter; policy drop;\n");
    for rule in &allow.rules {
        // Fail closed: a host that isn't a bare name/address/CIDR can't be safely
        // interpolated into the chain, so drop its accept rule rather than risk
        // injecting a directive that defeats the default-deny floor. A dropped host
        // simply stays denied (CLAUDE.md: validate and sanitize inputs). The port
        // is a `u16`, so it is always a safe numeric token.
        if !is_emittable_host(&rule.host) {
            // ...but not silently: a dropped entry means enforcement diverged from
            // config, so name it rather than hiding the no-op.
            tracing::warn!(
                host = ?rule.host,
                port = rule.port,
                "egress allow-list entry dropped: host is not a bare name/address/CIDR; it stays denied"
            );
            continue;
        }
        ruleset.push_str(&format!(
            "\t\tip daddr {host} tcp dport {port} accept comment \"allow {host}:{port}\"\n",
            host = rule.host,
            port = rule.port,
        ));
    }
    ruleset.push_str("\t}\n}\n");
    ruleset
}

/// Whether `host` is safe to interpolate into the nftables ruleset: a non-empty
/// bare DNS name, address, or CIDR of ASCII alphanumerics and `.:/-_` only —
/// nothing (whitespace, quotes, braces, newlines) that could close a rule or
/// inject a chain directive.
fn is_emittable_host(host: &str) -> bool {
    !host.is_empty()
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | ':' | '-' | '_' | '/'))
}

/// The honest macOS egress statement (D-REQ-3 macOS honesty).
///
/// macOS (vmnet) has no per-VM egress boundary, so sandy claims none: this names
/// the trusted-tasks-only posture and states that no boundary is enforced, rather
/// than pretending to filter.
#[must_use]
pub fn macos_egress_statement() -> &'static str {
    "sandy runs trusted tasks only on macOS: there is NO per-VM egress boundary. vmnet cannot enforce one, so guest \
     egress is unfiltered and sandy does not pretend to filter it."
}

/// The name of the nftables table [`to_nftables`] emits.
const EGRESS_TABLE: &str = "sandy_egress";

/// Resolve an [`AllowList`] and target [`EgressOs`] into an [`EgressPlan`].
///
/// Linux always [`EgressPlan::Enforce`]s — including an **empty** allow-list,
/// which still compiles to a default-deny (drop-all) ruleset so it blocks all
/// egress rather than failing open (#23). macOS always [`EgressPlan::NoBoundary`]s
/// with the honest [`macos_egress_statement`], because vmnet has no per-VM
/// boundary to enforce (#24).
#[must_use]
pub fn plan_egress(allow: &AllowList, target_os: EgressOs) -> EgressPlan {
    match target_os {
        EgressOs::Linux => EgressPlan::Enforce {
            ruleset: to_nftables(allow),
        },
        EgressOs::MacOs => EgressPlan::NoBoundary {
            reason: macos_egress_statement().to_string(),
        },
    }
}

/// Refuse an allow-list entry whose host is not a bare IPv4 address or IPv4 CIDR,
/// on the nftables (Linux) path (#359).
///
/// nft pins a hostname to one address at ruleset-load time, rejects a name with
/// more than one address, and the guest cannot resolve names through the
/// boundary anyway (DNS is UDP; the rules pass TCP only) — so a hostname entry
/// only ever helps a job that already connects by IP. Refusing it here, at plan
/// time, turns that silent no-op into a clear invalid-plan error (band 2, no
/// journal record, no boot) instead of loading a rule that never matches.
///
/// macOS (vmnet) enforces no per-VM boundary, so a hostname entry there is inert
/// rather than misleading, and stays accepted (#358). Hostname support returns
/// with the egress proxy (#360/#377), which resolves names host-side.
///
/// # Errors
///
/// Returns [`PlanError::Invalid`] naming the first entry that isn't a bare IPv4
/// address or CIDR, on Linux only.
pub fn validate_egress_hosts(allow: &AllowList, target_os: EgressOs) -> Result<(), PlanError> {
    if target_os != EgressOs::Linux {
        return Ok(());
    }
    for rule in &allow.rules {
        if !is_ipv4_or_cidr(&rule.host) {
            return Err(PlanError::Invalid(format!(
                "--allow `{}:{}` is not a valid IPv4 address or IPv4 CIDR; the nftables egress boundary matches by \
                 IPv4 address or CIDR only (see #377 for hostname support)",
                rule.host, rule.port
            )));
        }
    }
    Ok(())
}

/// Whether `host` is a bare IPv4 address or `IPv4/prefix` CIDR (0-32).
fn is_ipv4_or_cidr(host: &str) -> bool {
    match host.split_once('/') {
        Some((addr, prefix)) => {
            // `u8::from_str` accepts a leading `+` (`"+8"`), which would pass this
            // check but then fail `is_emittable_host`'s stricter grammar and get
            // silently dropped (denied, not a leak) at ruleset-build time instead
            // of refused here at plan time.
            addr.parse::<std::net::Ipv4Addr>().is_ok()
                && !prefix.is_empty()
                && prefix.bytes().all(|b| b.is_ascii_digit())
                && prefix.parse::<u8>().is_ok_and(|p| p <= 32)
        }
        None => host.parse::<std::net::Ipv4Addr>().is_ok(),
    }
}

/// Drive an [`EgressPlan`] through an [`EgressApplier`].
///
/// An [`EgressPlan::Enforce`] applies the ruleset and reports
/// [`EgressOutcome::Enforced`]. An [`EgressPlan::NoBoundary`] applies nothing —
/// it `tracing::warn!`s and returns [`EgressOutcome::Unenforced`] so the missing
/// boundary is surfaced, never silently treated as enforced (#24).
///
/// # Errors
/// Propagates any [`EgressError`] from [`EgressApplier::apply`].
pub fn enforce<A: EgressApplier + ?Sized>(plan: &EgressPlan, applier: &A) -> Result<EgressOutcome, EgressError> {
    match plan {
        EgressPlan::Enforce { ruleset } => {
            applier.apply(ruleset)?;
            Ok(EgressOutcome::Enforced)
        }
        EgressPlan::NoBoundary { reason } => {
            tracing::warn!(reason = %reason, "egress boundary not enforced");
            Ok(EgressOutcome::Unenforced { reason: reason.clone() })
        }
        // The backend's proxy is the boundary; the host applies nothing, so there is nothing to revert.
        EgressPlan::Proxy => Ok(EgressOutcome::Proxied),
    }
}

#[cfg(test)]
mod tests {
    use sandy_test_support::FakeApplier;

    use super::{
        AllowList, EgressOs, EgressOutcome, EgressPlan, EgressRule, enforce, macos_egress_statement, plan_egress,
        to_nftables, validate_egress_hosts,
    };
    use crate::backend::PlanError;

    /// One allow-list rule for `host:port`.
    fn allow_one(host: &str, port: u16) -> AllowList {
        AllowList {
            rules: vec![EgressRule {
                host: host.to_string(),
                port,
            }],
        }
    }

    /// #359: on Linux a hostname entry is refused at plan time, naming the entry
    /// and #377 — nft pins one address at load time, rejects a name with several
    /// addresses, and the guest can't resolve names through the boundary anyway.
    #[test]
    fn linux_refuses_a_hostname_allow_entry_naming_it_and_377() {
        for host in ["github.com", "one.one.one.one"] {
            let err = validate_egress_hosts(&allow_one(host, 443), EgressOs::Linux)
                .expect_err(&format!("a hostname entry `{host}` must be refused on Linux"));
            let PlanError::Invalid(msg) = err else {
                panic!("expected PlanError::Invalid, got {err:?}");
            };
            assert!(msg.contains(host), "the error must name the entry: {msg}");
            assert!(msg.contains("377"), "the error must point to #377: {msg}");
        }
    }

    /// Review finding on #418: an IPv6 address or an out-of-range CIDR is
    /// neither a hostname nor a valid IPv4/CIDR, so the refusal must not
    /// mislabel it as a hostname.
    #[test]
    fn linux_refuses_a_non_ipv4_entry_without_calling_it_a_hostname() {
        for host in ["2001:db8::1", "10.0.0.0/33"] {
            let err = validate_egress_hosts(&allow_one(host, 443), EgressOs::Linux)
                .expect_err(&format!("a non-IPv4 entry `{host}` must be refused on Linux"));
            let PlanError::Invalid(msg) = err else {
                panic!("expected PlanError::Invalid, got {err:?}");
            };
            assert!(msg.contains(host), "the error must name the entry: {msg}");
            assert!(
                !msg.contains("is a hostname"),
                "the error must not call a non-hostname entry a hostname: {msg}"
            );
            assert!(
                msg.contains("not a valid IPv4"),
                "the error must say what the entry actually fails to be: {msg}"
            );
        }
    }

    /// #359: an IPv4 address or IPv4 CIDR entry is accepted on Linux — the
    /// nftables boundary matches by address, not name.
    #[test]
    fn linux_accepts_an_ipv4_address_or_cidr_allow_entry() {
        for host in ["1.1.1.1", "10.0.0.0/8"] {
            assert!(
                validate_egress_hosts(&allow_one(host, 443), EgressOs::Linux).is_ok(),
                "an IPv4 entry `{host}` must be accepted on Linux"
            );
        }
    }

    /// `u8::from_str` accepts a leading `+` (`"+8"`); a CIDR prefix with one must
    /// still be refused here, at plan time, rather than passing validation and
    /// then getting silently dropped by `is_emittable_host`'s stricter grammar
    /// when the ruleset is built (review finding on #418).
    #[test]
    fn linux_refuses_a_cidr_prefix_with_a_non_decimal_sign() {
        for host in ["10.0.0.0/+8", "10.0.0.0/-8", "10.0.0.0/"] {
            assert!(
                validate_egress_hosts(&allow_one(host, 443), EgressOs::Linux).is_err(),
                "a malformed CIDR prefix `{host}` must be refused at plan time, not silently dropped later"
            );
        }
    }

    /// #358/#377: macOS enforces no per-VM boundary, so a hostname entry there is
    /// inert rather than misleading, and stays accepted until the egress proxy
    /// lands.
    #[test]
    fn macos_accepts_a_hostname_allow_entry() {
        assert!(
            validate_egress_hosts(&allow_one("github.com", 443), EgressOs::MacOs).is_ok(),
            "macOS has no per-VM boundary; a hostname entry is harmless there"
        );
    }

    /// D-REQ-3 (positive translation): each allowed `host:port` appears in the
    /// ruleset, a default-deny is present, and an unlisted host is absent.
    #[test]
    fn linux_egress_allow_deny_translation() {
        let allow = AllowList {
            rules: vec![EgressRule {
                host: "github.com".to_string(),
                port: 443,
            }],
        };
        let ruleset = to_nftables(&allow);
        assert!(
            ruleset.contains("github.com"),
            "allowed host must be present: {ruleset}"
        );
        assert!(ruleset.contains("443"), "allowed port must be present: {ruleset}");
        assert!(
            ruleset.contains("drop"),
            "ruleset must be default-deny (a drop policy): {ruleset}"
        );
        assert!(
            !ruleset.contains("evil.example"),
            "an unlisted host must be absent from the ruleset"
        );
    }

    /// D-REQ-3 (adversarial): a host carrying nftables syntax (newline + an
    /// `accept` directive) is dropped, never interpolated — the default-deny floor
    /// stays intact and no injected accept rule appears.
    #[test]
    fn injection_host_is_dropped_not_interpolated() {
        let allow = AllowList {
            rules: vec![EgressRule {
                host: "x\n\t\tip daddr 0.0.0.0/0 accept comment \"pwn".to_string(),
                port: 1,
            }],
        };
        let ruleset = to_nftables(&allow);
        assert!(
            ruleset.contains("policy drop"),
            "the default-deny floor must remain: {ruleset}"
        );
        assert!(
            !ruleset.contains("accept"),
            "an injection host must not produce any accept rule: {ruleset}"
        );
        assert!(
            !ruleset.contains("0.0.0.0/0"),
            "the injected payload must not reach the ruleset: {ruleset}"
        );
    }

    /// D-REQ-3 (macOS honesty): the statement names the trusted-only posture and
    /// claims no per-VM egress boundary exists.
    #[test]
    fn macos_warns_trusted_only() {
        let msg = macos_egress_statement().to_lowercase();
        assert!(msg.contains("trusted"), "must name trusted-tasks-only: {msg}");
        assert!(
            msg.contains("no") && msg.contains("boundary"),
            "must claim no egress boundary exists: {msg}"
        );
    }

    // --- tier-1: the enforcement plan (pure, OS injected) -----------------------

    /// #23: a Linux plan enforces, and its ruleset is exactly the nftables
    /// translation of the allow-list (default-deny chain present).
    #[test]
    fn linux_plan_enforces_the_nftables_ruleset() {
        let allow = AllowList {
            rules: vec![EgressRule {
                host: "github.com".to_string(),
                port: 443,
            }],
        };
        let plan = plan_egress(&allow, EgressOs::Linux);
        assert_eq!(
            plan,
            EgressPlan::Enforce {
                ruleset: to_nftables(&allow),
            },
            "Linux must enforce the nftables translation verbatim"
        );
        let EgressPlan::Enforce { ruleset } = &plan else {
            panic!("Linux plan must be Enforce, got {plan:?}");
        };
        assert!(
            ruleset.contains("policy drop"),
            "the enforced ruleset must carry the default-deny chain: {ruleset}"
        );
    }

    /// #23 (adversarial): an empty allow-list on Linux still enforces a drop-all
    /// ruleset — it blocks all egress and MUST NOT fail open with no boundary.
    #[test]
    fn empty_allow_list_on_linux_blocks_all_not_fail_open() {
        let plan = plan_egress(&AllowList::default(), EgressOs::Linux);
        let EgressPlan::Enforce { ruleset } = &plan else {
            panic!("an empty allow-list on Linux must still Enforce, not drop the boundary: {plan:?}");
        };
        assert!(
            ruleset.contains("policy drop"),
            "an empty allow-list must enforce a default-deny policy: {ruleset}"
        );
        assert!(
            !ruleset.contains("accept"),
            "an empty allow-list must emit no accept rule (nothing is permitted): {ruleset}"
        );
    }

    /// #24 (adversarial, macOS honesty): macOS yields `NoBoundary`, never an
    /// `Enforce`, and the reason is a non-empty message naming that there is no
    /// boundary / trusted-only — no silent no-op presented as enforcement.
    #[test]
    fn macos_plan_is_honest_no_boundary() {
        let allow = AllowList {
            rules: vec![EgressRule {
                host: "github.com".to_string(),
                port: 443,
            }],
        };
        let plan = plan_egress(&allow, EgressOs::MacOs);
        let EgressPlan::NoBoundary { reason } = &plan else {
            panic!("macOS must NOT pretend to enforce; expected NoBoundary, got {plan:?}");
        };
        assert!(
            !reason.trim().is_empty(),
            "the macOS reason must not be an empty/silent string"
        );
        let lower = reason.to_lowercase();
        assert!(
            lower.contains("no") && lower.contains("boundary"),
            "the reason must name that there is no egress boundary: {reason}"
        );
        assert!(
            lower.contains("trusted"),
            "the reason must name the trusted-tasks-only posture: {reason}"
        );
    }

    // --- tier-2: wiring over the applier seam (no root / no nft) ----------------

    /// #23: enforcing a Linux `Enforce` plan calls `apply` exactly once with the
    /// plan's ruleset, and reports the boundary as enforced.
    #[test]
    fn enforcing_linux_plan_applies_ruleset_once() {
        let allow = AllowList {
            rules: vec![EgressRule {
                host: "github.com".to_string(),
                port: 443,
            }],
        };
        let plan = plan_egress(&allow, EgressOs::Linux);
        let applier = FakeApplier::new();

        let outcome = enforce(&plan, &applier).expect("enforcing a Linux plan must succeed");

        assert_eq!(outcome, EgressOutcome::Enforced);
        assert_eq!(
            applier.applied_rulesets(),
            vec![to_nftables(&allow)],
            "apply must be called once with the plan's ruleset"
        );
    }

    /// #24: enforcing a macOS `NoBoundary` plan does NOT call `apply` (the applier
    /// records no ruleset) and surfaces the reason as an unenforced outcome.
    #[test]
    fn enforcing_macos_plan_does_not_apply_and_surfaces_reason() {
        let plan = plan_egress(&AllowList::default(), EgressOs::MacOs);
        let applier = FakeApplier::new();

        let outcome = enforce(&plan, &applier).expect("a NoBoundary plan is not a failure");

        assert!(
            applier.applied_rulesets().is_empty(),
            "a macOS NoBoundary plan must never call apply"
        );
        match outcome {
            EgressOutcome::Unenforced { reason } => {
                assert!(!reason.trim().is_empty(), "the unenforced reason must be surfaced");
            }
            other => panic!("macOS must yield Unenforced, got {other:?}"),
        }
    }

    /// #360: the proxy plan applies nothing on the host: the applier sees no apply
    /// and no revert, and the outcome says so rather than claiming a ruleset.
    #[test]
    fn the_proxy_plan_applies_nothing_and_reports_proxied() {
        let applier = FakeApplier::new();
        let outcome = enforce(&EgressPlan::Proxy, &applier);
        assert!(matches!(outcome, Ok(EgressOutcome::Proxied)), "{outcome:?}");
        assert!(applier.applied_rulesets().is_empty());
        assert!(!applier.was_reverted());
    }

    /// #359 is scoped to the nftables plan: the same hostname entries that
    /// `validate_egress_hosts` refuses on Linux are what the proxy plan exists for.
    #[test]
    fn the_hostname_refusal_belongs_to_the_nftables_plan_only() {
        for host in ["github.com", "localhost"] {
            assert!(
                validate_egress_hosts(&allow_one(host, 8080), EgressOs::Linux).is_err(),
                "the nftables plan refuses `{host}`"
            );
        }
    }
}
