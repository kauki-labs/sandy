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
//! (now in `sandy-test-support`) in tests, [`NftablesApplier`] (shells `nft -f -`)
//! on a real Linux host. The live Linux enforcement — the real `nft` load whose
//! boundary an in-guest root flush cannot bypass — is tier-3 and is asserted by
//! a root-gated live test (#29); it is not exercised here.

pub use sandy_api::egress::{
    AllowList, EgressApplier, EgressError, EgressOs, EgressOutcome, EgressPlan, EgressRule, NetworkMode,
    is_valid_tap_name,
};

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

/// Translate an [`AllowList`] into a **guest-scoped** nftables ruleset: a
/// `forward`-hook chain with a `policy accept` that filters only packets entering
/// from the guest's tap `iface` (`iifname "<iface>"`) and leaves every other
/// interface — the host's own egress included — untouched (#29), plus an
/// `input`-hook chain that closes the guest's path to the host itself (#376).
///
/// This is the safe counterpart to [`to_nftables`]: where that emits an
/// OUTPUT-hook `policy drop` (which, applied in the host netns, would drop the
/// HOST's own egress and lock it off the network), this scopes a default-deny to
/// one guest interface. The forward chain accepts the guest's established/related
/// return traffic and exactly the listed `host:port` pairs, then drops everything
/// else from that interface; the trailing `iifname "<iface>" drop` is the floor,
/// so an **empty** allow-list blocks all of the guest's new egress rather than
/// failing open. Host names that aren't a bare address/CIDR are dropped
/// (fail-closed), same as [`to_nftables`].
///
/// Traffic the guest sends **to the host itself** (the tap's gateway address, or
/// any other host address) is delivered through the `input` chain, never
/// `forward`, so the forward chain alone leaves it unfiltered (#376: a host-local
/// resolver or service stayed reachable, an empty allow-list included). The
/// `input` chain closes that gap: `policy accept` (so traffic on every other
/// interface stays untouched), the guest's DHCP request (`udp dport 67`) is the
/// one thing it needs from the host, and everything else from the guest's `iface`
/// is dropped. The allow-list never reaches this chain — a host-destined entry
/// (e.g. the tap's own resolver) has no forward-scoped effect either, since the
/// host is not a forward destination; allow-listing a host service is out of
/// scope until #360's proxy resolves names host-side.
///
/// An `iface` that is not a bare interface token can't be scoped to a guest
/// without risking rule injection and can't be matched to drop the guest either,
/// so both chains are emitted empty (table present, `policy accept`, no rules)
/// with a warning — nothing is filtered, but the host is never touched.
#[must_use]
pub fn to_nftables_forward(allow: &AllowList, iface: &str) -> String {
    let open = format!("table inet {} {{\n", forward_table_name(iface));
    if !is_emittable_host(iface) {
        tracing::warn!(
            ?iface,
            "egress forward ruleset: interface is not a bare token; emitting no guest filter (host untouched)"
        );
        return format!(
            "{open}\tchain forward {{\n\t\ttype filter hook forward priority filter; policy accept;\n\t}}\n}}\n"
        );
    }

    let mut ruleset = open;
    ruleset.push_str("\tchain forward {\n\t\ttype filter hook forward priority filter; policy accept;\n");
    // Return traffic for flows the guest was already permitted to open. With an
    // empty allow-list nothing is ever established, so this accepts nothing.
    ruleset.push_str(&format!(
        "\t\tiifname \"{iface}\" ct state established,related accept\n"
    ));
    for rule in &allow.rules {
        // Same fail-closed rule as `to_nftables`: a host that isn't a bare
        // name/address/CIDR can't be safely interpolated, so it stays denied —
        // named, not silently dropped.
        if !is_emittable_host(&rule.host) {
            tracing::warn!(
                host = ?rule.host,
                port = rule.port,
                "egress allow-list entry dropped: host is not a bare name/address/CIDR; it stays denied"
            );
            continue;
        }
        ruleset.push_str(&format!(
            "\t\tiifname \"{iface}\" ip daddr {host} tcp dport {port} accept comment \"allow {host}:{port}\"\n",
            host = rule.host,
            port = rule.port,
        ));
    }
    // The default-deny floor: anything from the guest not explicitly allowed above
    // is dropped. Scoped to `iifname`, so only the guest is filtered.
    ruleset.push_str(&format!("\t\tiifname \"{iface}\" drop\n"));
    ruleset.push_str("\t}\n");

    // #376: close the guest's path to the host. DHCP is the one thing the guest
    // needs from the host; everything else destined for the host is dropped. The
    // allow-list plays no part here — a host address is never a forward
    // destination, so it has no legitimate accept to carry over.
    ruleset.push_str("\tchain input {\n\t\ttype filter hook input priority filter; policy accept;\n");
    ruleset.push_str(&format!("\t\tiifname \"{iface}\" udp dport 67 accept\n"));
    ruleset.push_str(&format!("\t\tiifname \"{iface}\" drop\n"));
    ruleset.push_str("\t}\n");

    ruleset.push_str("}\n");
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

/// The name of the nftables table [`to_nftables`] emits and [`NftablesApplier`]
/// tears down on revert; the two must agree.
const EGRESS_TABLE: &str = "sandy_egress";

/// The table a guest-scoped forward ruleset for `iface` loads into (#602). One table per tap, so a run that reverts
/// its own boundary never deletes the table of another concurrent `nic` run. The suffix encoding is injective, so two
/// different taps never share a table: `_` becomes `__`, `-` becomes `_h` and `.` becomes `_d`. An `iface` that is
/// not a bare token falls back to [`EGRESS_TABLE`]; the plan-time tap check refuses such a name before any run
/// reaches here.
fn forward_table_name(iface: &str) -> String {
    if !is_emittable_host(iface) {
        return EGRESS_TABLE.to_string();
    }
    let mut suffix = String::with_capacity(iface.len());
    for c in iface.chars() {
        match c {
            '_' => suffix.push_str("__"),
            '-' => suffix.push_str("_h"),
            '.' => suffix.push_str("_d"),
            other => suffix.push(other),
        }
    }
    format!("{EGRESS_TABLE}_{suffix}")
}

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

/// Resolve an [`AllowList`] into an [`EgressPlan`] scoped to the guest's tap
/// interface when one is bound.
///
/// This is the tap-aware planner the run path uses. On Linux **with** a tap
/// (`iface = Some`), it enforces the **guest-scoped** [`to_nftables_forward`]
/// ruleset — the safe forward-hook model that filters only the guest and can
/// never lock the host off the network (#29). On Linux **without** a tap the
/// guest has no NIC, so there is nothing to enforce and it applies no boundary —
/// deliberately NOT the host-wide [`to_nftables`] OUTPUT drop, which would cut
/// the host's own egress. macOS is honestly [`EgressPlan::NoBoundary`] (vmnet has
/// no per-VM boundary). The host-wide [`plan_egress`] / [`to_nftables`] stay as
/// the translation API (#23/#24); the run path never applies them.
#[must_use]
pub fn plan_egress_scoped(allow: &AllowList, target_os: EgressOs, iface: Option<&str>) -> EgressPlan {
    match (target_os, iface) {
        // Linux with a guest tap: enforce the guest-scoped forward ruleset — the
        // safe model that filters only the guest, never the host (#29).
        (EgressOs::Linux, Some(iface)) => EgressPlan::Enforce {
            ruleset: to_nftables_forward(allow, iface),
        },
        // Linux without a tap: the guest has no NIC, so there is no egress to
        // enforce. Apply NOTHING — never the host-wide OUTPUT-hook drop, which
        // would lock the host off the network.
        (EgressOs::Linux, None) => EgressPlan::NoBoundary {
            reason: "no guest network interface; no egress boundary to enforce".to_string(),
        },
        // macOS (vmnet): no per-VM boundary — honestly unenforced.
        (EgressOs::MacOs, _) => plan_egress(allow, EgressOs::MacOs),
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

/// Validate a proxy-mode run (`SANDY_EGRESS=proxy`, #360) at plan time.
///
/// The proxy resolves names host-side, so hostname entries are valid here:
/// [`validate_egress_hosts`]' refusal (#359) is scoped to the nftables plan
/// only. What the proxy cannot share a run with is a guest NIC: on Linux a bound
/// `tap` means the nftables path and the proxy would both claim the boundary, so
/// the combination is refused rather than booted with two models.
///
/// # Errors
///
/// Returns [`PlanError::Invalid`] on Linux when `tap` is set.
pub fn validate_proxy_egress(os: EgressOs, tap: Option<&str>) -> Result<(), PlanError> {
    match (os, tap) {
        (EgressOs::Linux, Some(tap)) => Err(PlanError::Invalid(format!(
            "SANDY_EGRESS=proxy needs a guest with no NIC, but SANDY_TAP={tap} binds one; unset SANDY_TAP to use the \
             egress proxy, or unset SANDY_EGRESS to keep the nftables boundary"
        ))),
        _ => Ok(()),
    }
}

/// Validate the guest network profile against the tap and the proxy at plan time (#602).
///
/// On Linux a `nic` guest is filtered only by the guest-scoped nftables forward ruleset, which needs a bound tap, so
/// `nic` without a tap would boot a NIC with no boundary, and a tap without `nic` would be a silent NIC. The proxy
/// guest has no NIC, so `nic` and the proxy never share a run. On macOS `nic` is the trusted-only NAT NIC (#603) and
/// there is no tap. Refusing here makes each a band-2 invalid plan: no journal record, no boot.
///
/// # Errors
///
/// Returns [`PlanError::Invalid`] naming the conflicting settings.
pub fn validate_network_mode(os: EgressOs, mode: NetworkMode, tap: Option<&str>, proxy: bool) -> Result<(), PlanError> {
    let nic = mode == NetworkMode::Nic;
    if let Some(tap) = tap.filter(|t| !is_valid_tap_name(t)) {
        return Err(PlanError::Invalid(format!(
            "SANDY_TAP={tap:?} is not a valid interface name (1 to 15 of A-Z a-z 0-9 _ - .); refusing a NIC whose \
             boundary cannot be scoped to it"
        )));
    }
    match (os, nic, tap, proxy) {
        (_, true, _, true) => Err(PlanError::Invalid(
            "SANDY_NETWORK=nic and SANDY_EGRESS=proxy are exclusive: the proxy guest has no NIC".to_string(),
        )),
        (EgressOs::Linux, true, None, _) => Err(PlanError::Invalid(
            "SANDY_NETWORK=nic needs a bound tap (SANDY_TAP) with the host egress boundary; a NIC with no boundary is \
             refused"
                .to_string(),
        )),
        (EgressOs::Linux, false, Some(tap), _) => Err(PlanError::Invalid(format!(
            "SANDY_TAP={tap} binds a guest NIC, which needs SANDY_NETWORK=nic; unset SANDY_TAP, or set \
             SANDY_NETWORK=nic"
        ))),
        _ => Ok(()),
    }
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

/// Host-tier applier that loads the ruleset into the Linux kernel via `nft -f -`
/// and reverts by deleting the table that ruleset created (read from its first line, so a
/// per-tap table is the one removed, never another run's).
///
/// This is intentionally thin and is **not** unit-tested: the behaviour that
/// matters — that the loaded boundary holds against an in-guest root flush — is a
/// live, root-only, host-tier assertion (a live test, #29, removed in #483),
/// not something a unit test can observe.
#[derive(Debug, Default)]
pub struct NftablesApplier {
    /// The table the last applied ruleset created, for [`EgressApplier::revert`] to delete.
    applied_table: std::sync::Mutex<Option<String>>,
}

impl EgressApplier for NftablesApplier {
    fn apply(&self, ruleset: &str) -> Result<(), EgressError> {
        use std::{
            io::Write,
            process::{Command, Stdio},
        };

        let table = ruleset
            .lines()
            .next()
            .and_then(|line| line.strip_prefix("table inet "))
            .and_then(|rest| rest.split_whitespace().next())
            .ok_or_else(|| EgressError::Apply("the ruleset does not start with `table inet <name> {`".to_string()))?
            .to_string();
        let mut child = Command::new("nft").args(["-f", "-"]).stdin(Stdio::piped()).spawn()?;
        child
            .stdin
            .as_mut()
            .ok_or_else(|| EgressError::Apply("nft stdin was not captured".to_string()))?
            .write_all(ruleset.as_bytes())?;
        let status = child.wait()?;
        if !status.success() {
            return Err(EgressError::Apply(format!("`nft -f -` exited with {status}")));
        }
        *self
            .applied_table
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(table);
        Ok(())
    }

    fn revert(&self) -> Result<(), EgressError> {
        let table = self
            .applied_table
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
            .unwrap_or_else(|| EGRESS_TABLE.to_string());
        let status = std::process::Command::new("nft")
            .args(["delete", "table", "inet", &table])
            .status()?;
        if !status.success() {
            return Err(EgressError::Apply(format!(
                "`nft delete table inet {table}` exited with {status}"
            )));
        }
        Ok(())
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
        AllowList, EgressOs, EgressOutcome, EgressPlan, EgressRule, NetworkMode, enforce, forward_table_name,
        is_valid_tap_name, macos_egress_statement, plan_egress, plan_egress_scoped, to_nftables, to_nftables_forward,
        validate_egress_hosts, validate_network_mode, validate_proxy_egress,
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

    // --- tier-1: the guest-scoped forward ruleset (#29) -------------------------

    /// #29 (guest-scoped translation): a non-empty allow-list yields per-rule
    /// `iifname "<iface>" … accept` rules and a trailing `iifname "<iface>" drop`,
    /// all scoped to the guest's tap — the host is never named.
    #[test]
    fn forward_ruleset_scopes_accepts_and_the_drop_floor_to_the_guest_iface() {
        let allow = AllowList {
            rules: vec![EgressRule {
                host: "1.1.1.1".to_string(),
                port: 443,
            }],
        };
        let ruleset = to_nftables_forward(&allow, "sandytap0");
        assert!(
            ruleset.contains("iifname \"sandytap0\" ip daddr 1.1.1.1 tcp dport 443 accept"),
            "the allowed host must be a guest-scoped accept: {ruleset}"
        );
        assert!(
            ruleset.contains("iifname \"sandytap0\" drop"),
            "the ruleset must end in a guest-scoped drop floor: {ruleset}"
        );
    }

    /// #29 (no fail-open): an EMPTY allow-list still emits the `iifname "<iface>"
    /// drop` floor and permits NO destination (`ip daddr` absent), so all of the
    /// guest's new egress is blocked rather than failing open.
    #[test]
    fn empty_forward_ruleset_drops_all_guest_egress_no_fail_open() {
        let ruleset = to_nftables_forward(&AllowList::default(), "sandytap0");
        assert!(
            ruleset.contains("iifname \"sandytap0\" drop"),
            "an empty allow-list must still drop the guest's egress: {ruleset}"
        );
        assert!(
            !ruleset.contains("ip daddr"),
            "an empty allow-list must permit no destination (no `ip daddr` accept): {ruleset}"
        );
    }

    /// #29 (host safety): the chain policy is `accept`, so traffic on every other
    /// interface — the host's own egress included — is untouched and the host can
    /// never be locked off the network, unlike the OUTPUT-hook `policy drop`.
    #[test]
    fn forward_chain_policy_is_accept_so_the_host_is_never_dropped() {
        let ruleset = to_nftables_forward(&AllowList::default(), "sandytap0");
        assert!(
            ruleset.contains("hook forward") && ruleset.contains("policy accept"),
            "must be a forward-hook chain with an accept policy: {ruleset}"
        );
        assert!(
            !ruleset.contains("policy drop"),
            "the guest-scoped chain must NOT carry an OUTPUT-style drop policy: {ruleset}"
        );
    }

    /// #29 (adversarial): an injection host is dropped, never interpolated — no
    /// extra `accept` rule reaches the guest-scoped chain, and the drop floor and
    /// accept policy stay intact.
    #[test]
    fn forward_ruleset_fails_closed_on_an_injection_host() {
        let allow = AllowList {
            rules: vec![EgressRule {
                host: "x\n\t\tip daddr 0.0.0.0/0 accept comment \"pwn".to_string(),
                port: 1,
            }],
        };
        let ruleset = to_nftables_forward(&allow, "sandytap0");
        assert!(
            !ruleset.contains("0.0.0.0/0"),
            "the injected payload must not reach the ruleset: {ruleset}"
        );
        // The only `accept` tokens are the established/related line and the policy;
        // no per-destination `ip daddr … accept` was interpolated.
        assert!(
            !ruleset.contains("ip daddr"),
            "an injection host must not produce any destination accept: {ruleset}"
        );
        assert!(
            ruleset.contains("iifname \"sandytap0\" drop") && ruleset.contains("policy accept"),
            "the drop floor and accept policy must survive an injection attempt: {ruleset}"
        );
    }

    /// #29: `plan_egress_scoped` on Linux WITH a tap enforces the guest-scoped
    /// forward ruleset (not the OUTPUT model); WITHOUT a tap it falls back to
    /// `plan_egress` (the OUTPUT model, unchanged), and macOS stays honestly
    /// `NoBoundary`.
    #[test]
    fn plan_egress_scoped_uses_the_forward_ruleset_only_when_a_tap_is_bound() {
        let allow = AllowList {
            rules: vec![EgressRule {
                host: "1.1.1.1".to_string(),
                port: 443,
            }],
        };

        let EgressPlan::Enforce { ruleset } = plan_egress_scoped(&allow, EgressOs::Linux, Some("sandytap0")) else {
            panic!("Linux with a tap must Enforce");
        };
        assert_eq!(
            ruleset,
            to_nftables_forward(&allow, "sandytap0"),
            "a tap-bound Linux plan must enforce the guest-scoped forward ruleset"
        );

        assert!(
            matches!(
                plan_egress_scoped(&allow, EgressOs::Linux, None),
                EgressPlan::NoBoundary { .. }
            ),
            "Linux with no tap must apply NO boundary — never the host-wide OUTPUT drop"
        );
        assert_eq!(
            plan_egress_scoped(&allow, EgressOs::MacOs, Some("sandytap0")),
            plan_egress(&allow, EgressOs::MacOs),
            "macOS must stay honestly unenforced regardless of a tap"
        );
    }

    // --- tier-1: the input-hook host filter (#376) -------------------------------

    /// #376 (pinned translation): the forward ruleset also carries an `input`-hook
    /// chain scoped to the guest's `iface`, with `policy accept` (so every other
    /// interface's input is untouched), a DHCP accept, and a trailing drop. Pinned
    /// as one exact body so a partial emission (e.g. the drop without the DHCP
    /// accept) is caught, not just a loose `contains`.
    #[test]
    fn forward_ruleset_adds_an_input_chain_that_allows_only_dhcp_from_the_guest() {
        let ruleset = to_nftables_forward(&AllowList::default(), "sandytap0");
        let expected_input = "\tchain input {\n\t\ttype filter hook input priority filter; policy \
                              accept;\n\t\tiifname \"sandytap0\" udp dport 67 accept\n\t\tiifname \"sandytap0\" \
                              drop\n\t}\n";
        assert!(
            ruleset.contains(expected_input),
            "the input chain must be exactly this body: {ruleset}"
        );
    }

    /// #376 (no allow-list leak): a host-destined allow-list entry (the tap's own
    /// address, e.g. a host-local resolver) never reaches the input chain — the
    /// host is not a forward destination, so there is no legitimate accept to
    /// carry over, and the entry must not turn into an input-chain hole.
    #[test]
    fn forward_ruleset_input_chain_ignores_a_host_address_allow_entry() {
        let allow = AllowList {
            rules: vec![EgressRule {
                host: "10.77.0.1".to_string(),
                port: 53,
            }],
        };
        let ruleset = to_nftables_forward(&allow, "sandytap0");
        let input_start = ruleset.find("chain input").expect("ruleset must carry an input chain");
        let input_body = &ruleset[input_start..];
        assert!(
            !input_body.contains("10.77.0.1"),
            "an allow-list entry must never appear in the input chain: {ruleset}"
        );
        assert!(
            !input_body.contains("53"),
            "the allow-listed port must never appear in the input chain: {ruleset}"
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

    /// #360: on Linux a bound guest tap and the proxy would claim the boundary
    /// twice, so the combination is an invalid plan naming both variables.
    #[test]
    fn proxy_mode_on_linux_refuses_a_bound_tap() {
        let Err(PlanError::Invalid(msg)) = validate_proxy_egress(EgressOs::Linux, Some("sandytap0")) else {
            panic!("SANDY_EGRESS=proxy with a tap must be refused on Linux");
        };
        assert!(msg.contains("SANDY_EGRESS=proxy"), "{msg}");
        assert!(msg.contains("SANDY_TAP=sandytap0"), "{msg}");
    }

    /// #602: the profile, tap and proxy must agree, or the plan is invalid before any boot.
    #[test]
    fn network_mode_must_agree_with_the_tap_and_the_proxy() {
        use NetworkMode::{Nic, None as NoNic};
        let linux = EgressOs::Linux;
        assert!(validate_network_mode(linux, NoNic, None, false).is_ok());
        assert!(validate_network_mode(linux, NoNic, None, true).is_ok());
        assert!(validate_network_mode(linux, Nic, Some("sandytap0"), false).is_ok());
        for (mode, tap, proxy, needle) in [
            (Nic, None, false, "needs a bound tap"),
            (NoNic, Some("sandytap0"), false, "needs SANDY_NETWORK=nic"),
            (Nic, Some("sandytap0"), true, "exclusive"),
            (Nic, None, true, "exclusive"),
        ] {
            let Err(PlanError::Invalid(msg)) = validate_network_mode(linux, mode, tap, proxy) else {
                panic!("{mode:?} tap={tap:?} proxy={proxy} must be refused");
            };
            assert!(msg.contains(needle), "{msg}");
        }
        // macOS has no tap: `nic` is the trusted-only NAT NIC, but still never beside the proxy.
        assert!(validate_network_mode(EgressOs::MacOs, Nic, None, false).is_ok());
        assert!(validate_network_mode(EgressOs::MacOs, Nic, None, true).is_err());
    }

    /// #602: a tap name that cannot be scoped is refused at plan time, so a `,` cannot split the `-netdev` argument
    /// or open the ruleset.
    #[test]
    fn a_tap_name_that_is_not_a_bare_interface_is_refused() {
        for bad in [
            "sandytap0,vhost=on",
            "tap 0",
            "",
            "a/b",
            "waytoolonginterfacename",
            "..",
        ] {
            assert!(!is_valid_tap_name(bad), "{bad:?}");
            let refused = validate_network_mode(EgressOs::Linux, NetworkMode::Nic, Some(bad), false);
            assert!(matches!(refused, Err(PlanError::Invalid(_))), "{bad:?}: {refused:?}");
        }
        for good in ["sandytap0", "tap-1", "t.0", "SANDY_TAP_1"] {
            assert!(is_valid_tap_name(good), "{good:?}");
        }
    }

    /// #602: each tap gets its own table, so one run's revert cannot delete another run's boundary.
    #[test]
    fn each_tap_gets_its_own_forward_table() {
        let allow = AllowList::default();
        let first = to_nftables_forward(&allow, "sandytap0");
        let second = to_nftables_forward(&allow, "sandytap1");
        assert!(first.starts_with("table inet sandy_egress_sandytap0 {"), "{first}");
        assert!(second.starts_with("table inet sandy_egress_sandytap1 {"), "{second}");
        assert!(to_nftables_forward(&allow, "tap-1.x").starts_with("table inet sandy_egress_tap_h1_dx {"));
        // Distinct taps never share a table, even when they differ only in `_`, `-` or `.`.
        let tables: std::collections::HashSet<String> = ["tap-1", "tap_1", "tap.1", "tap1", "tap__1", "tap_h1"]
            .iter()
            .map(|tap| forward_table_name(tap))
            .collect();
        assert_eq!(tables.len(), 6, "{tables:?}");
    }

    /// #602 (NN5): the guest-scoped ruleset accepts only IPv4 TCP to allow-listed addresses and drops the rest of the
    /// guest's traffic, so IPv6 and UDP get no accept rule.
    #[test]
    fn the_forward_ruleset_accepts_only_allow_listed_ipv4_tcp() {
        let allow = AllowList {
            rules: vec![EgressRule {
                host: "10.1.2.3".to_string(),
                port: 443,
            }],
        };
        let ruleset = to_nftables_forward(&allow, "sandytap0");
        let (forward, input) = ruleset
            .split_once("chain input")
            .expect("a forward chain and an input chain");
        for line in forward
            .lines()
            .filter(|l| l.contains("accept") && l.contains("iifname"))
        {
            assert!(
                line.contains("ct state established,related")
                    || (line.contains("ip daddr") && line.contains("tcp dport")),
                "unexpected forward accept: {line}"
            );
        }
        assert!(!forward.contains("udp") && !forward.contains("ip6"), "{forward}");
        assert!(forward.contains("iifname \"sandytap0\" drop"), "{forward}");
        // Host-destined traffic (#376): only the guest's DHCP request is accepted, then everything else drops.
        let guest_accepts: Vec<&str> = input
            .lines()
            .filter(|l| l.contains("iifname") && l.contains("accept"))
            .collect();
        assert_eq!(
            guest_accepts,
            ["\t\tiifname \"sandytap0\" udp dport 67 accept"],
            "{input}"
        );
        assert!(input.contains("iifname \"sandytap0\" drop"), "{input}");
    }

    #[test]
    fn proxy_mode_accepts_a_guest_with_no_nic() {
        assert!(validate_proxy_egress(EgressOs::Linux, None).is_ok());
        assert!(validate_proxy_egress(EgressOs::MacOs, None).is_ok());
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
        assert!(validate_proxy_egress(EgressOs::Linux, None).is_ok());
    }
}
