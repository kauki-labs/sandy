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
//! [`enforce`] drives that plan over the [`EgressApplier`] seam — [`FakeApplier`]
//! in tests, [`NftablesApplier`] (shells `nft -f -`) on a real Linux host. The
//! live Linux enforcement — the real `nft` load whose boundary an in-guest root
//! flush cannot bypass — is tier-3 and is asserted by `cargo test --test phase_d`
//! (#29); it is not exercised here.

use std::cell::{Cell, RefCell};

use serde::{Deserialize, Serialize};

use crate::error::CoreError;

/// One permitted egress destination.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressRule {
    /// The destination host (DNS name or address) to permit.
    pub host: String,
    /// The destination TCP port to permit.
    pub port: u16,
}

/// A bundle's egress allow-list: the only destinations a guest may reach.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllowList {
    /// The permitted destinations; everything else is denied.
    pub rules: Vec<EgressRule>,
}

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
/// interface — the host's own egress included — untouched (#29).
///
/// This is the safe counterpart to [`to_nftables`]: where that emits an
/// OUTPUT-hook `policy drop` (which, applied in the host netns, would drop the
/// HOST's own egress and lock it off the network), this scopes a default-deny to
/// one guest interface. The chain accepts the guest's established/related return
/// traffic and exactly the listed `host:port` pairs, then drops everything else
/// from that interface; the trailing `iifname "<iface>" drop` is the floor, so an
/// **empty** allow-list blocks all of the guest's new egress rather than failing
/// open. Host names that aren't a bare address/CIDR are dropped (fail-closed),
/// same as [`to_nftables`].
///
/// An `iface` that is not a bare interface token can't be scoped to a guest
/// without risking rule injection and can't be matched to drop the guest either,
/// so the chain is emitted empty (table present, `policy accept`, no rules) with a
/// warning — nothing is filtered, but the host is never touched.
#[must_use]
pub fn to_nftables_forward(allow: &AllowList, iface: &str) -> String {
    let open = format!(
        "table inet {EGRESS_TABLE} {{\n\tchain forward {{\n\t\ttype filter hook forward priority filter; policy \
         accept;\n"
    );
    if !is_emittable_host(iface) {
        tracing::warn!(
            ?iface,
            "egress forward ruleset: interface is not a bare token; emitting no guest filter (host untouched)"
        );
        return format!("{open}\t}}\n}}\n");
    }

    let mut ruleset = open;
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

/// The name of the nftables table [`to_nftables`] emits and [`NftablesApplier`]
/// tears down on revert; the two must agree.
const EGRESS_TABLE: &str = "sandy_egress";

/// The target OS an egress plan is computed for — injected so [`plan_egress`] is
/// a pure function unit-testable without a real host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressOs {
    /// Linux: nftables enforces a default-deny per-VM egress boundary.
    Linux,
    /// macOS (vmnet): no per-VM egress boundary can be enforced.
    MacOs,
}

/// A typed, OS-resolved egress enforcement plan.
///
/// Keeping the plan a value (not an action) makes the Linux/macOS decision
/// testable without touching the host, and makes macOS honesty explicit: a
/// platform with no boundary yields [`EgressPlan::NoBoundary`], never an empty
/// [`EgressPlan::Enforce`] that would read as "filtered" while permitting all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EgressPlan {
    /// Apply this nftables ruleset as the per-VM boundary (Linux).
    Enforce {
        /// The default-deny ruleset to load; see [`to_nftables`].
        ruleset: String,
    },
    /// No boundary is enforced; `reason` states why, honestly (macOS).
    NoBoundary {
        /// Why no boundary exists — surfaced to the operator, never swallowed.
        reason: String,
    },
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
/// This is the tap-aware planner the live run path uses. On Linux **with** a tap
/// (`iface = Some`), it enforces the **guest-scoped** [`to_nftables_forward`]
/// ruleset — the safe forward-hook model that filters only the guest and can
/// never lock the host off the network (#29). On Linux **without** a tap, the
/// guest has no NIC, so it falls back to [`plan_egress`] (the OUTPUT-hook model,
/// unchanged). macOS is [`plan_egress`]'s honest [`EgressPlan::NoBoundary`]
/// regardless. Delegating the non-tap arms keeps the existing Linux/macOS
/// behaviour byte-for-byte identical.
#[must_use]
pub fn plan_egress_scoped(allow: &AllowList, target_os: EgressOs, iface: Option<&str>) -> EgressPlan {
    match (target_os, iface) {
        (EgressOs::Linux, Some(iface)) => EgressPlan::Enforce {
            ruleset: to_nftables_forward(allow, iface),
        },
        (os, _) => plan_egress(allow, os),
    }
}

/// The result of driving an [`EgressPlan`] through [`enforce`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EgressOutcome {
    /// The ruleset was applied as the per-VM boundary (Linux).
    Enforced,
    /// No boundary was applied; `reason` carries the honest explanation (macOS).
    Unenforced {
        /// Why egress is unenforced — mirrors [`EgressPlan::NoBoundary`]'s reason.
        reason: String,
    },
}

/// A seam that applies and reverts a compiled egress ruleset on the host.
///
/// Abstracting the host away lets [`enforce`] be wired and tested with
/// [`FakeApplier`] (no root, no `nft`); the real host-tier impl is
/// [`NftablesApplier`]. Egress rules are destinations, not secrets (INV-1), so
/// the ruleset is passed and logged in the clear.
pub trait EgressApplier {
    /// Load `ruleset` as the active egress boundary.
    ///
    /// # Errors
    /// Returns [`CoreError::Egress`] (or an underlying [`CoreError::Io`]) if the
    /// ruleset cannot be applied on the host.
    fn apply(&self, ruleset: &str) -> Result<(), CoreError>;

    /// Tear the applied boundary back down.
    ///
    /// # Errors
    /// Returns [`CoreError::Egress`] (or [`CoreError::Io`]) if the teardown fails.
    fn revert(&self) -> Result<(), CoreError>;
}

/// A test double that records what it was asked to apply and whether it was
/// reverted, instead of touching the host.
#[derive(Debug, Default)]
pub struct FakeApplier {
    applied: RefCell<Vec<String>>,
    reverted: Cell<bool>,
}

impl FakeApplier {
    /// A fresh double that has applied nothing and not been reverted.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The rulesets passed to [`EgressApplier::apply`], in call order.
    #[must_use]
    pub fn applied_rulesets(&self) -> Vec<String> {
        self.applied.borrow().clone()
    }

    /// Whether [`EgressApplier::revert`] has been called.
    #[must_use]
    pub fn was_reverted(&self) -> bool {
        self.reverted.get()
    }
}

impl EgressApplier for FakeApplier {
    fn apply(&self, ruleset: &str) -> Result<(), CoreError> {
        self.applied.borrow_mut().push(ruleset.to_string());
        Ok(())
    }

    fn revert(&self) -> Result<(), CoreError> {
        self.reverted.set(true);
        Ok(())
    }
}

/// Host-tier applier that loads the ruleset into the Linux kernel via `nft -f -`
/// and reverts by deleting the [`EGRESS_TABLE`].
///
/// This is intentionally thin and is **not** unit-tested: the behaviour that
/// matters — that the loaded boundary holds against an in-guest root flush — is a
/// live, root-only, host-tier assertion that binds into `cargo test --test
/// phase_d` (#29), not something a unit test can observe.
#[derive(Debug, Default, Clone, Copy)]
pub struct NftablesApplier;

impl EgressApplier for NftablesApplier {
    fn apply(&self, ruleset: &str) -> Result<(), CoreError> {
        use std::{
            io::Write,
            process::{Command, Stdio},
        };

        let mut child = Command::new("nft").args(["-f", "-"]).stdin(Stdio::piped()).spawn()?;
        child
            .stdin
            .as_mut()
            .ok_or_else(|| CoreError::Egress("nft stdin was not captured".to_string()))?
            .write_all(ruleset.as_bytes())?;
        let status = child.wait()?;
        if !status.success() {
            return Err(CoreError::Egress(format!("`nft -f -` exited with {status}")));
        }
        Ok(())
    }

    fn revert(&self) -> Result<(), CoreError> {
        let status = std::process::Command::new("nft")
            .args(["delete", "table", "inet", EGRESS_TABLE])
            .status()?;
        if !status.success() {
            return Err(CoreError::Egress(format!(
                "`nft delete table inet {EGRESS_TABLE}` exited with {status}"
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
/// Propagates any [`CoreError`] from [`EgressApplier::apply`].
pub fn enforce(plan: &EgressPlan, applier: &impl EgressApplier) -> Result<EgressOutcome, CoreError> {
    match plan {
        EgressPlan::Enforce { ruleset } => {
            applier.apply(ruleset)?;
            Ok(EgressOutcome::Enforced)
        }
        EgressPlan::NoBoundary { reason } => {
            tracing::warn!(reason = %reason, "egress boundary not enforced");
            Ok(EgressOutcome::Unenforced { reason: reason.clone() })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AllowList, EgressOs, EgressOutcome, EgressPlan, EgressRule, FakeApplier, enforce, macos_egress_statement,
        plan_egress, plan_egress_scoped, to_nftables, to_nftables_forward,
    };

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

        assert_eq!(
            plan_egress_scoped(&allow, EgressOs::Linux, None),
            plan_egress(&allow, EgressOs::Linux),
            "Linux with no tap must match the unchanged plan_egress (OUTPUT) behaviour"
        );
        assert_eq!(
            plan_egress_scoped(&allow, EgressOs::MacOs, Some("sandytap0")),
            plan_egress(&allow, EgressOs::MacOs),
            "macOS must stay honestly unenforced regardless of a tap"
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
}
