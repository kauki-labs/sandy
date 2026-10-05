//! `sandy-egress` — egress allow-list → nftables translation and macOS honesty
//! (Phase D, D.3 / D-REQ-3).
//!
//! On Linux the allow-list compiles to a default-deny nftables ruleset permitting
//! exactly the listed `host:port` pairs; the real kernel enforcement is host-tier
//! (tier-3). On macOS (vmnet) there is no per-VM egress boundary, so
//! [`macos_egress_statement`] says so honestly instead of pretending to filter.

use serde::{Deserialize, Serialize};

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
    let mut ruleset = String::from("table inet sandy_egress {\n\tchain output {\n");
    ruleset.push_str("\t\ttype filter hook output priority filter; policy drop;\n");
    for rule in &allow.rules {
        // Fail closed: a host that isn't a bare name/address/CIDR can't be safely
        // interpolated into the chain, so drop its accept rule rather than risk
        // injecting a directive that defeats the default-deny floor. A dropped host
        // simply stays denied (CLAUDE.md: validate and sanitize inputs). The port
        // is a `u16`, so it is always a safe numeric token.
        if !is_emittable_host(&rule.host) {
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

#[cfg(test)]
mod tests {
    use super::{AllowList, EgressRule, macos_egress_statement, to_nftables};

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
}
