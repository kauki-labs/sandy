//! Egress allow-list translation and the macOS honesty statement.
//!
//! Exercises `sandy_egress`'s public surface: an allow-list compiles to a
//! default-deny nftables ruleset that permits exactly the listed destinations
//! and nothing else, a host carrying nftables syntax is dropped rather than
//! interpolated, and the macOS statement admits there is no per-VM boundary.

use sandy::{AllowList, EgressRule, macos_egress_statement, to_nftables};

fn allow(host: &str, port: u16) -> AllowList {
    AllowList {
        rules: vec![EgressRule {
            host: host.to_string(),
            port,
        }],
    }
}

/// A listed `host:port` appears in the ruleset over a default-deny floor; an
/// unlisted host does not.
#[test]
fn an_allow_list_compiles_to_default_deny_plus_the_listed_destination() {
    let ruleset = to_nftables(&allow("github.com", 443));
    assert!(
        ruleset.contains("policy drop"),
        "default-deny floor is present: {ruleset}"
    );
    assert!(ruleset.contains("github.com"), "the allowed host is present: {ruleset}");
    assert!(ruleset.contains("443"), "the allowed port is present: {ruleset}");
    assert!(!ruleset.contains("evil.example"), "an unlisted host is absent");
}

/// A host carrying a newline and an `accept` directive is dropped, never
/// interpolated — the default-deny floor stays intact and no injected accept
/// rule appears.
#[test]
fn an_injection_host_is_dropped_not_interpolated() {
    let ruleset = to_nftables(&allow("x\n\t\tip daddr 0.0.0.0/0 accept comment \"pwn", 1));
    assert!(ruleset.contains("policy drop"), "the floor remains: {ruleset}");
    assert!(!ruleset.contains("accept"), "no accept rule is produced: {ruleset}");
    assert!(
        !ruleset.contains("0.0.0.0/0"),
        "the payload never reaches the ruleset: {ruleset}"
    );
}

/// The whole generated ruleset for a representative multi-destination allow-list,
/// pinned as a snapshot. The `contains` tests above prove individual properties;
/// this locks the complete nftables text so any change to the default-deny floor,
/// chain structure, or rule shape (all security-relevant) surfaces in the diff for
/// review rather than slipping through a partial assertion.
#[test]
fn the_ruleset_for_a_multi_destination_allow_list_is_stable() {
    let allow = AllowList {
        rules: vec![
            EgressRule {
                host: "github.com".to_string(),
                port: 443,
            },
            EgressRule {
                host: "objects.githubusercontent.com".to_string(),
                port: 443,
            },
        ],
    };
    insta::assert_snapshot!(to_nftables(&allow), @r#"
    table inet sandy_egress {
    	chain output {
    		type filter hook output priority filter; policy drop;
    		ip daddr github.com tcp dport 443 accept comment "allow github.com:443"
    		ip daddr objects.githubusercontent.com tcp dport 443 accept comment "allow objects.githubusercontent.com:443"
    	}
    }
    "#);
}

/// The macOS statement names the trusted-only posture and claims no per-VM
/// egress boundary rather than pretending to filter.
#[test]
fn the_macos_statement_claims_no_boundary() {
    let msg = macos_egress_statement().to_lowercase();
    assert!(msg.contains("trusted"), "names the trusted-only posture: {msg}");
    assert!(
        msg.contains("no") && msg.contains("boundary"),
        "claims no boundary: {msg}"
    );
}
