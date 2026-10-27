//! Property tests: arbitrary request heads never panic the parser and never
//! earn a tunnel to a target outside the allow-list.

use std::net::IpAddr;

use proptest::prelude::*;
use sandy_api::egress::{AllowList, EgressRule};
use sandy_egress_proxy::{Host, Policy, ResolveError, Resolver, Status, decide, parse_head};

/// Every name resolves to one public address, so only the policy can refuse.
struct Public;

impl Resolver for Public {
    fn resolve(&self, _name: &str) -> Result<Vec<IpAddr>, ResolveError> {
        Ok(vec!["93.184.216.34".parse().expect("ip")])
    }
}

fn policy() -> Policy {
    let rule = |host: &str, port| EgressRule {
        host: host.to_owned(),
        port,
    };
    Policy::from_allow_list(&AllowList {
        rules: vec![rule("allowed.example", 443), rule("192.0.2.0/24", 443)],
    })
    .expect("valid policy")
}

fn in_policy(host: &Host, port: u16) -> bool {
    port == 443
        && match host {
            Host::Name(n) => n == "allowed.example",
            Host::V4(ip) => ip.octets()[..3] == [192, 0, 2],
            Host::V6(_) => false,
        }
}

proptest! {
    #[test]
    fn arbitrary_bytes_never_panic_the_parser(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        let _ = parse_head(&bytes);
    }

    #[test]
    fn a_200_decision_only_follows_an_allow_listed_target(
        method in prop_oneof![Just("CONNECT".to_owned()), "[A-Za-z]{1,8}"],
        authority in "[ -~]{0,60}",
        version in prop_oneof![Just("HTTP/1.1".to_owned()), Just("HTTP/1.0".to_owned()), "[ -~]{0,10}"],
    ) {
        let head = format!("{method} {authority} {version}\r\n\r\n");
        if let Ok(target) = parse_head(head.as_bytes())
            && let Ok(addrs) = decide(&target, &policy(), &Public, &[])
        {
            prop_assert!(!addrs.is_empty());
            prop_assert!(in_policy(&target.host, target.port), "{head:?}");
        }
    }

    #[test]
    fn near_misses_of_an_allowed_name_never_pass(
        prefix in "[a-z0-9.@%-]{0,6}",
        suffix in "[a-z0-9.@%-]{0,6}",
        port in 0u32..70000,
    ) {
        let head = format!("CONNECT {prefix}allowed.example{suffix}:{port} HTTP/1.1\r\n\r\n");
        if let Ok(target) = parse_head(head.as_bytes())
            && decide(&target, &policy(), &Public, &[]).is_ok()
        {
            prop_assert!(in_policy(&target.host, target.port), "{head:?}");
        }
    }
}

#[test]
fn the_oracle_agrees_on_a_known_allowed_target() {
    let t = parse_head(b"CONNECT allowed.example:443 HTTP/1.1\r\n\r\n").expect("parses");
    assert!(decide(&t, &policy(), &Public, &[]).is_ok());
    let t = parse_head(b"CONNECT allowed.example:80 HTTP/1.1\r\n\r\n").expect("parses");
    assert_eq!(
        decide(&t, &policy(), &Public, &[]).unwrap_err().status,
        Status::Forbidden
    );
}
