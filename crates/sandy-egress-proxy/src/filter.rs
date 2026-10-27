//! The address filter: which resolved addresses the proxy may connect to.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::allow::Policy;

/// The IPv4 address an IPv4-mapped (`::ffff:0:0/96`) or NAT64 (`64:ff9b::/96`)
/// address embeds.
fn embedded_v4(ip: Ipv6Addr) -> Option<Ipv4Addr> {
    let s = ip.segments();
    let tail = || {
        let o = ip.octets();
        Ipv4Addr::new(o[12], o[13], o[14], o[15])
    };
    let mapped = s[..5] == [0; 5] && s[5] == 0xffff;
    let nat64 = s[0] == 0x64 && s[1] == 0xff9b && s[2..6] == [0; 4];
    (mapped || nat64).then(tail)
}

fn always_refused_v4(ip: Ipv4Addr) -> bool {
    ip.is_loopback() || ip.octets()[0] == 0
}

/// Special-use IPv4 ranges that an IP or CIDR entry may open up.
fn special_use_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    ip.is_private()
        || (a == 100 && (64..=127).contains(&b))
        || ip.is_link_local()
        || (a == 192 && b == 0 && c == 0)
        || (a == 198 && (b == 18 || b == 19))
        || ip.is_multicast()
        || a >= 240
}

/// Keep the addresses the proxy may connect to, in resolver order.
///
/// Loopback, unspecified, and `host_ifaces` addresses are always refused.
/// Special-use ranges are refused unless an IP or CIDR entry with `port`
/// contains the address. An IPv4-mapped or NAT64 address is judged by the
/// IPv4 address it embeds. Native IPv6 passes only when global unicast.
#[must_use]
pub fn filter_addrs(addrs: &[IpAddr], port: u16, policy: &Policy, host_ifaces: &[IpAddr]) -> Vec<IpAddr> {
    addrs
        .iter()
        .copied()
        .filter(|addr| permitted(*addr, port, policy, host_ifaces))
        .collect()
}

fn permitted(addr: IpAddr, port: u16, policy: &Policy, host_ifaces: &[IpAddr]) -> bool {
    let embedded = match addr {
        IpAddr::V4(v4) => Some(v4),
        IpAddr::V6(v6) => embedded_v4(v6),
    };
    if let Some(v4) = embedded {
        let on_host = host_ifaces.iter().any(|h| match h {
            IpAddr::V4(h4) => *h4 == v4,
            IpAddr::V6(h6) => embedded_v4(*h6) == Some(v4),
        });
        // `not(test)`: the library's own unit tests keep the refusal even when
        // the feature is on; only the binary under the integration tests loses it.
        let local_refusal = !cfg!(all(feature = "test-loopback", not(test)));
        if local_refusal && (always_refused_v4(v4) || on_host) {
            return false;
        }
        return !special_use_v4(v4) || policy.names_ip(v4, port);
    }
    let IpAddr::V6(v6) = addr else {
        return false;
    };
    let first = v6.segments()[0];
    let non_global = v6.is_loopback()
        || v6.is_unspecified()
        || v6.is_multicast()
        || first & 0xffc0 == 0xfe80
        || first & 0xfe00 == 0xfc00;
    !non_global && !host_ifaces.contains(&addr)
}

#[cfg(test)]
mod tests {
    use rstest::rstest;
    use sandy_api::egress::{AllowList, EgressRule};

    use super::*;

    fn policy(entries: &[(&str, u16)]) -> Policy {
        let rules = entries
            .iter()
            .map(|(h, p)| EgressRule {
                host: (*h).to_owned(),
                port: *p,
            })
            .collect();
        Policy::from_allow_list(&AllowList { rules }).expect("valid policy")
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("ip literal")
    }

    fn kept(addr: &str, p: &Policy, ifaces: &[IpAddr]) -> bool {
        !filter_addrs(&[ip(addr)], 443, p, ifaces).is_empty()
    }

    #[rstest]
    #[case("93.184.216.34")]
    #[case("2606:2800:220:1::1")]
    fn a_public_address_passes_with_an_empty_policy(#[case] addr: &str) {
        assert!(kept(addr, &Policy::default(), &[]));
    }

    #[rstest]
    #[case("127.0.0.1")]
    #[case("127.255.255.254")]
    #[case("0.0.0.0")]
    #[case("0.1.2.3")]
    #[case("::1")]
    #[case("::")]
    #[case("::ffff:127.0.0.1")]
    #[case("64:ff9b::7f00:1")]
    fn loopback_and_unspecified_are_refused_even_when_an_entry_names_them(#[case] addr: &str) {
        let wide = policy(&[("0.0.0.0/0", 443)]);
        assert!(!kept(addr, &wide, &[]), "{addr}");
    }

    #[test]
    fn a_host_interface_address_is_refused_even_when_named() {
        let wide = policy(&[("0.0.0.0/0", 443)]);
        let ifaces = [ip("203.0.113.5")];
        assert!(!kept("203.0.113.5", &wide, &ifaces));
        assert!(!kept("::ffff:203.0.113.5", &wide, &ifaces));
        assert!(kept("203.0.113.6", &wide, &ifaces));
    }

    #[rstest]
    #[case("10.0.0.5")]
    #[case("172.16.0.1")]
    #[case("172.31.255.255")]
    #[case("192.168.1.1")]
    #[case("100.64.0.1")]
    #[case("100.127.255.255")]
    #[case("169.254.169.254")]
    #[case("192.0.0.8")]
    #[case("198.18.0.1")]
    #[case("198.19.255.255")]
    #[case("224.0.0.1")]
    #[case("240.0.0.1")]
    #[case("255.255.255.255")]
    #[case("::ffff:10.0.0.5")]
    #[case("64:ff9b::a00:5")]
    #[case("fe80::1")]
    #[case("fc00::1")]
    #[case("fd12:3456::1")]
    #[case("ff02::1")]
    fn a_special_use_address_is_refused_without_a_naming_entry(#[case] addr: &str) {
        assert!(!kept(addr, &Policy::default(), &[]), "{addr}");
    }

    #[test]
    fn the_adjacent_public_ranges_are_not_caught_by_the_special_use_masks() {
        for addr in [
            "172.15.255.255",
            "172.32.0.1",
            "100.63.255.255",
            "100.128.0.1",
            "198.17.0.1",
            "198.20.0.1",
            "192.0.1.1",
            "223.255.255.255",
        ] {
            assert!(kept(addr, &Policy::default(), &[]), "{addr}");
        }
    }

    #[test]
    fn a_private_address_passes_when_an_entry_with_the_same_port_contains_it() {
        let p = policy(&[("10.0.0.0/8", 443)]);
        assert!(kept("10.0.0.5", &p, &[]));
        assert!(kept("::ffff:10.0.0.5", &p, &[]));
    }

    #[test]
    fn a_private_address_stays_refused_when_the_entry_port_differs() {
        let p = policy(&[("10.0.0.0/8", 8443)]);
        assert!(!kept("10.0.0.5", &p, &[]));
    }

    #[test]
    fn a_name_entry_never_opens_a_private_address() {
        let p = policy(&[("registry.internal", 443)]);
        assert!(!kept("10.0.0.5", &p, &[]));
    }

    #[test]
    fn the_filter_keeps_resolver_order_and_drops_only_refused_addresses() {
        let addrs = [
            ip("127.0.0.1"),
            ip("93.184.216.34"),
            ip("10.0.0.5"),
            ip("93.184.216.35"),
        ];
        let out = filter_addrs(&addrs, 443, &Policy::default(), &[]);
        assert_eq!(out, vec![ip("93.184.216.34"), ip("93.184.216.35")]);
    }

    #[test]
    fn the_original_address_is_returned_not_the_embedded_one() {
        let out = filter_addrs(&[ip("64:ff9b::5db8:d822")], 443, &Policy::default(), &[]);
        assert_eq!(out, vec![ip("64:ff9b::5db8:d822")]);
    }
}
