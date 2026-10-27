//! The run's allow-list as the proxy reads it: `name:port`, `IPv4:port`, or
//! `IPv4-CIDR:port`. Matching happens before any resolution.

use std::net::Ipv4Addr;

use sandy_api::egress::AllowList;

use crate::{
    head::{Host, Target, classify_host},
    verdict::{Status, Verdict},
};

/// A policy entry that cannot be used. The proxy exits without `READY`.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PolicyError {
    /// The entry's host is not a name, an IPv4 address, or an IPv4 CIDR.
    #[error("allow-list entry {0:?}: not a name, an IPv4 address, or an IPv4 CIDR")]
    BadHost(String),
    /// The entry's port is zero.
    #[error("allow-list entry {0:?}: port must be 1..=65535")]
    BadPort(String),
}

/// An IPv4 network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Cidr {
    base: u32,
    mask: u32,
}

impl Cidr {
    fn contains(self, ip: Ipv4Addr) -> bool {
        u32::from(ip) & self.mask == self.base
    }

    fn parse(text: &str) -> Option<Self> {
        let (addr, prefix) = match text.split_once('/') {
            Some((a, p)) => (a, p.parse::<u8>().ok().filter(|p| *p <= 32)?),
            None => (text, 32),
        };
        let addr: Ipv4Addr = addr.parse().ok()?;
        let mask = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
        Some(Self {
            base: u32::from(addr) & mask,
            mask,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Entry {
    Name { host: String, port: u16 },
    Net { net: Cidr, port: u16 },
}

/// The validated allow-list. An empty policy refuses every target.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Policy {
    entries: Vec<Entry>,
}

impl Policy {
    /// Validate and normalise an [`AllowList`].
    ///
    /// # Errors
    /// [`PolicyError`] for the first entry that is not usable.
    pub fn from_allow_list(list: &AllowList) -> Result<Self, PolicyError> {
        let mut entries = Vec::with_capacity(list.rules.len());
        for rule in &list.rules {
            let label = format!("{}:{}", rule.host, rule.port);
            if rule.port == 0 {
                return Err(PolicyError::BadPort(label));
            }
            let entry = if rule.host.contains('/') {
                let net = Cidr::parse(&rule.host).ok_or(PolicyError::BadHost(label))?;
                Entry::Net { net, port: rule.port }
            } else {
                match classify_host(&rule.host) {
                    Some(Host::V4(ip)) => Entry::Net {
                        net: Cidr::parse(&ip.to_string()).ok_or(PolicyError::BadHost(label))?,
                        port: rule.port,
                    },
                    Some(Host::Name(host)) => Entry::Name { host, port: rule.port },
                    _ => return Err(PolicyError::BadHost(label)),
                }
            };
            entries.push(entry);
        }
        Ok(Self { entries })
    }

    /// Match `target` against the entries, before any resolution.
    ///
    /// # Errors
    /// `403` naming the target when no entry matches or the host is an IPv6
    /// literal (v1 refuses them).
    pub fn check(&self, target: &Target) -> Result<(), Verdict> {
        let allowed = match &target.host {
            Host::Name(name) => self
                .entries
                .iter()
                .any(|e| matches!(e, Entry::Name { host, port } if host == name && *port == target.port)),
            Host::V4(ip) => self.names_ip(*ip, target.port),
            Host::V6(_) => {
                return Err(Verdict::new(
                    Status::Forbidden,
                    format!("{}: IPv6 literals are not supported", target.label()),
                ));
            }
        };
        if allowed {
            Ok(())
        } else {
            Err(Verdict::new(
                Status::Forbidden,
                format!("{}: not in the allow-list", target.label()),
            ))
        }
    }

    /// Whether an IP or CIDR entry with this port contains `ip`.
    #[must_use]
    pub fn names_ip(&self, ip: Ipv4Addr, port: u16) -> bool {
        self.entries
            .iter()
            .any(|e| matches!(e, Entry::Net { net, port: p } if *p == port && net.contains(ip)))
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Context;
    use rstest::rstest;
    use sandy_api::egress::EgressRule;

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

    fn name(host: &str, port: u16) -> Target {
        Target {
            host: Host::Name(host.to_owned()),
            port,
        }
    }

    fn v4(a: u8, b: u8, c: u8, d: u8, port: u16) -> Target {
        Target {
            host: Host::V4(Ipv4Addr::new(a, b, c, d)),
            port,
        }
    }

    #[test]
    fn a_name_matches_only_a_name_entry_with_the_same_port() -> anyhow::Result<()> {
        let p = policy(&[("github.com", 443)]);
        assert!(p.check(&name("github.com", 443)).is_ok());
        assert_eq!(
            p.check(&name("github.com", 80))
                .err()
                .context("expected a refusal")?
                .status,
            Status::Forbidden
        );
        assert!(p.check(&name("api.github.com", 443)).is_err());
        Ok(())
    }

    #[test]
    fn entry_names_are_normalised_like_targets() {
        let p = policy(&[("GitHub.com.", 443)]);
        assert!(p.check(&name("github.com", 443)).is_ok());
    }

    #[test]
    fn a_name_never_matches_an_ip_entry() {
        let p = policy(&[("0.0.0.0/0", 443), ("192.0.2.7", 443)]);
        assert!(p.check(&name("example.com", 443)).is_err());
    }

    #[test]
    fn an_ip_never_matches_a_name_entry() {
        let p = policy(&[("example.com", 443)]);
        assert!(p.check(&v4(93, 184, 216, 34, 443)).is_err());
    }

    #[test]
    fn an_ip_matches_an_exact_or_cidr_entry_with_the_same_port() {
        let p = policy(&[("192.0.2.7", 443), ("10.0.0.0/8", 8443)]);
        assert!(p.check(&v4(192, 0, 2, 7, 443)).is_ok());
        assert!(p.check(&v4(192, 0, 2, 8, 443)).is_err());
        assert!(p.check(&v4(10, 9, 8, 7, 8443)).is_ok());
        assert!(p.check(&v4(10, 9, 8, 7, 443)).is_err());
    }

    #[test]
    fn a_slash_zero_cidr_covers_every_address() {
        let p = policy(&[("0.0.0.0/0", 443)]);
        assert!(p.check(&v4(203, 0, 113, 9, 443)).is_ok());
    }

    #[test]
    fn an_empty_policy_refuses_everything() {
        let p = Policy::default();
        assert!(p.check(&name("example.com", 443)).is_err());
        assert!(p.check(&v4(1, 1, 1, 1, 443)).is_err());
    }

    #[test]
    fn an_ipv6_literal_is_refused_even_when_a_wide_entry_exists() -> anyhow::Result<()> {
        let p = policy(&[("0.0.0.0/0", 443)]);
        let t = Target {
            host: Host::V6("2001:db8::1".parse().context("ip")?),
            port: 443,
        };
        let v = p.check(&t).err().context("expected a refusal")?;
        assert_eq!(v.status, Status::Forbidden);
        assert!(v.reason.contains("2001:db8::1"));
        Ok(())
    }

    #[test]
    fn the_refusal_names_the_target() -> anyhow::Result<()> {
        let v = Policy::default()
            .check(&name("evil.example", 443))
            .err()
            .context("expected a refusal")?;
        assert!(v.reason.contains("evil.example:443"), "{}", v.reason);
        Ok(())
    }

    #[rstest]
    #[case::ipv6("2001:db8::/32", 443)]
    #[case::bad_prefix("10.0.0.0/33", 443)]
    #[case::empty_prefix("10.0.0.0/", 443)]
    #[case::short_form("127.1", 443)]
    #[case::bad_name("a_b.example", 443)]
    #[case::port_zero("example.com", 0)]
    fn an_unusable_entry_is_a_policy_error(#[case] host: &str, #[case] port: u16) {
        let list = AllowList {
            rules: vec![EgressRule {
                host: host.to_owned(),
                port,
            }],
        };
        assert!(Policy::from_allow_list(&list).is_err(), "{host}:{port}");
    }
}
