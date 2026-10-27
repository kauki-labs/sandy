//! From a parsed target to the addresses the proxy may connect to.
//!
//! The resolver is a seam so a test can prove two properties: a denied name
//! never reaches it, and the answer it gives once is the only one used.

use std::net::IpAddr;

use crate::{
    allow::Policy,
    filter::filter_addrs,
    head::{Host, Target},
    verdict::{Status, Verdict},
};

/// Why a name did not resolve.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolveError {
    /// The lookup failed.
    Failed,
    /// The lookup did not finish in time.
    TimedOut,
}

/// A name-to-address lookup (`getaddrinfo`, A and AAAA, in the binary).
pub trait Resolver {
    /// Resolve `name` once.
    ///
    /// # Errors
    /// [`ResolveError`] when the lookup fails or times out.
    fn resolve(&self, name: &str) -> Result<Vec<IpAddr>, ResolveError>;
}

/// Decide a CONNECT: match, resolve at most once, filter.
///
/// Returns the kept addresses in resolver order. The caller connects to one of
/// these and must not resolve again.
///
/// # Errors
/// `403` when the policy refuses the target or no resolved address survives
/// the filter; `502` or `504` when resolution fails.
pub fn decide(
    target: &Target,
    policy: &Policy,
    resolver: &impl Resolver,
    host_ifaces: &[IpAddr],
) -> Result<Vec<IpAddr>, Verdict> {
    policy.check(target)?;
    let resolved = match &target.host {
        Host::V4(ip) => vec![IpAddr::V4(*ip)],
        // `Policy::check` already refused IPv6 literals; stay closed if that changes.
        Host::V6(_) => {
            return Err(Verdict::new(
                Status::Forbidden,
                format!("{}: IPv6 literals are not supported", target.label()),
            ));
        }
        Host::Name(name) => resolver.resolve(name).map_err(|e| match e {
            ResolveError::Failed => {
                Verdict::new(Status::BadGateway, format!("{}: name did not resolve", target.label()))
            }
            ResolveError::TimedOut => Verdict::new(
                Status::GatewayTimeout,
                format!("{}: name resolution timed out", target.label()),
            ),
        })?,
    };
    let kept = filter_addrs(&resolved, target.port, policy, host_ifaces);
    if kept.is_empty() {
        return Err(Verdict::new(
            Status::Forbidden,
            format!("{}: resolves to a non-public address", target.label()),
        ));
    }
    Ok(kept)
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};

    use anyhow::Context;
    use sandy_api::egress::{AllowList, EgressRule};

    use super::*;
    use crate::head::parse_head;

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

    fn target(authority: &str) -> Target {
        parse_head(format!("CONNECT {authority} HTTP/1.1\r\n\r\n").as_bytes()).expect("target")
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("ip")
    }

    /// Answers each call from a queue and counts calls.
    struct Scripted {
        answers: RefCell<Vec<Result<Vec<IpAddr>, ResolveError>>>,
        calls: Cell<usize>,
    }

    impl Scripted {
        fn new(answers: Vec<Result<Vec<IpAddr>, ResolveError>>) -> Self {
            Self {
                answers: RefCell::new(answers),
                calls: Cell::new(0),
            }
        }
    }

    impl Resolver for Scripted {
        fn resolve(&self, _name: &str) -> Result<Vec<IpAddr>, ResolveError> {
            self.calls.set(self.calls.get() + 1);
            let mut answers = self.answers.borrow_mut();
            if answers.is_empty() {
                Err(ResolveError::Failed)
            } else {
                answers.remove(0)
            }
        }
    }

    #[test]
    fn a_denied_name_never_reaches_the_resolver() -> anyhow::Result<()> {
        let resolver = Scripted::new(vec![Ok(vec![ip("93.184.216.34")])]);
        let v = decide(
            &target("evil.example:443"),
            &policy(&[("ok.example", 443)]),
            &resolver,
            &[],
        )
        .err()
        .context("expected a refusal")?;
        assert_eq!(v.status, Status::Forbidden);
        assert_eq!(resolver.calls.get(), 0);
        Ok(())
    }

    #[test]
    fn a_wrong_port_name_never_reaches_the_resolver() {
        let resolver = Scripted::new(vec![]);
        let _ = decide(
            &target("ok.example:80"),
            &policy(&[("ok.example", 443)]),
            &resolver,
            &[],
        );
        assert_eq!(resolver.calls.get(), 0);
    }

    #[test]
    fn the_checked_address_is_the_one_returned_after_one_lookup() -> anyhow::Result<()> {
        // A rebinding resolver: public first, loopback on any later call.
        let resolver = Scripted::new(vec![Ok(vec![ip("93.184.216.34")]), Ok(vec![ip("127.0.0.1")])]);
        let kept = decide(
            &target("ok.example:443"),
            &policy(&[("ok.example", 443)]),
            &resolver,
            &[],
        )
        .context("allowed")?;
        assert_eq!(kept, vec![ip("93.184.216.34")]);
        assert_eq!(resolver.calls.get(), 1, "never resolves a second time");
        Ok(())
    }

    #[test]
    fn a_name_resolving_to_private_space_is_403_unless_an_ip_entry_names_it() -> anyhow::Result<()> {
        let answers = || Scripted::new(vec![Ok(vec![ip("10.0.0.5")])]);
        let v = decide(
            &target("reg.internal:443"),
            &policy(&[("reg.internal", 443)]),
            &answers(),
            &[],
        )
        .err()
        .context("expected a refusal")?;
        assert_eq!(v.status, Status::Forbidden);
        assert!(v.reason.contains("non-public"));
        let both = policy(&[("reg.internal", 443), ("10.0.0.0/8", 443)]);
        assert_eq!(
            decide(&target("reg.internal:443"), &both, &answers(), &[]).context("allowed")?,
            vec![ip("10.0.0.5")]
        );
        Ok(())
    }

    #[test]
    fn a_name_resolving_to_a_mapped_loopback_is_403() -> anyhow::Result<()> {
        let resolver = Scripted::new(vec![Ok(vec![ip("::ffff:127.0.0.1")])]);
        let v = decide(
            &target("ok.example:443"),
            &policy(&[("ok.example", 443)]),
            &resolver,
            &[],
        )
        .err()
        .context("expected a refusal")?;
        assert_eq!(v.status, Status::Forbidden);
        Ok(())
    }

    #[test]
    fn resolver_failure_is_502_and_timeout_is_504() -> anyhow::Result<()> {
        let p = policy(&[("ok.example", 443)]);
        let failed = Scripted::new(vec![Err(ResolveError::Failed)]);
        let timed_out = Scripted::new(vec![Err(ResolveError::TimedOut)]);
        assert_eq!(
            decide(&target("ok.example:443"), &p, &failed, &[])
                .err()
                .context("expected a refusal")?
                .status,
            Status::BadGateway
        );
        assert_eq!(
            decide(&target("ok.example:443"), &p, &timed_out, &[])
                .err()
                .context("expected a refusal")?
                .status,
            Status::GatewayTimeout
        );
        Ok(())
    }

    #[test]
    fn an_allowed_ip_literal_skips_the_resolver_and_still_passes_the_filter() -> anyhow::Result<()> {
        let resolver = Scripted::new(vec![]);
        let p = policy(&[("192.0.2.7", 443), ("127.0.0.1", 443)]);
        assert_eq!(
            decide(&target("192.0.2.7:443"), &p, &resolver, &[]).context("allowed")?,
            vec![ip("192.0.2.7")]
        );
        let v = decide(&target("127.0.0.1:443"), &p, &resolver, &[])
            .err()
            .context("expected a refusal")?;
        assert_eq!(v.status, Status::Forbidden);
        assert_eq!(resolver.calls.get(), 0);
        Ok(())
    }

    #[test]
    fn an_ipv6_literal_is_403_without_a_lookup() -> anyhow::Result<()> {
        let resolver = Scripted::new(vec![]);
        let p = policy(&[("0.0.0.0/0", 443)]);
        let v = decide(&target("[2001:db8::1]:443"), &p, &resolver, &[])
            .err()
            .context("expected a refusal")?;
        assert_eq!(v.status, Status::Forbidden);
        assert_eq!(resolver.calls.get(), 0);
        Ok(())
    }
}
