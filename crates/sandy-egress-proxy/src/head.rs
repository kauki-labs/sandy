//! Parse a CONNECT request head into a classified [`Target`].
//!
//! The host grammar is strict on purpose: every non-canonical numeric form
//! (`127.1`, `0x7f.0.0.1`, `2130706433`, `010.0.0.1`) is refused before any
//! resolver sees it.

use std::{
    net::{Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

use crate::verdict::{Status, Verdict};

/// Largest request head the proxy reads.
pub const MAX_HEAD: usize = 8 * 1024;

/// A classified CONNECT host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Host {
    /// A strict dotted-decimal IPv4 literal.
    V4(Ipv4Addr),
    /// A bracketed IPv6 literal; v1 refuses it.
    V6(Ipv6Addr),
    /// A normalised DNS name.
    Name(String),
}

/// The destination of one CONNECT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// The classified host.
    pub host: Host,
    /// The TCP port, `1..=65535`.
    pub port: u16,
}

impl Target {
    /// `host:port` for logs and reasons. Only a validated target is rendered.
    #[must_use]
    pub fn label(&self) -> String {
        match &self.host {
            Host::V4(ip) => format!("{ip}:{}", self.port),
            Host::V6(ip) => format!("[{ip}]:{}", self.port),
            Host::Name(name) => format!("{name}:{}", self.port),
        }
    }
}

/// Progress of reading a request head from a growing buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeadRead {
    /// No `CRLFCRLF` yet and the cap is not reached.
    Incomplete,
    /// The head ends at this offset (one past the `CRLFCRLF`).
    Complete(usize),
    /// More than [`MAX_HEAD`] bytes without a `CRLFCRLF`.
    TooLarge,
}

/// Locate the end of the request head in `buf`.
#[must_use]
pub fn read_head(buf: &[u8]) -> HeadRead {
    let window = &buf[..buf.len().min(MAX_HEAD)];
    match window.windows(4).position(|w| w == b"\r\n\r\n") {
        Some(at) => HeadRead::Complete(at + 4),
        None if buf.len() >= MAX_HEAD => HeadRead::TooLarge,
        None => HeadRead::Incomplete,
    }
}

fn bad(reason: &str) -> Verdict {
    Verdict::new(Status::BadRequest, format!("malformed: {reason}"))
}

/// Parse a complete request head (up to and including `CRLFCRLF`).
///
/// # Errors
/// `405` for a method other than `CONNECT`; `400` for a malformed request
/// line, version, port, or host.
pub fn parse_head(head: &[u8]) -> Result<Target, Verdict> {
    let line_end = head
        .windows(2)
        .position(|w| w == b"\r\n")
        .ok_or_else(|| bad("no request line"))?;
    let line = std::str::from_utf8(&head[..line_end]).map_err(|_| bad("non-UTF-8 request line"))?;
    let mut parts = line.split(' ');
    let (Some(method), Some(authority), Some(version), None) = (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(bad("request line"));
    };
    if method != "CONNECT" {
        return Err(Verdict::new(Status::MethodNotAllowed, "only CONNECT is supported"));
    }
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err(bad("HTTP version"));
    }
    parse_authority(authority)
}

fn parse_authority(authority: &str) -> Result<Target, Verdict> {
    let (host, port) = authority.rsplit_once(':').ok_or_else(|| bad("missing port"))?;
    let port = parse_port(port)?;
    let host = if let Some(inner) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        Host::V6(Ipv6Addr::from_str(inner).map_err(|_| bad("IPv6 literal"))?)
    } else {
        classify_host(host).ok_or_else(|| bad("host"))?
    };
    Ok(Target { host, port })
}

fn parse_port(port: &str) -> Result<u16, Verdict> {
    if port.is_empty() || port.len() > 5 || !port.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad("port"));
    }
    match port.parse::<u16>() {
        Ok(p) if p != 0 => Ok(p),
        _ => Err(bad("port")),
    }
}

/// Classify an unbracketed host as an IPv4 literal or a name.
///
/// Returns `None` for anything else. Also used to normalise allow-list names.
#[must_use]
pub fn classify_host(host: &str) -> Option<Host> {
    if let Ok(ip) = Ipv4Addr::from_str(host) {
        return Some(Host::V4(ip));
    }
    normalise_name(host).map(Host::Name)
}

fn normalise_name(host: &str) -> Option<String> {
    if !host.is_ascii() {
        return None;
    }
    let lowered = host.to_ascii_lowercase();
    let name = lowered.strip_suffix('.').unwrap_or(&lowered);
    if name.is_empty() || name.len() > 253 {
        return None;
    }
    let mut last = "";
    for label in name.split('.') {
        let ok = !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if !ok {
            return None;
        }
        last = label;
    }
    if last.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(name.to_owned())
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    fn req(line: &str) -> Vec<u8> {
        format!("{line}\r\nHost: ignored\r\n\r\n").into_bytes()
    }

    fn name(host: &str, port: u16) -> Target {
        Target {
            host: Host::Name(host.to_owned()),
            port,
        }
    }

    #[test]
    fn a_connect_to_a_name_parses_and_lowercases_it() -> anyhow::Result<()> {
        let t = parse_head(&req("CONNECT GitHub.COM.:443 HTTP/1.1")).map_err(|v| anyhow::anyhow!("{v}"))?;
        assert_eq!(t, name("github.com", 443));
        Ok(())
    }

    #[test]
    fn http_one_zero_is_accepted() {
        assert!(parse_head(&req("CONNECT a.example:80 HTTP/1.0")).is_ok());
    }

    #[test]
    fn a_strict_ipv4_literal_is_an_ip_target() -> anyhow::Result<()> {
        let t = parse_head(&req("CONNECT 192.0.2.7:8443 HTTP/1.1")).map_err(|v| anyhow::anyhow!("{v}"))?;
        assert_eq!(
            t,
            Target {
                host: Host::V4(Ipv4Addr::new(192, 0, 2, 7)),
                port: 8443
            }
        );
        Ok(())
    }

    #[test]
    fn a_bracketed_ipv6_literal_classifies_as_v6() -> anyhow::Result<()> {
        let t = parse_head(&req("CONNECT [2001:db8::1]:443 HTTP/1.1")).map_err(|v| anyhow::anyhow!("{v}"))?;
        assert!(matches!(t.host, Host::V6(_)));
        Ok(())
    }

    #[rstest]
    #[case("GET http://example.com/ HTTP/1.1")]
    #[case("POST example.com:443 HTTP/1.1")]
    #[case("connect example.com:443 HTTP/1.1")]
    fn any_other_method_is_405(#[case] line: &str) {
        let v = parse_head(&req(line)).unwrap_err();
        assert_eq!(v.status, Status::MethodNotAllowed);
    }

    #[rstest]
    #[case::no_port("CONNECT example.com HTTP/1.1")]
    #[case::empty_port("CONNECT example.com: HTTP/1.1")]
    #[case::port_zero("CONNECT example.com:0 HTTP/1.1")]
    #[case::port_too_big("CONNECT example.com:65536 HTTP/1.1")]
    #[case::port_signed("CONNECT example.com:+443 HTTP/1.1")]
    #[case::port_hex("CONNECT example.com:0x1bb HTTP/1.1")]
    #[case::port_long("CONNECT example.com:000443 HTTP/1.1")]
    #[case::bad_version("CONNECT example.com:443 HTTP/2")]
    #[case::no_version("CONNECT example.com:443")]
    #[case::extra_token("CONNECT example.com:443 HTTP/1.1 x")]
    #[case::double_space("CONNECT  example.com:443 HTTP/1.1")]
    fn a_malformed_line_or_port_is_400(#[case] line: &str) {
        let v = parse_head(&req(line)).unwrap_err();
        assert_eq!(v.status, Status::BadRequest, "{line}");
    }

    #[rstest]
    #[case::short_form("127.1")]
    #[case::hex("0x7f.0.0.1")]
    #[case::decimal("2130706433")]
    #[case::octal("010.0.0.1")]
    #[case::leading_zero("127.000.000.001")]
    #[case::too_many_parts("1.2.3.4.5")]
    #[case::numeric_tld("example.123")]
    #[case::userinfo("user@example.com")]
    #[case::percent("exa%6dple.com")]
    #[case::nul("exa\0mple.com")]
    #[case::non_ascii("exämple.com")]
    #[case::underscore("a_b.example")]
    #[case::leading_hyphen("-a.example")]
    #[case::trailing_hyphen("a-.example")]
    #[case::empty_label("a..example")]
    #[case::leading_dot(".example")]
    #[case::double_trailing_dot("example..")]
    #[case::empty("")]
    #[case::bad_ipv6("[not-an-ip]")]
    #[case::unbracketed_ipv6("2001:db8::1")]
    fn a_host_outside_the_grammar_is_400(#[case] host: &str) {
        let v = parse_head(&req(&format!("CONNECT {host}:443 HTTP/1.1"))).unwrap_err();
        assert_eq!(v.status, Status::BadRequest, "{host:?}");
        assert!(!v.reason.contains(host) || host.is_empty(), "no echo");
    }

    #[test]
    fn label_and_name_length_limits_are_enforced() {
        let label63 = "a".repeat(63);
        assert!(classify_host(&format!("{label63}.example")).is_some());
        assert!(classify_host(&format!("{}.example", "a".repeat(64))).is_none());
        let name253 = format!("{0}.{0}.{0}.{1}", label63, "a".repeat(61));
        assert_eq!(name253.len(), 253);
        assert!(classify_host(&name253).is_some());
        assert!(classify_host(&format!("{name253}a")).is_none());
    }

    #[test]
    fn read_head_finds_the_end_and_reports_the_offset() {
        let buf = b"CONNECT a.example:443 HTTP/1.1\r\n\r\nextra";
        assert_eq!(read_head(buf), HeadRead::Complete(buf.len() - 5));
        assert_eq!(read_head(b"CONNECT a.exa"), HeadRead::Incomplete);
    }

    #[test]
    fn read_head_caps_at_eight_kib_without_a_terminator() {
        assert_eq!(read_head(&vec![b'a'; MAX_HEAD]), HeadRead::TooLarge);
        assert_eq!(read_head(&vec![b'a'; MAX_HEAD - 1]), HeadRead::Incomplete);
    }

    #[test]
    fn a_head_whose_terminator_lies_past_the_cap_is_too_large() {
        let mut buf = vec![b'a'; MAX_HEAD];
        buf.extend_from_slice(b"\r\n\r\n");
        assert_eq!(read_head(&buf), HeadRead::TooLarge);
    }
}
