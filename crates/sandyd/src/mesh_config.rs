//! Mesh bind-address and allowlist configuration (#291): `sandyd` learns
//! where to bind its mesh-facing listeners from environment variables, never
//! a hardcoded address (D5: mesh-only, a deployer's explicit per-node
//! choice, never `0.0.0.0`). Pure parsing logic, unit-testable without
//! touching the real process environment — a caller reads the actual env var
//! once and hands the raw value to the functions here.
//!
//! Unset is the default and still fully supported: `sandyd` with no mesh env
//! vars set stays local-only, exactly today's behavior. M2 cross-machine
//! dispatch is additive, not a requirement to run `sandyd` at all.
//!
//! CAUTION: a loopback listen address (`127.0.0.1:PORT`) with a
//! `127.0.0.1`-only allowlist is a valid configuration this module accepts,
//! but it authenticates nothing more than "some process on this machine" —
//! every local user can reach it. That may be fine for local development,
//! but production deployments must set the real mesh address (D5), not
//! loopback, for the allowlist to mean anything.

use std::net::{IpAddr, SocketAddr};

use sandy_conn::Fingerprint;

use crate::host_registry::ExecutorAllowlist;

/// A mesh bind-address or allowlist environment variable failed to parse.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MeshConfigError {
    /// `SANDY_MESH_LISTEN`'s value is not a valid `host:port` socket address.
    #[error("SANDY_MESH_LISTEN is not a valid socket address: {0:?}")]
    InvalidListenAddr(String),
    /// `SANDY_MESH_LISTEN`'s value is an unspecified address (`0.0.0.0` or
    /// `::`), which binds every interface rather than the mesh address alone
    /// (D5: mesh-address-only). A wildcard bind would expose the pre-auth
    /// surface (the `Register` timeout window, the uncapped per-connection
    /// spawn, the frame parser) to every network the host is on, not just
    /// the mesh.
    #[error("SANDY_MESH_LISTEN ({0:?}) is an unspecified address (0.0.0.0/::); D5 requires a specific mesh address")]
    UnspecifiedListenAddr(String),
    /// One comma-separated entry in `SANDY_MESH_ALLOWLIST` is not `ip=fingerprint`
    /// (decision 20: pinned per-host keys, not a bare IP — this format
    /// changed when the mesh tier grew mutual TLS. A pre-#495 bare-IP entry
    /// hits this, not [`Self::InvalidAllowlistEntryIp`]/
    /// [`Self::InvalidAllowlistEntryFingerprint`] below, since it never even
    /// contains the required `=` separator: name the migration outright
    /// rather than mis-attribute it to a malformed IP or fingerprint.
    #[error(
        "SANDY_MESH_ALLOWLIST entry {0:?} is not ip=fingerprint (decision 20: the allowlist now pins a per-host key \
         fingerprint alongside each IP, not a bare IP list — mint one with `sandy mesh key generate`/`sandy mesh key \
         fingerprint`)"
    )]
    MissingFingerprintSeparator(String),
    /// One `ip=fingerprint` entry's `ip` half is not a valid IP address.
    #[error("SANDY_MESH_ALLOWLIST entry's IP is not valid: {0:?}")]
    InvalidAllowlistEntryIp(String),
    /// One `ip=fingerprint` entry's `fingerprint` half is not a 64-char hex
    /// SHA-256 digest.
    #[error("SANDY_MESH_ALLOWLIST entry's fingerprint is not valid: {0:?}")]
    InvalidAllowlistEntryFingerprint(String),
}

/// Parse `SANDY_MESH_LISTEN`'s raw value: the host-executor management
/// channel's mesh bind address. `None` (the env var unset) stays `None` —
/// `sandyd` does not bind a mesh listener at all in that case.
///
/// Shared by every mesh listener this daemon binds (#290's agent-link accept
/// included, once wired) — the unspecified-address refusal belongs here, not
/// duplicated per caller, so no mesh listener can land without it.
///
/// # Errors
/// [`MeshConfigError::InvalidListenAddr`] if set but not a valid `host:port`
/// socket address; [`MeshConfigError::UnspecifiedListenAddr`] if it parses
/// but names `0.0.0.0` or `::` (every interface, not the mesh alone).
pub fn parse_mesh_listen_addr(value: Option<&str>) -> Result<Option<SocketAddr>, MeshConfigError> {
    let Some(value) = value else { return Ok(None) };
    let addr: SocketAddr = value
        .parse()
        .map_err(|_| MeshConfigError::InvalidListenAddr(value.to_owned()))?;
    // to_canonical() unmaps an IPv4-mapped IPv6 address (`::ffff:0.0.0.0`)
    // down to plain IPv4 (`0.0.0.0`) before the check — is_unspecified()
    // alone misses that form, and under Linux dual-stack (bindv6only=0) it
    // binds IPv4 INADDR_ANY, every interface, same D5 hole as 0.0.0.0/::
    // directly. Same canonicalization ExecutorAllowlist already applies.
    if addr.ip().to_canonical().is_unspecified() {
        return Err(MeshConfigError::UnspecifiedListenAddr(value.to_owned()));
    }
    Ok(Some(addr))
}

/// Parse `SANDY_MESH_ALLOWLIST`'s raw value: a comma-separated list of
/// `ip=fingerprint` pairs permitted to register as executor hosts (decision
/// 20 — the transport's own peer identity AND its pinned mutual-TLS
/// certificate fingerprint, never the self-reported `host_id`). `None` (the
/// env var unset) is an empty allowlist, not an error here; the caller
/// decides whether an empty allowlist alongside a configured listener is
/// itself a misconfiguration (binding a listener nobody can ever pass).
///
/// # Errors
/// [`MeshConfigError::MissingFingerprintSeparator`] if an entry has no `=`
/// separator (the pre-decision-20 bare-IP format); the `Ip`/`Fingerprint`
/// variants if either half of a well-separated entry doesn't parse.
pub fn parse_mesh_allowlist(value: Option<&str>) -> Result<ExecutorAllowlist, MeshConfigError> {
    let Some(value) = value else {
        return Ok(ExecutorAllowlist::new([]));
    };
    let pairs = value
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(|entry| {
            let (ip_part, fp_part) = entry
                .split_once('=')
                .ok_or_else(|| MeshConfigError::MissingFingerprintSeparator(entry.to_owned()))?;
            let ip = ip_part
                .trim()
                .parse::<IpAddr>()
                .map_err(|_| MeshConfigError::InvalidAllowlistEntryIp(ip_part.to_owned()))?;
            let fingerprint = Fingerprint::from_hex(fp_part.trim())
                .map_err(|_| MeshConfigError::InvalidAllowlistEntryFingerprint(fp_part.to_owned()))?;
            Ok((ip, fingerprint))
        })
        .collect::<Result<Vec<_>, MeshConfigError>>()?;
    Ok(ExecutorAllowlist::new(pairs))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unset_listen_addr_is_none() {
        assert_eq!(parse_mesh_listen_addr(None), Ok(None));
    }

    #[test]
    fn a_valid_listen_addr_parses() -> anyhow::Result<()> {
        assert_eq!(
            parse_mesh_listen_addr(Some("100.64.0.1:7700")),
            Ok(Some("100.64.0.1:7700".parse()?))
        );
        Ok(())
    }

    #[test]
    fn an_invalid_listen_addr_is_refused_by_name() {
        assert_eq!(
            parse_mesh_listen_addr(Some("not-an-address")),
            Err(MeshConfigError::InvalidListenAddr("not-an-address".to_owned()))
        );
    }

    /// Adversarial: a bare IP with no port is a common mistake (host_conn's
    /// own address always needs a port), not silently accepted as "any port".
    #[test]
    fn a_listen_addr_with_no_port_is_refused() {
        assert_eq!(
            parse_mesh_listen_addr(Some("100.64.0.1")),
            Err(MeshConfigError::InvalidListenAddr("100.64.0.1".to_owned()))
        );
    }

    /// Adversarial (D5, sandy-73): a wildcard bind exposes the pre-auth
    /// surface off-mesh, on every interface the host has — IPv4 and IPv6
    /// unspecified forms both refused, not just one.
    #[test]
    fn an_unspecified_listen_addr_is_refused_on_both_ip_versions() {
        assert_eq!(
            parse_mesh_listen_addr(Some("0.0.0.0:7700")),
            Err(MeshConfigError::UnspecifiedListenAddr("0.0.0.0:7700".to_owned()))
        );
        assert_eq!(
            parse_mesh_listen_addr(Some("[::]:7700")),
            Err(MeshConfigError::UnspecifiedListenAddr("[::]:7700".to_owned()))
        );
    }

    /// Adversarial (sandy-73): the IPv4-mapped unspecified form
    /// (`::ffff:0.0.0.0`) bypasses a bare `is_unspecified()` check — under
    /// Linux dual-stack (bindv6only=0) it binds IPv4 `INADDR_ANY`, every
    /// interface, the same D5 hole as `0.0.0.0` directly. Canonicalizing
    /// before the check closes it.
    #[test]
    fn an_ipv4_mapped_unspecified_listen_addr_is_refused() {
        assert_eq!(
            parse_mesh_listen_addr(Some("[::ffff:0.0.0.0]:7700")),
            Err(MeshConfigError::UnspecifiedListenAddr(
                "[::ffff:0.0.0.0]:7700".to_owned()
            ))
        );
    }

    fn fp_a() -> Fingerprint {
        Fingerprint::from_hex(&"aa".repeat(32)).expect("64-char hex literal")
    }

    fn fp_b() -> Fingerprint {
        Fingerprint::from_hex(&"bb".repeat(32)).expect("64-char hex literal")
    }

    #[test]
    fn an_unset_allowlist_is_empty() -> anyhow::Result<()> {
        assert!(parse_mesh_allowlist(None)?.is_empty());
        Ok(())
    }

    #[test]
    fn a_valid_allowlist_parses_every_entry() -> anyhow::Result<()> {
        let allowlist = parse_mesh_allowlist(Some(&format!(
            "100.64.0.7={},100.64.0.9={}",
            fp_a().to_hex(),
            fp_b().to_hex()
        )))?;
        assert!(allowlist.permits("100.64.0.7".parse()?, fp_a()));
        assert!(allowlist.permits("100.64.0.9".parse()?, fp_b()));
        assert!(!allowlist.permits("100.64.0.10".parse()?, fp_a()));
        Ok(())
    }

    /// Adversarial: stray whitespace around a comma-separated entry (an easy
    /// operator typo in a config file) is trimmed, not treated as part of
    /// the address and refused.
    #[test]
    fn allowlist_entries_tolerate_surrounding_whitespace() -> anyhow::Result<()> {
        let allowlist = parse_mesh_allowlist(Some(&format!(
            " 100.64.0.7 = {} , 100.64.0.9 = {} ",
            fp_a().to_hex(),
            fp_b().to_hex()
        )))?;
        assert!(allowlist.permits("100.64.0.7".parse()?, fp_a()));
        assert!(allowlist.permits("100.64.0.9".parse()?, fp_b()));
        Ok(())
    }

    #[test]
    fn an_invalid_allowlist_entry_ip_is_refused_by_name() {
        assert_eq!(
            parse_mesh_allowlist(Some(&format!("not-an-ip={}", fp_a().to_hex()))).err(),
            Some(MeshConfigError::InvalidAllowlistEntryIp("not-an-ip".to_owned()))
        );
    }

    #[test]
    fn an_invalid_allowlist_entry_fingerprint_is_refused_by_name() {
        assert_eq!(
            parse_mesh_allowlist(Some("100.64.0.7=not-a-fingerprint")).err(),
            Some(MeshConfigError::InvalidAllowlistEntryFingerprint(
                "not-a-fingerprint".to_owned()
            ))
        );
    }

    /// Migration (decision 20): a pre-#495 bare-IP entry (no `=fingerprint`)
    /// is refused by a dedicated, named error, not folded into "invalid IP"
    /// — an operator upgrading from the old format needs to be told it's a
    /// migration, not a typo.
    #[test]
    fn a_bare_ip_entry_with_no_fingerprint_names_the_migration() {
        assert_eq!(
            parse_mesh_allowlist(Some("100.64.0.7")).err(),
            Some(MeshConfigError::MissingFingerprintSeparator("100.64.0.7".to_owned()))
        );
    }

    /// Adversarial: a trailing comma (another easy config typo) produces an
    /// empty entry, which is skipped rather than refused — the real entry
    /// before it must still parse.
    #[test]
    fn a_trailing_comma_is_tolerated() -> anyhow::Result<()> {
        let allowlist = parse_mesh_allowlist(Some(&format!("100.64.0.7={},", fp_a().to_hex())))?;
        assert!(allowlist.permits("100.64.0.7".parse()?, fp_a()));
        Ok(())
    }

    /// Adversarial (I-20): CIDR notation is not a single host IP, so it must
    /// be refused by name, not silently truncated to its address part or
    /// mistaken for a plain `IpAddr` — fail-closed, same as any other
    /// unparseable entry.
    #[test]
    fn a_cidr_entry_is_refused_not_mistaken_for_a_host() {
        assert_eq!(
            parse_mesh_allowlist(Some(&format!("100.64.0.0/24={}", fp_a().to_hex()))).err(),
            Some(MeshConfigError::InvalidAllowlistEntryIp("100.64.0.0/24".to_owned()))
        );
    }
}
