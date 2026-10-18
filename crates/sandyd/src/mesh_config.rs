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

use std::net::{IpAddr, SocketAddr};

use crate::host_registry::ExecutorAllowlist;

/// A mesh bind-address or allowlist environment variable failed to parse.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MeshConfigError {
    /// `SANDY_MESH_LISTEN`'s value is not a valid `host:port` socket address.
    #[error("SANDY_MESH_LISTEN is not a valid socket address: {0:?}")]
    InvalidListenAddr(String),
    /// One comma-separated entry in `SANDY_MESH_ALLOWLIST` is not a valid IP
    /// address.
    #[error("SANDY_MESH_ALLOWLIST entry is not a valid IP address: {0:?}")]
    InvalidAllowlistEntry(String),
}

/// Parse `SANDY_MESH_LISTEN`'s raw value: the host-client management
/// channel's mesh bind address. `None` (the env var unset) stays `None` —
/// `sandyd` does not bind a mesh listener at all in that case.
///
/// # Errors
/// [`MeshConfigError::InvalidListenAddr`] if set but not a valid `host:port`
/// socket address.
pub fn parse_mesh_listen_addr(value: Option<&str>) -> Result<Option<SocketAddr>, MeshConfigError> {
    let Some(value) = value else { return Ok(None) };
    value
        .parse()
        .map(Some)
        .map_err(|_| MeshConfigError::InvalidListenAddr(value.to_owned()))
}

/// Parse `SANDY_MESH_ALLOWLIST`'s raw value: a comma-separated list of IP
/// addresses permitted to register as executor hosts (D5 — the transport's
/// own peer identity, never the self-reported `host_id`). `None` (the env
/// var unset) is an empty allowlist, not an error here; the caller decides
/// whether an empty allowlist alongside a configured listener is itself a
/// misconfiguration (binding a listener nobody can ever pass).
///
/// # Errors
/// [`MeshConfigError::InvalidAllowlistEntry`] if any comma-separated entry is
/// not a valid IP address.
pub fn parse_mesh_allowlist(value: Option<&str>) -> Result<ExecutorAllowlist, MeshConfigError> {
    let Some(value) = value else {
        return Ok(ExecutorAllowlist::new([]));
    };
    let ips = value
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(|entry| {
            entry
                .parse::<IpAddr>()
                .map_err(|_| MeshConfigError::InvalidAllowlistEntry(entry.to_owned()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ExecutorAllowlist::new(ips))
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

    #[test]
    fn an_unset_allowlist_is_empty() -> anyhow::Result<()> {
        assert!(parse_mesh_allowlist(None)?.is_empty());
        Ok(())
    }

    #[test]
    fn a_valid_allowlist_parses_every_entry() -> anyhow::Result<()> {
        let allowlist = parse_mesh_allowlist(Some("100.64.0.7,100.64.0.9"))?;
        assert!(allowlist.permits("100.64.0.7".parse()?));
        assert!(allowlist.permits("100.64.0.9".parse()?));
        assert!(!allowlist.permits("100.64.0.10".parse()?));
        Ok(())
    }

    /// Adversarial: stray whitespace around a comma-separated entry (an easy
    /// operator typo in a config file) is trimmed, not treated as part of
    /// the address and refused.
    #[test]
    fn allowlist_entries_tolerate_surrounding_whitespace() -> anyhow::Result<()> {
        let allowlist = parse_mesh_allowlist(Some(" 100.64.0.7 , 100.64.0.9 "))?;
        assert!(allowlist.permits("100.64.0.7".parse()?));
        assert!(allowlist.permits("100.64.0.9".parse()?));
        Ok(())
    }

    #[test]
    fn an_invalid_allowlist_entry_is_refused_by_name() {
        assert_eq!(
            parse_mesh_allowlist(Some("100.64.0.7,not-an-ip")).err(),
            Some(MeshConfigError::InvalidAllowlistEntry("not-an-ip".to_owned()))
        );
    }

    /// Adversarial: a trailing comma (another easy config typo) produces an
    /// empty entry, which is skipped rather than refused as an invalid IP —
    /// the real entries before it must still parse.
    #[test]
    fn a_trailing_comma_is_tolerated() -> anyhow::Result<()> {
        let allowlist = parse_mesh_allowlist(Some("100.64.0.7,"))?;
        assert!(allowlist.permits("100.64.0.7".parse()?));
        Ok(())
    }
}
