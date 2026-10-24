//! Host-executor runtime config (#288): where to find the orchestrator, which
//! `host_id` to register as, and which binary to launch for the agent — from
//! environment variables, never a hardcoded value (same discipline as
//! `sandyd`'s own mesh bind-address config, #291). Pure parsing, unit
//! testable without touching the real process environment: a caller reads
//! the actual env vars once and hands the raw values to
//! [`parse_executor_config`].
//!
//! All three are required, with no guessed default: an unset orchestrator
//! address or host id is a misconfiguration to report, never silently
//! defaulted to something that would fail in a more confusing way later
//! (dialing `127.0.0.1`, registering as an empty-string host id).

use std::{net::SocketAddr, path::PathBuf};

/// A host-executor config environment variable is missing or fails to parse.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ExecutorConfigError {
    /// `SANDY_HOST_EXECUTOR_ORCHESTRATOR` is unset.
    #[error("SANDY_HOST_EXECUTOR_ORCHESTRATOR is required (the orchestrator's mesh host:port)")]
    MissingOrchestrator,
    /// `SANDY_HOST_EXECUTOR_ORCHESTRATOR` is set but not a valid `host:port`
    /// socket address.
    #[error("SANDY_HOST_EXECUTOR_ORCHESTRATOR is not a valid socket address: {0:?}")]
    InvalidOrchestrator(String),
    /// `SANDY_HOST_EXECUTOR_ID` is unset or empty.
    #[error("SANDY_HOST_EXECUTOR_ID is required and must be non-empty")]
    MissingHostId,
    /// `SANDY_AGENT_PATH` is unset or empty.
    #[error("SANDY_AGENT_PATH is required (the path to the sandy-agent binary)")]
    MissingAgentPath,
}

/// This host-executor's resolved runtime configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutorConfig {
    /// The orchestrator's mesh address to dial for `Register`/`Dispatch`.
    pub orchestrator: SocketAddr,
    /// The self-reported `host_id` this instance registers as — bookkeeping
    /// only, never the authorization boundary (decision 12: that's the
    /// transport's own peer identity, checked orchestrator-side).
    pub host_id: String,
    /// The `sandy-agent` binary this host-executor launches for each dispatch.
    pub agent_path: PathBuf,
}

/// Parse this host-executor's config from the raw values of
/// `SANDY_HOST_EXECUTOR_ORCHESTRATOR`, `SANDY_HOST_EXECUTOR_ID`, and
/// `SANDY_AGENT_PATH` (in that order), as a caller would read them from
/// `std::env::var`.
///
/// `agent_path` is not checked for existence here — that's a real-filesystem
/// concern this pure parsing function doesn't touch; a missing or
/// non-executable binary surfaces when the main loop actually tries to spawn
/// it for a dispatch.
///
/// # Errors
/// See [`ExecutorConfigError`]'s variants: each of the three inputs is
/// required, with its own named failure, never a silently guessed default.
pub fn parse_executor_config(
    orchestrator: Option<&str>,
    host_id: Option<&str>,
    agent_path: Option<&str>,
) -> Result<ExecutorConfig, ExecutorConfigError> {
    let orchestrator_raw = orchestrator.ok_or(ExecutorConfigError::MissingOrchestrator)?;
    let orchestrator = orchestrator_raw
        .parse()
        .map_err(|_| ExecutorConfigError::InvalidOrchestrator(orchestrator_raw.to_owned()))?;
    let host_id = host_id
        .filter(|v| !v.is_empty())
        .ok_or(ExecutorConfigError::MissingHostId)?
        .to_owned();
    let agent_path = agent_path
        .filter(|v| !v.is_empty())
        .ok_or(ExecutorConfigError::MissingAgentPath)?;
    Ok(ExecutorConfig {
        orchestrator,
        host_id,
        agent_path: PathBuf::from(agent_path),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fully_configured_set_parses() -> anyhow::Result<()> {
        let config = parse_executor_config(
            Some("203.0.113.10:7700"),
            Some("remote-host"),
            Some("/usr/bin/sandy-agent"),
        )?;
        assert_eq!(
            config,
            ExecutorConfig {
                orchestrator: "203.0.113.10:7700".parse()?,
                host_id: "remote-host".to_owned(),
                agent_path: PathBuf::from("/usr/bin/sandy-agent"),
            }
        );
        Ok(())
    }

    #[test]
    fn a_missing_orchestrator_is_refused_by_name() {
        assert_eq!(
            parse_executor_config(None, Some("remote-host"), Some("/usr/bin/sandy-agent")),
            Err(ExecutorConfigError::MissingOrchestrator)
        );
    }

    #[test]
    fn an_invalid_orchestrator_is_refused_by_name() {
        assert_eq!(
            parse_executor_config(
                Some("not-an-address"),
                Some("remote-host"),
                Some("/usr/bin/sandy-agent")
            ),
            Err(ExecutorConfigError::InvalidOrchestrator("not-an-address".to_owned()))
        );
    }

    /// Adversarial: a bare IP with no port is a common mistake, not silently
    /// accepted as "any port".
    #[test]
    fn an_orchestrator_with_no_port_is_refused() {
        assert_eq!(
            parse_executor_config(Some("203.0.113.10"), Some("remote-host"), Some("/usr/bin/sandy-agent")),
            Err(ExecutorConfigError::InvalidOrchestrator("203.0.113.10".to_owned()))
        );
    }

    #[test]
    fn a_missing_host_id_is_refused_by_name() {
        assert_eq!(
            parse_executor_config(Some("203.0.113.10:7700"), None, Some("/usr/bin/sandy-agent")),
            Err(ExecutorConfigError::MissingHostId)
        );
    }

    #[test]
    fn an_empty_host_id_is_refused_same_as_missing() {
        assert_eq!(
            parse_executor_config(Some("203.0.113.10:7700"), Some(""), Some("/usr/bin/sandy-agent")),
            Err(ExecutorConfigError::MissingHostId)
        );
    }

    #[test]
    fn a_missing_agent_path_is_refused_by_name() {
        assert_eq!(
            parse_executor_config(Some("203.0.113.10:7700"), Some("remote-host"), None),
            Err(ExecutorConfigError::MissingAgentPath)
        );
    }
}
