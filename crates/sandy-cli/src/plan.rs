//! CLI `run` grammar and bundle desugaring (tier-1, pure).
//!
//! Parses the `run` subcommand's raw option strings into an owned [`JobPlan`],
//! from which a borrowed [`sandy::RunSpec`] is built for the backend. Keeping the
//! owned form here lets `supervisor` build the borrowed spec without threading
//! lifetimes through clap.
//!
//! Grammar (each option may repeat):
//! - `--mount HOST:GUEST[:ro]` → a [`sandy::Mount`]; the optional `:ro` suffix selects a read-only mount, otherwise
//!   read-write.
//! - `--secret NAME=@PATH` → a [`sandy::SecretRef`] whose bytes come from the host file `PATH`
//!   ([`sandy::SecretSource::File`]). The leading `@` marks a file source and is required.
//! - `--env KEY=VALUE` → a `(KEY, VALUE)` pair. Env is never a secret channel (INV-1).
//! - `--allow HOST:PORT` → one [`sandy::EgressRule`] in the [`sandy::AllowList`]; the egress boundary, not part of
//!   [`RunSpec`] (the supervisor applies it around the boot).
//! - `--cpu N`, `--mem MiB`, `--timeout SECS` → resource knobs.
//! - the trailing `-- CMD ARGS...` → the guest command.
//!
//! Bundle desugaring: the positional template name becomes [`JobPlan::template`].
//! When no trailing `-- CMD` is given the command is left empty, which means
//! "boot the template's default command". Any malformed token yields
//! [`sandy::PlanError::Invalid`] (process band 2) — the parser never returns a
//! partial plan.

use std::path::PathBuf;

use sandy::{AllowList, EgressRule, Grants, Mount, PlanError, RunSpec, SecretRef, SecretSource};

/// Default wall-clock timeout when `--timeout` is omitted (5 minutes). Picked as
/// a sane bound for an interactive foreground `run`; override with `--timeout`.
const DEFAULT_TIMEOUT_SECS: u32 = 300;

/// The raw `run` arguments as clap's derived subcommand struct produces them:
/// already-split option values (one string per occurrence) plus the trailing
/// command. This is the stable seam the parser binds to; the clap `Run` struct in
/// `main` converts into it.
#[derive(Debug, Clone, Default)]
pub struct RunArgs {
    /// The positional template name (flake attr / image).
    pub template: String,
    /// `--mount HOST:GUEST[:ro]` occurrences, verbatim.
    pub mounts: Vec<String>,
    /// `--secret NAME=@PATH` occurrences, verbatim.
    pub secrets: Vec<String>,
    /// `--env KEY=VALUE` occurrences, verbatim.
    pub env: Vec<String>,
    /// `--allow HOST:PORT` occurrences, verbatim.
    pub allow: Vec<String>,
    /// `--cpu N`.
    pub cpu: Option<u32>,
    /// `--mem MiB`.
    pub mem: Option<u32>,
    /// `--timeout SECS`.
    pub timeout: Option<u32>,
    /// The trailing `-- CMD ARGS...`, already split into argv.
    pub command: Vec<String>,
}

/// The parsed, owned form of a `run` request. A borrowed [`RunSpec`] is built from
/// it via [`JobPlan::as_run_spec`].
#[derive(Debug)]
pub struct JobPlan {
    /// The template (flake attr / image) to boot.
    pub template: String,
    /// The guest command; empty means "boot the template's default".
    pub command: Vec<String>,
    /// Host→guest bind mounts.
    pub mounts: Vec<Mount>,
    /// Secrets injected over the secret channel.
    pub secrets: Vec<SecretRef>,
    /// Extra environment variables (never secrets — INV-1).
    pub env: Vec<(String, String)>,
    /// The egress allow-list enforced around the boot (empty = deny-all on Linux).
    pub allow: AllowList,
    /// Optional vCPU count.
    pub cpu: Option<u32>,
    /// Optional memory budget in MiB.
    pub mem: Option<u32>,
    /// Wall-clock timeout in seconds.
    pub timeout_secs: u32,
    /// The trust tokens the run is granted.
    pub grants: Grants,
}

impl JobPlan {
    /// Borrow this plan as a [`RunSpec`] for the backend. The spec borrows the
    /// plan's owned fields, so it lives no longer than `&self`.
    #[must_use]
    pub fn as_run_spec(&self) -> RunSpec<'_> {
        RunSpec {
            template: &self.template,
            command: &self.command,
            mounts: &self.mounts,
            secrets: &self.secrets,
            env: &self.env,
            cpu: self.cpu,
            mem: self.mem,
            timeout_secs: self.timeout_secs,
            grants: &self.grants,
            // Foreground local run uses fd3 for the outcome, not a file (D2/ssh only).
            outcome_file: None,
        }
    }
}

/// Parse raw `run` arguments into a [`JobPlan`], desugaring the mount/secret/env
/// grammar and the trailing command.
///
/// # Errors
///
/// Returns [`PlanError::Invalid`] for any malformed token (bad `--mount`,
/// `--secret`, or `--env`), never a partial plan.
pub fn parse_run(args: RunArgs) -> Result<JobPlan, PlanError> {
    // Each list is parsed in full before the plan is constructed, so a malformed
    // token short-circuits with `?` and never yields a partial plan.
    let mounts = args
        .mounts
        .iter()
        .map(|raw| parse_mount(raw))
        .collect::<Result<Vec<_>, _>>()?;
    let secrets = args
        .secrets
        .iter()
        .map(|raw| parse_secret(raw))
        .collect::<Result<Vec<_>, _>>()?;
    let env = args
        .env
        .iter()
        .map(|raw| parse_env(raw))
        .collect::<Result<Vec<_>, _>>()?;
    let rules = args
        .allow
        .iter()
        .map(|raw| parse_allow(raw))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(JobPlan {
        template: args.template,
        command: args.command,
        mounts,
        secrets,
        env,
        allow: AllowList { rules },
        cpu: args.cpu,
        mem: args.mem,
        timeout_secs: args.timeout.unwrap_or(DEFAULT_TIMEOUT_SECS),
        // Least-privilege default: grant no trust tokens. Capability granting is
        // out of #22 scope — the detection/routing seam lands with the host work.
        grants: Grants {
            secrets: false,
            agent: false,
            shares: false,
        },
    })
}

/// Parse one `--mount HOST:GUEST[:ro]` token into a [`Mount`].
fn parse_mount(raw: &str) -> Result<Mount, PlanError> {
    let invalid = || PlanError::Invalid(format!("--mount `{raw}` must be HOST:GUEST[:ro]"));
    let mut parts = raw.split(':');
    let host = parts.next().filter(|s| !s.is_empty()).ok_or_else(invalid)?;
    let guest = parts.next().filter(|s| !s.is_empty()).ok_or_else(invalid)?;
    let ro = match (parts.next(), parts.next()) {
        (None, _) => false,
        (Some("ro"), None) => true,
        _ => return Err(invalid()),
    };
    Ok(Mount {
        host: PathBuf::from(host),
        guest: PathBuf::from(guest),
        ro,
    })
}

/// Parse one `--secret NAME=@PATH` token into a file-sourced [`SecretRef`].
fn parse_secret(raw: &str) -> Result<SecretRef, PlanError> {
    let invalid = || PlanError::Invalid(format!("--secret `{raw}` must be NAME=@PATH"));
    let (name, value) = raw.split_once('=').ok_or_else(invalid)?;
    let path = value.strip_prefix('@').ok_or_else(invalid)?;
    if name.is_empty() || path.is_empty() {
        return Err(invalid());
    }
    Ok(SecretRef {
        name: name.to_string(),
        source: SecretSource::File(PathBuf::from(path)),
    })
}

/// Parse one `--env KEY=VALUE` token into a `(key, value)` pair.
fn parse_env(raw: &str) -> Result<(String, String), PlanError> {
    let (key, value) = raw
        .split_once('=')
        .ok_or_else(|| PlanError::Invalid(format!("--env `{raw}` must be KEY=VALUE")))?;
    if key.is_empty() {
        return Err(PlanError::Invalid(format!("--env `{raw}` has an empty key")));
    }
    Ok((key.to_string(), value.to_string()))
}

/// Parse one `--allow HOST:PORT` token into an [`EgressRule`].
///
/// The port must be a decimal `u16` (1..=65535); host must be non-empty. A
/// missing `:`, empty host, or non-numeric / out-of-range port yields
/// [`PlanError::Invalid`] — the allow-list is never a partial plan.
fn parse_allow(raw: &str) -> Result<EgressRule, PlanError> {
    let invalid = || PlanError::Invalid(format!("--allow `{raw}` must be HOST:PORT"));
    // `rsplit_once` keeps a colon-bearing host (e.g. an IPv6 literal) intact: only
    // the final `:PORT` is split off, and the port must parse as a `u16`.
    let (host, port) = raw.rsplit_once(':').ok_or_else(invalid)?;
    if host.is_empty() {
        return Err(invalid());
    }
    let port: u16 = port.parse().map_err(|_| invalid())?;
    if port == 0 {
        // Port 0 fits a u16 but is not a routable TCP dport — reject it rather
        // than compile a dead `tcp dport 0 accept` rule that permits nothing.
        return Err(invalid());
    }
    Ok(EgressRule {
        host: host.to_string(),
        port,
    })
}

#[cfg(test)]
mod tests {
    use sandy::{PlanError, SecretSource};

    use super::{RunArgs, parse_run};

    /// `--allow github.com:443` desugars to one [`EgressRule`] in the allow-list.
    #[test]
    fn allow_host_port_parses_one_egress_rule() -> anyhow::Result<()> {
        let args = RunArgs {
            template: "demo".to_string(),
            allow: vec!["github.com:443".to_string()],
            ..RunArgs::default()
        };
        let plan = parse_run(args).map_err(|e| anyhow::anyhow!("parse_run: {e}"))?;
        assert_eq!(plan.allow.rules.len(), 1, "one --allow token is one rule");
        let rule = plan.allow.rules.first().expect("one rule parsed");
        assert_eq!(rule.host, "github.com");
        assert_eq!(rule.port, 443);
        Ok(())
    }

    /// Each malformed `--allow` token is rejected as an invalid plan (band 2),
    /// never folded into a partial allow-list.
    #[test]
    fn malformed_allow_is_invalid_plan() {
        for token in [
            "no-colon",
            ":443",
            "github.com:",
            "github.com:nope",
            "github.com:70000",
            "host:0",
        ] {
            let args = RunArgs {
                template: "demo".to_string(),
                allow: vec![token.to_string()],
                ..RunArgs::default()
            };
            assert!(
                matches!(parse_run(args), Err(PlanError::Invalid(_))),
                "a malformed --allow `{token}` must yield PlanError::Invalid"
            );
        }
    }

    /// `--mount HOST:GUEST:ro` desugars to a read-only [`Mount`] with the split
    /// host and guest paths.
    #[test]
    fn mount_with_ro_suffix_parses_read_only() -> anyhow::Result<()> {
        let args = RunArgs {
            template: "demo".to_string(),
            mounts: vec!["/h:/g:ro".to_string()],
            ..RunArgs::default()
        };
        let plan = parse_run(args).map_err(|e| anyhow::anyhow!("parse_run: {e}"))?;
        let mount = plan.mounts.first().expect("one mount parsed");
        assert_eq!(mount.host.to_string_lossy(), "/h");
        assert_eq!(mount.guest.to_string_lossy(), "/g");
        assert!(mount.ro, "the :ro suffix must select a read-only mount");
        Ok(())
    }

    /// `--mount HOST:GUEST` without the suffix desugars to a read-write mount.
    #[test]
    fn mount_without_ro_suffix_parses_read_write() -> anyhow::Result<()> {
        let args = RunArgs {
            template: "demo".to_string(),
            mounts: vec!["/h:/g".to_string()],
            ..RunArgs::default()
        };
        let plan = parse_run(args).map_err(|e| anyhow::anyhow!("parse_run: {e}"))?;
        let mount = plan.mounts.first().expect("one mount parsed");
        assert!(!mount.ro, "no suffix must default to read-write");
        Ok(())
    }

    /// `--secret NAME=@PATH` desugars to a file-sourced [`SecretRef`].
    #[test]
    fn secret_file_source_parses() -> anyhow::Result<()> {
        let args = RunArgs {
            template: "demo".to_string(),
            secrets: vec!["TOK=@/run/tok".to_string()],
            ..RunArgs::default()
        };
        let plan = parse_run(args).map_err(|e| anyhow::anyhow!("parse_run: {e}"))?;
        let secret = plan.secrets.first().expect("one secret parsed");
        assert_eq!(secret.name, "TOK");
        match &secret.source {
            SecretSource::File(path) => assert_eq!(path.to_string_lossy(), "/run/tok"),
            other => panic!("expected a file source, got {other:?}"),
        }
        Ok(())
    }

    /// `--env KEY=VALUE` desugars to a `(key, value)` pair.
    #[test]
    fn env_pair_parses() -> anyhow::Result<()> {
        let args = RunArgs {
            template: "demo".to_string(),
            env: vec!["K=V".to_string()],
            ..RunArgs::default()
        };
        let plan = parse_run(args).map_err(|e| anyhow::anyhow!("parse_run: {e}"))?;
        assert_eq!(plan.env.first(), Some(&("K".to_string(), "V".to_string())));
        Ok(())
    }

    /// The trailing `-- CMD ARGS...` becomes the guest command argv.
    #[test]
    fn trailing_command_parses() -> anyhow::Result<()> {
        let args = RunArgs {
            template: "demo".to_string(),
            command: vec!["echo".to_string(), "hi".to_string()],
            ..RunArgs::default()
        };
        let plan = parse_run(args).map_err(|e| anyhow::anyhow!("parse_run: {e}"))?;
        assert_eq!(plan.command, vec!["echo".to_string(), "hi".to_string()]);
        Ok(())
    }

    /// A `--mount` with no `HOST:GUEST` separator is rejected as an invalid plan
    /// (band 2), never silently dropped into a partial plan.
    #[test]
    fn malformed_mount_is_invalid_plan() {
        let args = RunArgs {
            template: "demo".to_string(),
            mounts: vec!["no-colon-here".to_string()],
            ..RunArgs::default()
        };
        assert!(
            matches!(parse_run(args), Err(PlanError::Invalid(_))),
            "a malformed --mount must yield PlanError::Invalid"
        );
    }

    /// A `--secret` missing the `=@` file marker is rejected as an invalid plan.
    #[test]
    fn malformed_secret_is_invalid_plan() {
        let args = RunArgs {
            template: "demo".to_string(),
            secrets: vec!["TOKEN-with-no-source".to_string()],
            ..RunArgs::default()
        };
        assert!(
            matches!(parse_run(args), Err(PlanError::Invalid(_))),
            "a malformed --secret must yield PlanError::Invalid"
        );
    }
}
