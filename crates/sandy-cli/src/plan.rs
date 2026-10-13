//! CLI `run` grammar and bundle desugaring (tier-1, pure).
//!
//! Parses the `run` subcommand's raw option strings into an owned [`JobPlan`],
//! from which a borrowed [`sandy::RunSpec`] is built for the backend. Keeping the
//! owned form here lets `supervisor` build the borrowed spec without threading
//! lifetimes through clap.
//!
//! Grammar (each option may repeat):
//! - `--input HOST:NAME` → a [`sandy::Input`]; the host file/dir `HOST` appears read-only at `/run/sandy/inputs/NAME`
//!   in-guest.
//! - `--out NAME:DEST` → a [`sandy::Output`]; the guest writes under `/run/sandy/outputs/NAME`, collected to the host
//!   path `DEST` at teardown.
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

use sandy::{AllowList, EgressRule, Grants, Input, Output, PlanError, RunSpec, SecretRef, SecretSource};

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
    /// `--input HOST:NAME` occurrences, verbatim.
    pub inputs: Vec<String>,
    /// `--out NAME:DEST` occurrences, verbatim.
    pub outputs: Vec<String>,
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
    /// Read-only inputs staged at `/run/sandy/inputs/<name>` in-guest.
    pub inputs: Vec<Input>,
    /// Writable outputs collected from `/run/sandy/outputs/<name>` at teardown.
    pub outputs: Vec<Output>,
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
    /// `Some(dir)` makes the backend stage secrets into, and share the guest
    /// secret mount from, this caller-owned directory (see [`RunSpec::secret_dir`]).
    /// Set by the credential bracket for refresh re-delivery (#49); `None` for an
    /// ordinary run. Not a CLI option, the supervisor fills it.
    pub secret_dir: Option<PathBuf>,
}

impl JobPlan {
    /// Borrow this plan as a [`RunSpec`] for the backend. The spec borrows the
    /// plan's owned fields, so it lives no longer than `&self`.
    #[must_use]
    pub fn as_run_spec(&self) -> RunSpec<'_> {
        RunSpec {
            template: &self.template,
            command: &self.command,
            inputs: &self.inputs,
            outputs: &self.outputs,
            secrets: &self.secrets,
            env: &self.env,
            cpu: self.cpu,
            mem: self.mem,
            timeout_secs: self.timeout_secs,
            grants: &self.grants,
            // Foreground local run uses fd3 for the outcome, not a file (D2/ssh only).
            outcome_file: None,
            secret_dir: self.secret_dir.as_deref(),
        }
    }
}

/// Parse raw `run` arguments into a [`JobPlan`], desugaring the input/secret/env
/// grammar and the trailing command.
///
/// # Errors
///
/// Returns [`PlanError::Invalid`] for any malformed token (bad `--input`, `--out`,
/// `--secret`, or `--env`), never a partial plan.
pub fn parse_run(args: RunArgs) -> Result<JobPlan, PlanError> {
    // Each list is parsed in full before the plan is constructed, so a malformed
    // token short-circuits with `?` and never yields a partial plan.
    let inputs = args
        .inputs
        .iter()
        .map(|raw| parse_input(raw))
        .collect::<Result<Vec<_>, _>>()?;
    let outputs = args
        .outputs
        .iter()
        .map(|raw| parse_output(raw))
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
        inputs,
        outputs,
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
        secret_dir: None,
    })
}

/// Parse one `--input HOST:NAME` token into an [`Input`]: the host path `HOST`
/// (a file or directory) appears read-only at `/run/sandy/inputs/NAME` in-guest.
/// Split on the last `:`, so the host path is unrestricted and `NAME` is the
/// trailing component; `NAME` must be a single path element.
fn parse_input(raw: &str) -> Result<Input, PlanError> {
    let invalid = || PlanError::Invalid(format!("--input `{raw}` must be HOST:NAME"));
    let (host, name) = raw.rsplit_once(':').ok_or_else(invalid)?;
    if host.is_empty() || name.is_empty() || name.contains('/') || name == "." || name == ".." {
        return Err(invalid());
    }
    Ok(Input {
        host: PathBuf::from(host),
        name: name.to_string(),
    })
}

/// Parse one `--out NAME:DEST` token into an [`Output`]: the guest writes under
/// `/run/sandy/outputs/NAME` and sandy collects that subtree to the host path
/// `DEST` at teardown. Split on the first `:`, so `NAME` is a single path element
/// and `DEST` is the (possibly colon-free) host path.
fn parse_output(raw: &str) -> Result<Output, PlanError> {
    let invalid = || PlanError::Invalid(format!("--out `{raw}` must be NAME:DEST"));
    let (name, dest) = raw.split_once(':').ok_or_else(invalid)?;
    if name.is_empty() || dest.is_empty() || name.contains('/') || name == "." || name == ".." {
        return Err(invalid());
    }
    Ok(Output {
        name: name.to_string(),
        dest: PathBuf::from(dest),
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

    /// `--input HOST:NAME` desugars to an [`Input`] with the split host path and
    /// the trailing name.
    #[test]
    fn input_host_name_parses() -> anyhow::Result<()> {
        let args = RunArgs {
            template: "demo".to_string(),
            inputs: vec!["/host/data:data".to_string()],
            ..RunArgs::default()
        };
        let plan = parse_run(args).map_err(|e| anyhow::anyhow!("parse_run: {e}"))?;
        let input = plan.inputs.first().expect("one input parsed");
        assert_eq!(input.host.to_string_lossy(), "/host/data");
        assert_eq!(input.name, "data");
        Ok(())
    }

    /// Adversarial: an `--input` with no `:`, an empty side, or a name that is not
    /// a single path component is rejected as an invalid plan (band 2).
    #[test]
    fn malformed_input_is_invalid_plan() {
        for raw in ["no-colon", "/h:", ":name", "/h:a/b", "/h:..", "/h:."] {
            let args = RunArgs {
                template: "demo".to_string(),
                inputs: vec![raw.to_string()],
                ..RunArgs::default()
            };
            assert!(
                matches!(parse_run(args), Err(PlanError::Invalid(_))),
                "a malformed --input {raw:?} must yield PlanError::Invalid"
            );
        }
    }

    /// `--out NAME:DEST` desugars to an [`Output`] with the name and host dest.
    #[test]
    fn output_name_dest_parses() -> anyhow::Result<()> {
        let args = RunArgs {
            template: "demo".to_string(),
            outputs: vec!["result:/host/out".to_string()],
            ..RunArgs::default()
        };
        let plan = parse_run(args).map_err(|e| anyhow::anyhow!("parse_run: {e}"))?;
        let output = plan.outputs.first().expect("one output parsed");
        assert_eq!(output.name, "result");
        assert_eq!(output.dest.to_string_lossy(), "/host/out");
        Ok(())
    }

    /// Adversarial: an `--out` with no `:`, an empty side, or a name that is not
    /// a single path component is rejected as an invalid plan (band 2).
    #[test]
    fn malformed_output_is_invalid_plan() {
        for raw in ["no-colon", "name:", ":/dest", "a/b:/dest", "..:/dest", ".:/dest"] {
            let args = RunArgs {
                template: "demo".to_string(),
                outputs: vec![raw.to_string()],
                ..RunArgs::default()
            };
            assert!(
                matches!(parse_run(args), Err(PlanError::Invalid(_))),
                "a malformed --out {raw:?} must yield PlanError::Invalid"
            );
        }
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
