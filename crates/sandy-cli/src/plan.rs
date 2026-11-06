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
//! - `--out DEST` → a catch-all [`sandy::Output`]; everything under `/run/sandy/outputs` is collected to the host path
//!   `DEST` at teardown. `--out NAME:DEST` collects just `/run/sandy/outputs/NAME`.
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

use sandy::{
    AllowList, DirFingerprint, EgressRule, Grants, Input, Output, PlanError, RunControl, RunSpec, SecretRef,
    SecretSource,
};

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
    /// `--out DEST` / `--out NAME:DEST` occurrences, verbatim.
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
    /// `--digests`: record sha256 content digests of inputs and outputs in the receipt (#373).
    pub digests: bool,
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
    /// Run behind the backend's egress proxy (`SANDY_EGRESS=proxy`, #360) instead of
    /// the nftables boundary: the guest has no NIC and `allow` travels to the backend
    /// in [`RunSpec::egress`]. Not a CLI option: `dispatch_run` reads the environment.
    pub egress_proxy: bool,
    /// The guest network profile (`SANDY_NETWORK`, #602). `nic` boots the guest with a NIC behind the Linux nftables
    /// boundary (a bound tap) or, on macOS, the trusted-only NAT NIC. Not a CLI option: `dispatch_run` reads the
    /// environment, as it does for `egress_proxy`.
    pub network: sandy::NetworkMode,
    /// Record sha256 digests of inputs and collected outputs in the receipt (#373).
    /// Set by `sandy run --digests`; never from the environment.
    pub digests: bool,
    /// Optional vCPU count.
    pub cpu: Option<u32>,
    /// Optional memory budget in MiB.
    pub mem: Option<u32>,
    /// Wall-clock timeout in seconds.
    pub timeout_secs: u32,
    /// The trust tokens the run is granted.
    pub grants: Grants,
    /// `Some((dir, fingerprint))` makes the backend stage secrets into, and share
    /// the guest secret mount from, this caller-owned directory (see
    /// [`RunSpec::secret_dir`]). Set by the credential bracket for refresh
    /// re-delivery (#49), from the directory it validated itself and the
    /// fingerprint that validation captured (#323); `None` for an ordinary run.
    /// Not a CLI option, the supervisor fills it.
    pub secret_dir: Option<(PathBuf, DirFingerprint)>,
    /// This run's live cancellation/deadline handle (#340) — `sandy run` is a
    /// synchronous foreground command with no attach-state concept of its
    /// own, so this is constructed once from `timeout_secs` and never
    /// adjusted externally; it exists so `as_run_spec` has a real
    /// [`RunControl`] to hand the backend, the same contract every caller of
    /// [`VmBackend::run`] now has to satisfy.
    pub control: RunControl,
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
            secret_dir: self
                .secret_dir
                .as_ref()
                .map(|(dir, fingerprint)| (dir.as_path(), *fingerprint)),
            control: &self.control,
            egress: self.egress_proxy.then_some(&self.allow),
            digests: self.digests,
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
        .enumerate()
        .map(|(i, raw)| parse_input(raw, i))
        .collect::<Result<Vec<_>, _>>()?;
    reject_duplicate_input_names(&inputs)?;
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

    let timeout_secs = args.timeout.unwrap_or(DEFAULT_TIMEOUT_SECS);
    Ok(JobPlan {
        template: args.template,
        command: args.command,
        inputs,
        outputs,
        secrets,
        env,
        allow: AllowList { rules },
        egress_proxy: false,
        network: sandy::NetworkMode::None,
        digests: args.digests,
        cpu: args.cpu,
        mem: args.mem,
        timeout_secs,
        // Least-privilege default: grant no trust tokens. Capability granting is
        // out of #22 scope — the detection/routing seam lands with the host work.
        grants: Grants {
            secrets: false,
            agent: false,
            shares: false,
        },
        secret_dir: None,
        control: RunControl::with_timeout_secs(timeout_secs),
    })
}

/// Parse one `--input` token into an [`Input`]. Split on the last `:`, so the host
/// path is unrestricted; the trailing field is either:
///
/// - `NAME` (a single path element) — the input appears read-only at `/run/sandy/inputs/NAME` in-guest, as before.
/// - `/guest/path` (leading `/`) — the input is surfaced at that absolute guest path via a guest-side symlink; it is
///   staged under an internal name `in<index>` the job never needs to know.
///
/// `index` disambiguates the auto-assigned staging name across inputs.
/// `pub` for the same reason [`parse_env`] is: `sandy daemon submit`
/// (manifest-parity #496) reuses this validation from the `sandy` bin crate,
/// which only sees this library crate's `pub` surface, not `pub(crate)`.
pub fn parse_input(raw: &str, index: usize) -> Result<Input, PlanError> {
    let invalid = || PlanError::Invalid(format!("--input `{raw}` must be HOST:NAME or HOST:/guest/path"));
    let (host, spec) = raw.rsplit_once(':').ok_or_else(invalid)?;
    if host.is_empty() || spec.is_empty() {
        return Err(invalid());
    }
    if spec.starts_with('/') {
        validate_guest_path(spec).ok_or_else(|| {
            PlanError::Invalid(format!(
                "--input `{raw}`: guest path `{spec}` must be absolute with no `.`/`..` component"
            ))
        })?;
        return Ok(Input {
            host: resolve_input_host(host),
            name: format!("in{index}"),
            guest_path: Some(PathBuf::from(spec)),
        });
    }
    if spec.contains('/') || spec == "." || spec == ".." {
        return Err(invalid());
    }
    Ok(Input {
        host: resolve_input_host(host),
        name: spec.to_string(),
        guest_path: None,
    })
}

/// The host path of an input as the stage opens it. The stage refuses a symlink there (#618): it cannot tell a link the
/// user typed from one swapped in after a caller checked the path. So a link typed on the command line, such as a nix
/// `result`, is resolved here, once, by the user's own command. A path that is not a link, or whose link does not
/// resolve, is returned as given (the stage then refuses a dangling link by name).
fn resolve_input_host(host: &str) -> PathBuf {
    // `components` drops a trailing `/` and `/.`, which would make the check below follow the link.
    let path: PathBuf = PathBuf::from(host).components().collect();
    match std::fs::symlink_metadata(&path) {
        Ok(meta) if meta.file_type().is_symlink() => std::fs::canonicalize(&path).unwrap_or(path),
        _ => path,
    }
}

/// An input guest path is absolute and has no `.`/`..`/empty component (so the
/// guest symlink target is well-defined and cannot climb out). Returns `None`
/// when it is not usable.
fn validate_guest_path(path: &str) -> Option<()> {
    // Tab/newline would corrupt the tab-separated inputs manifest the guest reads.
    if path.chars().any(|c| c.is_control()) {
        return None;
    }
    let rest = path.strip_prefix('/')?;
    if rest.is_empty() {
        return None; // bare `/`
    }
    for part in rest.split('/') {
        if part.is_empty() || part == "." || part == ".." {
            return None;
        }
    }
    Some(())
}

/// Reject two inputs resolving to the same staging name (a user `NAME` colliding
/// with an auto-assigned `in<index>`), which would overwrite one in the share.
/// `pub` for the same reason [`parse_env`] is: `sandy daemon submit`
/// (manifest-parity #496) reuses this validation from the `sandy` bin crate.
pub fn reject_duplicate_input_names(inputs: &[Input]) -> Result<(), PlanError> {
    let mut seen = std::collections::HashSet::new();
    for input in inputs {
        if !seen.insert(input.name.as_str()) {
            return Err(PlanError::Invalid(format!(
                "two inputs resolve to the same name `{}` in the inputs share",
                input.name
            )));
        }
    }
    Ok(())
}

/// Parse one `--out` token into an [`Output`]. Two forms:
/// - `--out NAME:DEST` (named) — when the part before the first `:` is a single path element (non-empty, no `/`, not
///   `.`/`..`) and `DEST` is non-empty: the guest writes under `/run/sandy/outputs/NAME`, collected to `DEST`.
/// - `--out DEST` (catch-all) — anything else: the whole `/run/sandy/outputs` tree is collected to the host path
///   `DEST`. A `DEST` that itself contains a `:` must be path-like (contain `/`, e.g. `./out:dir`) so it is not read as
///   a name.
///
/// `pub` for the same reason [`parse_env`] is: `sandy daemon submit`
/// (manifest-parity #496) reuses this validation from the `sandy` bin crate.
pub fn parse_output(raw: &str) -> Result<Output, PlanError> {
    let invalid = || PlanError::Invalid(format!("--out `{raw}` must be DEST or NAME:DEST"));
    if raw.is_empty() {
        return Err(invalid());
    }
    if let Some((name, dest)) = raw.split_once(':')
        && is_single_component(name)
        && !dest.is_empty()
    {
        return Ok(Output {
            name: Some(name.to_string()),
            dest: PathBuf::from(dest),
        });
    }
    // Catch-all: the whole token is the destination.
    Ok(Output {
        name: None,
        dest: PathBuf::from(raw),
    })
}

/// Whether `s` is a single safe path component: non-empty, no `/`, not `.`/`..`.
fn is_single_component(s: &str) -> bool {
    !s.is_empty() && s != "." && s != ".." && !s.contains('/')
}

/// Parse one `--secret NAME=@PATH` token into a file-sourced [`SecretRef`].
/// `pub` for the same reason [`parse_env`] is: `sandy daemon submit`
/// (manifest-parity #496) reuses this validation from the `sandy` bin crate.
pub fn parse_secret(raw: &str) -> Result<SecretRef, PlanError> {
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

/// Parse one `--env KEY=VALUE` token into a `(key, value)` pair. `pub` so the
/// `sandy` binary's `daemon submit --flake` (manifest-parity #480) reuses
/// this validation instead of a second copy — the bin crate only sees this
/// library crate's `pub` surface, not `pub(crate)`.
pub fn parse_env(raw: &str) -> Result<(String, String), PlanError> {
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

    use super::{RunArgs, parse_input, parse_run};

    /// #618: the stage refuses an input that is a symlink, so `--input` resolves a link the user typed (a nix
    /// `result`, say) itself, once, before the path reaches the stage.
    #[test]
    fn a_symlinked_input_path_is_resolved_before_it_reaches_the_stage() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let real = dir.path().join("real.txt");
        std::fs::write(&real, b"x")?;
        let link = dir.path().join("result");
        std::os::unix::fs::symlink(&real, &link)?;

        let input = parse_input(&format!("{}:data", link.display()), 0)?;

        assert_eq!(input.host, std::fs::canonicalize(&real)?);
        Ok(())
    }

    /// #618 (review): `result/` typed with a trailing slash names the link too, and the stage refuses it, so it is
    /// resolved the same way.
    #[test]
    fn a_symlinked_input_path_with_a_trailing_slash_is_resolved() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let real = dir.path().join("real");
        std::fs::create_dir(&real)?;
        let link = dir.path().join("result");
        std::os::unix::fs::symlink(&real, &link)?;

        let input = parse_input(&format!("{}/:data", link.display()), 0)?;

        assert_eq!(input.host, std::fs::canonicalize(&real)?);
        Ok(())
    }

    /// A path that is not a link, or does not exist, is left as given.
    #[test]
    fn a_plain_or_missing_input_path_is_left_as_given() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let plain = dir.path().join("plain.txt");
        std::fs::write(&plain, b"x")?;

        assert_eq!(parse_input(&format!("{}:a", plain.display()), 0)?.host, plain);
        assert_eq!(
            parse_input("/no/such/path:b", 1)?.host,
            std::path::PathBuf::from("/no/such/path")
        );
        Ok(())
    }

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

    /// `--input HOST:/guest/path` parses to an input staged under an internal
    /// `in<index>` name and carrying the absolute guest path.
    #[test]
    fn input_guest_path_parses() -> anyhow::Result<()> {
        let args = RunArgs {
            template: "demo".to_string(),
            inputs: vec!["/host/data:/workspace".to_string()],
            ..RunArgs::default()
        };
        let plan = parse_run(args).map_err(|e| anyhow::anyhow!("parse_run: {e}"))?;
        let input = plan.inputs.first().expect("one input parsed");
        assert_eq!(input.host.to_string_lossy(), "/host/data");
        assert_eq!(input.name, "in0");
        assert_eq!(input.guest_path.as_deref(), Some(std::path::Path::new("/workspace")));
        Ok(())
    }

    /// Adversarial: a guest path that is bare `/` or has a `.`/`..`/empty component
    /// is rejected (the symlink target must be well-defined and cannot climb out).
    #[test]
    fn bad_guest_path_is_invalid_plan() {
        for raw in ["/h:/", "/h:/a/../b", "/h://x", "/h:/a/."] {
            let args = RunArgs {
                template: "demo".to_string(),
                inputs: vec![raw.to_string()],
                ..RunArgs::default()
            };
            assert!(
                matches!(parse_run(args), Err(PlanError::Invalid(_))),
                "a bad --input guest path {raw:?} must be rejected"
            );
        }
    }

    /// Adversarial: two inputs resolving to the same staging name are rejected,
    /// including a user name colliding with an auto-assigned `in<index>`.
    #[test]
    fn duplicate_input_names_are_invalid_plan() {
        for inputs in [
            vec!["/a:data".to_string(), "/b:data".to_string()],
            vec!["/a:/p".to_string(), "/b:in0".to_string()],
        ] {
            let args = RunArgs {
                template: "demo".to_string(),
                inputs,
                ..RunArgs::default()
            };
            assert!(
                matches!(parse_run(args), Err(PlanError::Invalid(_))),
                "colliding input names must be rejected"
            );
        }
    }

    /// `--out NAME:DEST` desugars to a named [`Output`]; `--out DEST` (no name) to
    /// a catch-all (`name = None`).
    #[test]
    fn output_named_and_catch_all_parse() -> anyhow::Result<()> {
        let parse_one = |raw: &str| -> anyhow::Result<sandy::Output> {
            let args = RunArgs {
                template: "demo".to_string(),
                outputs: vec![raw.to_string()],
                ..RunArgs::default()
            };
            let plan = parse_run(args).map_err(|e| anyhow::anyhow!("parse_run {raw:?}: {e}"))?;
            Ok(plan.outputs.into_iter().next().expect("one output parsed"))
        };

        // Named: a simple name before the first colon.
        let named = parse_one("result:/host/out")?;
        assert_eq!(named.name.as_deref(), Some("result"));
        assert_eq!(named.dest.to_string_lossy(), "/host/out");

        // Catch-all: no colon.
        let catch = parse_one("/host/out")?;
        assert_eq!(catch.name, None);
        assert_eq!(catch.dest.to_string_lossy(), "/host/out");

        // Catch-all: a path-like dest with a colon (the left side has a `/`, so it
        // is not a name).
        let path_colon = parse_one("./out:dir")?;
        assert_eq!(path_colon.name, None);
        assert_eq!(path_colon.dest.to_string_lossy(), "./out:dir");

        // A non-simple name before the colon falls back to catch-all, never named.
        let not_a_name = parse_one("a/b:/dest")?;
        assert_eq!(not_a_name.name, None);
        assert_eq!(not_a_name.dest.to_string_lossy(), "a/b:/dest");
        Ok(())
    }

    /// Adversarial: an empty `--out` is rejected as an invalid plan (band 2).
    #[test]
    fn empty_output_is_invalid_plan() {
        let args = RunArgs {
            template: "demo".to_string(),
            outputs: vec![String::new()],
            ..RunArgs::default()
        };
        assert!(matches!(parse_run(args), Err(PlanError::Invalid(_))));
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

    /// #373: `--digests` reaches the plan and its `RunSpec`; omitted, both are off.
    #[test]
    fn digests_flag_reaches_the_run_spec() -> anyhow::Result<()> {
        let on = parse_run(RunArgs {
            template: "demo".to_string(),
            digests: true,
            ..RunArgs::default()
        })
        .map_err(|e| anyhow::anyhow!("parse_run: {e}"))?;
        assert!(on.digests && on.as_run_spec().digests);
        let off = parse_run(RunArgs {
            template: "demo".to_string(),
            ..RunArgs::default()
        })
        .map_err(|e| anyhow::anyhow!("parse_run: {e}"))?;
        assert!(!off.digests && !off.as_run_spec().digests);
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
