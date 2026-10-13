//! The `sandy` command-line interface.
//!
//! A thin argv shell over the `sandy-cli` library: `doctor` (Block 0) and the
//! Block 6 job ops `run`/`ls`/`status`/`wait`/`kill`/`gc`. All orchestration lives
//! in the library modules; `main` only parses argv, selects the host backend, and
//! maps results to process exit bands (INV-11).

use clap::{Parser, Subcommand};
use sandy::{Capability, CoreError, GithubAdapter, Journal, ProcessExit, Scope, TrustRoot};
use sandy_cli::{
    app_register::{self, Owner},
    doctor,
    output::{OutputFormat, format_doctor, format_envelope, format_gc, format_record, format_records},
    plan::{RunArgs, parse_run},
    supervisor,
};

/// Command-line surface for `sandy`.
#[derive(Debug, Parser)]
#[command(name = "sandy", about = "Sandboxed job runner")]
struct Cli {
    /// The subcommand to run.
    #[command(subcommand)]
    command: Command,
    /// Output format: `text` (human, default) or `json` (for agents/automation).
    #[arg(long = "output", short = 'o', value_enum, default_value = "text", global = true)]
    output: OutputFormat,
}

/// Top-level `sandy` subcommands.
#[derive(Debug, Subcommand)]
enum Command {
    /// Verify environment preconditions before any job runs (Block 0, REQ-12).
    Doctor,
    /// Boot a template and run a job to completion in the foreground.
    Run {
        /// The template (flake attr / image) to boot.
        template: String,
        /// `--input HOST:NAME` read-only input at `/run/sandy/inputs/NAME` (repeatable).
        #[arg(long = "input")]
        inputs: Vec<String>,
        /// `--secret NAME=@PATH` (repeatable).
        #[arg(long = "secret")]
        secrets: Vec<String>,
        /// `--env KEY=VALUE` (repeatable).
        #[arg(long = "env")]
        env: Vec<String>,
        /// `--allow HOST:PORT` egress allow-list entry (repeatable).
        #[arg(long = "allow")]
        allow: Vec<String>,
        /// Optional vCPU count.
        #[arg(long)]
        cpu: Option<u32>,
        /// Optional memory budget in MiB.
        #[arg(long)]
        mem: Option<u32>,
        /// Optional wall-clock timeout in seconds.
        #[arg(long)]
        timeout: Option<u32>,
        /// Mint a scoped forge token for the job from the named trust root (a
        /// `sandy cred github` name); the token is injected as `GITHUB_TOKEN` and
        /// revoked at teardown.
        #[arg(long = "credential")]
        credential: Option<String>,
        /// Capability for the minted credential: `read-code` | `write-code` |
        /// `read-pr` | `write-pr` (repeatable; default `read-code`).
        #[arg(long = "cred-capability")]
        cred_capability: Vec<String>,
        /// The trailing `-- CMD ARGS...` guest command.
        #[arg(last = true)]
        command: Vec<String>,
    },
    /// List every job record.
    Ls,
    /// Reconcile and print one job's current state.
    Status {
        /// The job id to inspect.
        job_id: String,
    },
    /// Wait for one job to reach a terminal state, then print it.
    Wait {
        /// The job id to wait on.
        job_id: String,
    },
    /// Cancel a running job and tear its box down.
    Kill {
        /// The job id to cancel.
        job_id: String,
    },
    /// Garbage-collect terminal job records, keeping the newest N.
    Gc {
        /// How many terminal records to keep (newest first).
        #[arg(long, default_value_t = 20)]
        keep_last: usize,
    },
    /// Manage the forge credential trust roots the credential seam mints from.
    Cred {
        /// The forge provider the trust root belongs to.
        #[command(subcommand)]
        provider: CredProvider,
    },
}

/// `sandy cred <provider>`: the forge a trust root belongs to. Operations are
/// provider-specific, so each forge is its own subcommand group.
#[derive(Debug, Subcommand)]
enum CredProvider {
    /// GitHub App trust roots.
    Github {
        /// The operation on a GitHub trust root.
        #[command(subcommand)]
        op: GithubOp,
    },
}

/// `sandy cred github <op>`: register / verify / import / deregister a GitHub App
/// trust root.
#[derive(Debug, Subcommand)]
enum GithubOp {
    /// Register a GitHub App trust root in-code (drives the Create + Install
    /// clicks, captures the key and ids, writes the config — no hand-copying).
    Register {
        /// The local handle (the `<name>.json` / `<name>.pem` file stem). The
        /// GitHub App name is deterministic — `<name>-<org>` (or `<name>` for a
        /// user account) — so the whole org shares one App and the duplicate
        /// check can find it.
        name: String,
        /// Use this exact GitHub App name instead of the default `<name>-<org>`.
        #[arg(long)]
        name_override: Option<String>,
        /// Register under this organization instead of your user account.
        #[arg(long)]
        org: Option<String>,
        /// Web base for GitHub Enterprise Server.
        #[arg(long, default_value = "https://github.com")]
        base_url: String,
        /// The App homepage URL.
        #[arg(long, default_value = "https://github.com/kauki-labs/sandy")]
        homepage: String,
        /// A capability a minted token may need: read-code | write-code | read-pr
        /// | write-pr (repeatable, at least one).
        #[arg(long = "capability", required = true)]
        capabilities: Vec<String>,
        /// A repository the credential may be scoped to, as owner/repo (repeatable).
        #[arg(long = "repo")]
        repos: Vec<String>,
        /// Write the trust root WITHOUT the live scope-check probe (register
        /// verifies by default). An explicit key-only bootstrap escape.
        #[arg(long)]
        skip_verify: bool,
        /// Create the App even if one already exists on the owner (overrides the
        /// one-shared-org-App duplicate check).
        #[arg(long)]
        force: bool,
    },
    /// Import an existing shared GitHub App trust root from its credentials (no
    /// browser) — for members reusing the org's one shared App.
    Import {
        /// The local handle (the `<name>.json` / `<name>.pem` file stem).
        name: String,
        /// The GitHub App id.
        #[arg(long)]
        app_id: String,
        /// The installation id the token is minted for.
        #[arg(long)]
        installation_id: u64,
        /// Path to the shared App private key (obtained from the secret store).
        #[arg(long)]
        pem: std::path::PathBuf,
        /// API base for GitHub Enterprise Server (default github.com).
        #[arg(long)]
        base_url: Option<String>,
        /// A repository the credential may be scoped to, as owner/repo (repeatable).
        #[arg(long = "repo")]
        repos: Vec<String>,
    },
    /// Verify an existing trust root: dry-run mint a scoped token and check the
    /// installation grants the requested capabilities.
    Verify {
        /// The trust-root name (its config file stem).
        name: String,
        /// A capability to verify the installation grants: read-code | write-code
        /// | read-pr | write-pr (repeatable, at least one).
        #[arg(long = "capability", required = true)]
        capabilities: Vec<String>,
    },
    /// Remove a trust root: uninstall the App at the forge, then shred the local
    /// key and config.
    Deregister {
        /// The trust-root name (its config file stem).
        name: String,
        /// Shred locally only; uninstall the App yourself in the GitHub UI.
        #[arg(long)]
        keep_remote: bool,
    },
}

/// The macOS host backend: vfkit. The live boot is the #26 seam — the sandbox
/// gate exercises the generic `run_job` with a `FakeBackend`, never this path.
#[cfg(target_os = "macos")]
fn host_backend() -> sandy_backend::VfkitBackend {
    // Resolve the vfkit binary from $SANDY_VFKIT_BIN, else let PATH resolve it at
    // spawn time. Construction is lazy enough to stay off the sandbox path (#26).
    let vfkit_bin = std::env::var("SANDY_VFKIT_BIN").unwrap_or_else(|_| "vfkit".to_string());
    sandy_backend::VfkitBackend::new(vfkit_bin)
}

/// The Linux host backend: qemu/KVM. See [`host_backend`] above for the #26 seam.
#[cfg(not(target_os = "macos"))]
fn host_backend() -> sandy_backend::QemuBackend {
    sandy_backend::QemuBackend::new()
}

/// A no-op egress applier for platforms with no per-VM boundary. On macOS
/// `plan_egress` yields `NoBoundary`, so `enforce` never calls these — they exist
/// only to satisfy the `EgressApplier` bound off the Linux path.
#[cfg(not(target_os = "linux"))]
struct NoEgress;

#[cfg(not(target_os = "linux"))]
impl sandy::EgressApplier for NoEgress {
    fn apply(&self, _ruleset: &str) -> Result<(), CoreError> {
        Ok(())
    }

    fn revert(&self) -> Result<(), CoreError> {
        Ok(())
    }
}

/// The Linux egress applier: `nft`-backed default-deny enforcement. The live load
/// whose boundary an in-guest root flush cannot bypass is tier-3 (#29).
#[cfg(target_os = "linux")]
fn egress_applier() -> sandy::NftablesApplier {
    sandy::NftablesApplier
}

/// The non-Linux egress applier: a no-op, because `plan_egress` yields
/// `NoBoundary` off Linux and nothing is applied.
#[cfg(not(target_os = "linux"))]
fn egress_applier() -> NoEgress {
    NoEgress
}

/// Load the named trust root from `dir` and build the live [`GithubAdapter`] plus
/// the [`Scope`] to mint for: the trust root's own target repositories and the
/// requested capabilities (default `read-code`). Returns a human-readable error for
/// a missing/invalid trust root or an unknown capability (a config fault).
fn credential_setup(
    dir: &std::path::Path,
    name: &str,
    capabilities: &[String],
) -> Result<(GithubAdapter, Scope), String> {
    let cfg = dir.join(format!("{name}.json"));
    let root = TrustRoot::load(&cfg).map_err(|e| format!("load trust root {name:?}: {e}"))?;
    let targets = match &root {
        TrustRoot::Github { targets, .. } => targets.clone(),
        TrustRoot::Gitlab { .. } => return Err("GitLab trust roots are not supported yet".to_string()),
    };
    let mut caps = parse_caps(capabilities)
        .map_err(|tok| format!("unknown --cred-capability {tok:?} (expected read-code|write-code|read-pr|write-pr)"))?;
    if caps.is_empty() {
        caps.push(Capability::ReadCode);
    }
    let adapter = GithubAdapter::from_trust_root(&root).map_err(|e| format!("build credential adapter: {e}"))?;
    Ok((
        adapter,
        Scope {
            targets,
            capabilities: caps,
        },
    ))
}

fn main() {
    let cli = Cli::parse();
    std::process::exit(dispatch(cli.command, cli.output));
}

/// Dispatch a `sandy cred <provider>` command to the provider's handler.
fn dispatch_cred(provider: CredProvider) -> i32 {
    match provider {
        CredProvider::Github { op } => dispatch_github(op),
    }
}

/// Dispatch a `sandy cred github <op>`, mapping an [`InstallError`] to a nonzero
/// exit. These touch only the user config dir.
fn dispatch_github(op: GithubOp) -> i32 {
    let result = match op {
        GithubOp::Register {
            name,
            name_override,
            org,
            base_url,
            homepage,
            capabilities,
            repos,
            skip_verify,
            force,
        } => {
            let caps = match parse_caps(&capabilities) {
                Ok(caps) => caps,
                Err(bad) => {
                    eprintln!("sandy: unknown capability '{bad}' (use read-code | write-code | read-pr | write-pr)");
                    return ProcessExit::InvalidPlan.code();
                }
            };
            let owner = org.map_or(Owner::User, Owner::Org);
            let targets = repos.into_iter().map(sandy::Target).collect();
            let github_name = app_register::github_app_name(&name, &owner, name_override.as_deref());
            app_register::run_register(
                &name,
                &github_name,
                &homepage,
                owner,
                &base_url,
                &caps,
                targets,
                skip_verify,
                force,
            )
        }
        GithubOp::Import {
            name,
            app_id,
            installation_id,
            pem,
            base_url,
            repos,
        } => {
            let targets = repos.into_iter().map(sandy::Target).collect();
            app_register::run_import(&name, &app_id, installation_id, &pem, base_url, targets)
        }
        GithubOp::Verify { name, capabilities } => match parse_caps(&capabilities) {
            Ok(caps) => app_register::run_verify(&name, &caps),
            Err(bad) => {
                eprintln!("sandy: unknown capability '{bad}' (use read-code | write-code | read-pr | write-pr)");
                return ProcessExit::InvalidPlan.code();
            }
        },
        GithubOp::Deregister { name, keep_remote } => app_register::run_deregister(&name, keep_remote),
    };
    match result {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("sandy: {e}");
            ProcessExit::InvalidPlan.code()
        }
    }
}

/// Parse each `--capability` token into a [`sandy::Capability`], returning the
/// first unrecognized token as the error.
fn parse_caps(tokens: &[String]) -> Result<Vec<sandy::Capability>, String> {
    tokens.iter().map(|t| sandy::parse_capability(t)).collect()
}

/// Dispatch one parsed command and return the process exit band (INV-11).
fn dispatch(command: Command, output: OutputFormat) -> i32 {
    // Doctor needs no journal; handle it before touching `$SANDY_HOME`.
    if let Command::Doctor = command {
        let result = doctor::run_doctor();
        match output {
            // Text keeps the stream convention (ok→stdout, refusal→stderr); JSON
            // always goes to stdout so an agent reads the verdict from one channel.
            OutputFormat::Text if result.exit_code != 0 => eprintln!("{}", result.message),
            OutputFormat::Text => println!("{}", result.message),
            OutputFormat::Json => match format_doctor(result.exit_code, &result.message, output) {
                Ok(json) => println!("{json}"),
                Err(e) => {
                    eprintln!("sandy: could not serialize output: {e}");
                    return ProcessExit::InfraFault.code();
                }
            },
        }
        return result.exit_code;
    }

    // `cred` ops need only the user config dir, not $SANDY_HOME.
    if let Command::Cred { provider } = command {
        return dispatch_cred(provider);
    }

    let journal = Journal::new(doctor::sandy_home());
    if let Err(e) = journal.ensure_dirs() {
        eprintln!("sandy: cannot initialize $SANDY_HOME: {e}");
        return ProcessExit::InfraFault.code();
    }

    match command {
        Command::Doctor => unreachable!("doctor handled above"),
        Command::Cred { .. } => unreachable!("cred handled above"),
        Command::Run {
            template,
            inputs,
            secrets,
            env,
            allow,
            cpu,
            mem,
            timeout,
            credential,
            cred_capability,
            command,
        } => {
            let args = RunArgs {
                template,
                inputs,
                secrets,
                env,
                allow,
                cpu,
                mem,
                timeout,
                command,
            };
            let plan = match parse_run(args) {
                Ok(plan) => plan,
                Err(e) => {
                    eprintln!("sandy: {e}");
                    return ProcessExit::InvalidPlan.code();
                }
            };
            let backend = host_backend();
            // Egress is bracketed around the boot per platform: Linux enforces the
            // nftables boundary, macOS has none (`plan_egress` → NoBoundary, so the
            // no-op applier is never called).
            let egress = egress_applier();
            let egress_os = if cfg!(target_os = "macos") {
                sandy::EgressOs::MacOs
            } else {
                sandy::EgressOs::Linux
            };
            // The guest's tap (if any) comes from $SANDY_TAP — the same interface the
            // backend attaches the NIC to. On Linux a bound tap selects the
            // guest-scoped forward ruleset (safe), never the host-OUTPUT drop-all (#29).
            let tap = std::env::var("SANDY_TAP").ok().filter(|t| !t.is_empty());

            // With `--credential`, mint a scoped forge token from the named trust
            // root and bracket the run with it (mint → inject → revoke at teardown);
            // otherwise run with no credential. Setup errors (bad trust root or
            // capability) are config faults (band 2), before any boot.
            let report = if let Some(name) = credential {
                let dir = match app_register::trust_roots_dir() {
                    Ok(dir) => dir,
                    Err(e) => {
                        eprintln!("sandy: trust-roots dir: {e}");
                        return ProcessExit::InfraFault.code();
                    }
                };
                let (adapter, scope) = match credential_setup(&dir, &name, &cred_capability) {
                    Ok(pair) => pair,
                    Err(e) => {
                        eprintln!("sandy: {e}");
                        return ProcessExit::InvalidPlan.code();
                    }
                };
                let cred_dir = std::env::temp_dir().join(format!("sandy-cred-{}", std::process::id()));
                if let Err(e) = std::fs::create_dir_all(&cred_dir) {
                    eprintln!("sandy: create credential staging dir: {e}");
                    return ProcessExit::InfraFault.code();
                }
                let result = supervisor::run_job_with_credential(
                    &backend,
                    &journal,
                    plan,
                    &egress,
                    egress_os,
                    tap.as_deref(),
                    &adapter,
                    &scope,
                    "GITHUB_TOKEN",
                    &cred_dir,
                    sandy::MAX_TTL_SECS,
                );
                let _ = std::fs::remove_dir_all(&cred_dir);
                match result {
                    Ok(report) => report,
                    Err(e) => {
                        eprintln!("sandy: run failed: {e}");
                        return ProcessExit::InfraFault.code();
                    }
                }
            } else {
                match supervisor::run_job(&backend, &journal, &plan, &egress, egress_os, tap.as_deref()) {
                    Ok(report) => report,
                    Err(e) => {
                        eprintln!("sandy: run failed: {e}");
                        return ProcessExit::InfraFault.code();
                    }
                }
            };
            // The envelope is the result, not a diagnostic — print it (the band,
            // not stdout, signals failure) and exit on the process band.
            if let Err(code) = emit(format_envelope(&report.envelope, output)) {
                return code;
            }
            report.process_exit.code()
        }
        Command::Ls => match supervisor::ls(&journal) {
            Ok(records) => succeed_or(emit(format_records(&records, output))),
            Err(e) => report_error(&e),
        },
        Command::Status { job_id } => {
            let backend = host_backend();
            match supervisor::status(&journal, &backend, &job_id) {
                Ok(record) => succeed_or(emit(format_record(&record, output))),
                Err(e) => report_error(&e),
            }
        }
        Command::Wait { job_id } => {
            let backend = host_backend();
            match supervisor::wait(&journal, &backend, &job_id) {
                Ok(record) => succeed_or(emit(format_record(&record, output))),
                Err(e) => report_error(&e),
            }
        }
        Command::Kill { job_id } => {
            let backend = host_backend();
            match supervisor::kill(&journal, &backend, &job_id) {
                Ok(record) => succeed_or(emit(format_record(&record, output))),
                Err(e) => report_error(&e),
            }
        }
        Command::Gc { keep_last } => match supervisor::gc(&journal, keep_last) {
            Ok(evicted) => succeed_or(emit(format_gc(&evicted, output))),
            Err(e) => report_error(&e),
        },
    }
}

/// Print a formatted result to stdout, or report a serialization failure.
///
/// An empty text rendering (e.g. `ls` with no jobs) prints nothing; JSON always
/// prints (an empty list is a valid `[]`). On a `serde_json` failure, returns the
/// infra-fault band so the caller can exit on it.
fn emit(formatted: serde_json::Result<String>) -> Result<(), i32> {
    match formatted {
        Ok(out) => {
            if !out.is_empty() {
                println!("{out}");
            }
            Ok(())
        }
        Err(e) => {
            eprintln!("sandy: could not serialize output: {e}");
            Err(ProcessExit::InfraFault.code())
        }
    }
}

/// Map an [`emit`] result to a process band: success (band 0) or the serialization
/// failure band it carries.
fn succeed_or(emitted: Result<(), i32>) -> i32 {
    match emitted {
        Ok(()) => ProcessExit::Succeeded.code(),
        Err(code) => code,
    }
}

/// Print a management-op error and map it to an exit band: an unknown job id is a
/// usage error (band 2); every other journal fault is an infra fault (band 3).
fn report_error(error: &CoreError) -> i32 {
    eprintln!("sandy: {error}");
    match error {
        CoreError::NotFound(_) => ProcessExit::InvalidPlan.code(),
        _ => ProcessExit::InfraFault.code(),
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use anyhow::Context;
    use sandy::Target;

    use super::*;

    /// Write a GitHub trust root (and a `0600` dummy key) under `dir`, so
    /// `credential_setup` has something to load without a live forge.
    fn write_trust_root(dir: &std::path::Path, name: &str, targets: &[&str]) -> anyhow::Result<()> {
        std::fs::create_dir_all(dir).context("mkdir")?;
        let pem = dir.join(format!("{name}.pem"));
        std::fs::write(&pem, b"-----dummy-----").context("write pem")?;
        std::fs::set_permissions(&pem, std::fs::Permissions::from_mode(0o600)).context("chmod pem")?;
        let root = TrustRoot::Github {
            base_url: None,
            app_id: "123".to_string(),
            private_key_path: pem,
            installation_id: 7,
            targets: targets.iter().map(|t| Target((*t).to_string())).collect(),
        };
        root.write(&dir.join(format!("{name}.json")))
            .context("write trust root")?;
        Ok(())
    }

    #[test]
    fn credential_setup_scopes_to_the_trust_root_targets_and_capabilities() -> anyhow::Result<()> {
        let tmp = tempfile::tempdir()?;
        write_trust_root(tmp.path(), "runner", &["kauki-labs/sandy-pilot-test"])?;

        let (_adapter, scope) = credential_setup(
            tmp.path(),
            "runner",
            &["write-code".to_string(), "write-pr".to_string()],
        )
        .map_err(|e| anyhow::anyhow!(e))?;

        assert_eq!(scope.targets, vec![Target("kauki-labs/sandy-pilot-test".to_string())]);
        assert_eq!(scope.capabilities, vec![Capability::WriteCode, Capability::WritePr]);
        Ok(())
    }

    #[test]
    fn credential_setup_defaults_to_read_code_when_no_capability_is_given() -> anyhow::Result<()> {
        let tmp = tempfile::tempdir()?;
        write_trust_root(tmp.path(), "runner", &["o/r"])?;

        let (_adapter, scope) = credential_setup(tmp.path(), "runner", &[]).map_err(|e| anyhow::anyhow!(e))?;

        assert_eq!(
            scope.capabilities,
            vec![Capability::ReadCode],
            "no capability flag defaults to read-code"
        );
        Ok(())
    }

    #[test]
    fn credential_setup_rejects_an_unknown_capability() -> anyhow::Result<()> {
        let tmp = tempfile::tempdir()?;
        write_trust_root(tmp.path(), "runner", &["o/r"])?;

        let err = credential_setup(tmp.path(), "runner", &["admin".to_string()])
            .map(|_| ())
            .expect_err("an unknown capability must be rejected");
        assert!(err.contains("unknown --cred-capability"), "got: {err}");
        Ok(())
    }
}
