//! The `sandy` command-line interface.
//!
//! A thin argv shell over the `sandy-cli` library: `doctor` (Block 0) and the
//! Block 6 job ops `run`/`ls`/`status`/`wait`/`kill`/`gc`. All orchestration lives
//! in the library modules; `main` only parses argv, selects the host backend, and
//! maps results to process exit bands (INV-11).

use clap::{Parser, Subcommand};
use sandy::{CoreError, Journal, ProcessExit};
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
        /// `--mount HOST:GUEST[:ro]` (repeatable).
        #[arg(long = "mount")]
        mounts: Vec<String>,
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
    /// Manage the GitHub App trust root the credential seam mints from.
    App {
        /// The trust-root subcommand.
        #[command(subcommand)]
        app: AppCommand,
    },
}

/// `sandy app` subcommands: register / deregister a forge trust root.
#[derive(Debug, Subcommand)]
enum AppCommand {
    /// Register a GitHub App trust root in-code (drives the Create + Install
    /// clicks, captures the key and ids, writes the config — no hand-copying).
    Register {
        /// The local handle (the `<name>.json` / `<name>.pem` file stem). By
        /// default the GitHub App name is `<name>-<random>` to avoid clashes.
        name: String,
        /// Use this exact GitHub App name instead of the default `<name>-<random>`.
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
        /// Write the trust root WITHOUT the live scope-check probe. Explicit pilot
        /// bootstrap only, until the credential adapter lands.
        #[arg(long)]
        skip_verify: bool,
    },
    /// Remove a trust root: revoke at the forge (pending the adapter), then shred
    /// the local key and config.
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

fn main() {
    let cli = Cli::parse();
    std::process::exit(dispatch(cli.command, cli.output));
}

/// Dispatch a `sandy app` subcommand, mapping an [`InstallError`] to a nonzero
/// exit. Registration/deregistration touch only the user config dir.
fn dispatch_app(app: AppCommand) -> i32 {
    let result = match app {
        AppCommand::Register {
            name,
            name_override,
            org,
            base_url,
            homepage,
            capabilities,
            repos,
            skip_verify,
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
            let github_name = app_register::github_app_name(&name, name_override.as_deref());
            app_register::run_register(
                &name,
                &github_name,
                &homepage,
                owner,
                &base_url,
                &caps,
                targets,
                skip_verify,
            )
        }
        AppCommand::Deregister { name, keep_remote } => app_register::run_deregister(&name, keep_remote),
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

    // App register/deregister need only the user config dir, not $SANDY_HOME.
    if let Command::App { app } = command {
        return dispatch_app(app);
    }

    let journal = Journal::new(doctor::sandy_home());
    if let Err(e) = journal.ensure_dirs() {
        eprintln!("sandy: cannot initialize $SANDY_HOME: {e}");
        return ProcessExit::InfraFault.code();
    }

    match command {
        Command::Doctor => unreachable!("doctor handled above"),
        Command::App { .. } => unreachable!("app handled above"),
        Command::Run {
            template,
            mounts,
            secrets,
            env,
            allow,
            cpu,
            mem,
            timeout,
            command,
        } => {
            let args = RunArgs {
                template,
                mounts,
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
            // no-op applier is never called). Cred stays WALLED: the live GitHub
            // `CredentialProvider` adapter and `mint_run_token` bind in once the App
            // is registered (#49); there is no `--github-token` flag because no live
            // provider exists to honor it yet.
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
            let report = match supervisor::run_job(&backend, &journal, &plan, &egress, egress_os, tap.as_deref()) {
                Ok(report) => report,
                Err(e) => {
                    eprintln!("sandy: run failed: {e}");
                    return ProcessExit::InfraFault.code();
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
