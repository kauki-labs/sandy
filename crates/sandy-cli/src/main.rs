//! The `sandy` command-line interface.
//!
//! A thin argv shell over the `sandy-cli` library: `doctor` (Block 0) and the
//! Block 6 job ops `run`/`ls`/`status`/`wait`/`kill`/`gc`. All orchestration lives
//! in the library modules; `main` only parses argv, selects the host backend, and
//! maps results to process exit bands (INV-11).

use clap::{Parser, Subcommand};
use sandy::{CoreError, JobRecord, Journal, ProcessExit};
use sandy_cli::{
    doctor,
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

fn main() {
    let cli = Cli::parse();
    std::process::exit(dispatch(cli.command));
}

/// Dispatch one parsed command and return the process exit band (INV-11).
fn dispatch(command: Command) -> i32 {
    // Doctor needs no journal; handle it before touching `$SANDY_HOME`.
    if let Command::Doctor = command {
        let result = doctor::run_doctor();
        if result.exit_code == 0 {
            println!("{}", result.message);
        } else {
            eprintln!("{}", result.message);
        }
        return result.exit_code;
    }

    let journal = Journal::new(doctor::sandy_home());
    if let Err(e) = journal.ensure_dirs() {
        eprintln!("sandy: cannot initialize $SANDY_HOME: {e}");
        return ProcessExit::InfraFault.code();
    }

    match command {
        Command::Doctor => unreachable!("doctor handled above"),
        Command::Run {
            template,
            mounts,
            secrets,
            env,
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
            let report = match supervisor::run_job(&backend, &journal, &plan) {
                Ok(report) => report,
                Err(e) => {
                    eprintln!("sandy: run failed: {e}");
                    return ProcessExit::InfraFault.code();
                }
            };
            match serde_json::to_string_pretty(&report.envelope) {
                Ok(json) => println!("{json}"),
                Err(e) => {
                    eprintln!("sandy: could not serialize the result envelope: {e}");
                    return ProcessExit::InfraFault.code();
                }
            }
            report.process_exit.code()
        }
        Command::Ls => match supervisor::ls(&journal) {
            Ok(records) => {
                for record in &records {
                    print_record(record);
                }
                ProcessExit::Succeeded.code()
            }
            Err(e) => report_error(&e),
        },
        Command::Status { job_id } => {
            let backend = host_backend();
            match supervisor::status(&journal, &backend, &job_id) {
                Ok(record) => {
                    print_record(&record);
                    ProcessExit::Succeeded.code()
                }
                Err(e) => report_error(&e),
            }
        }
        Command::Wait { job_id } => {
            let backend = host_backend();
            match supervisor::wait(&journal, &backend, &job_id) {
                Ok(record) => {
                    print_record(&record);
                    ProcessExit::Succeeded.code()
                }
                Err(e) => report_error(&e),
            }
        }
        Command::Kill { job_id } => {
            let backend = host_backend();
            match supervisor::kill(&journal, &backend, &job_id) {
                Ok(record) => {
                    print_record(&record);
                    ProcessExit::Succeeded.code()
                }
                Err(e) => report_error(&e),
            }
        }
        Command::Gc { keep_last } => match supervisor::gc(&journal, keep_last) {
            Ok(evicted) => {
                println!("gc: evicted {} record(s)", evicted.len());
                for id in &evicted {
                    println!("  {id}");
                }
                ProcessExit::Succeeded.code()
            }
            Err(e) => report_error(&e),
        },
    }
}

/// Print one job record as a human-readable line.
fn print_record(record: &JobRecord) {
    println!("{:<36}  {:?}", record.job_id, record.state);
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
