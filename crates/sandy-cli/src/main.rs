//! The `sandy` command-line interface.
//!
//! Scaffold entry point. Block 0's `doctor` subcommand and Block 6's
//! `run`/`ls`/`status`/`wait`/`kill`/`gc` land here.

mod doctor;

use clap::{Parser, Subcommand};

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
}

fn main() {
    let _cli = Cli::parse();
    todo!("dispatch Command::Doctor to doctor::run_doctor(), print the message, std::process::exit(result.exit_code)")
}
