//! The LOCKED result envelope and classification types (INV-6, INV-7, INV-11).
//!
//! The envelope is `snake_case` on the wire and in Rust, with no serde rename
//! layer. These are the data types only; the classification *functions* that map
//! a physical `Outcome` (or a backend / plan error) into a [`Classification`]
//! live in the core crate that depends on this one.

use serde::{Deserialize, Serialize};

/// The schema version stamped into every envelope (INV-6/INV-11).
pub const RESULT_SCHEMA_VERSION: u32 = 1;

/// Terminal status of a job on the wire. The lowercase values are part of the
/// LOCKED schema; `rename_all` selects them without renaming any field key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// Guest exited 0 and all required outputs were collected.
    Succeeded,
    /// A task/contract fault, or an infra fault that aborted the run.
    Failed,
    /// The job was cancelled before a terminal guest result.
    Cancelled,
}

/// sandy's own *process* exit band (INV-11) — never conflated with the guest's
/// `exit_code`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessExit {
    /// `0` — succeeded.
    Succeeded,
    /// `1` — task failure (guest-nonzero / timeout / missing-required /
    /// cancelled); `retryable: false`.
    TaskFailure,
    /// `2` — invalid plan / usage; `retryable: false`; no boot.
    InvalidPlan,
    /// `3` — infra fault (boot / transport / unreachable / host-IO);
    /// `retryable: true`.
    InfraFault,
}

impl ProcessExit {
    /// The numeric process exit code for this band (`0`/`1`/`2`/`3`).
    #[must_use]
    pub fn code(self) -> i32 {
        match self {
            ProcessExit::Succeeded => 0,
            ProcessExit::TaskFailure => 1,
            ProcessExit::InvalidPlan => 2,
            ProcessExit::InfraFault => 3,
        }
    }
}

/// How a job's declared outputs resolved, fed into the core's `classify_outcome`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputStatus {
    /// Every required output was collected.
    Complete,
    /// A required output was absent after a clean exit.
    RequiredMissing,
    /// Collection exceeded the per-job cap.
    OverQuota,
}

/// The terminal classification of a job: the three values that MUST stay
/// consistent (INV-11 cross-checks). The core builds these; this crate only
/// defines the shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Classification {
    /// The envelope status.
    pub status: Status,
    /// Whether the platform may retry (true only for infra faults, INV-7).
    pub retryable: bool,
    /// sandy's process exit band.
    pub process_exit: ProcessExit,
}

/// One collected output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputRef {
    /// Path of the collected output, relative to the job's `out/`.
    pub path: String,
}

/// A side effect produced by the job (e.g. a GitHub PR).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receipt {
    /// The receipt kind, e.g. `"github-pr"`.
    pub kind: String,
    /// A reference for the receipt, e.g. a PR URL. Serializes as the `ref` key.
    pub r#ref: String,
}

/// Provenance of the run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    /// The Nix store path of the template that was booted.
    pub template_store_path: String,
}

/// Captured guest logs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Logs {
    /// The tail of the guest's combined output.
    pub tail: String,
}

/// The LOCKED result envelope (INV-11). Written to the journal at the terminal
/// transition (INV-6) and printed by foreground `run`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResultEnvelope {
    /// Schema version of this envelope.
    pub result_schema_version: u32,
    /// The job id.
    pub job_id: String,
    /// The box the job ran in, if one booted.
    pub box_id: Option<String>,
    /// Terminal status.
    pub status: Status,
    /// Whether the platform may retry (INV-7).
    pub retryable: bool,
    /// A human-readable message.
    pub message: String,
    /// The GUEST's exit code (never sandy's process band — INV-11).
    pub exit_code: Option<i32>,
    /// Collected outputs.
    pub outputs: Vec<OutputRef>,
    /// Side-effect receipts.
    pub receipts: Vec<Receipt>,
    /// Run provenance.
    pub provenance: Provenance,
    /// Captured logs.
    pub logs: Logs,
}
