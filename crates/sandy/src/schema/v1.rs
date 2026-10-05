//! Version 1 of the serialized per-job journal record.

use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use crate::result::ResultEnvelope;

/// The schema version stamped into every journal record.
pub const JOURNAL_SCHEMA_VERSION: u32 = 1;

/// The lifecycle state of a job record. Terminal states carry the result
/// envelope (INV-6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    /// The box is (believed to be) running.
    Running,
    /// Reconcile found the owner gone before a terminal transition (INV-3).
    Crashed,
    /// The guest exited 0 and outputs were collected.
    Succeeded,
    /// A task or infra fault ended the job.
    Failed,
    /// The job was cancelled.
    Cancelled,
}

/// One job's journal record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobRecord {
    /// Schema version of this record.
    pub schema_version: u32,
    /// The job id.
    pub job_id: String,
    /// The box the job ran in, if one booted.
    pub box_id: Option<String>,
    /// The current lifecycle state.
    pub state: JobState,
    /// The pid that wrote this record — informational only (INV-3).
    pub writer_pid: u32,
    /// When the record was first created.
    pub started: SystemTime,
    /// The terminal result envelope, present once the job reaches a terminal
    /// state (INV-6).
    pub result: Option<ResultEnvelope>,
}
