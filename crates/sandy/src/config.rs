//! Configuration types for the core crate.

/// Collection limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CollectionConfig {
    /// The per-job output byte cap; exceeding it fails the job.
    pub per_job_cap_bytes: u64,
}
