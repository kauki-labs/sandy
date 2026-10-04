//! Output collection: exit-0-only, atomic, `O_NOFOLLOW` (INV-2, INV-4).
//!
//! Outputs are collected only on a clean guest `exit 0`. Each declared output is
//! read from the guest's host-side RW area with `O_NOFOLLOW`, regular files
//! only — a symlink is refused, so its target bytes are never collected (INV-2).
//! Files are staged into `out.tmp/`, fsynced, and `out.tmp/` is renamed to
//! `out/` only once every `required` output is present (INV-4); a partial `out/`
//! is never observable. Exceeding the per-job cap fails the job (it is never
//! truncated).

use std::path::{Path, PathBuf};

use crate::{backend::Outcome, result::OutputRef};

/// A declared output to collect from the guest RW area.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputSpec {
    /// Path of the output within the guest RW area (host-side source).
    pub guest_path: String,
    /// The name it is collected as under `out/`.
    pub name: String,
    /// Whether the job fails if this output is absent.
    pub required: bool,
}

/// Collection limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CollectionConfig {
    /// The per-job output byte cap; exceeding it fails the job.
    pub per_job_cap_bytes: u64,
}

/// A collection failure.
#[derive(Debug, thiserror::Error)]
pub enum CollectError {
    /// A required output was absent after a clean exit (INV-4).
    #[error("required output missing: {0}")]
    RequiredMissing(String),
    /// An output path was a symlink; refused by `O_NOFOLLOW` (INV-2).
    #[error("output is a symlink, refused: {0}")]
    Symlink(PathBuf),
    /// An output path was not a regular file (INV-2).
    #[error("output is not a regular file: {0}")]
    NotRegularFile(PathBuf),
    /// Collection would exceed the per-job cap (INV: fail, not truncate).
    #[error("output exceeds per-job cap: {actual} > {cap} bytes")]
    OverQuota {
        /// The configured cap in bytes.
        cap: u64,
        /// The observed size in bytes.
        actual: u64,
    },
    /// A filesystem error.
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
}

/// Collect the declared outputs for a finished job.
///
/// Collects only when `outcome` is a clean `exit 0` (INV-2). Reads each output
/// from `source_dir` with `O_NOFOLLOW` (regular files only), stages it under
/// `job_dir/out.tmp/`, fsyncs, and renames `out.tmp/` to `job_dir/out/` only
/// after every `required` output is present (INV-4). On any failure `out/` is
/// never created and `out.tmp/` is discarded.
///
/// # Errors
///
/// Returns [`CollectError`] on a missing required output, a symlink / non-regular
/// source, an over-quota total, or an I/O error.
pub fn collect(
    _outcome: &Outcome,
    _source_dir: &Path,
    _job_dir: &Path,
    _declared: &[OutputSpec],
    _config: &CollectionConfig,
) -> Result<Vec<OutputRef>, CollectError> {
    todo!("exit-0-gated, O_NOFOLLOW read, atomic out.tmp -> out, cap-enforced")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// INV-2: a nonzero guest exit collects no outputs and leaves no `out/`.
    #[test]
    fn nonzero_exit_collects_nothing() -> anyhow::Result<()> {
        let tmp = tempfile::tempdir()?;
        let source = tmp.path().join("rw");
        let job = tmp.path().join("job");
        std::fs::create_dir_all(&source)?;
        std::fs::create_dir_all(&job)?;
        std::fs::write(source.join("result.txt"), b"data")?;
        let declared = [OutputSpec {
            guest_path: "result.txt".to_string(),
            name: "result.txt".to_string(),
            required: true,
        }];
        let config = CollectionConfig {
            per_job_cap_bytes: 1 << 20,
        };
        let outcome = Outcome {
            booted: true,
            guest_exit: Some(1),
            transport_error: None,
            timed_out: false,
        };
        let collected = collect(&outcome, &source, &job, &declared, &config)?;
        assert!(collected.is_empty(), "nonzero exit must collect nothing");
        assert!(!job.join("out").exists(), "no out/ may appear for a nonzero exit");
        Ok(())
    }
}
