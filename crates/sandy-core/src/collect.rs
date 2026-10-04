//! Output collection: exit-0-only, atomic, `O_NOFOLLOW` (INV-2, INV-4).
//!
//! Outputs are collected only on a clean guest `exit 0`. Each declared output is
//! read from the guest's host-side RW area with `O_NOFOLLOW`, regular files
//! only — a symlink is refused, so its target bytes are never collected (INV-2).
//! Files are staged into `out.tmp/`, fsynced, and `out.tmp/` is renamed to
//! `out/` only once every `required` output is present (INV-4); a partial `out/`
//! is never observable. Exceeding the per-job cap fails the job (it is never
//! truncated).

use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

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
    outcome: &Outcome,
    source_dir: &Path,
    job_dir: &Path,
    declared: &[OutputSpec],
    config: &CollectionConfig,
) -> Result<Vec<OutputRef>, CollectError> {
    // INV-2: collect only on a clean guest `exit 0`. A nonzero exit, a timeout,
    // or a guest that never booted collects nothing and leaves no `out/`.
    let clean_exit = outcome.booted && !outcome.timed_out && outcome.guest_exit == Some(0);
    if !clean_exit {
        return Ok(Vec::new());
    }

    let out_tmp = job_dir.join("out.tmp");
    let out = job_dir.join("out");

    // Start from a clean staging dir: a torn `out.tmp/` left by a killed run must
    // never be promoted, so its contents are discarded before we stage (INV-4).
    if out_tmp.exists() {
        std::fs::remove_dir_all(&out_tmp)?;
    }
    std::fs::create_dir_all(&out_tmp)?;

    match stage_outputs(source_dir, &out_tmp, declared, config) {
        Ok(collected) => {
            // Promote atomically: fsync the staging dir, rename it to `out/`, then
            // fsync the parent so the rename survives a crash (INV-4).
            fsync_dir(&out_tmp)?;
            std::fs::rename(&out_tmp, &out)?;
            fsync_dir(job_dir)?;
            Ok(collected)
        }
        Err(e) => {
            // On any failure `out/` is never created and the partial staging is
            // discarded (INV-2/INV-4).
            let _ = std::fs::remove_dir_all(&out_tmp);
            Err(e)
        }
    }
}

/// Stage every declared output into `out_tmp`, enforcing `O_NOFOLLOW`,
/// regular-file-only, and the per-job cap (INV-2). Returns the collected refs;
/// the caller promotes `out_tmp` to `out/` only on success.
fn stage_outputs(
    source_dir: &Path,
    out_tmp: &Path,
    declared: &[OutputSpec],
    config: &CollectionConfig,
) -> Result<Vec<OutputRef>, CollectError> {
    let mut collected = Vec::new();
    let mut total: u64 = 0;

    for spec in declared {
        let src = source_dir.join(&spec.guest_path);
        // O_NOFOLLOW: a symlink final component fails with ELOOP, so the target
        // bytes are never read (INV-2). O_CLOEXEC keeps the fd off forked children.
        let open = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&src);
        let mut file = match open {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if spec.required {
                    return Err(CollectError::RequiredMissing(spec.name.clone()));
                }
                continue;
            }
            Err(e) if e.raw_os_error() == Some(libc::ELOOP) => {
                return Err(CollectError::Symlink(src));
            }
            Err(e) => return Err(e.into()),
        };

        let metadata = file.metadata()?;
        if !metadata.file_type().is_file() {
            return Err(CollectError::NotRegularFile(src));
        }

        // Enforce the cap before copying; the source is only read, never
        // truncated — over-quota fails the job (INV), it does not shrink output.
        total = total.saturating_add(metadata.len());
        if total > config.per_job_cap_bytes {
            return Err(CollectError::OverQuota {
                cap: config.per_job_cap_bytes,
                actual: total,
            });
        }

        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        let dest = out_tmp.join(&spec.name);
        let mut dest_file = File::create(&dest)?;
        dest_file.write_all(&bytes)?;
        dest_file.sync_all()?;

        collected.push(OutputRef {
            path: spec.name.clone(),
        });
    }

    Ok(collected)
}

/// fsync a directory so a preceding create/rename within it is durable.
fn fsync_dir(dir: &Path) -> std::io::Result<()> {
    File::open(dir)?.sync_all()
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
