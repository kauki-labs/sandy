//! Output staging and collection: a writable share the guest writes into, copied
//! to host destinations at teardown.
//!
//! [`prepare_outputs`] creates a `0700` dir (and a `<name>` subdir per *named*
//! output); the backend shares it read-write at a fixed [`OUTPUT_MOUNT_TAG`] and
//! the guest mounts it at `/run/sandy/outputs`, so the job writes under
//! `/run/sandy/outputs` (catch-all) or `/run/sandy/outputs/<name>` (named).
//! [`collect_outputs`] copies, per output, either the `<name>` subtree or the whole
//! output dir (catch-all, `name = None`) to its host [`Output::dest`] at teardown.
//!
//! The output share is the one guest-writable, host-visible surface, so collection
//! is adversarial-safe: it **skips symlinks** entirely (a job can drop
//! `out/name/x -> /etc/shadow`; following it would copy the host file's bytes, and
//! even preserving it would expose the host target when the dest is later read), it
//! never follows a symlinked directory, and it caps total bytes and entries so a
//! runaway job cannot exhaust the host (INV-1 on the way out). Copying only regular
//! files and directories; preserving in-tree relative symlinks is a follow-up.

use std::{
    fs,
    io::{self, Read},
    os::unix::fs::PermissionsExt,
    path::Path,
};

use crate::backend::{BackendError, Output};

/// The virtiofs `mountTag` for the writable outputs share. Fixed, not per-run, so
/// the guest can statically mount it at `/run/sandy/outputs`; it MUST match the
/// guest flake's `fileSystems` device for that mount.
pub const OUTPUT_MOUNT_TAG: &str = "sandy-outputs";

/// A collection ceiling: refuse to copy out more than this many bytes or entries
/// per run, so a runaway job cannot fill the host disk from inside the sandbox.
const MAX_OUTPUT_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const MAX_OUTPUT_ENTRIES: u64 = 100_000;

/// Create a `0700` outputs dir, with an empty writable `<name>` subdir per *named*
/// output (a catch-all needs no subdir; the guest writes the dir root).
///
/// Returns the number of outputs prepared; `0` means the backend attaches no
/// share (the guest mount is `nofail`, so a run with no outputs still boots).
///
/// # Errors
///
/// Returns [`BackendError::Spawn`] when the dir cannot be prepared or a name is
/// not a single safe path component.
pub fn prepare_outputs(outputs: &[Output], outputs_dir: &Path) -> Result<usize, BackendError> {
    if outputs.is_empty() {
        return Ok(0);
    }
    fs::create_dir_all(outputs_dir).map_err(|e| err("create outputs dir", outputs_dir, &e))?;
    fs::set_permissions(outputs_dir, fs::Permissions::from_mode(0o700))
        .map_err(|e| err("tighten outputs dir to 0700", outputs_dir, &e))?;
    for output in outputs {
        if let Some(name) = &output.name {
            validate_output_name(name)?;
            let sub = outputs_dir.join(name);
            fs::create_dir_all(&sub).map_err(|e| err("create output subdir", &sub, &e))?;
        }
    }
    Ok(outputs.len())
}

/// Copy each output's `<name>` subtree from `outputs_dir` to its host destination.
///
/// Best-effort per output (a failure is returned, not silently dropped); the
/// caller runs this before wiping the share. Symlinks are skipped (never followed
/// or recreated), and the run-wide byte/entry ceiling is enforced.
///
/// # Errors
///
/// Returns [`BackendError::Spawn`] on a copy failure or when the ceiling is hit.
pub fn collect_outputs(outputs: &[Output], outputs_dir: &Path) -> Result<(), BackendError> {
    let mut budget = Budget {
        bytes: MAX_OUTPUT_BYTES,
        entries: MAX_OUTPUT_ENTRIES,
    };
    for output in outputs {
        // A named output collects its subtree; a catch-all (`name = None`) collects
        // the whole output dir root.
        let src = match &output.name {
            Some(name) => outputs_dir.join(name),
            None => outputs_dir.to_path_buf(),
        };
        if !src.exists() {
            // The guest declared but never wrote the output: nothing to collect.
            continue;
        }
        copy_tree(&src, &output.dest, &mut budget)?;
        tracing::debug!(name = ?output.name, dest = %output.dest.display(), "collected output");
    }
    Ok(())
}

/// Remaining collection ceiling, decremented as entries are copied.
struct Budget {
    bytes: u64,
    entries: u64,
}

impl Budget {
    fn charge(&mut self, bytes: u64, path: &Path) -> Result<(), BackendError> {
        self.entries = self.entries.checked_sub(1).ok_or_else(|| {
            BackendError::Spawn(format!(
                "output collection exceeded {MAX_OUTPUT_ENTRIES} entries at {}",
                path.display()
            ))
        })?;
        self.bytes = self.bytes.checked_sub(bytes).ok_or_else(|| {
            BackendError::Spawn(format!(
                "output collection exceeded {MAX_OUTPUT_BYTES} bytes at {}",
                path.display()
            ))
        })?;
        Ok(())
    }
}

/// An output name is a single safe path component: non-empty, no `/`, and not `.`
/// or `..` — it is a directory entry under the outputs share.
fn validate_output_name(name: &str) -> Result<(), BackendError> {
    let safe = !name.is_empty() && name != "." && name != ".." && !name.contains('/');
    if !safe {
        return Err(BackendError::Spawn(format!(
            "output name {name:?} must be a single path component (no `/`, not `.`/`..`)"
        )));
    }
    Ok(())
}

/// Copy `src` to `dest`, charging the budget. A directory is created and its
/// entries recursed, and a regular file is streamed. A symlink is skipped (never
/// followed, never recreated — see the module docs), as is any other special file
/// (fifo, socket, device).
fn copy_tree(src: &Path, dest: &Path, budget: &mut Budget) -> Result<(), BackendError> {
    let meta = fs::symlink_metadata(src).map_err(|e| err("stat output entry", src, &e))?;
    let ty = meta.file_type();

    if ty.is_symlink() {
        tracing::warn!(path = %src.display(), "skipping symlink in collected output (host-escape guard)");
        return Ok(());
    }

    budget.charge(if ty.is_file() { meta.len() } else { 0 }, src)?;

    if ty.is_dir() {
        fs::create_dir_all(dest).map_err(|e| err("create output dir", dest, &e))?;
        for entry in fs::read_dir(src).map_err(|e| err("read output dir", src, &e))? {
            let entry = entry.map_err(|e| err("read output entry", src, &e))?;
            copy_tree(&entry.path(), &dest.join(entry.file_name()), budget)?;
        }
        Ok(())
    } else if ty.is_file() {
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent).map_err(|e| err("create output parent", parent, &e))?;
        }
        stream_copy(src, dest)
    } else {
        tracing::warn!(path = %src.display(), "skipping non-regular output entry");
        Ok(())
    }
}

/// Stream `src` to `dest` a block at a time (outputs may be large).
fn stream_copy(src: &Path, dest: &Path) -> Result<(), BackendError> {
    let mut reader = fs::File::open(src).map_err(|e| err("open output file", src, &e))?;
    let mut writer = fs::File::create(dest).map_err(|e| err("create output file", dest, &e))?;
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = reader.read(&mut buf).map_err(|e| err("read output file", src, &e))?;
        if n == 0 {
            break;
        }
        io::Write::write_all(&mut writer, &buf[..n]).map_err(|e| err("write output file", dest, &e))?;
    }
    Ok(())
}

/// A named [`BackendError::Spawn`] carrying the failed op, path, and os error.
fn err(op: &str, path: &Path, e: &std::io::Error) -> BackendError {
    BackendError::Spawn(format!("{op} {}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `prepare_outputs` makes a `0700` dir with an empty writable subdir per
    /// output, and `collect_outputs` copies what the "guest" wrote to each dest.
    #[test]
    fn prepares_subdirs_and_collects_to_dest() -> anyhow::Result<()> {
        let run = tempfile::TempDir::new()?;
        let outputs_dir = run.path().join("outputs");
        let dest = run.path().join("collected");
        let outputs = [Output {
            name: Some("result".to_string()),
            dest: dest.clone(),
        }];

        let n = prepare_outputs(&outputs, &outputs_dir)?;
        assert_eq!(n, 1);
        assert_eq!(fs::metadata(&outputs_dir)?.permissions().mode() & 0o777, 0o700);
        // The "guest" writes into the share.
        fs::write(outputs_dir.join("result").join("f"), b"produced")?;
        fs::create_dir(outputs_dir.join("result").join("sub"))?;
        fs::write(outputs_dir.join("result").join("sub").join("g"), b"deep")?;

        collect_outputs(&outputs, &outputs_dir)?;

        assert_eq!(fs::read(dest.join("f"))?, b"produced");
        assert_eq!(fs::read(dest.join("sub").join("g"))?, b"deep");
        Ok(())
    }

    /// Adversarial: a symlink the "guest" drops into the share pointing at a host
    /// file is skipped during collection — neither its bytes nor the symlink itself
    /// reach the dest, so the host file is not exposed when the dest is read.
    #[test]
    fn a_symlink_escape_is_skipped() -> anyhow::Result<()> {
        let run = tempfile::TempDir::new()?;
        let outputs_dir = run.path().join("outputs");
        let dest = run.path().join("collected");
        let secret = run.path().join("host-secret");
        fs::write(&secret, b"TOP-SECRET")?;
        let outputs = [Output {
            name: Some("o".to_string()),
            dest: dest.clone(),
        }];
        prepare_outputs(&outputs, &outputs_dir)?;
        std::os::unix::fs::symlink(&secret, outputs_dir.join("o").join("leak"))?;
        fs::write(outputs_dir.join("o").join("real"), b"ok")?;

        collect_outputs(&outputs, &outputs_dir)?;

        assert!(
            fs::symlink_metadata(dest.join("leak")).is_err(),
            "the escaping symlink must not be collected at all"
        );
        // Real files alongside it are still collected.
        assert_eq!(fs::read(dest.join("real"))?, b"ok");
        Ok(())
    }

    /// No outputs prepares nothing and creates no dir.
    #[test]
    fn no_outputs_prepares_nothing() -> anyhow::Result<()> {
        let run = tempfile::TempDir::new()?;
        let outputs_dir = run.path().join("outputs");
        assert_eq!(prepare_outputs(&[], &outputs_dir)?, 0);
        assert!(!outputs_dir.exists());
        Ok(())
    }

    /// A catch-all output (`name = None`) collects everything the "guest" wrote
    /// under the output dir root — named subdirs and loose files alike.
    #[test]
    fn catch_all_collects_the_whole_output_dir() -> anyhow::Result<()> {
        let run = tempfile::TempDir::new()?;
        let outputs_dir = run.path().join("outputs");
        let dest = run.path().join("collected");
        let outputs = [Output {
            name: None,
            dest: dest.clone(),
        }];

        let n = prepare_outputs(&outputs, &outputs_dir)?;
        assert_eq!(n, 1);
        // The "guest" writes loose into the share root (no declared name).
        fs::write(outputs_dir.join("top"), b"root")?;
        fs::create_dir(outputs_dir.join("d"))?;
        fs::write(outputs_dir.join("d").join("nested"), b"deep")?;

        collect_outputs(&outputs, &outputs_dir)?;

        assert_eq!(fs::read(dest.join("top"))?, b"root");
        assert_eq!(fs::read(dest.join("d").join("nested"))?, b"deep");
        Ok(())
    }

    /// Adversarial: an output name with a separator or `..` is rejected.
    #[test]
    fn rejects_a_name_that_escapes_the_share() {
        let run = tempfile::TempDir::new().expect("tempdir");
        for bad in ["../escape", "a/b", "..", "."] {
            let outputs = [Output {
                name: Some(bad.to_string()),
                dest: run.path().join("d"),
            }];
            assert!(
                prepare_outputs(&outputs, &run.path().join("outputs")).is_err(),
                "name {bad:?} must be rejected"
            );
        }
    }
}
