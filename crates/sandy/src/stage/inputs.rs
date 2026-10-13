//! Input staging: expose read-only host paths to the guest under one fixed-tag
//! share, mounted at `/run/sandy/inputs`.
//!
//! Each `--input HOST:NAME` is copied into a freshly created `0700` staging dir
//! as `<name>`; the backend shares that dir read-only (tag [`INPUT_MOUNT_TAG`]),
//! and the guest mounts it at `/run/sandy/inputs`, so the job reads an input at
//! `/run/sandy/inputs/<name>`. The share is read-only, so a write fails `EROFS`.
//!
//! Inputs are copied (not bind-mounted) so multiple arbitrary host paths share
//! one fixed tag — the same single-share shape the secret channel uses, which
//! keeps the guest mount static. A no-copy / arbitrary-guest-path variant is a
//! follow-up (#34).

use std::{fs, os::unix::fs::PermissionsExt, path::Path};

use crate::backend::{BackendError, Input};

/// The virtiofs `mountTag` for the inputs share. Fixed, not per-run, so the guest
/// can statically mount it at `/run/sandy/inputs`; it MUST match the guest flake's
/// `fileSystems` device for that mount.
pub const INPUT_MOUNT_TAG: &str = "sandy-inputs";

/// Stage each input under `inputs_dir/<name>` in a freshly created `0700` dir,
/// copying the host file or directory tree.
///
/// Returns the number of inputs staged; `0` means the backend attaches no share
/// (the guest mount is `nofail`, so a run with no inputs still boots).
///
/// # Errors
///
/// Returns [`BackendError::Spawn`] when `inputs_dir` cannot be prepared, an input
/// name is not a single safe path component, or a host source cannot be read or
/// copied.
pub fn stage_inputs(inputs: &[Input], inputs_dir: &Path) -> Result<usize, BackendError> {
    if inputs.is_empty() {
        return Ok(0);
    }
    fs::create_dir_all(inputs_dir).map_err(|e| err("create inputs dir", inputs_dir, &e))?;
    fs::set_permissions(inputs_dir, fs::Permissions::from_mode(0o700))
        .map_err(|e| err("tighten inputs dir to 0700", inputs_dir, &e))?;

    for input in inputs {
        validate_input_name(&input.name)?;
        copy_path(&input.host, &inputs_dir.join(&input.name))?;
        tracing::debug!(name = %input.name, host = %input.host.display(), "staged input (ro)");
    }
    Ok(inputs.len())
}

/// An input name is a single safe path component: non-empty, no `/`, and not `.`
/// or `..`. It becomes a directory entry under the inputs share, so a separator or
/// `..` would be a path-traversal out of the staging dir.
fn validate_input_name(name: &str) -> Result<(), BackendError> {
    let safe = !name.is_empty() && name != "." && name != ".." && !name.contains('/');
    if !safe {
        return Err(BackendError::Spawn(format!(
            "input name {name:?} must be a single path component (no `/`, not `.`/`..`)"
        )));
    }
    Ok(())
}

/// Copy `src` (a file or directory tree) to `dest`. Directories are created and
/// recursed; files are copied. `symlink_metadata` is used so a symlinked directory
/// is not recursed into as if it were real.
fn copy_path(src: &Path, dest: &Path) -> Result<(), BackendError> {
    let meta = fs::symlink_metadata(src).map_err(|e| err("stat input source", src, &e))?;
    if meta.is_dir() {
        fs::create_dir_all(dest).map_err(|e| err("create input subdir", dest, &e))?;
        for entry in fs::read_dir(src).map_err(|e| err("read input dir", src, &e))? {
            let entry = entry.map_err(|e| err("read input entry", src, &e))?;
            copy_path(&entry.path(), &dest.join(entry.file_name()))?;
        }
        Ok(())
    } else {
        fs::copy(src, dest).map(|_| ()).map_err(|e| err("copy input", src, &e))
    }
}

/// A named [`BackendError::Spawn`] carrying the failed op, path, and os error.
fn err(op: &str, path: &Path, e: &std::io::Error) -> BackendError {
    BackendError::Spawn(format!("{op} {}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    /// A file and a nested directory input are both copied under their names into
    /// a `0700` staging dir, so the guest sees `/run/sandy/inputs/<name>`.
    #[test]
    fn stages_a_file_and_a_directory_under_their_names() -> anyhow::Result<()> {
        let src = tempfile::TempDir::new()?;
        fs::write(src.path().join("f.txt"), b"hello")?;
        fs::create_dir(src.path().join("tree"))?;
        fs::write(src.path().join("tree").join("nested"), b"deep")?;

        let out = tempfile::TempDir::new()?;
        let inputs_dir = out.path().join("inputs");
        let inputs = [
            Input {
                host: src.path().join("f.txt"),
                name: "file".to_string(),
            },
            Input {
                host: src.path().join("tree"),
                name: "dir".to_string(),
            },
        ];

        let n = stage_inputs(&inputs, &inputs_dir)?;

        assert_eq!(n, 2);
        assert_eq!(fs::read(inputs_dir.join("file"))?, b"hello");
        assert_eq!(fs::read(inputs_dir.join("dir").join("nested"))?, b"deep");
        let mode = fs::metadata(&inputs_dir)?.permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "inputs dir is 0700, got {mode:#o}");
        Ok(())
    }

    /// No inputs stages nothing and creates no dir (the share is simply not
    /// attached, and the guest mount is `nofail`).
    #[test]
    fn no_inputs_stages_nothing() -> anyhow::Result<()> {
        let out = tempfile::TempDir::new()?;
        let inputs_dir = out.path().join("inputs");
        assert_eq!(stage_inputs(&[], &inputs_dir)?, 0);
        assert!(!inputs_dir.exists(), "no inputs dir is created for an empty input set");
        Ok(())
    }

    /// Adversarial: an input name with a path separator or `..` is rejected, not
    /// staged outside the share.
    #[test]
    fn rejects_a_name_that_escapes_the_share() -> anyhow::Result<()> {
        let src = tempfile::TempDir::new()?;
        let host = src.path().join("f");
        fs::write(&host, b"x")?;
        let out = tempfile::TempDir::new()?;
        for bad in ["../escape", "a/b", "..", "."] {
            let inputs = [Input {
                host: host.clone(),
                name: bad.to_string(),
            }];
            assert!(
                stage_inputs(&inputs, &out.path().join("inputs")).is_err(),
                "name {bad:?} must be rejected"
            );
        }
        Ok(())
    }
}
