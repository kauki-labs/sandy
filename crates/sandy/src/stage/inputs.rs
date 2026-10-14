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
//! keeps the guest mount static.
//!
//! An input may also declare an absolute guest path; [`stage_inputs`] then writes
//! an [`INPUT_MANIFEST_NAME`] manifest into the share and a guest boot step
//! symlinks each path to the staged entry. A no-copy direct-share variant (for
//! large inputs) is still a follow-up (#82).

use std::{fs, os::unix::fs::PermissionsExt, path::Path};

use crate::backend::{BackendError, Input};

/// The virtiofs `mountTag` for the inputs share. Fixed, not per-run, so the guest
/// can statically mount it at `/run/sandy/inputs`; it MUST match the guest flake's
/// `fileSystems` device for that mount.
pub const INPUT_MOUNT_TAG: &str = "sandy-inputs";

/// The manifest file the host writes into the inputs share when any input declares
/// a guest path. A guest boot step reads it and symlinks each `guest_path` to the
/// staged entry. Reserved: a user input may not take this name. It MUST match the
/// path the guest flake's symlink step reads.
///
/// Format: a version line (`1`), then one tab-separated record per guest-path
/// input, `name<TAB>guest_path<TAB>source<TAB>hash`. `source`/`hash` are reserved
/// for the direct-share (#82) and content-addressing work (`copy` / empty today).
/// Tab-separated, not JSON, so the tiny guest parses it with coreutils, no `jq`.
pub const INPUT_MANIFEST_NAME: &str = ".sandy-inputs";

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
    write_manifest(inputs, inputs_dir)?;
    Ok(inputs.len())
}

/// Write the inputs manifest ([`INPUT_MANIFEST_NAME`]) for every input that
/// declares a guest path, so the guest can symlink it into place. Writes nothing
/// when no input declares a path, keeping the no-guest-path run byte-for-byte as
/// before.
fn write_manifest(inputs: &[Input], inputs_dir: &Path) -> Result<(), BackendError> {
    let mut records = String::new();
    for input in inputs {
        if let Some(path) = &input.guest_path {
            // source=copy, hash empty: both reserved for #82 / content-addressing.
            records.push_str(&format!("{}\t{}\tcopy\t\n", input.name, path.to_string_lossy()));
        }
    }
    if records.is_empty() {
        return Ok(());
    }
    let body = format!("1\n{records}");
    let path = inputs_dir.join(INPUT_MANIFEST_NAME);
    fs::write(&path, body).map_err(|e| err("write input manifest", &path, &e))
}

/// An input name is a single safe path component: non-empty, no `/`, and not `.`
/// or `..`. It becomes a directory entry under the inputs share, so a separator or
/// `..` would be a path-traversal out of the staging dir.
fn validate_input_name(name: &str) -> Result<(), BackendError> {
    if name == INPUT_MANIFEST_NAME {
        return Err(BackendError::Spawn(format!(
            "input name {name:?} is reserved for the inputs manifest"
        )));
    }
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
                guest_path: None,
            },
            Input {
                host: src.path().join("tree"),
                name: "dir".to_string(),
                guest_path: None,
            },
        ];

        let n = stage_inputs(&inputs, &inputs_dir)?;

        assert_eq!(n, 2);
        assert_eq!(fs::read(inputs_dir.join("file"))?, b"hello");
        assert_eq!(fs::read(inputs_dir.join("dir").join("nested"))?, b"deep");
        let mode = fs::metadata(&inputs_dir)?.permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "inputs dir is 0700, got {mode:#o}");
        // No input declared a guest path, so no manifest is written (unchanged shape).
        assert!(
            !inputs_dir.join(INPUT_MANIFEST_NAME).exists(),
            "no manifest without a guest path"
        );
        Ok(())
    }

    /// An input with a guest path is staged under its internal name and recorded
    /// in the manifest with the reserved `source`/`hash` slots, so the guest step
    /// can symlink the path to the staged entry.
    #[test]
    fn writes_a_manifest_for_guest_path_inputs() -> anyhow::Result<()> {
        let src = tempfile::TempDir::new()?;
        fs::write(src.path().join("d"), b"data")?;
        let out = tempfile::TempDir::new()?;
        let inputs_dir = out.path().join("inputs");
        let inputs = [
            Input {
                host: src.path().join("d"),
                name: "in0".to_string(),
                guest_path: Some(std::path::PathBuf::from("/workspace/data")),
            },
            Input {
                host: src.path().join("d"),
                name: "plain".to_string(),
                guest_path: None,
            },
        ];

        stage_inputs(&inputs, &inputs_dir)?;

        let raw = fs::read_to_string(inputs_dir.join(INPUT_MANIFEST_NAME))?;
        let lines: Vec<&str> = raw.lines().collect();
        assert_eq!(lines[0], "1", "version line");
        let records: Vec<&str> = lines[1..].to_vec();
        assert_eq!(records.len(), 1, "only the guest-path input is recorded");
        let cols: Vec<&str> = records[0].split('\t').collect();
        assert_eq!(cols[0], "in0", "name");
        assert_eq!(cols[1], "/workspace/data", "guest path");
        assert_eq!(cols[2], "copy", "source slot");
        assert_eq!(cols[3], "", "hash slot reserved, empty today");
        Ok(())
    }

    /// Adversarial: an input may not take the reserved manifest name.
    #[test]
    fn rejects_the_reserved_manifest_name() -> anyhow::Result<()> {
        let src = tempfile::TempDir::new()?;
        let host = src.path().join("f");
        fs::write(&host, b"x")?;
        let out = tempfile::TempDir::new()?;
        let inputs = [Input {
            host,
            name: INPUT_MANIFEST_NAME.to_string(),
            guest_path: None,
        }];
        assert!(stage_inputs(&inputs, &out.path().join("inputs")).is_err());
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
                guest_path: None,
            }];
            assert!(
                stage_inputs(&inputs, &out.path().join("inputs")).is_err(),
                "name {bad:?} must be rejected"
            );
        }
        Ok(())
    }
}
