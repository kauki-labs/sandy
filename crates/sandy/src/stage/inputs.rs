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

use sandy_api::result::ContentDigests;

use super::digest::digest_tree;
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

/// Hash the STAGED copy of each input under `inputs_dir` (#373), after
/// [`stage_inputs`] copied it and before the guest boots, so the digest names
/// what the guest will read, not whatever the host source holds by then. A
/// directory input yields one digest per regular file at `<name>/<relpath>`.
/// The manifest file is not an input and is not hashed. Opt-in
/// (`RunSpec::digests`): never called on an ordinary run.
///
/// # Errors
///
/// Returns [`BackendError::Spawn`] when a staged entry cannot be read.
pub fn digest_staged_inputs(inputs: &[Input], inputs_dir: &Path) -> Result<ContentDigests, BackendError> {
    let mut digests = ContentDigests::default();
    for input in inputs {
        digest_tree(&inputs_dir.join(&input.name), &input.name, &mut digests)?;
    }
    digests.sort();
    Ok(digests)
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

    /// #618: a symlink inside an input tree is staged as a link. The host never reads it, so the bytes of the host
    /// file it names cannot reach the guest.
    #[test]
    fn a_symlink_inside_an_input_tree_is_not_copied_by_value() -> anyhow::Result<()> {
        let src = tempfile::TempDir::new()?;
        let victim = src.path().join("victim");
        fs::write(&victim, b"HOST-SECRET")?;
        let tree = src.path().join("tree");
        fs::create_dir(&tree)?;
        fs::write(tree.join("real"), b"ok")?;
        std::os::unix::fs::symlink(&victim, tree.join("leak"))?;
        std::os::unix::fs::symlink(src.path(), tree.join("dir-leak"))?;
        let out = tempfile::TempDir::new()?;
        let inputs_dir = out.path().join("inputs");
        let inputs = [Input {
            host: tree,
            name: "dir".to_string(),
            guest_path: None,
        }];

        stage_inputs(&inputs, &inputs_dir)?;

        assert_eq!(fs::read(inputs_dir.join("dir").join("real"))?, b"ok");
        for link in ["leak", "dir-leak"] {
            let staged = inputs_dir.join("dir").join(link);
            assert!(
                fs::symlink_metadata(&staged)?.file_type().is_symlink(),
                "{link} must be staged as a link, not as the bytes it names"
            );
        }
        assert_eq!(fs::read_link(inputs_dir.join("dir").join("leak"))?, victim);
        Ok(())
    }

    /// #618: an input that is itself a symlink is refused, whatever it names: the host path may have been swapped
    /// for a link after a caller checked it.
    #[test]
    fn a_symlinked_input_is_refused() -> anyhow::Result<()> {
        let src = tempfile::TempDir::new()?;
        let victim = src.path().join("victim");
        fs::write(&victim, b"HOST-SECRET")?;
        let link = src.path().join("link");
        std::os::unix::fs::symlink(&victim, &link)?;
        let out = tempfile::TempDir::new()?;
        let inputs_dir = out.path().join("inputs");
        let inputs = [Input {
            host: link,
            name: "in".to_string(),
            guest_path: None,
        }];

        let err = stage_inputs(&inputs, &inputs_dir).expect_err("a symlinked input must be refused");

        assert!(err.to_string().contains("symlink"), "{err}");
        assert!(!inputs_dir.join("in").exists(), "nothing of the target is staged");
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

    /// #373: the digest is of the STAGED copy. A file and a directory input get
    /// known sha256 vectors under `<name>` / `<name>/<relpath>`, the manifest is
    /// not hashed, and mutating the host source after staging changes nothing.
    #[test]
    fn digests_the_staged_copy_with_known_vectors() -> anyhow::Result<()> {
        use anyhow::Context;

        const HELLO: &str = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
        const EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let src = tempfile::TempDir::new()?;
        fs::write(src.path().join("f"), b"hello")?;
        fs::create_dir(src.path().join("tree"))?;
        fs::write(src.path().join("tree").join("nested"), b"hello")?;
        fs::write(src.path().join("tree").join("empty"), b"")?;
        let out = tempfile::TempDir::new()?;
        let inputs_dir = out.path().join("inputs");
        let inputs = [
            Input {
                host: src.path().join("f"),
                name: "file".to_string(),
                guest_path: Some(std::path::PathBuf::from("/w/f")),
            },
            Input {
                host: src.path().join("tree"),
                name: "dir".to_string(),
                guest_path: None,
            },
        ];
        stage_inputs(&inputs, &inputs_dir).context("stage")?;
        // The host source changes after staging: the digest must still be the staged bytes.
        fs::write(src.path().join("f"), b"tampered")?;

        let digests = digest_staged_inputs(&inputs, &inputs_dir).context("digest")?;

        let got: Vec<(&str, &str)> = digests
            .files
            .iter()
            .map(|d| (d.path.as_str(), d.sha256.as_str()))
            .collect();
        assert_eq!(got, [("dir/empty", EMPTY), ("dir/nested", HELLO), ("file", HELLO)]);
        assert!(digests.skipped.is_empty());
        Ok(())
    }

    /// Adversarial: the staged tree is hashed without following a symlink; one
    /// planted there is recorded as skipped, not read.
    #[test]
    fn a_symlink_in_the_staged_tree_is_recorded_as_skipped() -> anyhow::Result<()> {
        use sandy_api::result::{SkipReason, SkippedEntry};

        let out = tempfile::TempDir::new()?;
        let inputs_dir = out.path().join("inputs");
        fs::create_dir_all(inputs_dir.join("d"))?;
        std::os::unix::fs::symlink("/etc/hostname", inputs_dir.join("d").join("link"))?;
        let inputs = [Input {
            host: out.path().to_path_buf(),
            name: "d".to_string(),
            guest_path: None,
        }];

        let digests = digest_staged_inputs(&inputs, &inputs_dir)?;

        assert!(digests.files.is_empty());
        assert_eq!(
            digests.skipped,
            [SkippedEntry {
                path: "d/link".to_string(),
                reason: SkipReason::Symlink
            }]
        );
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
