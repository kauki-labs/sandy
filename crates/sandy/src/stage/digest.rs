//! Content digests of a staged tree (#373): one sha256 per regular file, keyed by
//! logical path, with symlinks and special files recorded as skipped.
//!
//! Hashing is opt-in (`RunSpec::digests`); nothing here runs on an ordinary run.

use std::{fs, path::Path};

use sandy_api::{
    backend::BackendError,
    result::{ContentDigests, FileDigest, SkipReason, SkippedEntry},
};

use crate::seed::hash::sha256_hex_file;

/// Append `name` to a logical path (`<prefix>/<name>`, or the bare `name` when
/// `prefix` is empty), the convention `OutputRef::path` uses.
pub(super) fn join_logical(prefix: &str, name: &str) -> String {
    if prefix.is_empty() {
        name.to_owned()
    } else {
        format!("{prefix}/{name}")
    }
}

/// Digest every regular file under `path` into `out`, with logical path
/// `logical` (for the root) and `<logical>/<relpath>` below it. A symlink is
/// never followed: it is recorded as skipped, as is a fifo, socket, or device.
/// Files are streamed through the hasher, never read whole.
///
/// # Errors
///
/// [`BackendError::Spawn`] when an entry cannot be stat'ed, listed, or read.
pub(super) fn digest_tree(path: &Path, logical: &str, out: &mut ContentDigests) -> Result<(), BackendError> {
    let meta = fs::symlink_metadata(path).map_err(|e| err("stat digest entry", path, &e))?;
    let ty = meta.file_type();
    if ty.is_symlink() {
        out.skipped.push(SkippedEntry {
            path: logical.to_owned(),
            reason: SkipReason::Symlink,
        });
    } else if ty.is_dir() {
        for entry in fs::read_dir(path).map_err(|e| err("read digest dir", path, &e))? {
            let entry = entry.map_err(|e| err("read digest entry", path, &e))?;
            let name = entry.file_name();
            digest_tree(&entry.path(), &join_logical(logical, &name.to_string_lossy()), out)?;
        }
    } else if ty.is_file() {
        let sha256 = sha256_hex_file(path).map_err(|e| err("digest file", path, &e))?;
        out.files.push(FileDigest {
            path: logical.to_owned(),
            sha256,
        });
    } else {
        out.skipped.push(SkippedEntry {
            path: logical.to_owned(),
            reason: SkipReason::NonRegular,
        });
    }
    Ok(())
}

fn err(op: &str, path: &Path, e: &std::io::Error) -> BackendError {
    BackendError::Spawn(format!("{op} {}: {e}", path.display()))
}
