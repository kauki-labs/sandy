//! The sandy-owned staging base (CWE-732, #138). The check itself lives in
//! `sandy-fsutil` (#174) so light crates share it; this maps its error into the
//! backend contract.

use std::path::PathBuf;

use crate::BackendError;

/// Validate (or create) the sandy-owned staging base under the OS temp dir and
/// return its path. See [`sandy_fsutil::ensure_sandy_staging_base`].
///
/// # Errors
///
/// Returns [`BackendError::Spawn`] when the base cannot be created, is a
/// symlink, is owned by a different uid, or is group/world-writable.
pub fn ensure_sandy_staging_base() -> Result<PathBuf, BackendError> {
    sandy_fsutil::ensure_sandy_staging_base().map_err(|e| BackendError::Spawn(e.to_string()))
}
