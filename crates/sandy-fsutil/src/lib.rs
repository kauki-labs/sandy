//! Security-sensitive filesystem primitives, in one place so every sandy crate
//! (the core, the backends, the light fabric impls) uses the same code (#174).
//!
//! - [`staging`]: the sandy-owned staging base under the OS temp dir (CWE-732, #138, #141).
//! - [`secret`]: an [`OwnedDir`] handle and the `0600` secret writer every secret staging path goes through (INV-1).
//!
//! Everything works through directory handles (`openat`, `renameat`, `fstat` on
//! the opened fd), never a path re-resolved after it was checked, and refuses to
//! follow a symlink where one could redirect a write.

use std::{
    io,
    path::{Path, PathBuf},
};

pub mod secret;
pub mod staging;

pub use secret::{OwnedDir, private_staging_dir};
pub use staging::{ensure_sandy_staging_base, ensure_staging_base_in};

/// A filesystem operation failed, or a path was refused as unsafe.
#[derive(Debug, thiserror::Error)]
pub enum FsError {
    /// An I/O call failed.
    #[error("{action} at {}: {source}", path.display())]
    Io {
        /// What was being done.
        action: &'static str,
        /// The path it was done to.
        path: PathBuf,
        /// The underlying error.
        source: io::Error,
    },
    /// The path exists but is not safe to use: wrong owner, too-wide mode, a
    /// non-sticky world-writable parent. The reason names the rule.
    #[error("{reason} ({})", path.display())]
    Unsafe {
        /// The refused path.
        path: PathBuf,
        /// Why it was refused.
        reason: String,
    },
}

impl FsError {
    fn io(action: &'static str, path: &Path, source: impl Into<io::Error>) -> Self {
        Self::Io {
            action,
            path: path.to_owned(),
            source: source.into(),
        }
    }
}

/// fsync a directory so a preceding create or rename within it survives a crash.
pub fn fsync_dir(dir: &Path) -> io::Result<()> {
    std::fs::File::open(dir)?.sync_all()
}
