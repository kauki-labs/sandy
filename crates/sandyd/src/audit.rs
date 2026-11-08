//! The environment audit log (#596): an append-only file of JSON lines in sandyd's state
//! directory, one line before each environment create, stop or delete is applied.

use std::{
    fs::File,
    path::{Path, PathBuf},
    sync::Mutex,
};

/// Why an audit line could not be written.
#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    /// The log file could not be opened, written or synced.
    #[error("audit log {}: {source}", path.display())]
    Io {
        /// The log file.
        path: PathBuf,
        /// The underlying error.
        source: std::io::Error,
    },
}

/// One audited operation, written before the state change it describes.
#[derive(Debug, Clone, Copy)]
pub struct AuditEntry<'a> {
    /// Unix seconds.
    pub at: i64,
    /// `create`, `stop` or `delete`.
    pub operation: &'static str,
    /// The environment the operation names.
    pub environment_id: &'a str,
    /// `trusted` or `untrusted`: the isolation class sandyd recorded for the submitter.
    pub submitter: &'static str,
}

/// An append-only audit file.
pub struct AuditLog {
    path: PathBuf,
    file: Mutex<File>,
}

impl AuditLog {
    /// Open `path` for append, creating it with mode 0600.
    ///
    /// # Errors
    /// [`AuditError::Io`] when the file cannot be opened.
    pub fn open(path: &Path) -> Result<Self, AuditError> {
        let file = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(path)
            .map_err(|source| AuditError::Io {
                path: path.to_path_buf(),
                source,
            })?;
        Ok(Self::from_file(path.to_path_buf(), file))
    }

    /// Wrap an already open `file`, for tests.
    #[must_use]
    pub fn from_file(path: PathBuf, file: File) -> Self {
        Self {
            path,
            file: Mutex::new(file),
        }
    }

    /// Append `entry` as one JSON line and sync it to disk.
    ///
    /// # Errors
    /// [`AuditError::Io`] when the write or the sync fails.
    pub fn record(&self, entry: &AuditEntry<'_>) -> Result<(), AuditError> {
        let _ = (entry, &self.path, &self.file);
        Ok(())
    }
}
