//! The environment audit log (#596): an append-only file of JSON lines in sandyd's state
//! directory, one line before each environment create, stop or delete is applied.

use std::{
    fs::File,
    io::Write,
    os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::{Mutex, PoisonError},
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
    /// `trusted` or `untrusted`: the isolation class sandyd recorded when the environment was
    /// created. For a stop or delete it is the creator's class, not the caller's.
    pub submitter_class: &'static str,
}

/// An append-only audit file.
pub struct AuditLog {
    path: PathBuf,
    state: Mutex<State>,
}

struct State {
    file: File,
    /// Set when a failed write could not be cut back: a fragment may sit at the end of the file,
    /// so every later line is refused until the operator restarts sandyd on a repaired log.
    blocked: bool,
}

impl AuditLog {
    /// Open `path` for append, creating it with mode 0600. A symlink at `path`, a file that is not
    /// a regular file, a file with a second hard link, and a file another user owns are refused.
    ///
    /// # Errors
    /// [`AuditError::Io`] when the file cannot be opened or is not safe to append to.
    pub fn open(path: &Path) -> Result<Self, AuditError> {
        let io = |source| AuditError::Io {
            path: path.to_path_buf(),
            source,
        };
        let file = std::fs::OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .mode(0o600)
            // NONBLOCK so a FIFO at the path fails the open instead of hanging startup; it has no
            // effect on a regular file, and the check below refuses anything else.
            .custom_flags(
                (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK)
                    .bits()
                    .cast_signed(),
            )
            .open(path)
            .map_err(io)?;
        let meta = file.metadata().map_err(io)?;
        let unsafe_file = !meta.is_file()
            || meta.uid() != rustix::process::geteuid().as_raw()
            || meta.mode() & 0o077 != 0
            || meta.nlink() != 1;
        if unsafe_file {
            return Err(io(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "the audit log must be a regular file with one name, owned by this user, mode 0600",
            )));
        }
        // A daemon killed during a write can leave a cut-off line. Appending to it would join two
        // records into one that does not parse, so the operator repairs the file first.
        if meta.len() > 0 {
            let mut last = [0_u8; 1];
            file.read_exact_at(&mut last, meta.len() - 1).map_err(io)?;
            if last[0] != b'\n' {
                return Err(io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "the audit log ends in an incomplete line; repair or move the file",
                )));
            }
        }
        Ok(Self::from_file(path.to_path_buf(), file))
    }

    /// Wrap an already open `file`, for tests.
    #[must_use]
    pub fn from_file(path: PathBuf, file: File) -> Self {
        Self {
            path,
            state: Mutex::new(State { file, blocked: false }),
        }
    }

    fn record_using(
        &self,
        entry: &AuditEntry<'_>,
        write: impl FnOnce(&mut File, &[u8]) -> std::io::Result<()>,
    ) -> Result<(), AuditError> {
        let line = serde_json::json!({
            "at": entry.at,
            "operation": entry.operation,
            "environment_id": entry.environment_id,
            "submitter_class": entry.submitter_class,
            // The line is written before the change, so the change may still be refused.
            "outcome": "attempted",
        });
        let mut bytes = line.to_string().into_bytes();
        bytes.push(b'\n');
        let io = |source| AuditError::Io {
            path: self.path.clone(),
            source,
        };
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if state.blocked {
            return Err(io(std::io::Error::other(
                "the audit log is blocked after a failed write that could not be cut back",
            )));
        }
        let before = state.file.metadata().map_err(io)?.len();
        let written = write(&mut state.file, &bytes).and_then(|()| state.file.sync_data());
        if let Err(source) = written {
            // A write that failed part way (a full disk) must not leave a fragment that the next
            // line would be appended to. If the cut back fails too, refuse every later line.
            if state.file.set_len(before).is_err() {
                state.blocked = true;
            }
            return Err(io(source));
        }
        Ok(())
    }

    /// Append `entry` as one JSON line and sync it to disk.
    ///
    /// # Errors
    /// [`AuditError::Io`] when the write or the sync fails.
    pub fn record(&self, entry: &AuditEntry<'_>) -> Result<(), AuditError> {
        self.record_using(entry, |file, bytes| file.write_all(bytes))
    }
}

/// Whether `a` and `b` name one existing file, by device and inode.
#[must_use]
pub fn same_file(a: &Path, b: &Path) -> bool {
    match (std::fs::metadata(a), std::fs::metadata(b)) {
        (Ok(a), Ok(b)) => a.dev() == b.dev() && a.ino() == b.ino(),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use anyhow::{Context, Result};

    use super::*;

    fn entry(id: &str) -> AuditEntry<'_> {
        AuditEntry {
            at: 1,
            operation: "create",
            environment_id: id,
            submitter_class: "trusted",
        }
    }

    #[test]
    fn a_new_log_is_mode_0600_and_a_reopened_one_keeps_appending() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("audit.jsonl");
        AuditLog::open(&path)?.record(&entry("env-1"))?;
        AuditLog::open(&path)?.record(&entry("env-2"))?;
        assert_eq!(std::fs::metadata(&path)?.mode() & 0o777, 0o600);
        assert_eq!(std::fs::read_to_string(&path)?.lines().count(), 2);
        Ok(())
    }

    #[test]
    fn a_log_another_user_could_read_or_a_symlink_is_refused() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir()?;
        let loose = dir.path().join("loose.jsonl");
        std::fs::write(&loose, "")?;
        std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o644))?;
        assert!(AuditLog::open(&loose).is_err(), "a world-readable log is refused");
        let link = dir.path().join("link.jsonl");
        std::os::unix::fs::symlink(&loose, &link)?;
        assert!(AuditLog::open(&link).is_err(), "a symlink is refused");
        Ok(())
    }

    #[test]
    fn a_line_carries_the_fields_and_the_environment_id_is_data_not_markup() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("audit.jsonl");
        AuditLog::open(&path)?.record(&entry("a\"b\nc"))?;
        let text = std::fs::read_to_string(&path)?;
        assert_eq!(text.lines().count(), 1, "a newline in a field must not split the line");
        let v: serde_json::Value = serde_json::from_str(text.trim_end()).context("one JSON object")?;
        assert_eq!(v["environment_id"], "a\"b\nc");
        assert_eq!(v["outcome"], "attempted");
        Ok(())
    }

    #[test]
    fn a_fifo_at_the_path_is_refused_instead_of_blocking_startup() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("audit.jsonl");
        let made = std::process::Command::new("mkfifo")
            .arg(&path)
            .status()
            .context("run mkfifo")?;
        assert!(made.success(), "mkfifo must work on the test host");
        assert!(AuditLog::open(&path).is_err(), "a FIFO is not a log file");
        Ok(())
    }

    #[test]
    fn a_hard_link_to_another_file_is_refused() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let first = dir.path().join("a.jsonl");
        AuditLog::open(&first)?.record(&entry("env-1"))?;
        let second = dir.path().join("b.jsonl");
        std::fs::hard_link(&first, &second)?;
        assert!(AuditLog::open(&second).is_err(), "a log with a second name is refused");
        Ok(())
    }

    #[test]
    fn a_log_that_ends_in_a_cut_off_line_is_refused_until_repaired() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("audit.jsonl");
        std::fs::write(&path, "{\"at\":1}\n{\"at\"")?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        assert!(
            AuditLog::open(&path).is_err(),
            "a fragment at the end would swallow the next line"
        );
        std::fs::write(&path, "{\"at\":1}\n")?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        AuditLog::open(&path)?.record(&entry("env-1"))?;
        Ok(())
    }

    #[test]
    fn a_write_that_fails_part_way_is_cut_back_and_the_next_line_parses() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("audit.jsonl");
        let log = AuditLog::open(&path)?;
        log.record(&entry("env-1"))?;
        let before = std::fs::read_to_string(&path)?;
        let failed = log.record_using(&entry("env-2"), |file, bytes| {
            file.write_all(&bytes[..bytes.len() / 2])?;
            Err(std::io::Error::other("disk full"))
        });
        assert!(failed.is_err());
        assert_eq!(std::fs::read_to_string(&path)?, before, "the fragment is removed");
        log.record(&entry("env-3"))?;
        for line in std::fs::read_to_string(&path)?.lines() {
            serde_json::from_str::<serde_json::Value>(line).context("every line parses")?;
        }
        Ok(())
    }

    #[test]
    fn a_log_whose_cut_back_fails_blocks_every_later_line() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("audit.jsonl");
        std::fs::write(&path, "")?;
        let log = AuditLog::from_file(path.clone(), std::fs::File::open(&path)?);
        assert!(
            log.record(&entry("env-1")).is_err(),
            "a read-only file cannot be written"
        );
        let blocked = log
            .record(&entry("env-2"))
            .err()
            .context("a later line must be refused")?;
        assert!(blocked.to_string().contains("blocked"), "{blocked}");
        Ok(())
    }

    #[test]
    fn two_paths_to_one_file_are_the_same_file() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let a = dir.path().join("a");
        std::fs::write(&a, "")?;
        let b = dir.path().join("b");
        std::fs::hard_link(&a, &b)?;
        let c = dir.path().join("c");
        std::fs::write(&c, "")?;
        assert!(same_file(&a, &b));
        assert!(!same_file(&a, &c));
        assert!(!same_file(&a, &dir.path().join("missing")));
        Ok(())
    }
}
