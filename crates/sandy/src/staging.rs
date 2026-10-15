//! The sandy-owned staging base (CWE-732, #138): validates the host staging
//! root before any backend stages secrets or inputs under it, so a local
//! attacker who pre-creates a world-writable or symlinked base cannot redirect
//! staged bytes into a path they control.
//!
//! [`ensure_sandy_staging_base`] creates the base `0700`, owned by the current
//! uid, the first time; on every later call it re-verifies those same
//! properties and fails closed rather than repairing a base it no longer
//! trusts — a world-writable or wrong-owner base is rejected, never silently
//! chmod'd back into shape.

use std::path::{Path, PathBuf};

use rustix::fs::{Mode, OFlags, fstat, mkdirat, open, openat};

use crate::BackendError;

const STAGING_DIR_NAME: &str = "sandy";

/// Mode bits that would let group or other write into the staging base.
const GROUP_OTHER_WRITE: u32 = 0o022;

/// Validate (or create) the sandy-owned staging base under the OS temp dir and
/// return its path.
///
/// # Errors
///
/// Returns [`BackendError::Spawn`] when the base cannot be created, is a
/// symlink, is owned by a different uid, or is group/world-writable.
pub fn ensure_sandy_staging_base() -> Result<PathBuf, BackendError> {
    ensure_staging_base_in(&std::env::temp_dir())
}

/// Same validation as [`ensure_sandy_staging_base`], against an injected
/// `parent` rather than `std::env::temp_dir()` — tests use this to run fully
/// isolated from the real `/tmp/sandy`, without the `unsafe` `env::set_var`
/// edition-2024 forbids under this workspace's `unsafe_code = "forbid"` lint.
///
/// `parent` itself is opened following symlinks (macOS's `/tmp` legitimately
/// is one, pointing at `/private/tmp`); only the staging dir name underneath
/// it is opened with `O_NOFOLLOW`, so a symlink planted at that name — before
/// `mkdirat` or racing right after it — is rejected rather than followed,
/// whether the base was just created or already existed.
///
/// This assumes `parent` itself is not attacker-writable (true for a
/// sticky-bit `/tmp` or a per-user `$TMPDIR`): once the base passes
/// validation below, nothing can be swapped underneath it only while
/// `parent` stays out of attacker control. A world-writable, non-sticky
/// `TMPDIR` is out of scope for this check.
fn ensure_staging_base_in(parent: &Path) -> Result<PathBuf, BackendError> {
    let base = parent.join(STAGING_DIR_NAME);
    let parent_fd = open(
        parent,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| staging_err("open staging parent", parent, &e))?;

    match mkdirat(&parent_fd, STAGING_DIR_NAME, Mode::RWXU) {
        Ok(()) => {}
        Err(rustix::io::Errno::EXIST) => {} // already exists — validated below
        Err(e) => return Err(staging_err("create sandy staging base", &base, &e)),
    }

    let base_fd = openat(
        &parent_fd,
        STAGING_DIR_NAME,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| staging_err("open sandy staging base (symlinked base?)", &base, &e))?;

    let stat = fstat(&base_fd).map_err(|e| staging_err("stat sandy staging base", &base, &e))?;
    let current_uid = rustix::process::getuid().as_raw();
    // `st_mode` is `u16` on macOS and `u32` on Linux: the conversion is needed on
    // macOS and a no-op clippy flags as `useless_conversion` on Linux.
    #[allow(clippy::useless_conversion)]
    let mode = u32::from(stat.st_mode);
    validate_owner_and_mode(stat.st_uid, current_uid, mode)
        .map_err(|e| BackendError::Spawn(format!("{e} (base: {})", base.display())))?;

    Ok(base)
}

/// Pure check, isolated from the filesystem so the owner-mismatch and
/// bad-mode paths are unit-testable without needing a second uid or root:
/// `uid` must match `current_uid`, and `mode` must carry no group/world write
/// bit. A failure here is fail-closed and final — the base is never
/// chmod'd/chowned back into shape (CWE-732, INV-1).
fn validate_owner_and_mode(uid: u32, current_uid: u32, mode: u32) -> Result<(), BackendError> {
    if uid != current_uid {
        return Err(BackendError::Spawn(format!(
            "sandy staging base is owned by uid {uid}, not the current uid {current_uid}; refusing to stage"
        )));
    }
    if mode & GROUP_OTHER_WRITE != 0 {
        return Err(BackendError::Spawn(format!(
            "sandy staging base is group/world-writable (mode {mode:#o}); refusing to stage"
        )));
    }
    Ok(())
}

fn staging_err(action: &str, path: &Path, err: &rustix::io::Errno) -> BackendError {
    BackendError::Spawn(format!("{action} at {}: {err}", path.display()))
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{PermissionsExt, symlink};

    use anyhow::Context;

    use super::*;

    /// Positive: a clean, self-owned base is created `0700` and the path is
    /// returned.
    #[test]
    fn clean_self_owned_base_is_ok() -> anyhow::Result<()> {
        let tmp = tempfile::TempDir::new().context("tempdir")?;

        let base = ensure_staging_base_in(tmp.path()).expect("clean base must validate");

        let mode = std::fs::metadata(&base).context("stat base")?.permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "freshly created base must be 0700, got {mode:#o}");
        Ok(())
    }

    /// Adversarial (CWE-732): a pre-created world-writable base must be
    /// rejected outright — fail closed, not a silent downgrade.
    #[test]
    fn world_writable_existing_base_is_rejected() -> anyhow::Result<()> {
        let tmp = tempfile::TempDir::new().context("tempdir")?;
        let base = tmp.path().join("sandy");
        std::fs::create_dir(&base).context("pre-create base")?;
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o777)).context("widen perms")?;

        let err = ensure_staging_base_in(tmp.path()).expect_err("a world-writable base must be rejected");

        assert!(
            err.to_string().contains("group/world-writable"),
            "expected a group/world-writable rejection, got {err}"
        );
        Ok(())
    }

    /// Adversarial (CWE-732): a base that is a symlink to an attacker-chosen
    /// directory must be rejected, not followed. `attacker_dir` is pinned to
    /// `0700` so this fails only via the `O_NOFOLLOW` symlink rejection —
    /// without the pin, a lenient create-dir umask (e.g. `0002` on
    /// user-private-group distros) could make `attacker_dir` group-writable
    /// and the test would pass for the wrong reason (the mode check, not the
    /// symlink check) if `O_NOFOLLOW` were ever dropped.
    #[test]
    fn symlinked_base_is_rejected() -> anyhow::Result<()> {
        let tmp = tempfile::TempDir::new().context("tempdir")?;
        let attacker_dir = tmp.path().join("attacker-controlled");
        std::fs::create_dir(&attacker_dir).context("create attacker dir")?;
        std::fs::set_permissions(&attacker_dir, std::fs::Permissions::from_mode(0o700))
            .context("pin attacker perms")?;
        let base = tmp.path().join("sandy");
        symlink(&attacker_dir, &base).context("symlink base")?;

        let err = ensure_staging_base_in(tmp.path()).expect_err("a symlinked base must be rejected");

        assert!(
            err.to_string().contains("symlinked base?"),
            "expected the symlink-rejection open to fail, got {err}"
        );
        Ok(())
    }

    /// Pure unit coverage for the owner/mode check, independent of real
    /// filesystem ownership: simulating a different uid needs root (there is
    /// no in-process way to create a file owned by another uid), so this
    /// exercises the comparison logic directly with a synthetic uid instead.
    #[test]
    fn owner_mismatch_is_rejected() {
        let result = validate_owner_and_mode(999, 1000, 0o700);
        assert!(result.is_err(), "a uid mismatch must be rejected: {result:?}");
    }

    #[test]
    fn group_write_bit_is_rejected() {
        let result = validate_owner_and_mode(1000, 1000, 0o720);
        assert!(result.is_err(), "a group-writable mode must be rejected: {result:?}");
    }

    #[test]
    fn world_write_bit_is_rejected() {
        let result = validate_owner_and_mode(1000, 1000, 0o702);
        assert!(result.is_err(), "a world-writable mode must be rejected: {result:?}");
    }

    #[test]
    fn clean_owner_and_mode_is_ok() {
        let result = validate_owner_and_mode(1000, 1000, 0o700);
        assert!(result.is_ok(), "self-owned 0700 must validate: {result:?}");
    }
}
