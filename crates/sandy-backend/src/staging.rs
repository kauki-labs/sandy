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

use sandy::BackendError;

const STAGING_DIR_NAME: &str = "sandy";

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
/// # Placeholder (pre-fix)
///
/// This currently reproduces the vulnerable behaviour the three backends had
/// inline: it joins the path and creates it with the process default mode,
/// without checking ownership, write bits, or following symlinks. The
/// adversarial tests in this module are written against the fixed contract
/// above and are expected to fail against this placeholder.
fn ensure_staging_base_in(parent: &Path) -> Result<PathBuf, BackendError> {
    let base = parent.join(STAGING_DIR_NAME);
    std::fs::create_dir_all(&base)
        .map_err(|e| BackendError::Spawn(format!("create staging base {}: {e}", base.display())))?;
    Ok(base)
}

/// Placeholder (pre-fix): always accepts, matching the inline sites' total
/// absence of an owner/mode check. Replaced by the real comparison next.
fn validate_owner_and_mode(_uid: u32, _current_uid: u32, _mode: u32) -> Result<(), BackendError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{PermissionsExt, symlink};

    use super::*;

    /// Positive: a clean, self-owned base is created `0700` and the path is
    /// returned.
    #[test]
    fn clean_self_owned_base_is_ok() {
        let tmp = tempfile::TempDir::new().expect("tempdir");

        let base = ensure_staging_base_in(tmp.path()).expect("clean base must validate");

        let mode = std::fs::metadata(&base).expect("stat base").permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "freshly created base must be 0700, got {mode:#o}");
    }

    /// Adversarial (CWE-732): a pre-created world-writable base must be
    /// rejected outright — fail closed, not a silent downgrade.
    #[test]
    fn world_writable_existing_base_is_rejected() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let base = tmp.path().join("sandy");
        std::fs::create_dir(&base).expect("pre-create base");
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o777)).expect("widen perms");

        let result = ensure_staging_base_in(tmp.path());

        assert!(
            result.is_err(),
            "a world-writable base must be rejected, not returned as usable: {result:?}"
        );
    }

    /// Adversarial (CWE-732): a base that is a symlink to an attacker-chosen
    /// directory must be rejected, not followed.
    #[test]
    fn symlinked_base_is_rejected() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let attacker_dir = tmp.path().join("attacker-controlled");
        std::fs::create_dir(&attacker_dir).expect("create attacker dir");
        let base = tmp.path().join("sandy");
        symlink(&attacker_dir, &base).expect("symlink base");

        let result = ensure_staging_base_in(tmp.path());

        assert!(
            result.is_err(),
            "a symlinked base must be rejected, not followed: {result:?}"
        );
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
