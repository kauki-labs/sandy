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

use crate::FsError;

const STAGING_DIR_NAME: &str = "sandy";

/// Mode bits that would let group or other write into the staging base.
const GROUP_OTHER_WRITE: u32 = 0o022;

/// Other-write bit (`S_IWOTH`): on the staging *parent*, it is only safe when the
/// parent is also sticky (see [`validate_parent_sticky`]).
const OTHER_WRITE: u32 = 0o002;

/// Sticky bit (`S_ISVTX`): on a world-writable directory it restricts rename/unlink
/// to the entry's owner, which is what makes a shared `/tmp` (`01777`) safe to stage
/// under.
const STICKY: u32 = 0o1000;

/// Validate (or create) the sandy-owned staging base under the OS temp dir and
/// return its path.
///
/// # Errors
///
/// Returns [`FsError`] when the base cannot be created, is a symlink, is owned
/// by a different uid, or is group/world-writable.
pub fn ensure_sandy_staging_base() -> Result<PathBuf, FsError> {
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
/// The parent must not be attacker-writable: a world-writable `parent` without
/// the sticky bit lets an attacker who controls it swap the base underneath our
/// validation, so it is rejected (#141, `validate_parent_sticky`). A sticky
/// `/tmp` (`01777`) or a private `$TMPDIR` (`0700`) passes. The check `fstat`s the
/// same `parent_fd` the base is created/opened relative to, so it is TOCTOU-safe.
pub fn ensure_staging_base_in(parent: &Path) -> Result<PathBuf, FsError> {
    let base = parent.join(STAGING_DIR_NAME);
    let parent_fd = open(
        parent,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| staging_err("open staging parent", parent, &e))?;

    // Defence in depth (#141): reject a world-writable, non-sticky parent before
    // trusting anything created under it. fstat on the already-open fd, not a path.
    let parent_stat = fstat(&parent_fd).map_err(|e| staging_err("stat staging parent", parent, &e))?;
    #[allow(clippy::useless_conversion)]
    let parent_mode = u32::from(parent_stat.st_mode);
    validate_parent_sticky(parent_mode).map_err(|reason| FsError::Unsafe {
        path: parent.to_owned(),
        reason,
    })?;

    match mkdirat(&parent_fd, STAGING_DIR_NAME, Mode::RWXU) {
        // Just created: the umask may have cleared bits from 0700, even the
        // owner's read bit, which would make it unopenable (#204). An existing
        // base is never repaired, only validated below.
        Ok(()) => {
            if let Err(e) = crate::secret::chmod_new_dir_0700(&parent_fd, std::ffi::OsStr::new(STAGING_DIR_NAME)) {
                // Best effort: never leave a half-set-up base to block a retry.
                let _ = rustix::fs::unlinkat(&parent_fd, STAGING_DIR_NAME, rustix::fs::AtFlags::REMOVEDIR);
                return Err(staging_err("set sandy staging base to 0700", &base, &e));
            }
        }
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
    validate_owner_and_mode("sandy staging base", stat.st_uid, current_uid, mode).map_err(|reason| {
        FsError::Unsafe {
            path: base.clone(),
            reason,
        }
    })?;

    Ok(base)
}

/// Pure check, isolated from the filesystem so the owner-mismatch and
/// bad-mode paths are unit-testable without needing a second uid or root:
/// `uid` must match `current_uid`, and `mode` must carry no group/world write
/// bit. `what` names the directory in the refusal. A failure here is fail-closed
/// and final — the directory is never chmod'd/chowned back into shape (CWE-732,
/// INV-1).
pub(crate) fn validate_owner_and_mode(what: &str, uid: u32, current_uid: u32, mode: u32) -> Result<(), String> {
    if uid != current_uid {
        return Err(format!(
            "{what} is owned by uid {uid}, not the current uid {current_uid}; refusing to stage"
        ));
    }
    if mode & GROUP_OTHER_WRITE != 0 {
        return Err(format!(
            "{what} is group/world-writable (mode {mode:#o}); refusing to stage"
        ));
    }
    Ok(())
}

/// A world-writable staging parent must carry the sticky bit (`S_ISVTX`), or an
/// attacker who controls the parent could swap the validated base out underneath us
/// (CWE-732, #141). A sticky `/tmp` (`01777`) or a private `$TMPDIR` (`0700`) passes;
/// a world-writable non-sticky parent fails closed. Pure, so the reject path is
/// unit-testable without a real world-writable directory.
fn validate_parent_sticky(parent_mode: u32) -> Result<(), String> {
    if parent_mode & OTHER_WRITE != 0 && parent_mode & STICKY == 0 {
        return Err(format!(
            "staging parent is world-writable without the sticky bit (mode {parent_mode:#o}); an attacker controlling \
             it could redirect staged bytes; refusing to stage"
        ));
    }
    Ok(())
}

fn staging_err(action: &'static str, path: &Path, err: &rustix::io::Errno) -> FsError {
    FsError::io(action, path, *err)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{PermissionsExt, symlink};

    use anyhow::Context;

    use super::*;

    /// A `0700` temp dir, whatever the umask, so the fixture never depends on it.
    fn private_tmp() -> anyhow::Result<tempfile::TempDir> {
        let tmp = tempfile::TempDir::new().context("tempdir")?;
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).context("chmod tempdir")?;
        Ok(tmp)
    }

    /// Positive: a clean, self-owned base is created `0700` and the path is
    /// returned.
    #[test]
    fn clean_self_owned_base_is_ok() -> anyhow::Result<()> {
        let tmp = private_tmp()?;

        let base = ensure_staging_base_in(tmp.path()).expect("clean base must validate");

        let mode = std::fs::metadata(&base).context("stat base")?.permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "freshly created base must be 0700, got {mode:#o}");
        Ok(())
    }

    /// #204: a umask that clears the owner's read bit (0400 makes mkdir's 0700
    /// into 0300) must not leave a base that cannot be opened.
    /// The umask is process-wide; nextest runs each test in its own process.
    #[test]
    fn a_new_base_survives_a_umask_that_clears_owner_read() -> anyhow::Result<()> {
        let tmp = private_tmp()?;
        let previous = rustix::process::umask(Mode::from_raw_mode(0o400));
        let base = ensure_staging_base_in(tmp.path());
        rustix::process::umask(previous);
        let base = base?;
        let mode = std::fs::metadata(&base).context("stat base")?.permissions().mode() & 0o777;
        anyhow::ensure!(mode == 0o700, "a created base came out {mode:#o}");
        Ok(())
    }

    /// Adversarial (CWE-732): a pre-created world-writable base must be
    /// rejected outright — fail closed, not a silent downgrade.
    #[test]
    fn world_writable_existing_base_is_rejected() -> anyhow::Result<()> {
        let tmp = private_tmp()?;
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
        let tmp = private_tmp()?;
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
        let result = validate_owner_and_mode("base", 999, 1000, 0o700);
        assert!(result.is_err(), "a uid mismatch must be rejected: {result:?}");
    }

    #[test]
    fn group_write_bit_is_rejected() {
        let result = validate_owner_and_mode("base", 1000, 1000, 0o720);
        assert!(result.is_err(), "a group-writable mode must be rejected: {result:?}");
    }

    #[test]
    fn world_write_bit_is_rejected() {
        let result = validate_owner_and_mode("base", 1000, 1000, 0o702);
        assert!(result.is_err(), "a world-writable mode must be rejected: {result:?}");
    }

    #[test]
    fn clean_owner_and_mode_is_ok() {
        let result = validate_owner_and_mode("base", 1000, 1000, 0o700);
        assert!(result.is_ok(), "self-owned 0700 must validate: {result:?}");
    }

    /// Adversarial (#141): a world-writable, non-sticky parent must be rejected —
    /// fail closed with a named reason, before trusting anything created under it.
    #[test]
    fn world_writable_nonsticky_parent_is_rejected() -> anyhow::Result<()> {
        let tmp = private_tmp()?;
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o777))
            .context("make parent world-writable, non-sticky")?;

        let err = ensure_staging_base_in(tmp.path()).expect_err("a world-writable non-sticky parent must be rejected");

        assert!(
            err.to_string().contains("sticky"),
            "expected a sticky-bit rejection naming the parent, got {err}"
        );
        Ok(())
    }

    /// Positive (#141): a world-writable parent WITH the sticky bit (like `/tmp`,
    /// `01777`) is trusted — the base is created and validated under it as usual.
    #[test]
    fn world_writable_sticky_parent_is_ok() -> anyhow::Result<()> {
        let tmp = private_tmp()?;
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o1777))
            .context("make parent sticky world-writable")?;

        let base = ensure_staging_base_in(tmp.path()).expect("a sticky world-writable parent must be trusted");

        let mode = std::fs::metadata(&base).context("stat base")?.permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o700,
            "base under a sticky parent is still created 0700, got {mode:#o}"
        );
        Ok(())
    }

    /// Pure coverage for the parent sticky check, independent of a real
    /// world-writable directory: world-writable without sticky fails; sticky,
    /// non-world-writable, and private modes pass.
    #[test]
    fn parent_sticky_check_covers_the_boundaries() {
        assert!(
            validate_parent_sticky(0o777).is_err(),
            "world-writable without sticky must be rejected"
        );
        assert!(
            validate_parent_sticky(0o1777).is_ok(),
            "world-writable WITH sticky (/tmp) must pass"
        );
        assert!(
            validate_parent_sticky(0o755).is_ok(),
            "a non-world-writable parent must pass"
        );
        assert!(validate_parent_sticky(0o700).is_ok(), "a private parent must pass");
    }
}
