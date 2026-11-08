//! Loading the identity-profile registry (#704, slice 2 of #592).
//!
//! `SANDY_PROFILES` names a registry file the operator owns. The daemon reads it once at start; a file that
//! cannot be trusted stops the daemon. The text never reaches a log: every error here names a path or a reason,
//! never a value read from the file (INV-1).

use std::{
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use sandy::{IdentityProfileError, IdentityProfiles};

/// The registry may not be larger than this; the parser enforces the same bound on the text.
const MAX_BYTES: u64 = 1024 * 1024;

/// Why the registry could not be loaded.
#[derive(Debug, thiserror::Error)]
pub enum ProfilesError {
    /// The file could not be opened or read.
    #[error("cannot read the identity profile registry at {}: {source}", path.display())]
    Read {
        /// The registry path.
        path: PathBuf,
        /// The operating system error.
        source: std::io::Error,
    },
    /// The file is not a private regular file the daemon user owns.
    #[error("the identity profile registry at {} {reason}", path.display())]
    Unsafe {
        /// The registry path.
        path: PathBuf,
        /// What is wrong with the file.
        reason: &'static str,
    },
    /// The file parsed badly. The text is safe to log.
    #[error("{0}")]
    Invalid(#[from] IdentityProfileError),
}

/// Load the registry at `path`: a regular file, mode 0600 or stricter, owned by this user, at most 1 MiB. A symlink
/// at `path` is refused, never followed.
///
/// # Errors
///
/// [`ProfilesError`]: the file is unreadable, unsafe, or does not parse.
pub fn load(path: &Path) -> Result<IdentityProfiles, ProfilesError> {
    let read = |source| ProfilesError::Read {
        path: path.to_owned(),
        source,
    };
    let unsafe_file = |reason| ProfilesError::Unsafe {
        path: path.to_owned(),
        reason,
    };
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits().cast_signed())
        .open(path)
        .map_err(read)?;
    // Checked on the open handle, so the file cannot change between the check and the read.
    let meta = file.metadata().map_err(read)?;
    if !meta.is_file() {
        return Err(unsafe_file("is not a regular file"));
    }
    if meta.uid() != sandy_fsutil::current_uid() {
        return Err(unsafe_file("is not owned by the daemon user"));
    }
    if meta.permissions().mode() & 0o077 != 0 {
        return Err(unsafe_file("is readable or writable by others (mode must be 0600)"));
    }
    if meta.len() > MAX_BYTES {
        return Err(unsafe_file("is larger than 1 MiB"));
    }
    let mut text = String::new();
    // Bounded again: the file may have grown since `metadata`.
    (&mut file)
        .take(MAX_BYTES + 1)
        .read_to_string(&mut text)
        .map_err(read)?;
    Ok(IdentityProfiles::parse(&text)?)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use anyhow::{Context, Result};

    use super::*;

    const GOOD: &str = r#"{"profiles":[{"name":"harness","credential":"github-main","targets":["o/r"],"capabilities":["read_code"]}]}"#;

    fn write(dir: &Path, name: &str, text: &str, mode: u32) -> Result<PathBuf> {
        let path = dir.join(name);
        std::fs::write(&path, text).context("write registry")?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).context("chmod registry")?;
        Ok(path)
    }

    #[test]
    fn a_private_registry_loads_and_resolves_its_profiles() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let profiles = load(&write(dir.path(), "p.json", GOOD, 0o600)?)?;
        assert!(profiles.resolve("harness").is_ok());
        assert!(profiles.resolve("other").is_err());
        Ok(())
    }

    #[test]
    fn a_registry_others_can_read_is_refused() -> Result<()> {
        let dir = tempfile::tempdir()?;
        for mode in [0o644, 0o640, 0o602] {
            let err = load(&write(dir.path(), "p.json", GOOD, mode)?)
                .err()
                .context("must refuse")?;
            assert!(matches!(err, ProfilesError::Unsafe { .. }), "{mode:o}: {err}");
        }
        Ok(())
    }

    #[test]
    fn a_symlink_a_directory_and_a_missing_file_are_refused() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let real = write(dir.path(), "real.json", GOOD, 0o600)?;
        let link = dir.path().join("link.json");
        symlink(&real, &link)?;
        assert!(
            matches!(load(&link), Err(ProfilesError::Read { .. })),
            "symlink followed"
        );
        assert!(matches!(
            load(dir.path()),
            Err(ProfilesError::Unsafe { .. } | ProfilesError::Read { .. })
        ));
        assert!(matches!(
            load(&dir.path().join("none.json")),
            Err(ProfilesError::Read { .. })
        ));
        Ok(())
    }

    #[test]
    fn an_oversized_registry_is_refused() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let big = " ".repeat(usize::try_from(MAX_BYTES)? + 1);
        let err = load(&write(dir.path(), "p.json", &big, 0o600)?)
            .err()
            .context("must refuse")?;
        assert!(matches!(err, ProfilesError::Unsafe { .. }), "{err}");
        Ok(())
    }

    #[test]
    fn a_bad_registry_fails_with_text_that_never_repeats_the_file() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let secret = "ghp_abcdefghijklmnopqrstuvwxyz0123456789";
        let text = format!(r#"{{"profiles":[{{"name":"{secret}","credential":"c"}}]}}"#);
        let err = load(&write(dir.path(), "p.json", &text, 0o600)?)
            .err()
            .context("must refuse")?;
        assert!(matches!(err, ProfilesError::Invalid(_)), "{err}");
        assert!(!err.to_string().contains(secret), "{err}");
        Ok(())
    }
}
