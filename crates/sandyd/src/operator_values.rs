//! The operator secret store (#705): a directory of one file per secret name, the source for values no
//! credential provider mints (a model-provider API key). A value lives in a [`SecretValue`], which
//! redacts in `Debug` and zeroes on drop. Staging a value on an environment is a later slice.

use std::{
    fs::File,
    io::Read as _,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

use zeroize::Zeroizing;

/// The largest secret file the store reads.
pub const MAX_SECRET_BYTES: u64 = 64 * 1024;

/// Why a secret could not be read. A message names the secret, never its value.
#[derive(Debug, thiserror::Error)]
pub enum SecretStoreError {
    /// The store directory is unusable.
    #[error("secret store {}: {reason}", path.display())]
    Store {
        /// The store directory.
        path: PathBuf,
        /// What is wrong with it.
        reason: String,
    },
    /// The name is not `[A-Z][A-Z0-9_]{0,63}`. The text is not echoed: it may be a secret.
    #[error("secret name is not [A-Z][A-Z0-9_]{{0,63}}")]
    BadName,
    /// The store has no file for the name.
    #[error("secret {name} is not in the store")]
    Missing {
        /// The secret name.
        name: String,
    },
    /// The file is a symlink, not a regular file, owned by another user, group- or world-accessible, or too large.
    #[error("secret {name} is refused: {reason}")]
    Refused {
        /// The secret name.
        name: String,
        /// The rule it broke.
        reason: &'static str,
    },
    /// The file could not be read.
    #[error("secret {name} could not be read: {kind}")]
    Unreadable {
        /// The secret name.
        name: String,
        /// The I/O error kind. Not the message: it may carry a path or value.
        kind: std::io::ErrorKind,
    },
}

/// A secret's bytes. `Debug` prints nothing of them and the buffer is zeroed on drop.
pub struct SecretValue(Zeroizing<Vec<u8>>);

impl SecretValue {
    /// The secret bytes. Callers must not log or store them.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretValue(<redacted>)")
    }
}

/// A directory of secret files, one per name.
#[derive(Debug)]
pub struct SecretStore {
    dir: sandy_fsutil::OwnedDir,
}

impl SecretStore {
    /// Open the store at `dir`. The handle is held: every read goes through it, so a swap of the
    /// directory after this call is not followed.
    ///
    /// # Errors
    ///
    /// [`SecretStoreError::Store`] when `dir` is a symlink (with or without a trailing slash), not a
    /// directory, owned by another user, or writable by group or other.
    pub fn open(dir: &Path) -> Result<Self, SecretStoreError> {
        // `Path::components` drops a trailing `/`, which would make the kernel follow a link in the leaf.
        let dir: PathBuf = dir.components().collect();
        let held = sandy_fsutil::OwnedDir::open(&dir).map_err(|e| SecretStoreError::Store {
            path: dir.clone(),
            reason: match e {
                sandy_fsutil::FsError::Unsafe { reason, .. } => reason,
                sandy_fsutil::FsError::Io { source, .. } | sandy_fsutil::FsError::NotDurable { source, .. } => {
                    format!(
                        "cannot be opened as a directory (missing, a symlink, or not a directory): {}",
                        source.kind()
                    )
                }
            },
        })?;
        Ok(Self { dir: held })
    }

    /// Read the secret called `name`.
    ///
    /// # Errors
    ///
    /// A [`SecretStoreError`]: a bad name, a missing file, a refused file or an I/O failure.
    pub fn read(&self, name: &str) -> Result<SecretValue, SecretStoreError> {
        use rustix::{fs::OFlags, io::Errno};

        if !name_ok(name) {
            return Err(SecretStoreError::BadName);
        }
        let refused = |reason: &'static str| SecretStoreError::Refused {
            name: name.to_owned(),
            reason,
        };
        let unreadable = |kind| SecretStoreError::Unreadable {
            name: name.to_owned(),
            kind,
        };
        // Relative to the held directory, leaf not followed. NONBLOCK keeps a fifo from blocking the open;
        // the regular-file check below refuses it.
        let fd = rustix::fs::openat(
            &self.dir,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            rustix::fs::Mode::empty(),
        )
        .map_err(|e| match e {
            Errno::NOENT => SecretStoreError::Missing { name: name.to_owned() },
            Errno::LOOP => refused("a symlink"),
            other => unreadable(std::io::Error::from(other).kind()),
        })?;
        let mut file = File::from(fd);
        let meta = file.metadata().map_err(|e| unreadable(e.kind()))?;
        if !meta.is_file() {
            return Err(refused("not a regular file"));
        }
        if meta.uid() != sandy_fsutil::current_uid() {
            return Err(refused("owned by another user"));
        }
        // Group and other bits, owner execute, setuid, setgid and sticky: the file is exactly `0600` or tighter.
        if meta.mode() & 0o7177 != 0 {
            return Err(refused("not mode 0600 or tighter"));
        }
        let declared = meta.len();
        if declared > MAX_SECRET_BYTES {
            return Err(refused("larger than the 64 KiB cap"));
        }
        let len = usize::try_from(declared).map_err(|_| refused("larger than the 64 KiB cap"))?;
        // One buffer, zeroed first and never grown, read into directly: no reallocation and no stack copy
        // leaves a second copy outside the wrapper. The extra byte detects a file that grew.
        let mut bytes = Zeroizing::new(vec![0_u8; len + 1]);
        let mut filled = 0;
        while filled < bytes.len() {
            match file.read(&mut bytes[filled..]) {
                Ok(0) => break,
                Ok(n) => filled += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(unreadable(e.kind())),
            }
        }
        if filled != len {
            return Err(refused("changed while it was being read"));
        }
        bytes.truncate(len);
        Ok(SecretValue(bytes))
    }
}

/// `[A-Z][A-Z0-9_]{0,63}`: the rule `service_secrets` names follow. Checked again here because the name
/// becomes a path component.
fn name_ok(name: &str) -> bool {
    let mut bytes = name.bytes();
    name.len() <= 64
        && bytes.next().is_some_and(|b| b.is_ascii_uppercase())
        && bytes.all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::fs::{PermissionsExt, symlink},
    };

    use anyhow::{Context, Result};

    use super::*;

    const VALUE: &[u8] = b"sk-test-0123456789-not-a-real-key";

    fn put(dir: &Path, name: &str, mode: u32, bytes: &[u8]) -> Result<PathBuf> {
        let path = dir.join(name);
        // A file left read-only by an earlier call cannot be rewritten.
        let _ = fs::remove_file(&path);
        fs::write(&path, bytes).context("write secret file")?;
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).context("chmod secret file")?;
        Ok(path)
    }

    fn store() -> Result<(tempfile::TempDir, SecretStore)> {
        let tmp = tempfile::tempdir().context("tempdir")?;
        fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o700)).context("chmod store")?;
        let store = SecretStore::open(tmp.path()).context("open store")?;
        Ok((tmp, store))
    }

    #[test]
    fn a_0600_file_reads_back_byte_for_byte() -> Result<()> {
        let (tmp, store) = store()?;
        put(tmp.path(), "MODEL_API_KEY", 0o600, VALUE)?;
        assert_eq!(store.read("MODEL_API_KEY").context("read")?.expose(), VALUE);
        Ok(())
    }

    #[test]
    fn a_missing_file_is_missing_and_names_the_secret() -> Result<()> {
        let (_tmp, store) = store()?;
        let err = store.read("MODEL_API_KEY").expect_err("no such file");
        assert!(
            matches!(&err, SecretStoreError::Missing { name } if name == "MODEL_API_KEY"),
            "{err}"
        );
        Ok(())
    }

    #[test]
    fn a_file_with_group_or_other_bits_is_refused() -> Result<()> {
        let (tmp, store) = store()?;
        for mode in [
            0o640, 0o604, 0o644, 0o660, 0o666, 0o601, 0o700, 0o500, 0o4600, 0o2600, 0o1600,
        ] {
            put(tmp.path(), "WIDE", mode, VALUE)?;
            let got = store.read("WIDE");
            let stored = fs::metadata(tmp.path().join("WIDE"))
                .context("stat")?
                .permissions()
                .mode()
                & 0o7777;
            // The OS may drop a bit it does not allow this user to set (sticky on a macOS file).
            if stored != mode {
                continue;
            }
            assert!(
                matches!(got, Err(SecretStoreError::Refused { .. })),
                "mode {mode:o}: {got:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn a_symlink_is_refused_even_to_a_good_file() -> Result<()> {
        let (tmp, store) = store()?;
        let real = put(tmp.path(), "REAL", 0o600, VALUE)?;
        symlink(&real, tmp.path().join("LINKED")).context("symlink")?;
        let err = store.read("LINKED").expect_err("symlink");
        assert!(matches!(err, SecretStoreError::Refused { .. }), "{err}");
        Ok(())
    }

    #[test]
    fn a_directory_in_place_of_a_file_is_refused() -> Result<()> {
        let (tmp, store) = store()?;
        fs::create_dir(tmp.path().join("DIR")).context("mkdir")?;
        let err = store.read("DIR").expect_err("a directory");
        assert!(matches!(err, SecretStoreError::Refused { .. }), "{err}");
        Ok(())
    }

    #[test]
    fn a_file_over_the_cap_is_refused_and_the_cap_itself_reads() -> Result<()> {
        let (tmp, store) = store()?;
        let cap = usize::try_from(MAX_SECRET_BYTES).context("cap")?;
        put(tmp.path(), "AT_CAP", 0o600, &vec![b'a'; cap])?;
        assert_eq!(store.read("AT_CAP").context("at the cap")?.expose().len(), cap);
        put(tmp.path(), "OVER", 0o600, &vec![b'a'; cap + 1])?;
        let err = store.read("OVER").expect_err("over the cap");
        assert!(matches!(err, SecretStoreError::Refused { .. }), "{err}");
        Ok(())
    }

    #[test]
    fn a_bad_name_is_refused_before_any_path_is_built() -> Result<()> {
        let (tmp, store) = store()?;
        put(tmp.path(), "lower", 0o600, VALUE)?;
        let too_long = format!("A{}", "B".repeat(64));
        for name in ["", "lower", "1ABC", "A-B", "../escape", "A/B", "A.B", "A B", &too_long] {
            let err = store.read(name).expect_err(name);
            assert!(matches!(err, SecretStoreError::BadName), "{name:?}: {err}");
        }
        let longest = format!("A{}", "B".repeat(63));
        put(tmp.path(), &longest, 0o600, VALUE)?;
        store.read(&longest).context("a 64 character name is allowed")?;
        Ok(())
    }

    #[test]
    fn no_error_and_no_debug_output_carries_the_value() -> Result<()> {
        let (tmp, store) = store()?;
        let path = put(tmp.path(), "MODEL_API_KEY", 0o600, VALUE)?;
        let text = String::from_utf8_lossy(VALUE).into_owned();
        let value = store.read("MODEL_API_KEY").context("read")?;
        assert_eq!(format!("{value:?}"), "SecretValue(<redacted>)");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).context("widen")?;
        let wide = store.read("MODEL_API_KEY").expect_err("wide");
        assert!(!format!("{wide} {wide:?}").contains(&text));
        // A bad name that looks like a key is not echoed either.
        let bad = store.read(&text).expect_err("bad name");
        assert!(!format!("{bad} {bad:?}").contains(&text));
        Ok(())
    }

    #[test]
    fn a_store_that_is_not_a_private_directory_is_refused() -> Result<()> {
        let tmp = tempfile::tempdir().context("tempdir")?;
        let file = tmp.path().join("not-a-dir");
        fs::write(&file, b"x").context("write")?;
        assert!(matches!(SecretStore::open(&file), Err(SecretStoreError::Store { .. })));
        assert!(matches!(
            SecretStore::open(&tmp.path().join("absent")),
            Err(SecretStoreError::Store { .. })
        ));
        for mode in [0o777, 0o770, 0o707, 0o720, 0o702, 0o722] {
            fs::set_permissions(tmp.path(), fs::Permissions::from_mode(mode)).context("chmod")?;
            assert!(
                matches!(SecretStore::open(tmp.path()), Err(SecretStoreError::Store { .. })),
                "mode {mode:o}"
            );
        }
        fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o700)).context("restore")?;
        SecretStore::open(tmp.path()).context("a 0700 directory opens")?;
        Ok(())
    }

    #[test]
    fn a_symlinked_store_directory_is_refused_with_or_without_a_trailing_slash() -> Result<()> {
        let tmp = tempfile::tempdir().context("tempdir")?;
        let real = tmp.path().join("real");
        fs::create_dir(&real).context("mkdir")?;
        fs::set_permissions(&real, fs::Permissions::from_mode(0o700)).context("chmod")?;
        let link = tmp.path().join("link");
        symlink(&real, &link).context("symlink")?;
        for path in [link.clone(), PathBuf::from(format!("{}/", link.display()))] {
            assert!(
                matches!(SecretStore::open(&path), Err(SecretStoreError::Store { .. })),
                "{}",
                path.display()
            );
        }
        Ok(())
    }

    #[test]
    fn a_directory_swapped_for_a_symlink_after_open_is_not_followed() -> Result<()> {
        let tmp = tempfile::tempdir().context("tempdir")?;
        let secrets = tmp.path().join("secrets");
        fs::create_dir(&secrets).context("mkdir")?;
        fs::set_permissions(&secrets, fs::Permissions::from_mode(0o700)).context("chmod")?;
        put(&secrets, "MODEL_API_KEY", 0o600, VALUE)?;
        let store = SecretStore::open(&secrets).context("open")?;
        // An attacker with write access to the parent swaps the directory for a link to their own.
        let evil = tmp.path().join("evil");
        fs::create_dir(&evil).context("mkdir evil")?;
        put(&evil, "MODEL_API_KEY", 0o600, b"attacker-value")?;
        fs::rename(&secrets, tmp.path().join("moved")).context("rename")?;
        symlink(&evil, &secrets).context("symlink")?;
        let read = store
            .read("MODEL_API_KEY")
            .context("read from the directory opened first")?;
        assert_eq!(
            read.expose(),
            VALUE,
            "the read must come from the directory that was checked"
        );
        Ok(())
    }
}
