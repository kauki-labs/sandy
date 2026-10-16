//! The `0600` secret writer (INV-1): an [`OwnedDir`] handle and
//! [`OwnedDir::write_secret`], the one writer for every secret staged for a job.
//!
//! The directory is opened once and everything after is relative to that handle:
//! the owner and mode check, the create, the rename and the sync. A path swapped
//! after the check cannot redirect the write, and a symlink planted at the
//! temporary or final name is never followed.

use std::{
    fs::File,
    io::{self, Write},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

use rustix::fs::{AtFlags, Mode, OFlags};

use crate::{FsError, staging::validate_owner_and_mode};

/// A directory opened for staging secrets: this user's, not group- or
/// world-writable, and not a symlink at its final component.
#[derive(Debug)]
pub struct OwnedDir {
    handle: File,
    path: PathBuf,
}

impl OwnedDir {
    /// Open `path` as a staging directory.
    ///
    /// # Errors
    ///
    /// [`FsError::Io`] when it cannot be opened (including a symlink at `path`),
    /// [`FsError::Unsafe`] when it is not owned by this user or is group- or
    /// world-writable: another principal could otherwise replace a staged file.
    pub fn open(path: &Path) -> Result<Self, FsError> {
        let handle = rustix::fs::open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map(File::from)
        .map_err(|e| FsError::io("open staging dir", path, e))?;
        let meta = handle
            .metadata()
            .map_err(|e| FsError::io("stat staging dir", path, e))?;
        validate_owner_and_mode(
            "staging dir",
            meta.uid(),
            rustix::process::getuid().as_raw(),
            meta.mode(),
        )
        .map_err(|reason| FsError::Unsafe {
            path: path.to_owned(),
            reason,
        })?;
        Ok(Self {
            handle,
            path: path.to_owned(),
        })
    }

    /// Open `path` as a staging directory, creating it first if it is missing.
    ///
    /// A directory this creates is `0700`, whatever the umask; missing parents are
    /// created normally. An existing directory is opened and validated as in
    /// [`OwnedDir::open`], never repaired: a group- or world-writable one is
    /// refused, because it may already have been tampered with.
    ///
    /// # Errors
    ///
    /// As [`OwnedDir::open`], plus [`FsError::Io`] when creation fails.
    pub fn open_or_create(path: &Path) -> Result<Self, FsError> {
        match std::fs::symlink_metadata(path) {
            Ok(_) => return Self::open(path),
            Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(FsError::io("stat dir", path, e)),
            Err(_) => {}
        }
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let name = path
            .file_name()
            .ok_or_else(|| FsError::io("create dir", path, io::Error::from(io::ErrorKind::InvalidInput)))?;
        std::fs::create_dir_all(parent).map_err(|e| FsError::io("create parent dirs", parent, e))?;
        let parent_fd = rustix::fs::open(
            parent,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| FsError::io("open parent dir", parent, e))?;
        match rustix::fs::mkdirat(&parent_fd, name, Mode::RWXU) {
            Ok(()) => {}
            // Created concurrently: validated like any existing dir.
            Err(rustix::io::Errno::EXIST) => return Self::open(path),
            Err(e) => return Err(FsError::io("create dir", path, e)),
        }
        // The umask may have cleared bits from 0700, even the owner's read bit,
        // which would make the dir unopenable. Set 0700 relative to the parent
        // handle before opening it; a swapped-in link can only be narrowed here, and
        // the open below validates whatever is there.
        // create_private_dir, the staging base and write_0600_at do not follow
        // this pattern yet; #204 aligns them.
        let secured = rustix::fs::chmodat(&parent_fd, name, Mode::RWXU, AtFlags::SYMLINK_NOFOLLOW)
            .or_else(|e| match e {
                // Linux before fchmodat2 cannot honour NOFOLLOW here.
                // A guard, not a pattern: the two are one value on Linux, two on macOS.
                e if e == rustix::io::Errno::NOTSUP || e == rustix::io::Errno::OPNOTSUPP => {
                    rustix::fs::chmodat(&parent_fd, name, Mode::RWXU, AtFlags::empty())
                }
                other => Err(other),
            })
            .map_err(|e| FsError::io("set created dir to 0700", path, e))
            .and_then(|()| Self::open(path));
        if secured.is_err() {
            // Best effort: never leave a half-set-up dir to block a retry.
            let _ = rustix::fs::unlinkat(&parent_fd, name, AtFlags::REMOVEDIR);
        }
        secured
    }

    /// The path this directory was opened at.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Create the new directory `name` inside this one, `0700`, and open it.
    ///
    /// An existing entry at `name` (a directory, a file, a symlink) is an error,
    /// never reused: a pre-created entry may belong to someone else. The mode is
    /// set to `0700` on the opened handle, so the umask cannot widen it.
    ///
    /// # Errors
    ///
    /// [`FsError::Io`] when `name` already exists or a step fails;
    /// [`FsError::Unsafe`] when the created directory is somehow not this user's.
    pub fn create_private_dir(&self, name: &str) -> Result<Self, FsError> {
        let path = self.path.join(name);
        rustix::fs::mkdirat(&self.handle, name, Mode::RWXU).map_err(|e| FsError::io("create private dir", &path, e))?;
        let handle = rustix::fs::openat(
            &self.handle,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map(File::from)
        .map_err(|e| FsError::io("open private dir", &path, e))?;
        rustix::fs::fchmod(&handle, Mode::RWXU).map_err(|e| FsError::io("set private dir to 0700", &path, e))?;
        let meta = handle
            .metadata()
            .map_err(|e| FsError::io("stat private dir", &path, e))?;
        validate_owner_and_mode(
            "private dir",
            meta.uid(),
            rustix::process::getuid().as_raw(),
            meta.mode(),
        )
        .map_err(|reason| FsError::Unsafe {
            path: path.clone(),
            reason,
        })?;
        Ok(Self { handle, path })
    }

    /// Write `bytes` as the file `name` in this directory and return its path.
    ///
    /// The file is created `0600` (never wider, not even briefly) under a unique
    /// temporary name with `O_EXCL | O_NOFOLLOW`, synced, renamed over `name`, and
    /// the directory is synced. A reader never sees a partial or wider file. A
    /// failed write leaves no temporary behind. If the final directory sync fails,
    /// the error is returned and the file stays in place, visible but possibly not
    /// durable: removing it by name could delete a concurrent write of the same
    /// name, and writing again replaces it.
    ///
    /// `name` must be a single file name: empty, `.`, `..`, or a name containing
    /// `/` is refused.
    ///
    /// # Errors
    ///
    /// [`FsError::Unsafe`] for a name that is not a single file name;
    /// [`FsError::Io`] for any failed step.
    pub fn write_secret(&self, name: &str, bytes: &[u8]) -> Result<PathBuf, FsError> {
        if name.is_empty() || name == "." || name == ".." || name.contains(['/', '\0']) {
            return Err(FsError::Unsafe {
                path: self.path.clone(),
                reason: format!("{name:?} is not a single file name; refusing to write a secret under it"),
            });
        }
        let dest = self.path.join(name);
        let tmp = format!(
            ".{name}.{}.staging",
            unique_suffix().map_err(|e| FsError::io("draw a temp name", &self.path, e))?
        );
        let discard_tmp = || {
            // Best effort: the original error is the one worth reporting.
            let _ = rustix::fs::unlinkat(&self.handle, tmp.as_str(), AtFlags::empty());
        };
        if let Err(e) = write_0600_at(&self.handle, &tmp, bytes) {
            discard_tmp();
            return Err(FsError::io("write secret temp", &self.path.join(&tmp), e));
        }
        if let Err(e) = rustix::fs::renameat(&self.handle, tmp.as_str(), &self.handle, name) {
            discard_tmp();
            return Err(FsError::io("rename secret into place", &dest, e));
        }
        self.handle
            .sync_all()
            .map_err(|e| FsError::io("sync staging dir", &self.path, e))?;
        Ok(dest)
    }
}

/// A new private (`0700`) directory under the validated sandy staging base, named
/// `<prefix>-<random>` so it cannot be predicted or pre-created.
///
/// # Errors
///
/// [`FsError`] when the staging base is unsafe or the directory cannot be made.
pub fn private_staging_dir(prefix: &str) -> Result<OwnedDir, FsError> {
    let base = crate::ensure_sandy_staging_base()?;
    let suffix = unique_suffix().map_err(|e| FsError::io("draw a dir name", &base, e))?;
    OwnedDir::open(&base)?.create_private_dir(&format!("{prefix}-{suffix}"))
}

/// A random suffix so concurrent writes of one name never share a temp file.
fn unique_suffix() -> io::Result<String> {
    let mut raw = [0_u8; 8];
    getrandom::fill(&mut raw).map_err(|e| io::Error::other(e.to_string()))?;
    Ok(raw.iter().map(|b| format!("{b:02x}")).collect())
}

/// Create `name` in `dir` as a new `0600` file holding `bytes`, synced to disk.
/// `O_EXCL` with `O_NOFOLLOW` refuses anything already there, including a planted
/// symlink.
fn write_0600_at(dir: &File, name: &str, bytes: &[u8]) -> io::Result<()> {
    let fd = rustix::fs::openat(
        dir,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )?;
    let mut file = File::from(fd);
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::fs::{PermissionsExt, symlink},
    };

    use super::*;

    /// A 0700 temp dir: a safe staging dir.
    fn staging_dir() -> anyhow::Result<tempfile::TempDir> {
        let dir = tempfile::tempdir()?;
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700))?;
        Ok(dir)
    }

    #[test]
    fn a_secret_is_written_0600_with_its_exact_bytes() -> anyhow::Result<()> {
        let dir = staging_dir()?;
        let path = OwnedDir::open(dir.path())?.write_secret("S", b"secret")?;
        anyhow::ensure!(path == dir.path().join("S"), "wrote to {}", path.display());
        let mode = fs::metadata(&path)?.permissions().mode() & 0o777;
        anyhow::ensure!(mode == 0o600, "mode {mode:o}");
        anyhow::ensure!(fs::read(&path)? == b"secret", "bytes differ");
        Ok(())
    }

    #[test]
    fn rewriting_over_a_wide_file_leaves_a_0600_secret_and_no_temp_file() -> anyhow::Result<()> {
        let dir = staging_dir()?;
        let old = dir.path().join("S");
        fs::write(&old, b"old")?;
        fs::set_permissions(&old, fs::Permissions::from_mode(0o644))?;
        let path = OwnedDir::open(dir.path())?.write_secret("S", b"new")?;
        anyhow::ensure!(fs::read(&path)? == b"new", "secret not replaced");
        let mode = fs::metadata(&path)?.permissions().mode() & 0o777;
        anyhow::ensure!(mode == 0o600, "a pre-existing 0644 file kept its mode: {mode:o}");
        anyhow::ensure!(fs::read_dir(dir.path())?.count() == 1, "a temp file was left behind");
        Ok(())
    }

    #[test]
    fn a_failed_rename_leaves_no_temp_file() -> anyhow::Result<()> {
        let dir = staging_dir()?;
        fs::create_dir(dir.path().join("S"))?;
        fs::write(dir.path().join("S").join("keep"), b"x")?;
        let res = OwnedDir::open(dir.path())?.write_secret("S", b"secret");
        anyhow::ensure!(matches!(res, Err(FsError::Io { .. })), "got {res:?}");
        let names: Vec<_> = fs::read_dir(dir.path())?
            .map(|e| e.map(|e| e.file_name()))
            .collect::<Result<_, _>>()?;
        anyhow::ensure!(names == ["S"], "left behind: {names:?}");
        Ok(())
    }

    #[test]
    fn a_symlink_planted_at_the_destination_never_touches_its_target() -> anyhow::Result<()> {
        let dir = staging_dir()?;
        let victim_dir = tempfile::tempdir()?;
        let victim = victim_dir.path().join("id_ed25519");
        fs::write(&victim, b"private key")?;
        symlink(&victim, dir.path().join("S"))?;
        let path = OwnedDir::open(dir.path())?.write_secret("S", b"secret")?;
        anyhow::ensure!(
            fs::read(&victim)? == b"private key",
            "the symlink target was overwritten"
        );
        anyhow::ensure!(
            !fs::symlink_metadata(&path)?.is_symlink(),
            "the secret is still a symlink"
        );
        anyhow::ensure!(fs::read(&path)? == b"secret", "staged bytes differ");
        Ok(())
    }

    #[test]
    fn a_group_or_world_writable_dir_is_refused() -> anyhow::Result<()> {
        for mode in [0o770, 0o707, 0o777] {
            let dir = staging_dir()?;
            fs::set_permissions(dir.path(), fs::Permissions::from_mode(mode))?;
            let res = OwnedDir::open(dir.path());
            anyhow::ensure!(matches!(res, Err(FsError::Unsafe { .. })), "mode {mode:o} gave {res:?}");
        }
        Ok(())
    }

    #[test]
    fn a_private_dir_refuses_a_pre_existing_entry() -> anyhow::Result<()> {
        let dir = staging_dir()?;
        let parent = OwnedDir::open(dir.path())?;
        // An attacker's pre-created directory, and a symlink to one.
        fs::create_dir(dir.path().join("taken"))?;
        let elsewhere = tempfile::tempdir()?;
        symlink(elsewhere.path(), dir.path().join("linked"))?;
        for name in ["taken", "linked"] {
            match parent.create_private_dir(name) {
                Err(FsError::Io { source, .. }) if source.kind() == io::ErrorKind::AlreadyExists => {}
                other => anyhow::bail!("{name}: a pre-existing entry was not refused: {other:?}"),
            }
        }
        Ok(())
    }

    /// The umask is process-wide; nextest runs each test in its own process.
    #[test]
    fn a_private_dir_is_0700_under_a_group_writable_umask() -> anyhow::Result<()> {
        let dir = staging_dir()?;
        let parent = OwnedDir::open(dir.path())?;
        let previous = rustix::process::umask(Mode::from_raw_mode(0o002));
        let created = parent.create_private_dir("cred");
        rustix::process::umask(previous);
        let created = created?;
        let mode = fs::metadata(created.path())?.permissions().mode() & 0o777;
        anyhow::ensure!(mode == 0o700, "a private dir came out {mode:o}");
        let secret = created.write_secret("GITHUB_TOKEN", b"token")?;
        let mode = fs::metadata(&secret)?.permissions().mode() & 0o777;
        anyhow::ensure!(mode == 0o600, "a secret in a private dir came out {mode:o}");
        Ok(())
    }

    #[test]
    fn private_staging_dirs_are_fresh_private_and_under_the_staging_base() -> anyhow::Result<()> {
        let (first, second) = (private_staging_dir("contract")?, private_staging_dir("contract")?);
        let base = crate::ensure_sandy_staging_base()?;
        let checks = [
            (first.path().starts_with(&base), "outside the staging base"),
            (first.path() != second.path(), "two calls gave the same dir"),
            (
                fs::metadata(first.path())?.permissions().mode() & 0o777 == 0o700,
                "not 0700",
            ),
        ];
        for dir in [first.path(), second.path()] {
            let _ = fs::remove_dir_all(dir);
        }
        for (ok, why) in checks {
            anyhow::ensure!(ok, "a private staging dir was {why}");
        }
        Ok(())
    }

    /// The umask is process-wide; nextest runs each test in its own process.
    #[test]
    fn open_or_create_makes_a_missing_dir_0700_under_a_group_writable_umask() -> anyhow::Result<()> {
        let root = staging_dir()?;
        let path = root.path().join("config").join("trust-roots");
        let previous = rustix::process::umask(Mode::from_raw_mode(0o002));
        let opened = OwnedDir::open_or_create(&path);
        rustix::process::umask(previous);
        opened?;
        let mode = fs::metadata(&path)?.permissions().mode() & 0o777;
        anyhow::ensure!(mode == 0o700, "a created dir came out {mode:o}");
        Ok(())
    }

    /// A umask that clears the owner's read bit (0400 makes mkdir's 0700 into
    /// 0300) must not leave a dir that cannot be opened: it is set to 0700 first.
    /// The umask is process-wide; nextest runs each test in its own process.
    #[test]
    fn open_or_create_survives_a_umask_that_clears_owner_read() -> anyhow::Result<()> {
        let root = staging_dir()?;
        let path = root.path().join("d");
        let previous = rustix::process::umask(Mode::from_raw_mode(0o400));
        let opened = OwnedDir::open_or_create(&path);
        rustix::process::umask(previous);
        opened?;
        let mode = fs::metadata(&path)?.permissions().mode() & 0o777;
        anyhow::ensure!(mode == 0o700, "a created dir came out {mode:o}");
        Ok(())
    }

    #[test]
    fn open_or_create_accepts_an_existing_private_dir_and_refuses_a_wide_one() -> anyhow::Result<()> {
        let root = staging_dir()?;
        let private = root.path().join("private");
        fs::create_dir(&private)?;
        fs::set_permissions(&private, fs::Permissions::from_mode(0o700))?;
        OwnedDir::open_or_create(&private)?;
        let wide = root.path().join("wide");
        fs::create_dir(&wide)?;
        fs::set_permissions(&wide, fs::Permissions::from_mode(0o775))?;
        let res = OwnedDir::open_or_create(&wide);
        anyhow::ensure!(
            matches!(res, Err(FsError::Unsafe { .. })),
            "a 0775 dir was accepted: {res:?}"
        );
        let mode = fs::metadata(&wide)?.permissions().mode() & 0o777;
        anyhow::ensure!(mode == 0o775, "a refused dir was silently repaired to {mode:o}");
        Ok(())
    }

    #[test]
    fn open_or_create_refuses_a_symlink_at_the_path() -> anyhow::Result<()> {
        let root = staging_dir()?;
        let real = root.path().join("real");
        fs::create_dir(&real)?;
        fs::set_permissions(&real, fs::Permissions::from_mode(0o700))?;
        let link = root.path().join("link");
        symlink(&real, &link)?;
        let res = OwnedDir::open_or_create(&link);
        anyhow::ensure!(res.is_err(), "a symlink at the path was followed");
        Ok(())
    }

    #[test]
    fn a_name_that_is_not_one_path_component_is_refused() -> anyhow::Result<()> {
        let dir = staging_dir()?;
        // `a` and `.a` exist, so the temp file `.a/b.<hex>.staging` can be created
        // and renamed to `a/b`: only a name check stops "a/b" landing in `a/`.
        for sub in ["a", ".a"] {
            fs::create_dir(dir.path().join(sub))?;
            fs::set_permissions(dir.path().join(sub), fs::Permissions::from_mode(0o700))?;
        }
        let owned = OwnedDir::open(dir.path())?;
        for bad in ["", ".", "..", "a/b", "../escape"] {
            let res = owned.write_secret(bad, b"x");
            anyhow::ensure!(res.is_err(), "{bad:?} was written");
        }
        anyhow::ensure!(fs::read_dir(dir.path())?.count() == 2, "a refused name left a file");
        anyhow::ensure!(
            fs::read_dir(dir.path().join("a"))?.count() == 0,
            "a path-traversing name wrote into a/"
        );
        Ok(())
    }

    #[test]
    fn a_symlinked_dir_is_refused() -> anyhow::Result<()> {
        let dir = staging_dir()?;
        let real = dir.path().join("real");
        fs::create_dir(&real)?;
        fs::set_permissions(&real, fs::Permissions::from_mode(0o700))?;
        let link = dir.path().join("link");
        symlink(&real, &link)?;
        let res = OwnedDir::open(&link);
        anyhow::ensure!(
            matches!(res, Err(FsError::Io { .. })),
            "a symlinked dir was opened: {res:?}"
        );
        Ok(())
    }
}
