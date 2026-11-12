//! Opening host paths without following a symlink at or below the leaf (#618).
//!
//! A path that one call checks and another opens can be swapped for a symlink in between, and the daemon then reads
//! or writes whatever the link names, as its own user. [`Beneath`] opens a directory once with `O_NOFOLLOW`, then
//! works only through that handle (`openat`, `mkdirat`, `fstat` on the opened fd): nothing at or below the leaf is
//! resolved a second time, and a link planted there is refused.
//!
//! The components above the leaf are resolved as the OS resolves them, so a system link such as macOS `/tmp` still
//! works. Closing those needs a trusted root to open beneath, which the callers do not have yet (#607).

use std::{
    ffi::{OsStr, OsString},
    fs::File,
    os::unix::ffi::{OsStrExt as _, OsStringExt as _},
    path::{Path, PathBuf},
};

use rustix::{
    fs::{AtFlags, Dir, FileType, Mode, OFlags},
    io::Errno,
};

use crate::FsError;

/// What a directory entry is, read without following a link.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EntryKind {
    /// A regular file.
    File,
    /// A directory.
    Dir,
    /// A symlink.
    Symlink,
    /// A fifo, socket, or device.
    Other,
}

impl EntryKind {
    fn of(mode: rustix::fs::RawMode) -> Self {
        match FileType::from_raw_mode(mode) {
            FileType::RegularFile => Self::File,
            FileType::Directory => Self::Dir,
            FileType::Symlink => Self::Symlink,
            _ => Self::Other,
        }
    }
}

/// Which file an entry is: the device and the inode, as the filesystem reports them. Two names that reach the same
/// file (a hard link, or two spellings on a case-insensitive filesystem) have the same id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileId {
    /// The device the file is on.
    pub dev: u64,
    /// The inode on that device.
    pub ino: u64,
}

/// A device or inode number as the `u64` of a [`FileId`], keeping its bits: a negative `i32` device (a major number of
/// 128 or more on macOS) becomes the same `u64` the standard library's `MetadataExt::dev` gives, not an error.
#[allow(
    clippy::cast_possible_truncation,
    reason = "the wrap is the point: the bits of the value are kept"
)]
fn wrap_u64(value: i128) -> u64 {
    value as u64
}

/// A directory opened without following a symlink, to read or write beneath.
#[derive(Debug)]
pub struct Beneath {
    fd: std::os::fd::OwnedFd,
    path: PathBuf,
}

impl Beneath {
    /// Open the directory at `path`. The leaf is not followed: a symlink there is refused. The components above it
    /// resolve as usual.
    ///
    /// # Errors
    ///
    /// [`FsError::Unsafe`] when the leaf is a symlink or not a directory, else [`FsError::Io`].
    pub fn open_dir(path: &Path) -> Result<Self, FsError> {
        // A trailing `/` or `/.` makes the kernel resolve a link in the last component even with `O_NOFOLLOW`, so the
        // leaf is opened by name below its parent, which `Path` normalizes. A path with no final name (`.`, `..`,
        // `/`) names no link.
        match split(path) {
            Ok((parent, name)) => Self::open_parent(parent)?.open_subdir(name),
            Err(_) => Self::open_dir_following_leaf(path),
        }
    }

    /// Create the directory at `path` (its parents by path, as `create_dir_all` does) and open it. The leaf is
    /// created or adopted without following a link: an existing symlink there is refused.
    ///
    /// # Errors
    ///
    /// [`FsError::Unsafe`] when the leaf is a symlink or not a directory, else [`FsError::Io`].
    pub fn create_dir_at(path: &Path) -> Result<Self, FsError> {
        match split(path) {
            Ok((parent, name)) => {
                std::fs::create_dir_all(parent).map_err(|e| FsError::io("create parent directories", parent, e))?;
                Self::open_parent(parent)?.create_dir(name)
            }
            // `.`, `..` and `/` name an existing directory and no link.
            Err(_) => {
                std::fs::create_dir_all(path).map_err(|e| FsError::io("create directories", path, e))?;
                Self::open_dir_following_leaf(path)
            }
        }
    }

    /// The path this handle was opened at, for messages. It is never resolved again.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The entries of the directory, without `.` and `..`, each with what it is (a link is a link). They are read one
    /// at a time, so a caller that enforces a ceiling stops the scan of a huge directory early.
    ///
    /// # Errors
    ///
    /// [`FsError::Io`] when the directory cannot be read. Each item can fail on its own.
    pub fn entries(&self) -> Result<Entries<'_>, FsError> {
        let dir = Dir::read_from(&self.fd).map_err(|e| FsError::io("read directory", &self.path, e))?;
        Ok(Entries { dir, owner: self })
    }

    /// What the entry `name` is, without following it.
    ///
    /// # Errors
    ///
    /// [`FsError::Unsafe`] for a name that is not a single component, else [`FsError::Io`].
    pub fn kind(&self, name: &OsStr) -> Result<EntryKind, FsError> {
        let name = component(name, &self.path)?;
        let stat = rustix::fs::statat(&self.fd, name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|e| FsError::io("stat entry", &self.path.join(name), e))?;
        Ok(EntryKind::of(stat.st_mode))
    }

    /// The identity of the entry `name`, or `None` when there is no such entry, or when the filesystem reports no
    /// inode for it (0, as some FUSE and 9p mounts do: the assumption is that such an entry cannot be told apart from
    /// another, so it has no id). A symlink is not followed: its own id is returned.
    ///
    /// # Errors
    ///
    /// [`FsError::Unsafe`] for a name that is not a single component, else [`FsError::Io`].
    pub fn file_id(&self, name: &OsStr) -> Result<Option<FileId>, FsError> {
        let name = component(name, &self.path)?;
        let path = self.path.join(name);
        match rustix::fs::statat(&self.fd, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => {
                // Some filesystems (FUSE, 9p mounts) report no inode: 0 is "no id", never a key two files could share.
                if stat.st_ino == 0 {
                    return Ok(None);
                }
                // `st_dev` is a `u64` on Linux and an `i32` on macOS; the bits are kept either way.
                Ok(Some(FileId {
                    dev: wrap_u64(i128::from(stat.st_dev)),
                    ino: stat.st_ino,
                }))
            }
            Err(Errno::NOENT) => Ok(None),
            Err(e) => Err(FsError::io("stat entry", &path, e)),
        }
    }

    /// Open the subdirectory `name`, refusing a symlink.
    ///
    /// # Errors
    ///
    /// [`FsError::Unsafe`] when it is a symlink or not a directory, else [`FsError::Io`].
    pub fn open_subdir(&self, name: &OsStr) -> Result<Self, FsError> {
        let name = component(name, &self.path)?;
        let path = self.path.join(name);
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let fd = rustix::fs::openat(&self.fd, name, flags, Mode::empty())
            .map_err(|e| refused("open directory", &path, e, true))?;
        Ok(Self { fd, path })
    }

    /// Create the subdirectory `name`, or adopt it when it already is a directory. A symlink there is refused.
    ///
    /// # Errors
    ///
    /// [`FsError::Unsafe`] when it exists as a symlink or not a directory, else [`FsError::Io`].
    pub fn create_dir(&self, name: &OsStr) -> Result<Self, FsError> {
        let component = component(name, &self.path)?;
        match rustix::fs::mkdirat(&self.fd, component, Mode::from_raw_mode(0o777)) {
            Ok(()) | Err(Errno::EXIST) => {}
            Err(e) => return Err(FsError::io("create directory", &self.path.join(component), e)),
        }
        self.open_subdir(name)
    }

    /// Open the regular file `name` for reading, refusing a symlink or anything that is not a regular file.
    ///
    /// # Errors
    ///
    /// [`FsError::Unsafe`] when it is a symlink or not a regular file, else [`FsError::Io`].
    pub fn open_file(&self, name: &OsStr) -> Result<File, FsError> {
        let name = component(name, &self.path)?;
        let path = self.path.join(name);
        // NONBLOCK: a fifo swapped in after a check must not block the open; it is refused by the `fstat` below.
        let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
        let fd = rustix::fs::openat(&self.fd, name, flags, Mode::empty())
            .map_err(|e| refused("open file", &path, e, false))?;
        regular(fd, &path)
    }

    /// Create the regular file `name` for writing. It must not exist: an existing entry, a symlink included, is
    /// refused, so staging never writes through a link. The file is `0600`; the caller sets its final mode through
    /// the returned handle.
    ///
    /// # Errors
    ///
    /// [`FsError::Unsafe`] when `name` exists (as a symlink or anything else), else [`FsError::Io`].
    pub fn create_new_file(&self, name: &OsStr) -> Result<File, FsError> {
        let name = component(name, &self.path)?;
        let path = self.path.join(name);
        let flags = OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let fd = rustix::fs::openat(&self.fd, name, flags, Mode::from_raw_mode(0o600)).map_err(|e| {
            if e == Errno::EXIST {
                FsError::Unsafe {
                    path: path.clone(),
                    reason: "already exists; refusing to write through it".to_owned(),
                }
            } else {
                refused("create file", &path, e, false)
            }
        })?;
        Ok(File::from(fd))
    }

    /// Create the symlink `name` pointing at `target`. It must not exist. The host never follows it.
    ///
    /// # Errors
    ///
    /// [`FsError::Io`] when `name` exists or the link cannot be created.
    pub fn create_symlink(&self, name: &OsStr, target: &Path) -> Result<(), FsError> {
        let name = component(name, &self.path)?;
        rustix::fs::symlinkat(target, &self.fd, name)
            .map_err(|e| FsError::io("create symlink", &self.path.join(name), e))
    }

    /// Create the regular file `name` for writing, or truncate it when it already is one. A symlink there is
    /// refused, so the daemon never writes through a link.
    ///
    /// # Errors
    ///
    /// [`FsError::Unsafe`] when it is a symlink or not a regular file, else [`FsError::Io`].
    pub fn create_file(&self, name: &OsStr) -> Result<File, FsError> {
        let name = component(name, &self.path)?;
        let path = self.path.join(name);
        let flags = OFlags::WRONLY | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
        let fd = rustix::fs::openat(&self.fd, name, flags, Mode::from_raw_mode(0o666))
            .map_err(|e| refused("create file", &path, e, false))?;
        let file = regular(fd, &path)?;
        file.set_len(0).map_err(|e| FsError::io("truncate file", &path, e))?;
        Ok(file)
    }

    /// Rename the entry `from` to `to` within this directory, replacing whatever is at `to` (a file, or a symlink,
    /// which is replaced and never followed).
    ///
    /// # Errors
    ///
    /// [`FsError::Unsafe`] for a name that is not a single component, else [`FsError::Io`] (`to` is a directory and
    /// `from` is not, `to` is a non-empty directory, or `from` is missing).
    pub fn rename(&self, from: &OsStr, to: &OsStr) -> Result<(), FsError> {
        let from = component(from, &self.path)?;
        let to = component(to, &self.path)?;
        rustix::fs::renameat(&self.fd, from, &self.fd, to)
            .map_err(|e| FsError::io("rename entry", &self.path.join(from), e))
    }

    /// Remove the file or symlink `name`. A symlink is removed, not followed. A directory is refused.
    ///
    /// # Errors
    ///
    /// [`FsError::Unsafe`] for a name that is not a single component, else [`FsError::Io`].
    pub fn remove_file(&self, name: &OsStr) -> Result<(), FsError> {
        let name = component(name, &self.path)?;
        rustix::fs::unlinkat(&self.fd, name, AtFlags::empty())
            .map_err(|e| FsError::io("remove file", &self.path.join(name), e))
    }

    /// The target text of the symlink `name`. The host never follows it.
    ///
    /// # Errors
    ///
    /// [`FsError::Io`] when `name` is not a symlink or cannot be read.
    pub fn read_link(&self, name: &OsStr) -> Result<PathBuf, FsError> {
        let name = component(name, &self.path)?;
        let target = rustix::fs::readlinkat(&self.fd, name, Vec::new())
            .map_err(|e| FsError::io("read symlink", &self.path.join(name), e))?;
        Ok(PathBuf::from(OsString::from_vec(target.into_bytes())))
    }
}

/// Open the regular file at `path` for reading. The leaf is not followed: a symlink there is refused.
///
/// # Errors
///
/// [`FsError::Unsafe`] when it is a symlink or not a regular file, else [`FsError::Io`].
pub fn open_file(path: &Path) -> Result<File, FsError> {
    let (parent, name) = split(path)?;
    Beneath::open_parent(parent)?.open_file(name)
}

/// Create (or truncate) the regular file at `path` for writing, with its parents created by path. The leaf is not
/// followed: a symlink there is refused.
///
/// # Errors
///
/// [`FsError::Unsafe`] when it is a symlink or not a regular file, else [`FsError::Io`].
pub fn create_file_at(path: &Path) -> Result<File, FsError> {
    let (parent, name) = split(path)?;
    std::fs::create_dir_all(parent).map_err(|e| FsError::io("create parent directories", parent, e))?;
    Beneath::open_parent(parent)?.create_file(name)
}

/// The entries of a directory, produced lazily by [`Beneath::entries`].
pub struct Entries<'a> {
    dir: Dir,
    owner: &'a Beneath,
}

impl Iterator for Entries<'_> {
    type Item = Result<(OsString, EntryKind), FsError>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let entry = match self.dir.next()? {
                Ok(entry) => entry,
                Err(e) => return Some(Err(FsError::io("read directory entry", &self.owner.path, e))),
            };
            let name = entry.file_name().to_bytes();
            if name == b"." || name == b".." {
                continue;
            }
            let name = OsStr::from_bytes(name).to_owned();
            return Some(self.owner.kind(&name).map(|kind| (name, kind)));
        }
    }
}

impl Beneath {
    /// Open `dir`, the parent of a leaf a caller is about to open, only to search it. On Linux that is an `O_PATH`
    /// handle, which needs search (execute) permission and not read, so a file under an execute-only directory, or a
    /// destination under a write-and-execute-only one, still works. Elsewhere it is a plain read open. The parent
    /// resolves as the OS resolves it, links included: the leaf is what the callers refuse to follow.
    fn open_parent(dir: &Path) -> Result<Self, FsError> {
        #[cfg(target_os = "linux")]
        let flags = OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC;
        #[cfg(not(target_os = "linux"))]
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC;
        let fd = rustix::fs::open(dir, flags, Mode::empty()).map_err(|e| refused("open directory", dir, e, true))?;
        Ok(Self {
            fd,
            path: dir.to_owned(),
        })
    }

    /// Open `dir`, which holds the leaf a caller is about to open. The parent of a leaf resolves as the OS resolves
    /// it, links included: the leaf itself is what [`open_file`] and [`create_file_at`] refuse to follow.
    fn open_dir_following_leaf(dir: &Path) -> Result<Self, FsError> {
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC;
        let fd = rustix::fs::open(dir, flags, Mode::empty()).map_err(|e| refused("open directory", dir, e, true))?;
        Ok(Self {
            fd,
            path: dir.to_owned(),
        })
    }
}

/// `fd` as a [`File`], when it is a regular file.
fn regular(fd: std::os::fd::OwnedFd, path: &Path) -> Result<File, FsError> {
    let stat = rustix::fs::fstat(&fd).map_err(|e| FsError::io("stat file", path, e))?;
    if EntryKind::of(stat.st_mode) != EntryKind::File {
        return Err(FsError::Unsafe {
            path: path.to_owned(),
            reason: "is not a regular file".to_owned(),
        });
    }
    // NONBLOCK only guarded the open against a fifo; a regular file does not need it.
    if let Ok(flags) = rustix::fs::fcntl_getfl(&fd) {
        let _ = rustix::fs::fcntl_setfl(&fd, flags & !OFlags::NONBLOCK);
    }
    Ok(File::from(fd))
}

/// Split `path` into its parent and its last component.
fn split(path: &Path) -> Result<(&Path, &OsStr), FsError> {
    match (path.parent(), path.file_name()) {
        (Some(parent), Some(name)) => {
            // `Path::parent` of a bare name is empty; it means the current directory.
            let parent = if parent.as_os_str().is_empty() {
                Path::new(".")
            } else {
                parent
            };
            Ok((parent, name))
        }
        _ => Err(FsError::Unsafe {
            path: path.to_owned(),
            reason: "has no parent directory and file name".to_owned(),
        }),
    }
}

/// `name` as one directory entry: not empty, not `.` or `..`, no `/`.
fn component<'a>(name: &'a OsStr, dir: &Path) -> Result<&'a OsStr, FsError> {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes == b"." || bytes == b".." || bytes.contains(&b'/') {
        return Err(FsError::Unsafe {
            path: dir.join(name),
            reason: "is not a single path component".to_owned(),
        });
    }
    Ok(name)
}

/// Turn the error of a no-follow open into [`FsError`]: a link (or a non-directory, for a directory open) is
/// refused with the rule named, anything else is an I/O error.
fn refused(action: &'static str, path: &Path, errno: Errno, directory: bool) -> FsError {
    if errno == Errno::LOOP || (directory && errno == Errno::NOTDIR) {
        let reason = if directory {
            "is a symlink or not a directory; refusing to follow it"
        } else {
            "is a symlink; refusing to follow it"
        };
        return FsError::Unsafe {
            path: path.to_owned(),
            reason: reason.to_owned(),
        };
    }
    FsError::io(action, path, errno)
}

#[cfg(test)]
mod tests {
    use std::{fs, io, os::unix::fs::symlink};

    use anyhow::Context as _;

    use super::*;

    fn name(s: &str) -> &OsStr {
        OsStr::new(s)
    }

    /// #618: a symlink at the leaf is refused, even when it names a directory.
    #[test]
    fn a_symlink_at_the_leaf_is_refused() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let real = dir.path().join("real");
        fs::create_dir(&real)?;
        let link = dir.path().join("link");
        symlink(&real, &link)?;

        let err = Beneath::open_dir(&link).expect_err("a symlinked directory must be refused");

        assert!(matches!(err, FsError::Unsafe { .. }), "{err}");
        assert!(err.to_string().contains("symlink"), "{err}");
        Ok(())
    }

    /// #618: a link below the leaf is refused whether it names a file or a directory, and its target is not read.
    #[test]
    fn a_symlink_below_the_leaf_is_refused() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let victim = dir.path().join("victim");
        fs::write(&victim, b"HOST-SECRET")?;
        let tree = dir.path().join("tree");
        fs::create_dir(&tree)?;
        symlink(&victim, tree.join("file-link"))?;
        symlink(dir.path(), tree.join("dir-link"))?;
        let held = Beneath::open_dir(&tree)?;

        assert!(matches!(held.open_file(name("file-link")), Err(FsError::Unsafe { .. })));
        assert!(matches!(
            held.open_subdir(name("dir-link")),
            Err(FsError::Unsafe { .. })
        ));
        assert!(matches!(
            held.create_file(name("file-link")),
            Err(FsError::Unsafe { .. })
        ));
        assert!(matches!(held.create_dir(name("dir-link")), Err(FsError::Unsafe { .. })));
        assert_eq!(fs::read(&victim)?, b"HOST-SECRET", "the target is untouched");
        Ok(())
    }

    /// #618, the swap between check and use: once a directory is open, replacing its path with a symlink to another
    /// directory changes nothing, because the handle is not resolved again.
    #[test]
    fn a_directory_swapped_for_a_symlink_after_it_was_opened_is_not_followed() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let victim = dir.path().join("victim");
        fs::create_dir(&victim)?;
        fs::write(victim.join("secret"), b"HOST-SECRET")?;
        let target = dir.path().join("target");
        fs::create_dir(&target)?;
        fs::write(target.join("mine"), b"original")?;
        let held = Beneath::open_dir(&target)?;

        // The swap: the checked path now names the victim.
        fs::rename(&target, dir.path().join("target.moved"))?;
        symlink(&victim, &target)?;

        let entries = held
            .entries()?
            .map(|e| e.map(|(n, _)| n))
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(
            entries,
            [OsString::from("mine")],
            "the handle still lists the original directory"
        );
        let mut mine = held.open_file(name("mine"))?;
        let mut read = String::new();
        io::Read::read_to_string(&mut mine, &mut read)?;
        assert_eq!(read, "original");
        io::Write::write_all(&mut held.create_file(name("new"))?, b"written")?;
        assert!(
            dir.path().join("target.moved").join("new").exists(),
            "the write landed in the original"
        );
        assert!(
            !victim.join("new").exists(),
            "nothing was written through the swapped path"
        );
        Ok(())
    }

    /// `.` and `..` are never entries, and a link is reported as a link.
    #[test]
    fn entries_skip_dot_entries_and_report_links_as_links() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        fs::write(dir.path().join("f"), b"x")?;
        fs::create_dir(dir.path().join("d"))?;
        symlink("/nonexistent", dir.path().join("l"))?;

        let mut entries = Beneath::open_dir(dir.path())?
            .entries()?
            .collect::<Result<Vec<_>, _>>()?;
        entries.sort();

        assert_eq!(
            entries,
            [
                (OsString::from("d"), EntryKind::Dir),
                (OsString::from("f"), EntryKind::File),
                (OsString::from("l"), EntryKind::Symlink),
            ]
        );
        Ok(())
    }

    /// #618 (review): a trailing `/` or `/.` must not make the kernel follow a link in the last component.
    #[test]
    fn a_trailing_slash_or_dot_does_not_make_a_symlink_followable() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let real = dir.path().join("real");
        fs::create_dir(&real)?;
        let link = dir.path().join("link");
        symlink(&real, &link)?;

        for suffix in ["", "/", "/."] {
            let path = PathBuf::from(format!("{}{suffix}", link.display()));
            assert!(
                matches!(Beneath::open_dir(&path), Err(FsError::Unsafe { .. })),
                "{suffix:?}"
            );
        }
        // A real directory still opens, however it is spelled, and `.` names no link.
        for suffix in ["", "/", "/."] {
            Beneath::open_dir(&PathBuf::from(format!("{}{suffix}", real.display()))).context("a real directory")?;
        }
        Beneath::open_dir(Path::new(".")).context("the current directory")?;
        Ok(())
    }

    /// #680 (review): `--out .` names the current directory, and `/.` after an existing directory names that
    /// directory. Neither is a link, so both open.
    #[test]
    fn create_dir_at_accepts_a_destination_without_a_final_name() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;

        Beneath::create_dir_at(Path::new(".")).context("the current directory")?;
        Beneath::create_dir_at(&PathBuf::from(format!("{}/.", dir.path().display())))
            .context("an existing directory, spelled with /.")?;
        Ok(())
    }

    /// #680 (review): a parent above the leaf only needs search (execute) permission, not read: an input file under an
    /// execute-only directory still opens, and a destination under a write-and-execute-only one is still created.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_parent_without_read_permission_is_still_usable() -> anyhow::Result<()> {
        use std::os::unix::fs::PermissionsExt as _;

        if rustix::process::geteuid().is_root() {
            return Ok(());
        }
        let dir = tempfile::tempdir()?;
        let exec_only = dir.path().join("exec-only");
        fs::create_dir(&exec_only)?;
        fs::write(exec_only.join("f"), b"x")?;
        let write_exec = dir.path().join("write-exec");
        fs::create_dir(&write_exec)?;
        fs::set_permissions(&exec_only, fs::Permissions::from_mode(0o100))?;
        fs::set_permissions(&write_exec, fs::Permissions::from_mode(0o300))?;

        let opened = open_file(&exec_only.join("f"));
        let created = create_file_at(&write_exec.join("new"));
        let dest = Beneath::create_dir_at(&write_exec.join("sub"));

        fs::set_permissions(&exec_only, fs::Permissions::from_mode(0o700))?;
        fs::set_permissions(&write_exec, fs::Permissions::from_mode(0o700))?;
        opened.context("a file under an execute-only parent")?;
        created.context("a file under a write-and-execute-only parent")?;
        dest.context("a directory under a write-and-execute-only parent")?;
        assert!(write_exec.join("new").exists() && write_exec.join("sub").is_dir());
        Ok(())
    }

    /// #618 (review): only the destination is not followed; a link above it (macOS `/tmp`) resolves as usual.
    #[test]
    fn create_dir_at_resolves_a_link_above_the_destination() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let real = dir.path().join("real");
        fs::create_dir(&real)?;
        symlink(&real, dir.path().join("via"))?;

        Beneath::create_dir_at(&dir.path().join("via").join("out")).context("a link above the leaf")?;

        assert!(real.join("out").is_dir());
        Ok(())
    }

    /// #618 (review): a new file is refused when the name exists, a symlink included, and the target is untouched.
    #[test]
    fn create_new_file_never_writes_through_an_existing_entry() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let victim = dir.path().join("victim");
        fs::write(&victim, b"HOST-FILE")?;
        symlink(&victim, dir.path().join("link"))?;
        fs::write(dir.path().join("plain"), b"x")?;
        let held = Beneath::open_dir(dir.path())?;

        assert!(matches!(
            held.create_new_file(name("link")),
            Err(FsError::Unsafe { .. })
        ));
        assert!(matches!(
            held.create_new_file(name("plain")),
            Err(FsError::Unsafe { .. })
        ));
        io::Write::write_all(&mut held.create_new_file(name("fresh"))?, b"ok")?;
        assert_eq!(fs::read(&victim)?, b"HOST-FILE");
        assert_eq!(fs::read(dir.path().join("fresh"))?, b"ok");
        Ok(())
    }

    /// A staged symlink keeps its text and is not followed to create it.
    #[test]
    fn create_symlink_keeps_the_target_text() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let held = Beneath::open_dir(dir.path())?;

        held.create_symlink(name("l"), Path::new("/no/such/target"))?;

        assert_eq!(fs::read_link(dir.path().join("l"))?, Path::new("/no/such/target"));
        assert!(
            held.create_symlink(name("l"), Path::new("/x")).is_err(),
            "it must not exist"
        );
        Ok(())
    }

    /// An existing real directory is adopted; an existing regular file is not a directory.
    #[test]
    fn create_dir_adopts_a_directory_and_refuses_a_file() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        fs::create_dir(dir.path().join("d"))?;
        fs::write(dir.path().join("f"), b"x")?;
        let held = Beneath::open_dir(dir.path())?;

        held.create_dir(name("d")).context("an existing directory is adopted")?;
        held.create_dir(name("new")).context("a new directory is created")?;

        assert!(dir.path().join("new").is_dir());
        assert!(matches!(held.create_dir(name("f")), Err(FsError::Unsafe { .. })));
        Ok(())
    }

    /// An existing regular file is truncated, as `File::create` does.
    #[test]
    fn create_file_truncates_an_existing_file() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        fs::write(dir.path().join("f"), b"long old content")?;

        io::Write::write_all(&mut Beneath::open_dir(dir.path())?.create_file(name("f"))?, b"new")?;

        assert_eq!(fs::read(dir.path().join("f"))?, b"new");
        Ok(())
    }

    /// A name that is not one component cannot climb out of the directory.
    #[test]
    fn a_name_that_is_not_one_component_is_refused() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let held = Beneath::open_dir(dir.path())?;

        for bad in ["", ".", "..", "a/b", "../x"] {
            assert!(
                matches!(held.open_file(name(bad)), Err(FsError::Unsafe { .. })),
                "{bad:?}"
            );
            assert!(
                matches!(held.create_file(name(bad)), Err(FsError::Unsafe { .. })),
                "{bad:?}"
            );
        }
        Ok(())
    }

    /// By path: a symlinked leaf file is refused, a symlinked parent is resolved as the OS resolves it.
    #[test]
    fn a_leaf_file_by_path_is_not_followed_but_its_parents_resolve() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let real = dir.path().join("real");
        fs::create_dir(&real)?;
        fs::write(real.join("f"), b"x")?;
        symlink(&real, dir.path().join("via"))?; // a system-style link above the leaf
        symlink(real.join("f"), real.join("link"))?;

        open_file(&dir.path().join("via").join("f")).context("a link above the leaf resolves")?;
        assert!(matches!(open_file(&real.join("link")), Err(FsError::Unsafe { .. })));
        let victim = real.join("f");
        assert!(matches!(
            create_file_at(&real.join("link")),
            Err(FsError::Unsafe { .. })
        ));
        assert_eq!(fs::read(victim)?, b"x");
        Ok(())
    }

    /// A rename over a symlink replaces the link and never writes through it: the link's target is untouched.
    #[test]
    fn a_rename_replaces_a_symlink_without_following_it() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let victim = dir.path().join("victim");
        fs::write(&victim, b"HOST-SECRET")?;
        let tree = dir.path().join("tree");
        fs::create_dir(&tree)?;
        symlink(&victim, tree.join("final"))?;
        fs::write(tree.join("tmp"), b"new")?;
        let held = Beneath::open_dir(&tree)?;

        held.rename(name("tmp"), name("final")).context("rename")?;

        assert_eq!(fs::read(tree.join("final"))?, b"new");
        assert!(!fs::symlink_metadata(tree.join("final"))?.file_type().is_symlink());
        assert_eq!(fs::read(&victim)?, b"HOST-SECRET");
        assert!(!tree.join("tmp").exists(), "the source name is gone");
        Ok(())
    }

    /// A rename over a directory fails and leaves both entries, and a name with a separator is refused.
    #[test]
    fn a_rename_refuses_a_directory_target_and_a_path_name() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        fs::create_dir(dir.path().join("final"))?;
        fs::write(dir.path().join("tmp"), b"x")?;
        let held = Beneath::open_dir(dir.path())?;

        assert!(matches!(
            held.rename(name("tmp"), name("final")),
            Err(FsError::Io { .. })
        ));
        assert!(dir.path().join("final").is_dir());
        assert!(dir.path().join("tmp").is_file());
        assert!(matches!(
            held.rename(name("tmp"), name("sub/x")),
            Err(FsError::Unsafe { .. })
        ));
        assert!(matches!(
            held.rename(name("../tmp"), name("x")),
            Err(FsError::Unsafe { .. })
        ));
        Ok(())
    }

    /// Removing a symlink removes the link and leaves its target; a directory is refused.
    #[test]
    fn remove_file_removes_a_link_not_its_target_and_refuses_a_directory() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let victim = dir.path().join("victim");
        fs::write(&victim, b"HOST-SECRET")?;
        symlink(&victim, dir.path().join("link"))?;
        fs::write(dir.path().join("plain"), b"x")?;
        fs::create_dir(dir.path().join("sub"))?;
        let held = Beneath::open_dir(dir.path())?;

        held.remove_file(name("link")).context("remove the link")?;
        held.remove_file(name("plain")).context("remove the file")?;

        assert!(fs::symlink_metadata(dir.path().join("link")).is_err());
        assert!(!dir.path().join("plain").exists());
        assert_eq!(fs::read(&victim)?, b"HOST-SECRET");
        assert!(matches!(held.remove_file(name("sub")), Err(FsError::Io { .. })));
        assert!(dir.path().join("sub").is_dir());
        assert!(matches!(held.remove_file(name("a/b")), Err(FsError::Unsafe { .. })));
        Ok(())
    }

    /// `file_id` is the device and inode of the entry, the same a `stat` reports, so two names of one file agree.
    #[test]
    fn file_id_is_the_device_and_inode_of_the_entry() -> anyhow::Result<()> {
        use std::os::unix::fs::MetadataExt as _;

        let dir = tempfile::tempdir()?;
        fs::write(dir.path().join("a"), b"x")?;
        fs::hard_link(dir.path().join("a"), dir.path().join("b"))?;
        fs::write(dir.path().join("other"), b"y")?;
        let held = Beneath::open_dir(dir.path())?;

        let meta = fs::metadata(dir.path().join("a"))?;
        let id = held.file_id(name("a")).context("file_id a")?.context("a exists")?;
        assert_eq!((id.dev, id.ino), (meta.dev(), meta.ino()));
        assert_eq!(held.file_id(name("b"))?, Some(id), "a hard link is the same file");
        assert_ne!(held.file_id(name("other"))?, Some(id), "another file has another id");
        Ok(())
    }

    /// A missing entry has no id, a symlink has its own id (not its target's), and a name with a separator is refused.
    #[test]
    fn file_id_of_a_missing_entry_a_link_and_a_bad_name() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        fs::write(dir.path().join("target"), b"x")?;
        symlink(dir.path().join("target"), dir.path().join("link"))?;
        let held = Beneath::open_dir(dir.path())?;

        assert_eq!(held.file_id(name("missing"))?, None);
        let target = held.file_id(name("target"))?.context("target exists")?;
        let link = held.file_id(name("link"))?.context("link exists")?;
        assert_ne!(link, target, "a symlink is not followed: it has its own id");
        assert!(matches!(held.file_id(name("a/b")), Err(FsError::Unsafe { .. })));
        Ok(())
    }

    /// A device number keeps its bits when it becomes a `u64`: a negative `i32` is its two's complement, as
    /// `MetadataExt::dev` reports it, and a `u64` is itself.
    #[test]
    fn wrap_u64_keeps_the_bits_of_a_device_number() {
        assert_eq!(wrap_u64(5), 5);
        assert_eq!(wrap_u64(i128::from(u64::MAX)), u64::MAX);
        assert_eq!(wrap_u64(-1), u64::MAX);
        assert_eq!(
            wrap_u64(i128::from(i32::MIN)),
            u64::from_ne_bytes(i64::from(i32::MIN).to_ne_bytes())
        );
    }
}
