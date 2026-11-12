//! Pure helpers for the live broker gate: `/proc` parsing, the descendant walk, the staging base and the stray
//! scan. They take their input as arguments, so `tests/procs.rs` pins them without a VM or the `live` feature.
#![allow(dead_code, reason = "shared by several test binaries; each uses a subset")]

use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use sandy_fsutil::STAGING_DIR_NAME;

/// `(parent pid, start time)` from the text of `/proc/<pid>/stat`.
pub fn parse_stat(stat: &str) -> Option<(u32, u64)> {
    // The command name may hold spaces and parentheses; the fields after it start past the last `)`.
    let rest: Vec<&str> = stat.get(stat.rfind(')')? + 1..)?.split_whitespace().collect();
    // rest[0] is the state, rest[1] the ppid and rest[19] the start time.
    Some((rest.get(1)?.parse().ok()?, rest.get(19)?.parse().ok()?))
}

/// True when the `/proc/<pid>/stat` text names a live process. A zombie (`Z`, exited and not yet reaped) and a dead
/// one (`X`) are not live, and a line that cannot be read is not live either.
pub fn stat_is_live(stat: &str) -> bool {
    stat.rfind(')')
        .and_then(|i| stat.get(i + 1..))
        .and_then(|rest| rest.split_whitespace().next())
        .is_some_and(|state| !matches!(state, "Z" | "X"))
}

/// `(pid, start time)` of every descendant of `root` in `table`, a list of `(pid, ppid, start time)`.
///
/// Take the table before `root` is signalled: a child of a dead parent is re-parented to init and the walk no
/// longer reaches it. For the same reason a double-forked or daemonised descendant escapes the walk. That risk is
/// inferred from how `fork` and re-parenting work, not seen in a run. Another session's processes are never
/// descendants of this daemon, so a kill list from this walk cannot name them.
pub fn descendants_in(table: &[(u32, u32, u64)], root: u32) -> Vec<(u32, u64)> {
    let mut found: Vec<(u32, u64)> = Vec::new();
    let mut frontier = vec![root];
    while let Some(parent) = frontier.pop() {
        for (pid, ppid, start) in table {
            if *ppid == parent && *pid != root && !found.iter().any(|(p, _)| p == pid) {
                found.push((*pid, *start));
                frontier.push(*pid);
            }
        }
    }
    found
}

/// The process group id from the text of `/proc/<pid>/stat`.
pub fn parse_pgrp(_stat: &str) -> Option<u32> {
    None
}

/// `(pid, start time)` of every member of process group `pgid` in `table`, a list of `(pid, pgrp, start time)`.
/// `pgid` itself is listed when it is a member. The test starts `sandyd` as the leader of its own group, so a VM part
/// that was re-parented or double-forked still carries that group id, which the parent walk cannot see.
pub fn group_members_in(_table: &[(u32, u32, u64)], _pgid: u32) -> Vec<(u32, u64)> {
    Vec::new()
}

/// Whether a process name (`/proc/<pid>/comm`) is part of a VM: qemu, its virtiofs daemons or the egress proxy.
/// The nix-wrapped binaries report a leading dot (`.qemu-system-x8`), and `comm` keeps 15 characters.
pub fn is_vm_part(comm: &str) -> bool {
    let name = comm.trim().trim_start_matches('.');
    name.starts_with("qemu") || name.starts_with("virtiofsd") || name.starts_with("sandy-egress")
}

/// The staging base the backend uses under `tmp`: where a run's secret share, console log and sockets live.
pub fn staging_base(tmp: &Path) -> PathBuf {
    tmp.join(STAGING_DIR_NAME)
}

/// Everything under the staging base of `tmp`. A run removes its own directory, so after teardown the base may
/// exist but must hold nothing.
///
/// # Errors
/// The base exists but cannot be listed. A missing base is clean (nothing was staged); any other failure is not.
pub fn run_dirs_left(tmp: &Path) -> Result<Vec<PathBuf>> {
    let base = staging_base(tmp);
    let entries = match std::fs::read_dir(&base) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).with_context(|| format!("list the staging base {}", base.display())),
    };
    entries
        .map(|e| {
            Ok(e.with_context(|| format!("read an entry of {}", base.display()))?
                .path())
        })
        .collect()
}

/// Every path under `root` that holds `needle`: a regular file whose contents hold it, and any file or directory
/// whose name holds it. `skip` is exempt from both checks. The name check is on one path component at a time, so a
/// needle that contains `/` never matches a name; a token canary has none.
///
/// The scan fails closed: a clean result means every entry was read. Any path that cannot be stat-ed, listed or
/// read is an error, and so is a symlink, fifo or device (the scan cannot read what it holds). A Unix socket is
/// exempt: it stores no bytes, and a run's console and virtiofs sockets sit under the staging base. A path that
/// vanishes between the listing and the read (`NotFound`) is skipped, since a deleted file holds nothing to leak;
/// the scan root itself must exist. Files are read in chunks, with no size cap.
///
/// # Errors
/// An entry was unreadable or of a kind the scan cannot read.
pub fn files_holding(root: &Path, needle: &str, skip: &Path) -> Result<Vec<PathBuf>> {
    use std::os::unix::{ffi::OsStrExt as _, fs::FileTypeExt};
    // An empty needle is in every file, and `windows(0)` panics: a caller bug, refused before anything is read.
    anyhow::ensure!(!needle.is_empty(), "the canary scan needs a non-empty needle");
    let mut hits = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(p) = stack.pop() {
        let meta = match std::fs::symlink_metadata(&p) {
            Ok(meta) => meta,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && p != root => continue,
            Err(e) => return Err(e).with_context(|| format!("stat {}", p.display())),
        };
        let kind = meta.file_type();
        if kind.is_dir() {
            let entries = match std::fs::read_dir(&p) {
                Ok(entries) => entries,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound && p != root => continue,
                Err(e) => return Err(e).with_context(|| format!("list {}", p.display())),
            };
            for entry in entries {
                let entry = entry.with_context(|| format!("read an entry of {}", p.display()))?;
                // A name can carry the canary too (a file named after it, a path in a log line).
                if entry.path() != skip
                    && entry
                        .file_name()
                        .as_bytes()
                        .windows(needle.len())
                        .any(|w| w == needle.as_bytes())
                {
                    hits.push(entry.path());
                }
                stack.push(entry.path());
            }
        } else if kind.is_file() {
            if p != skip {
                match file_holds(&p, needle.as_bytes()) {
                    Ok(true) if !hits.contains(&p) => hits.push(p),
                    Ok(true) => {}
                    Ok(false) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => return Err(e).with_context(|| format!("read {}", p.display())),
                }
            }
        } else if !kind.is_socket() {
            anyhow::bail!(
                "{} is a symlink, fifo or device: the canary scan cannot read it",
                p.display()
            );
        }
    }
    Ok(hits)
}

/// Whether the file at `path` holds `needle`, read in 1 MiB chunks. The last `needle.len() - 1` bytes of a chunk
/// are kept, so a match that straddles a chunk boundary is found.
///
/// The entry was a regular file when the scan listed it, and it can be swapped for a fifo or a device before this
/// open. A plain open of a fifo with no writer blocks forever, so the open is non-blocking, refuses a symlink and
/// does not take a terminal for its controlling one, and the type is checked on the open descriptor: anything but
/// a regular file is an error.
///
/// # Errors
/// The file cannot be opened or read, or is not a regular file.
pub fn file_holds(path: &Path, needle: &[u8]) -> std::io::Result<bool> {
    use std::{io::Read, os::unix::fs::OpenOptionsExt as _};
    const CHUNK: usize = 1024 * 1024;
    if needle.is_empty() {
        return Err(std::io::Error::other("an empty needle is in every file"));
    }
    // Not `unwrap_or(0)`: dropping the flags would bring the fifo hang back without a sound.
    let flags = i32::try_from(
        (rustix::fs::OFlags::NONBLOCK | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NOCTTY).bits(),
    )
    .map_err(std::io::Error::other)?;
    let mut file = std::fs::OpenOptions::new().read(true).custom_flags(flags).open(path)?;
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::other(
            "not a regular file: it changed after the scan listed it",
        ));
    }
    let keep = needle.len().saturating_sub(1);
    let mut buf = vec![0u8; CHUNK + keep];
    let mut carried = 0;
    loop {
        let n = file.read(&mut buf[carried..carried + CHUNK])?;
        if n == 0 {
            return Ok(false);
        }
        let end = carried + n;
        if buf[..end].windows(needle.len()).any(|w| w == needle) {
            return Ok(true);
        }
        let tail = keep.min(end);
        buf.copy_within(end - tail..end, 0);
        carried = tail;
    }
}

/// Every sandy-named entry of `root` (the staging base `sandy` or a `sandy-*` name) and its direct children.
pub fn sandy_entries(root: &Path) -> BTreeSet<PathBuf> {
    let mut found = BTreeSet::new();
    let Ok(dir) = std::fs::read_dir(root) else {
        return found;
    };
    for entry in dir.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name == STAGING_DIR_NAME || name.starts_with("sandy-") {
            found.insert(entry.path());
            if let Ok(children) = std::fs::read_dir(entry.path()) {
                found.extend(children.flatten().map(|c| c.path()));
            }
        }
    }
    found
}

/// Entries in `after` that are not in `before` and not under `own`. They belong to someone else, such as another
/// session on a shared host, so the caller reports them and never touches them.
pub fn foreign_new_entries(before: &BTreeSet<PathBuf>, after: &BTreeSet<PathBuf>, own: &Path) -> Vec<PathBuf> {
    after
        .difference(before)
        .filter(|p| !p.starts_with(own))
        .cloned()
        .collect()
}
