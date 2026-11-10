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

/// Every file under `root` that holds `needle`, except `skip`.
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
    use std::os::unix::fs::FileTypeExt;
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
                stack.push(
                    entry
                        .with_context(|| format!("read an entry of {}", p.display()))?
                        .path(),
                );
            }
        } else if kind.is_file() {
            if p != skip {
                match file_holds(&p, needle.as_bytes()) {
                    Ok(true) => hits.push(p),
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
fn file_holds(path: &Path, needle: &[u8]) -> std::io::Result<bool> {
    use std::io::Read;
    const CHUNK: usize = 1024 * 1024;
    let mut file = std::fs::File::open(path)?;
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
