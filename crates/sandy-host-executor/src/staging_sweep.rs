//! Staging roots a crashed executor left behind (#763).
//!
//! A job's input and output staging roots live under the host's temp directory and are removed when the job's
//! handler drops them. A crash or a SIGKILL skips that, and up to `MAX_TRANSFER_BYTES` per job stays on disk, outside
//! the base `sandy gc` sweeps. Each root is named `sandy-<inputs|outputs>-<pid>-<random>`; at start the executor
//! removes the ones whose process is gone.

use std::path::Path;

/// The directory-name prefix of a staging root of `kind` (`inputs` or `outputs`) made by this process.
#[must_use]
pub fn root_prefix(kind: &str) -> String {
    format!("sandy-{kind}-{}-", std::process::id())
}

/// The pid in a `sandy-<inputs|outputs>-<pid>-<random>` name, or `None` for any other name.
fn root_name_pid(name: &str) -> Option<u32> {
    let rest = name
        .strip_prefix("sandy-inputs-")
        .or_else(|| name.strip_prefix("sandy-outputs-"))?;
    let (pid, random) = rest.split_once('-')?;
    (!random.is_empty()).then_some(())?;
    pid.parse().ok()
}

/// Whether a process with this pid exists. A pid that cannot be signalled for lack of permission still exists.
fn process_is_alive(pid: u32) -> bool {
    use rustix::process::{Pid, test_kill_process};

    let Some(pid) = i32::try_from(pid).ok().and_then(Pid::from_raw) else {
        return true;
    };
    !matches!(test_kill_process(pid), Err(rustix::io::Errno::SRCH))
}

/// Remove the staging roots under `parent` that a process that is gone left behind. Returns how many it removed.
/// Only a real directory owned by this user with a root name is a candidate: a symlink, a file or a foreign name is
/// left, and this process's own roots are never touched (a job may be using one). A live process's roots are left, and
/// a pid reused by a live process keeps its leftover. Best effort: nothing here fails the start.
#[must_use]
pub fn sweep_stale_roots(parent: &Path) -> usize {
    use std::os::unix::fs::MetadataExt as _;

    let Ok(entries) = std::fs::read_dir(parent) else {
        return 0;
    };
    let (own, uid) = (std::process::id(), rustix::process::getuid().as_raw());
    let mut removed = 0;
    for entry in entries.filter_map(Result::ok) {
        let Some(pid) = entry.file_name().to_str().and_then(root_name_pid) else {
            continue;
        };
        if pid == own || process_is_alive(pid) {
            continue;
        }
        let path = entry.path();
        let Ok(metadata) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if !metadata.is_dir() || metadata.uid() != uid {
            continue;
        }
        match std::fs::remove_dir_all(&path) {
            Ok(()) => removed += 1,
            Err(e) => tracing::warn!(error = %e, root = %path.display(), "could not remove a stale staging root"),
        }
    }
    removed
}

#[cfg(test)]
mod tests {
    use anyhow::Context;

    use super::*;

    /// The pid of a process that has exited: a short-lived child of this test binary, waited for.
    fn a_dead_pid() -> anyhow::Result<u32> {
        let mut child = std::process::Command::new(std::env::current_exe().context("current exe")?)
            .arg("--help")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .context("spawn a child")?;
        let pid = child.id();
        child.wait().context("wait for the child")?;
        Ok(pid)
    }

    fn make_root(parent: &Path, name: &str) -> anyhow::Result<()> {
        std::fs::create_dir_all(parent.join(name).join("sub")).context("root")?;
        std::fs::write(parent.join(name).join("sub/f"), b"staged").context("file")
    }

    /// Roots of a dead process, inputs and outputs, are removed with their contents; nothing else is touched.
    #[test]
    fn roots_of_a_dead_process_are_removed_and_nothing_else() -> anyhow::Result<()> {
        use std::os::unix::fs::symlink;

        let dead = a_dead_pid()?;
        let own = std::process::id();
        let parent_pid = std::os::unix::process::parent_id();
        let tmp = tempfile::tempdir().context("tmp")?;
        let outside = tempfile::tempdir().context("outside")?;
        std::fs::write(outside.path().join("target"), b"TARGET").context("target")?;

        for stale in [
            format!("sandy-inputs-{dead}-aB3x"),
            format!("sandy-outputs-{dead}-Zz9q"),
        ] {
            make_root(tmp.path(), &stale)?;
        }
        let kept = [
            format!("sandy-inputs-{own}-live1"),
            format!("sandy-outputs-{parent_pid}-live2"),
            "sandy-inputs-notapid-x".to_owned(),
            format!("sandy-other-{dead}-x"),
            format!("keep-sandy-inputs-{dead}-x"),
        ];
        for name in &kept {
            make_root(tmp.path(), name)?;
        }
        std::fs::write(tmp.path().join(format!("sandy-inputs-{dead}-file")), b"x").context("a file")?;
        symlink(outside.path(), tmp.path().join(format!("sandy-outputs-{dead}-link"))).context("a symlink")?;

        assert_eq!(sweep_stale_roots(tmp.path()), 2);

        for name in [
            format!("sandy-inputs-{dead}-aB3x"),
            format!("sandy-outputs-{dead}-Zz9q"),
        ] {
            assert!(!tmp.path().join(&name).exists(), "{name} was not removed");
        }
        for name in &kept {
            assert!(tmp.path().join(name).join("sub/f").is_file(), "{name} was removed");
        }
        assert!(
            tmp.path().join(format!("sandy-inputs-{dead}-file")).is_file(),
            "a file was removed"
        );
        assert!(
            std::fs::symlink_metadata(tmp.path().join(format!("sandy-outputs-{dead}-link")))?
                .file_type()
                .is_symlink(),
            "a symlink was removed"
        );
        assert_eq!(
            std::fs::read(outside.path().join("target")).context("target")?,
            b"TARGET"
        );
        Ok(())
    }

    /// A new root carries its owner's pid, which is what the sweep reads.
    #[test]
    fn a_new_root_name_carries_the_owner_pid() {
        assert_eq!(root_prefix("inputs"), format!("sandy-inputs-{}-", std::process::id()));
    }
}
