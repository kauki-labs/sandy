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
    format!("sandy-{kind}-")
}

/// Remove the staging roots under `parent` that a process that is gone left behind. Returns how many it removed.
/// Best effort: nothing here fails the start.
#[must_use]
pub fn sweep_stale_roots(parent: &Path) -> usize {
    let _ = parent;
    0
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
