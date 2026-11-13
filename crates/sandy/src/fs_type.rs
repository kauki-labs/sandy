//! Which filesystem backs a path: the host-side check `sandy doctor` makes of `$SANDY_HOME` (INV-5), where a networked
//! filesystem cannot be trusted for flock.

use std::path::{Path, PathBuf};

/// Return the filesystem type backing `path`, by matching it against the host's
/// mount table. `None` when it cannot be determined (then the caller accepts).
#[must_use]
pub fn detect_fs_type(path: &Path) -> Option<String> {
    let target = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    mount_table()
        .into_iter()
        .filter(|(mount_point, _)| target.starts_with(mount_point))
        .max_by_key(|(mount_point, _)| mount_point.as_os_str().len())
        .map(|(_, fstype)| fstype)
}

/// Mount points and their filesystem types, read from `/proc/mounts` on Linux.
#[cfg(target_os = "linux")]
fn mount_table() -> Vec<(PathBuf, String)> {
    let content = std::fs::read_to_string("/proc/mounts").unwrap_or_default();
    content
        .lines()
        .filter_map(|line| {
            // `<device> <mount-point> <fstype> <opts> <freq> <passno>`
            let mut fields = line.split_whitespace();
            let _device = fields.next()?;
            let mount_point = fields.next()?;
            let fstype = fields.next()?;
            Some((PathBuf::from(mount_point), fstype.to_string()))
        })
        .collect()
}

/// Mount points and their filesystem types, parsed from `mount(8)` elsewhere
/// (macOS and other BSDs have no `/proc/mounts`).
#[cfg(not(target_os = "linux"))]
fn mount_table() -> Vec<(PathBuf, String)> {
    let Ok(output) = std::process::Command::new("mount").output() else {
        return Vec::new();
    };
    let text = String::from_utf8_lossy(&output.stdout);
    text.lines()
        .filter_map(|line| {
            // `<device> on <mount-point> (<fstype>, <opts>...)`
            let (_device, rest) = line.split_once(" on ")?;
            let (mount_point, paren) = rest.rsplit_once(" (")?;
            let fstype = paren.trim_end_matches(')').split(',').next()?.trim();
            Some((PathBuf::from(mount_point), fstype.to_string()))
        })
        .collect()
}

/// Whether `fstype` names a networked / shared filesystem where flock cannot be
/// trusted (INV-5).
#[must_use]
pub fn is_networked_fs(fstype: &str) -> bool {
    const DENY: &[&str] = &[
        "nfs",
        "nfs4",
        "cifs",
        "smbfs",
        "smb",
        "afpfs",
        "webdav",
        "sshfs",
        "virtiofs",
        "9p",
        "ncpfs",
        "glusterfs",
        "lustre",
        "ceph",
        "fuse.sshfs",
        "fuse.glusterfs",
    ];
    let lower = fstype.to_ascii_lowercase();
    DENY.contains(&lower.as_str())
}

#[cfg(test)]
mod tests {
    use super::{detect_fs_type, is_networked_fs};

    #[test]
    fn a_networked_filesystem_is_recognised_by_its_type() {
        for fstype in ["nfs", "NFS4", "virtiofs", "9p", "fuse.sshfs"] {
            assert!(is_networked_fs(fstype), "{fstype}");
        }
        for fstype in ["ext4", "apfs", "tmpfs", "btrfs", "xfs"] {
            assert!(!is_networked_fs(fstype), "{fstype}");
        }
    }

    #[test]
    fn a_temp_dir_is_not_on_a_networked_filesystem() -> anyhow::Result<()> {
        let tmp = tempfile::tempdir()?;
        if let Some(fstype) = detect_fs_type(tmp.path()) {
            assert!(!is_networked_fs(&fstype), "{fstype}");
        }
        Ok(())
    }
}
