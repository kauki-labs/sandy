//! Block 0 precondition check: `sandy doctor` (REQ-12).
//!
//! Resolves `$SANDY_HOME`, probes the filesystem backing it, and refuses to start when it
//! is not a local POSIX filesystem. A networked/share mount (NFS, SMB, virtiofs, 9p, ...)
//! makes `flock` unreliable, which breaks the journal's single-writer guarantee (INV-5).

use std::{
    io,
    path::{Path, PathBuf},
    process::Command,
};

/// Verdict for whether a filesystem type is acceptable for `$SANDY_HOME`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FsVerdict {
    /// A local POSIX filesystem (e.g. apfs, hfs, ext4/3/2, xfs, btrfs, zfs, tmpfs). `flock`
    /// is reliable here.
    Local,
    /// A networked or share filesystem (e.g. nfs, smbfs, cifs, virtiofs, 9p) where `flock`
    /// is unreliable (INV-5).
    NonLocal {
        /// The filesystem type name as reported by the OS probe, kept for diagnostics.
        fstype: String,
    },
}

/// Classifies a filesystem type name (as reported by `stat`/`mount`) into an [`FsVerdict`].
///
/// Pure, no I/O — this is the seam the adversarial tests exercise directly, without a real
/// network mount.
pub fn classify_fs(fstype: &str) -> FsVerdict {
    const LOCAL: &[&str] = &["apfs", "hfs", "ext4", "ext3", "ext2", "xfs", "btrfs", "zfs", "tmpfs"];

    let normalized = fstype.trim().to_ascii_lowercase();
    if LOCAL.contains(&normalized.as_str()) {
        FsVerdict::Local
    } else {
        // Covers known networked/share types (nfs, smbfs, cifs, virtiofs, 9p, fuse.*) and,
        // deliberately, anything unrecognized: an unknown fstype can't be vouched for as
        // flock-safe, so INV-5 means refuse rather than silently continue.
        FsVerdict::NonLocal { fstype: normalized }
    }
}

/// The outcome of a `sandy doctor` run: a process exit code and a human-readable message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctorResult {
    /// The process exit code sandy should use: `0` ok, `2` invalid env (INV-11).
    pub exit_code: i32,
    /// A human-readable message; on refusal, names the violated invariant (INV-5).
    pub message: String,
}

/// Maps an [`FsVerdict`] to the [`DoctorResult`] (exit code + message) `sandy doctor` reports.
///
/// `Local` maps to exit `0`. `NonLocal` maps to exit `2` (INV-11 invalid-env), with a
/// message that names INV-5 — never a silent continue.
pub fn doctor_result_for(verdict: FsVerdict) -> DoctorResult {
    match verdict {
        FsVerdict::Local => DoctorResult {
            exit_code: 0,
            message: "sandy doctor: $SANDY_HOME is on a local POSIX filesystem — OK".to_string(),
        },
        FsVerdict::NonLocal { fstype } => DoctorResult {
            exit_code: 2,
            message: format!(
                "sandy doctor: refusing to start — $SANDY_HOME is on '{fstype}', a networked or share filesystem; \
                 this violates INV-5 (flock is unreliable there). Point $SANDY_HOME at a local POSIX filesystem \
                 instead."
            ),
        },
    }
}

/// Whether the `stat` binary found on `$PATH` is GNU coreutils' (vs. BSD/macOS stat).
///
/// `cfg!(target_os = "macos")` alone isn't enough: a nix dev shell commonly puts GNU
/// coreutils ahead of `/usr/bin/stat` on `$PATH` even when compiled for macOS, so the two
/// stat flavors have to be told apart at run time, not compile time. GNU stat accepts
/// `--version` (exit 0); BSD stat rejects it as an unknown option (nonzero exit).
fn stat_is_gnu() -> bool {
    Command::new("stat")
        .arg("--version")
        .output()
        .is_ok_and(|output| output.status.success())
}

/// Probes the filesystem type backing `path` via `stat`: GNU's `-f -c %T`, or BSD/macOS's
/// `-f %T` (see [`stat_is_gnu`] for how the flavor is chosen).
///
/// Shells out rather than calling libc directly, since `unsafe_code` is forbidden
/// workspace-wide. Not unit-tested in the sandbox (that would require a real network
/// mount) — covered instead by [`classify_fs`] / [`doctor_result_for`] unit tests and the
/// local-filesystem integration test.
///
/// # Errors
/// Returns an error if the probe command cannot be run or its output cannot be parsed.
pub fn fstype_of(path: &Path) -> std::io::Result<String> {
    let output = if stat_is_gnu() {
        Command::new("stat").args(["-f", "-c", "%T"]).arg(path).output()?
    } else {
        Command::new("stat").args(["-f", "%T"]).arg(path).output()?
    };

    if !output.status.success() {
        return Err(io::Error::other(format!(
            "stat -f probe for {path:?} exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }

    let fstype = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if fstype.is_empty() {
        return Err(io::Error::other(format!(
            "stat -f probe for {path:?} returned no fstype"
        )));
    }
    Ok(fstype)
}

/// Resolves `$SANDY_HOME`: the `SANDY_HOME` environment variable, defaulting to
/// `$HOME/.sandy`.
pub fn sandy_home() -> PathBuf {
    if let Ok(sandy_home) = std::env::var("SANDY_HOME") {
        return PathBuf::from(sandy_home);
    }
    PathBuf::from(std::env::var("HOME").unwrap_or_default()).join(".sandy")
}

/// Runs the full `sandy doctor` check: resolves `$SANDY_HOME`, probes its filesystem,
/// classifies it, and returns the exit decision. This is the entry point the `doctor`
/// subcommand wires to.
pub fn run_doctor() -> DoctorResult {
    let home = sandy_home();

    // A fresh install has no $SANDY_HOME yet; create it so there is something to probe.
    if let Err(err) = std::fs::create_dir_all(&home) {
        return DoctorResult {
            exit_code: 2,
            message: format!(
                "sandy doctor: refusing to start — could not create $SANDY_HOME at {}: {err}",
                home.display()
            ),
        };
    }

    match fstype_of(&home) {
        Ok(fstype) => doctor_result_for(classify_fs(&fstype)),
        Err(err) => DoctorResult {
            exit_code: 2,
            message: format!(
                "sandy doctor: refusing to start — could not verify the filesystem backing $SANDY_HOME at {}: {err}",
                home.display()
            ),
        },
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::{FsVerdict, classify_fs, doctor_result_for};

    #[rstest]
    #[case::apfs("apfs")]
    #[case::hfs("hfs")]
    #[case::ext4("ext4")]
    #[case::ext3("ext3")]
    #[case::ext2("ext2")]
    #[case::xfs("xfs")]
    #[case::btrfs("btrfs")]
    #[case::zfs("zfs")]
    #[case::tmpfs("tmpfs")]
    fn classify_fs_accepts_known_local_filesystems(#[case] fstype: &str) {
        assert_eq!(classify_fs(fstype), FsVerdict::Local);
    }

    #[rstest]
    #[case::nfs("nfs")]
    #[case::smbfs("smbfs")]
    #[case::cifs("cifs")]
    #[case::virtiofs("virtiofs")]
    #[case::ninep("9p")]
    fn classify_fs_rejects_known_networked_filesystems(#[case] fstype: &str) {
        assert_eq!(
            classify_fs(fstype),
            FsVerdict::NonLocal {
                fstype: fstype.to_string()
            }
        );
    }

    #[test]
    fn local_verdict_maps_to_exit_0() {
        let result = doctor_result_for(FsVerdict::Local);
        assert_eq!(result.exit_code, 0);
    }

    #[test]
    fn nonlocal_verdict_maps_to_exit_2_and_names_inv_5() {
        let verdict = FsVerdict::NonLocal {
            fstype: "nfs".to_string(),
        };
        let result = doctor_result_for(verdict);
        assert_eq!(result.exit_code, 2);
        assert!(
            result.message.contains("INV-5"),
            "refusal message must name INV-5, got: {}",
            result.message
        );
    }

    #[test]
    fn nonlocal_message_names_the_detected_fstype() {
        let verdict = FsVerdict::NonLocal {
            fstype: "virtiofs".to_string(),
        };
        let result = doctor_result_for(verdict);
        assert!(
            result.message.contains("virtiofs"),
            "expected the message to name the offending fstype, got: {}",
            result.message
        );
    }
}
