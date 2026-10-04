//! Block 0 precondition check: `sandy doctor` (REQ-12).
//!
//! Resolves `$SANDY_HOME`, probes the filesystem backing it, and refuses to start when it
//! is not a local POSIX filesystem. A networked/share mount (NFS, SMB, virtiofs, 9p, ...)
//! makes `flock` unreliable, which breaks the journal's single-writer guarantee (INV-5).
#![allow(
    dead_code,
    reason = "skeleton for the implementer to wire into main()'s doctor dispatch; exercised directly by the unit \
              tests below in the meantime"
)]

use std::path::{Path, PathBuf};

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
    todo!("classify {fstype} as Local or NonLocal per INV-5; see the unit tests below for the known-type table")
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
    todo!("map {verdict:?} to a DoctorResult; the NonLocal message must contain \"INV-5\"")
}

/// Probes the filesystem type backing `path` (e.g. via `stat -f %T` on macOS, or the
/// equivalent `mount`/`stat` incantation on Linux).
///
/// Shells out rather than calling libc directly, since `unsafe_code` is forbidden
/// workspace-wide. Not unit-tested in the sandbox (that would require a real network
/// mount) — covered instead by [`classify_fs`] / [`doctor_result_for`] unit tests and the
/// local-filesystem integration test.
///
/// # Errors
/// Returns an error if the probe command cannot be run or its output cannot be parsed.
pub fn fstype_of(path: &Path) -> std::io::Result<String> {
    todo!("shell out to stat/mount to determine the fstype backing {path:?}")
}

/// Resolves `$SANDY_HOME`: the `SANDY_HOME` environment variable, defaulting to
/// `$HOME/.sandy`.
pub fn sandy_home() -> PathBuf {
    todo!("read the SANDY_HOME env var, defaulting to $HOME/.sandy")
}

/// Runs the full `sandy doctor` check: resolves `$SANDY_HOME`, probes its filesystem,
/// classifies it, and returns the exit decision. This is the entry point the `doctor`
/// subcommand wires to.
pub fn run_doctor() -> DoctorResult {
    todo!("compose sandy_home() -> fstype_of() -> classify_fs() -> doctor_result_for()")
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
