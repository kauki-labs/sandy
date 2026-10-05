//! Block 0 precondition check: `sandy doctor` (REQ-12).
//!
//! Resolves `$SANDY_HOME`, probes the filesystem backing it, and refuses to start when it
//! is not a local POSIX filesystem. A networked/share mount (NFS, SMB, virtiofs, 9p, ...)
//! makes `flock` unreliable, which breaks the journal's single-writer guarantee (INV-5).

use std::path::PathBuf;

use sandy::ProcessExit;

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

/// Classifies a filesystem type name into an [`FsVerdict`], using the same
/// networked-filesystem policy as the journal's INV-5 gate
/// ([`sandy::is_networked_fs`]) so doctor and the runtime agree.
///
/// Pure, no I/O — this is the seam the adversarial tests exercise directly, without a real
/// network mount.
pub fn classify_fs(fstype: &str) -> FsVerdict {
    let normalized = fstype.trim().to_ascii_lowercase();
    if sandy::is_networked_fs(&normalized) {
        FsVerdict::NonLocal { fstype: normalized }
    } else {
        FsVerdict::Local
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
            exit_code: ProcessExit::Succeeded.code(),
            message: "sandy doctor: $SANDY_HOME is on a local POSIX filesystem — OK".to_string(),
        },
        FsVerdict::NonLocal { fstype } => DoctorResult {
            exit_code: ProcessExit::InvalidPlan.code(),
            message: format!(
                "sandy doctor: refusing to start — $SANDY_HOME is on '{fstype}', a networked or share filesystem; \
                 this violates INV-5 (flock is unreliable there). Point $SANDY_HOME at a local POSIX filesystem \
                 instead."
            ),
        },
    }
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
            exit_code: ProcessExit::InvalidPlan.code(),
            message: format!(
                "sandy doctor: refusing to start — could not create $SANDY_HOME at {}: {err}",
                home.display()
            ),
        };
    }

    // Reuse sandy's mount-table detector — the same seam the journal's INV-5
    // gate uses — so doctor and the runtime agree. An undetectable fstype is
    // accepted (like the journal), so the common local case never false-refuses.
    match sandy::detect_fs_type(&home) {
        Some(fstype) => doctor_result_for(classify_fs(&fstype)),
        None => DoctorResult {
            exit_code: ProcessExit::Succeeded.code(),
            message: "sandy doctor: $SANDY_HOME filesystem type is undetectable; proceeding — OK".to_string(),
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
