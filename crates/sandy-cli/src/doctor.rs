//! Block 0 precondition check: `sandy doctor` (REQ-12).
//!
//! Resolves `$SANDY_HOME`, probes the filesystem backing it, and refuses to start when it
//! is not a local POSIX filesystem. A networked/share mount (NFS, SMB, virtiofs, 9p, ...)
//! makes `flock` unreliable, which breaks the journal's single-writer guarantee (INV-5).

use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};

use sandy::{Discovery, ProcessExit, StaticRegistry, parse_builder_systems};

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
    let fs_result = match sandy::detect_fs_type(&home) {
        Some(fstype) => doctor_result_for(classify_fs(&fstype)),
        None => DoctorResult {
            exit_code: ProcessExit::Succeeded.code(),
            message: "sandy doctor: $SANDY_HOME filesystem type is undetectable; proceeding — OK".to_string(),
        },
    };
    if fs_result.exit_code != ProcessExit::Succeeded.code() {
        return fs_result;
    }

    // On macOS the only native boot path is vfkit, which builds its guest with
    // nix on an <arch>-linux remote builder (the nix-darwin linux-builder). If
    // nix or that builder is missing, the boot cannot even be built — refuse now
    // with a named reason rather than failing opaquely at run time (gate honesty).
    if cfg!(target_os = "macos")
        && let Some(refusal) = mac_prereq_result(detect_mac_prereq())
    {
        return refusal;
    }

    fs_result
}

/// The macOS native-boot (vfkit) prerequisite verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MacPrereq {
    /// `nix` is present and a builder for the guest arch is configured.
    Ok,
    /// `nix` is not on `PATH`; the guest cannot be built.
    MissingNix,
    /// No remote builder is configured for this Linux guest system.
    MissingBuilder {
        /// The required guest system, e.g. `aarch64-linux`.
        system: String,
        /// The machines-file path that was actually checked — `/etc/nix/machines`
        /// in production, or `SANDY_NIX_MACHINES_FILE`'s override under test — so
        /// the refusal message never names a file it didn't read (#163 review).
        machines_path: PathBuf,
    },
}

/// Decide the macOS vfkit prerequisite from the probed facts (pure, the seam the
/// tests drive without touching the host).
///
/// vfkit matches host and guest architecture, so the guest is `<arch>-linux`,
/// which a darwin host can only produce on a remote `<arch>-linux` builder.
#[must_use]
pub fn mac_prereq_verdict(
    nix_present: bool,
    builder_systems: &BTreeSet<String>,
    guest_system: &str,
    machines_path: &Path,
) -> MacPrereq {
    if !nix_present {
        return MacPrereq::MissingNix;
    }
    if builder_systems.contains(guest_system) {
        MacPrereq::Ok
    } else {
        MacPrereq::MissingBuilder {
            system: guest_system.to_string(),
            machines_path: machines_path.to_path_buf(),
        }
    }
}

/// Map a [`MacPrereq`] to a refusing [`DoctorResult`] (exit `2`, INV-11 invalid
/// env), or `None` when the prerequisite is satisfied.
#[must_use]
pub fn mac_prereq_result(verdict: MacPrereq) -> Option<DoctorResult> {
    match verdict {
        MacPrereq::Ok => None,
        MacPrereq::MissingNix => Some(DoctorResult {
            exit_code: ProcessExit::InvalidPlan.code(),
            message: "sandy doctor: refusing to start — `nix` is not on PATH, but the macOS vfkit path builds the \
                      guest with nix. Install nix (https://nixos.org/download)."
                .to_string(),
        }),
        MacPrereq::MissingBuilder { system, machines_path } => Some(DoctorResult {
            exit_code: ProcessExit::InvalidPlan.code(),
            message: format!(
                "sandy doctor: refusing to start — no `{system}` remote builder is configured (checked \
                 {}), but the macOS vfkit path must build an `{system}` guest. Enable nix-darwin's \
                 linux-builder (`nix.linux-builder.enable = true;`) or register an `{system}` builder.",
                machines_path.display()
            ),
        }),
    }
}

/// Probe the macOS vfkit prerequisites: `nix` on `PATH` and a builder for the
/// guest system in `/etc/nix/machines` (missing file → no builders). `pub(crate)`:
/// `flake_wrap` (#325) reuses this same check before building a `--flake` kind-2/3
/// guest on macOS, rather than re-probing `/etc/nix/machines` itself.
///
/// The machines-file path honors `SANDY_NIX_MACHINES_FILE` (same override style
/// as `SANDY_VFKIT_BIN`/`SANDY_TAP`), falling back to the real `/etc/nix/machines`.
/// Together with the already-real `PATH` read in `nix_on_path`, this lets the
/// `sandy doctor` binary-level integration test (`tests/doctor.rs`) inject both
/// host facts into the child process it spawns, instead of depending on the
/// sandbox that built the test binary happening to have `nix` and a configured
/// builder (#163).
pub(crate) fn detect_mac_prereq() -> MacPrereq {
    let machines_path = std::env::var_os("SANDY_NIX_MACHINES_FILE")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/etc/nix/machines"));
    let machines = std::fs::read_to_string(&machines_path).unwrap_or_default();
    let guest = crate::host_target::host_target().guest_system;
    // Resolve placement through the Discovery seam — a static registry over the host
    // matrix. The buildable-systems check is the matrix systems, exactly as before.
    let placement = StaticRegistry::new(parse_builder_systems(&machines)).resolve(&guest);
    mac_prereq_verdict(nix_on_path(), &placement.systems, &guest, &machines_path)
}

/// Whether a `nix` executable resolves on `PATH`.
fn nix_on_path() -> bool {
    std::env::var_os("PATH").is_some_and(|path| std::env::split_paths(&path).any(|dir| dir.join("nix").is_file()))
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use rstest::rstest;

    use super::{FsVerdict, MacPrereq, classify_fs, doctor_result_for, mac_prereq_result, mac_prereq_verdict};

    const MACHINES_PATH: &str = "/etc/nix/machines";

    /// Missing nix wins over the builder check.
    #[test]
    fn missing_nix_is_flagged() {
        let systems = std::collections::BTreeSet::from(["aarch64-linux".to_string()]);
        assert_eq!(
            mac_prereq_verdict(false, &systems, "aarch64-linux", Path::new(MACHINES_PATH)),
            MacPrereq::MissingNix
        );
    }

    /// nix present but no builder for the guest arch → `MissingBuilder` naming it
    /// and the machines file that was checked.
    #[test]
    fn missing_builder_names_the_guest_system() {
        let systems = std::collections::BTreeSet::from(["x86_64-linux".to_string()]);
        assert_eq!(
            mac_prereq_verdict(true, &systems, "aarch64-linux", Path::new(MACHINES_PATH)),
            MacPrereq::MissingBuilder {
                system: "aarch64-linux".to_string(),
                machines_path: MACHINES_PATH.into(),
            }
        );
    }

    /// nix present and the matching builder configured → `Ok`.
    #[test]
    fn prereq_ok_when_nix_and_builder_present() {
        let systems = std::collections::BTreeSet::from(["aarch64-linux".to_string()]);
        assert_eq!(
            mac_prereq_verdict(true, &systems, "aarch64-linux", Path::new(MACHINES_PATH)),
            MacPrereq::Ok
        );
    }

    /// `Ok` maps to no refusal; each missing case maps to exit 2 with a named fix.
    #[test]
    fn prereq_result_refuses_with_a_named_reason() {
        assert!(mac_prereq_result(MacPrereq::Ok).is_none());

        let nix = mac_prereq_result(MacPrereq::MissingNix).expect("missing nix must refuse");
        assert_eq!(nix.exit_code, 2);
        assert!(nix.message.contains("nix"), "message must name nix: {}", nix.message);

        let builder = mac_prereq_result(MacPrereq::MissingBuilder {
            system: "aarch64-linux".to_string(),
            machines_path: MACHINES_PATH.into(),
        })
        .expect("missing builder must refuse");
        assert_eq!(builder.exit_code, 2);
        assert!(
            builder.message.contains("aarch64-linux"),
            "names the system: {}",
            builder.message
        );
        assert!(
            builder.message.contains("linux-builder"),
            "names the fix: {}",
            builder.message
        );
        assert!(
            builder.message.contains(MACHINES_PATH),
            "names the machines file actually checked: {}",
            builder.message
        );
    }

    /// The refusal names a `SANDY_NIX_MACHINES_FILE` override path, not the
    /// hardcoded `/etc/nix/machines`, when one was checked instead (#163 review).
    #[test]
    fn prereq_result_names_an_overridden_machines_path() {
        let builder = mac_prereq_result(MacPrereq::MissingBuilder {
            system: "aarch64-linux".to_string(),
            machines_path: "/tmp/fake-machines".into(),
        })
        .expect("missing builder must refuse");
        assert!(
            builder.message.contains("/tmp/fake-machines"),
            "names the overridden path, not /etc/nix/machines: {}",
            builder.message
        );
    }

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
