//! The guest filesystem-share seam: how a hypervisor presents staged host
//! directories to the guest as virtio-fs mounts.
//!
//! The [`GuestShareTransport`] trait and its data types are the contract; the
//! per-hypervisor implementations (qemu virtiofsd, vfkit virtio-fs, process
//! local-dir) live in the backend crate. A [`ShareSpec`] is the backend-neutral
//! unit every implementation consumes.

use std::{path::PathBuf, process::Child};

use crate::backend::BackendError;

/// One guest filesystem share, served as virtio-fs. The guest matches it by [`tag`];
/// the host serves [`host_dir`]. For the daemon transport the host also serves it
/// over [`socket`]; `readonly` is enforced at the virtiofsd boundary (qemu) or the
/// guest mount (vfkit), so a share stays read-only even against a guest-root
/// remount where the transport enforces it host-side.
///
/// [`tag`]: ShareSpec::tag
/// [`host_dir`]: ShareSpec::host_dir
/// [`socket`]: ShareSpec::socket
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareSpec {
    /// The host directory shared into the guest.
    pub host_dir: PathBuf,
    /// The virtio-fs mount tag the guest keys its mount on (e.g. `sandy-secrets`).
    pub tag: String,
    /// Deny guest writes (secrets, inputs); outputs are writable.
    pub readonly: bool,
    /// The `virtiofsd` vhost-user socket the daemon transport launches it on and the
    /// hypervisor connects to. Unused by the daemonless vfkit transport.
    pub socket: PathBuf,
}

/// How presenting the shares wires the guest, the pure output of
/// [`GuestShareTransport::plan`]. One enum so the seam has a single return type
/// across every transport (the shared contract test covers all three uniformly).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Presentation {
    /// A VM: the hypervisor argv fragment wiring the shares as virtio-fs.
    Vm {
        /// The per-share devices (and, for the daemon transport, the shared-memory
        /// backend), as argv tokens.
        args: Vec<String>,
    },
    /// A host process (no virtio-fs): the staged share dirs, each with its mount
    /// tag and read-only flag, under a per-run `root`. The executor exposes them
    /// to the job as `SANDY_<TAG>_DIR` env vars (the process profile's access
    /// contract, distinct from the VM's fixed `/run/sandy/...` mount paths — a
    /// weak-isolation divergence, faithful-path fidelity is deferred to #135).
    LocalDir {
        /// The per-run root the staged share dirs live under.
        root: PathBuf,
        /// One entry per share: its tag, the host dir holding the staged bytes,
        /// and whether it is read-only.
        placements: Vec<Placement>,
    },
}

impl Presentation {
    /// The hypervisor argv for a VM presentation, consumed owned so a VM backend
    /// can splice it into its command; empty for any non-VM presentation.
    #[must_use]
    pub fn into_vm_args(self) -> Vec<String> {
        match self {
            Presentation::Vm { args } => args,
            Presentation::LocalDir { .. } => Vec::new(),
        }
    }
}

/// One staged share a host process reads: its [`ShareSpec::tag`], the host dir
/// holding the staged bytes, and whether it is read-only (enforced cooperatively,
/// `chmod a-w`, for the process profile — a same-user job can undo it, matching
/// the vfkit RO asymmetry in `docs/decisions/guest-shares.md` §2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Placement {
    /// The share's mount tag, also the `SANDY_<TAG>_DIR` env key stem.
    pub tag: String,
    /// The host dir holding the staged bytes.
    pub dir: PathBuf,
    /// Deny the job writes (inputs, secrets); outputs are writable.
    pub readonly: bool,
}

/// How a backend presents [`ShareSpec`]s to its guest. One implementation per
/// profile: qemu `VirtiofsdTransport`, vfkit `VirtioFsTransport`, process
/// `LocalDirTransport`. The pure/IO split is preserved (run-plane decision #1):
/// [`plan`](GuestShareTransport::plan) computes the wiring with no IO, so it stays
/// tier-1 testable; [`activate`](GuestShareTransport::activate) does the IO.
pub trait GuestShareTransport {
    /// Compute how the shares are presented. PURE, no IO. `mem_mib` is the guest
    /// RAM in MiB (the qemu memory-backend size; the others ignore it).
    fn plan(&self, shares: &[ShareSpec], mem_mib: u32) -> Presentation;

    /// Bring the presentation live. IO. A VM transport launches its helper daemons
    /// (returning children to reap at teardown); a local-dir transport prepares the
    /// staged dirs (enforces read-only). Sockets and paths are derived
    /// deterministically from the [`ShareSpec`]s, so `activate` needs no
    /// coordination with [`plan`](GuestShareTransport::plan).
    ///
    /// # Errors
    /// [`BackendError::Spawn`] if a daemon cannot be spawned or its socket never
    /// appears; [`BackendError`] if a local dir cannot be prepared.
    fn activate(&self, shares: &[ShareSpec]) -> Result<Vec<Child>, BackendError>;
}
