//! The guest filesystem-share transport: how a hypervisor presents staged host
//! directories to the guest as virtio-fs mounts.
//!
//! Hidden behind the backends via the [`GuestShareTransport`] trait, with one
//! implementation per hypervisor — the "variable implementations":
//!
//! - [`VirtiofsdTransport`] (qemu): launches a `virtiofsd` daemon per share and wires a `vhost-user-fs-pci` device on
//!   its socket, backed by a shared `memory-backend-memfd` NUMA node (virtio-fs needs shareable guest RAM).
//! - [`VirtioFsTransport`] (vfkit): Virtualization.framework serves virtio-fs itself, so there is no daemon — just one
//!   `--device virtio-fs,…` per share.
//!
//! Both land the guest at the same `fsType = "virtiofs"` mount, so the guest config
//! is identical across hypervisors. A [`ShareSpec`] is the backend-neutral unit both
//! consume.

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use sandy::{
    BackendError, INPUT_MOUNT_TAG, OUTPUT_MOUNT_TAG, RunSpec, SECRET_MOUNT_TAG, prepare_outputs, stage_inputs,
    stage_secrets,
};

/// The id of the shared memfd memory backend that virtio-fs shares map through.
/// virtio-fs needs the guest RAM to be a shareable object (`share=on`).
const VIRTIOFS_MEM_ID: &str = "sandy-mem";

/// One guest filesystem share, served as virtio-fs. The guest matches it by [`tag`];
/// the host serves [`host_dir`]. For the daemon transport the host also serves it
/// over [`socket`]; `readonly` is enforced at the virtiofsd boundary (qemu) or the
/// guest mount (vfkit), so a share stays read-only even against a guest-root
/// remount where the transport enforces it host-side.
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

/// The per-run staging directories a backend hands to [`plan_shares`]. The backend
/// owns the naming (qemu keys them on the run id, vfkit on its `inst-<id>` box id)
/// and reuses `inputs_dir` / `outputs_dir` for collection and teardown wipe, so the
/// planner takes them rather than deriving its own.
pub struct ShareDirs<'a> {
    /// Sandy-owned dir holding the virtiofsd sockets and the default secret dir.
    pub inst_dir: &'a Path,
    /// Where declared inputs are copied, shared read-only.
    pub inputs_dir: &'a Path,
    /// Where declared outputs are collected from, shared writable.
    pub outputs_dir: &'a Path,
}

/// Stage one run's secret, inputs, and outputs per `spec` and return the
/// [`ShareSpec`]s both backends attach, in a fixed secret → input → output order.
///
/// This is the single home for the share-staging *policy*: which dirs are shared
/// under which tag, each share's read-only flag (secret and inputs read-only,
/// outputs writable), the `secret_dir` re-delivery rule (#49: stage into the
/// caller's dir when given so a mid-run refresh reaches the guest, else `inst_dir`),
/// and the attach-when-present guards. qemu and vfkit previously open-coded this in
/// lockstep, so a change to the policy had to be made twice; now it is made once.
/// The guest mounts each share by tag with `nofail`, so the order here is the argv
/// order only, never a guest dependency.
///
/// INV-1: only share *metadata* (host path, tag, flags) is produced here; the secret
/// bytes live only in the staged `0600` files, never in a [`ShareSpec`].
///
/// # Errors
/// [`BackendError`] if staging the secret, inputs, or outputs fails.
pub fn plan_shares(spec: &RunSpec, dirs: &ShareDirs) -> Result<Vec<ShareSpec>, BackendError> {
    let mut shares = Vec::new();
    let share = |host_dir: PathBuf, tag: &str, readonly: bool| ShareSpec {
        socket: dirs.inst_dir.join(format!("vfsd-{tag}.sock")),
        host_dir,
        tag: tag.to_string(),
        readonly,
    };

    // Secrets: stage into `spec.secret_dir` when the caller owns one (refresh
    // re-delivery, #49, rewrites the token in it mid-run), else our own inst_dir.
    // Attach when the run carries secrets or a pre-staged dir. Read-only.
    let secret_dir = spec.secret_dir.unwrap_or(dirs.inst_dir);
    let staged_secrets = stage_secrets(spec.secrets, secret_dir)?;
    if !staged_secrets.is_empty() || spec.secret_dir.is_some() {
        shares.push(share(secret_dir.to_path_buf(), SECRET_MOUNT_TAG, true));
    }
    // Inputs: their own per-run dir (never under the secret share), read-only.
    if stage_inputs(spec.inputs, dirs.inputs_dir)? > 0 {
        shares.push(share(dirs.inputs_dir.to_path_buf(), INPUT_MOUNT_TAG, true));
    }
    // Outputs: their own per-run dir, writable; collected to the host after boot.
    if prepare_outputs(spec.outputs, dirs.outputs_dir)? > 0 {
        shares.push(share(dirs.outputs_dir.to_path_buf(), OUTPUT_MOUNT_TAG, false));
    }
    Ok(shares)
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
/// profile: qemu [`VirtiofsdTransport`], vfkit [`VirtioFsTransport`], process
/// [`LocalDirTransport`]. The pure/IO split is preserved (run-plane decision #1):
/// [`plan`](GuestShareTransport::plan) computes the wiring with no IO, so it stays
/// tier-1 testable; [`activate`](GuestShareTransport::activate) does the IO.
pub trait GuestShareTransport {
    /// Compute how the shares are presented. PURE, no IO. `mem_mib` is the guest
    /// RAM in MiB (the qemu memory-backend size; the others ignore it).
    fn plan(&self, shares: &[ShareSpec], mem_mib: u32) -> Presentation;

    /// Bring the presentation live. IO. A VM transport launches its helper daemons
    /// (returning children to reap at teardown with [`kill_children`]); a local-dir
    /// transport prepares the staged dirs (enforces read-only). Sockets and paths
    /// are derived deterministically from the [`ShareSpec`]s, so `activate` needs
    /// no coordination with [`plan`](GuestShareTransport::plan).
    ///
    /// # Errors
    /// [`BackendError::Spawn`] if a daemon cannot be spawned or its socket never
    /// appears; [`BackendError`] if a local dir cannot be prepared.
    fn activate(&self, shares: &[ShareSpec]) -> Result<Vec<Child>, BackendError>;
}

/// The qemu virtio-fs transport: a `virtiofsd` daemon per share + a
/// `vhost-user-fs-pci` device on its socket, over a shared memfd memory backend.
#[derive(Debug, Clone, Copy, Default)]
pub struct VirtiofsdTransport;

impl GuestShareTransport for VirtiofsdTransport {
    fn activate(&self, shares: &[ShareSpec]) -> Result<Vec<Child>, BackendError> {
        let mut children = Vec::with_capacity(shares.len());
        for share in shares {
            let launched = spawn_virtiofsd(share).and_then(|child| {
                children.push(child);
                wait_for_socket(&share.socket, Duration::from_secs(5))
            });
            if let Err(err) = launched {
                kill_children(&mut children);
                return Err(err);
            }
        }
        Ok(children)
    }

    fn plan(&self, shares: &[ShareSpec], mem_mib: u32) -> Presentation {
        let mut args = Vec::new();
        if shares.is_empty() {
            return Presentation::Vm { args };
        }
        // One shareable memfd NUMA node, mapped by every virtio-fs device.
        args.push("-object".to_string());
        args.push(format!(
            "memory-backend-memfd,id={VIRTIOFS_MEM_ID},size={mem_mib}M,share=on"
        ));
        args.push("-numa".to_string());
        args.push(format!("node,memdev={VIRTIOFS_MEM_ID}"));
        for (i, share) in shares.iter().enumerate() {
            args.push("-chardev".to_string());
            args.push(format!("socket,id=vfs{i},path={}", share.socket.display()));
            args.push("-device".to_string());
            args.push(format!("vhost-user-fs-pci,chardev=vfs{i},tag={}", share.tag));
        }
        Presentation::Vm { args }
    }
}

/// The vfkit virtio-fs transport: Virtualization.framework serves virtio-fs itself,
/// so there is no daemon, just one `--device virtio-fs,…` per share.
///
/// Read-only is NOT enforced host-side here, unlike the qemu transport's
/// `virtiofsd --readonly`: vfkit's `virtio-fs` device takes only `sharedDir` and
/// `mountTag` (verified against vfkit v0.6.3), with no read-only option, so
/// [`plan`](GuestShareTransport::plan) emits no readonly flag for
/// `readonly` flag through. On macOS a `readonly` share is enforced only by the guest's `ro` mount,
/// which a guest-root `mount -o remount,rw` can defeat. This asymmetry is accepted:
/// each share is a single per-run, sandy-owned dir wiped at teardown, so a guest
/// that remounts rw can corrupt only its own run's staging, never escape the share
/// or reach another run (the VM is the trust boundary). See
/// `docs/decisions/guest-shares.md` §2.
#[derive(Debug, Clone, Copy, Default)]
pub struct VirtioFsTransport;

impl GuestShareTransport for VirtioFsTransport {
    fn activate(&self, _shares: &[ShareSpec]) -> Result<Vec<Child>, BackendError> {
        Ok(Vec::new())
    }

    fn plan(&self, shares: &[ShareSpec], _mem_mib: u32) -> Presentation {
        let mut args = Vec::with_capacity(shares.len() * 2);
        for share in shares {
            args.push("--device".to_string());
            args.push(format!(
                "virtio-fs,sharedDir={},mountTag={}",
                share.host_dir.display(),
                share.tag
            ));
        }
        Presentation::Vm { args }
    }
}

/// The process profile's share transport: no virtio-fs, no daemon. Presents each
/// staged share dir to the host job via a `SANDY_<TAG>_DIR` env var (see
/// [`Presentation::LocalDir`]) and enforces read-only cooperatively (`chmod a-w`)
/// on inputs/secrets. Constructed per run with the backend's inst dir as the root.
#[derive(Debug, Clone)]
pub struct LocalDirTransport {
    root: PathBuf,
}

impl LocalDirTransport {
    /// A transport rooting the staged share dirs at `root` (the per-run inst dir).
    #[must_use]
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }
}

impl GuestShareTransport for LocalDirTransport {
    fn plan(&self, shares: &[ShareSpec], _mem_mib: u32) -> Presentation {
        let placements = shares
            .iter()
            .map(|share| Placement {
                tag: share.tag.clone(),
                dir: share.host_dir.clone(),
                readonly: share.readonly,
            })
            .collect();
        Presentation::LocalDir {
            root: self.root.clone(),
            placements,
        }
    }

    fn activate(&self, shares: &[ShareSpec]) -> Result<Vec<Child>, BackendError> {
        // Cooperative read-only: strip write from the FILES in each read-only share
        // dir so a job cannot modify the staged input/secret bytes (the dir stays
        // writable so teardown can wipe it). A same-user job can undo it (weak, like
        // the vfkit RO asymmetry in guest-shares §2); the VM backend is the real
        // boundary. No daemons, so the live-children set is empty.
        for share in shares {
            if share.readonly {
                set_dir_readonly(&share.host_dir)?;
            }
        }
        Ok(Vec::new())
    }
}

/// Strip write (`chmod a-w`) from the FILES under `dir` (recursively), so a
/// same-user job cannot modify a read-only share's staged bytes. Best-effort
/// cooperative RO, not a hard boundary (the VM backend is the real boundary): only
/// files are stripped, never the dirs, so teardown's `remove_dir_all` can still
/// unlink entries (unlinking needs write on the parent dir, not the file). A
/// same-user job can add or remove entries, or chmod the files back; what this
/// protects is the integrity of the given input/secret bytes.
fn set_dir_readonly(dir: &Path) -> Result<(), BackendError> {
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        let Ok(entries) = fs::read_dir(&current) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(meta) = fs::symlink_metadata(&path) else {
                continue;
            };
            if meta.is_dir() {
                stack.push(path);
            } else {
                let mut perms = meta.permissions();
                perms.set_mode(perms.mode() & !0o222);
                // Best-effort cooperative RO: a failure to chmod one staged file
                // does not fail the run (the VM boundary is the real guarantee).
                let _ = fs::set_permissions(&path, perms);
            }
        }
    }
    Ok(())
}

/// Kill and reap a set of child processes, best-effort (the virtiofsd daemons at
/// teardown, or any already up when a later launch fails).
pub fn kill_children(children: &mut Vec<Child>) {
    for mut child in children.drain(..) {
        let _ = child.kill();
        let _ = child.wait();
    }
}

/// The `virtiofsd` CLI args (after the binary) serving `share`: its socket, the
/// shared dir, `--sandbox=none`, and `--readonly` for a read-only share so guest
/// writes are denied at the host boundary (INV-1), not only by the guest mount.
///
/// `--sandbox=none` disables virtiofsd's own namespace/chroot confinement (it is
/// NOT a sandbox): the `namespace` and `chroot` modes need privileges sandy's
/// unprivileged launch does not have. The daemon only ever serves a single
/// per-run, sandy-owned dir that is wiped at teardown, and the guest is confined to
/// the VM, so the daemon's own confinement is not the containment boundary here.
///
/// Pure, so the read-only decision per share is unit-testable without launching the
/// daemon.
#[must_use]
pub fn virtiofsd_args(share: &ShareSpec) -> Vec<String> {
    let mut args = vec![
        format!("--socket-path={}", share.socket.display()),
        format!("--shared-dir={}", share.host_dir.display()),
        "--sandbox=none".to_string(),
    ];
    if share.readonly {
        args.push("--readonly".to_string());
    }
    args
}

/// Launch a `virtiofsd` serving `share.host_dir` on `share.socket`. Its stdio is
/// discarded; a failure to come up surfaces as the socket never appearing (see
/// [`wait_for_socket`]), which the caller turns into a boot fault.
///
/// # Errors
/// [`BackendError::Spawn`] if the `virtiofsd` process cannot be spawned.
fn spawn_virtiofsd(share: &ShareSpec) -> Result<Child, BackendError> {
    let bin = std::env::var("SANDY_VIRTIOFSD_BIN").unwrap_or_else(|_| "virtiofsd".to_string());
    // Clear any stale socket so wait_for_socket can't observe a previous run's.
    let _ = std::fs::remove_file(&share.socket);
    Command::new(&bin)
        .args(virtiofsd_args(share))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|err| BackendError::Spawn(format!("spawn virtiofsd `{bin}` for share {}: {err}", share.tag)))
}

/// Wait for `socket` to appear, bounded by `budget`: virtiofsd creates its socket
/// asynchronously after launch, and the hypervisor connects to it as a client. A
/// socket still missing at the deadline means virtiofsd failed to start.
///
/// # Errors
/// [`BackendError::Spawn`] when the socket does not appear within `budget`.
fn wait_for_socket(socket: &Path, budget: Duration) -> Result<(), BackendError> {
    let deadline = Instant::now() + budget;
    while !socket.exists() {
        if Instant::now() >= deadline {
            return Err(BackendError::Spawn(format!(
                "virtiofsd socket {} did not appear within {budget:?}",
                socket.display()
            )));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Ok(())
}
