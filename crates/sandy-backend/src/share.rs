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
pub use sandy_api::share::{GuestShareTransport, Placement, Presentation, ShareSpec};

/// The id of the shared memfd memory backend that virtio-fs shares map through.
/// virtio-fs needs the guest RAM to be a shareable object (`share=on`).
const VIRTIOFS_MEM_ID: &str = "sandy-mem";

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
            // Cooperative RO applies to the INPUT share only. The secret share is
            // never chmod'd: its files are already 0600 (INV-1), and a caller-owned
            // secret_dir supports in-place token refresh (#49) — making it a-w would
            // break the refresh and mutate caller-owned files. Outputs are writable
            // (readonly=false), so they are skipped by the flag.
            if share.readonly && share.tag != SECRET_MOUNT_TAG {
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
        // Fatal: if we cannot even enumerate the share dir, the RO step would be a
        // silent no-op — surface it rather than ship a silent gate.
        let entries = fs::read_dir(&current)
            .map_err(|e| BackendError::Spawn(format!("read share dir {}: {e}", current.display())))?;
        for entry in entries {
            let path = entry
                .map_err(|e| BackendError::Spawn(format!("read share entry in {}: {e}", current.display())))?
                .path();
            let meta = fs::symlink_metadata(&path)
                .map_err(|e| BackendError::Spawn(format!("stat {}: {e}", path.display())))?;
            if meta.is_dir() {
                stack.push(path);
            } else {
                let mut perms = meta.permissions();
                perms.set_mode(perms.mode() & !0o222);
                // Non-fatal but OBSERVABLE: cooperative RO is defence-in-depth (the
                // VM is the real boundary), so one stubborn file does not fail the
                // run — but a swallowed partial failure is the silent-gate smell, so
                // it is warn-logged with the path rather than dropped.
                if let Err(err) = fs::set_permissions(&path, perms) {
                    tracing::warn!(path = %path.display(), %err, "failed to strip write from a read-only share file");
                }
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
