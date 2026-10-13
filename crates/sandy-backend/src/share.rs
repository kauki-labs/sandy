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
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use sandy::BackendError;

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

/// How a hypervisor presents [`ShareSpec`]s to the guest as virtio-fs. One
/// implementation per backend (qemu [`VirtiofsdTransport`], vfkit
/// [`VirtioFsTransport`]); the backend owns which it uses.
pub trait GuestShareTransport {
    /// Launch any helper daemons the shares need before the VM starts, returning
    /// child handles to reap at teardown (with [`kill_children`]). Each share's
    /// socket is ready when this returns `Ok`. A launch or socket fault kills any
    /// daemon already up and returns the error (fail-closed).
    ///
    /// # Errors
    /// [`BackendError::Spawn`] if a daemon cannot be spawned or its socket never
    /// appears.
    fn launch(&self, shares: &[ShareSpec]) -> Result<Vec<Child>, BackendError>;

    /// The hypervisor argv fragment wiring the shares into the guest: the per-share
    /// devices, and for the daemon transport the shared-memory backend. Pure (no IO),
    /// so it stays tier-1 testable. `mem_mib` is the guest RAM in MiB (the qemu
    /// memory-backend size; the vfkit transport ignores it).
    fn device_args(&self, shares: &[ShareSpec], mem_mib: u32) -> Vec<String>;
}

/// The qemu virtio-fs transport: a `virtiofsd` daemon per share + a
/// `vhost-user-fs-pci` device on its socket, over a shared memfd memory backend.
#[derive(Debug, Clone, Copy, Default)]
pub struct VirtiofsdTransport;

impl GuestShareTransport for VirtiofsdTransport {
    fn launch(&self, shares: &[ShareSpec]) -> Result<Vec<Child>, BackendError> {
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

    fn device_args(&self, shares: &[ShareSpec], mem_mib: u32) -> Vec<String> {
        let mut args = Vec::new();
        if shares.is_empty() {
            return args;
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
        args
    }
}

/// The vfkit virtio-fs transport: Virtualization.framework serves virtio-fs itself,
/// so there is no daemon — one `--device virtio-fs,…` per share, and the guest mount
/// enforces read-only (vfkit's virtio-fs device rejects a `,ro` option).
#[derive(Debug, Clone, Copy, Default)]
pub struct VirtioFsTransport;

impl GuestShareTransport for VirtioFsTransport {
    fn launch(&self, _shares: &[ShareSpec]) -> Result<Vec<Child>, BackendError> {
        Ok(Vec::new())
    }

    fn device_args(&self, shares: &[ShareSpec], _mem_mib: u32) -> Vec<String> {
        let mut args = Vec::with_capacity(shares.len() * 2);
        for share in shares {
            args.push("--device".to_string());
            args.push(format!(
                "virtio-fs,sharedDir={},mountTag={}",
                share.host_dir.display(),
                share.tag
            ));
        }
        args
    }
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
/// shared dir, an unprivileged sandbox, and `--readonly` for a read-only share so
/// guest writes are denied at the host boundary (INV-1), not only by the guest
/// mount. Pure, so the read-only decision per share is unit-testable without
/// launching the daemon.
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
