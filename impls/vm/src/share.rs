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
    path::Path,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use sandy::{BackendError, kill_children};
use sandy_api::share::{GuestShareTransport, Presentation, ShareSpec};

/// The id of the shared memfd memory backend that virtio-fs shares map through.
/// virtio-fs needs the guest RAM to be a shareable object (`share=on`).
const VIRTIOFS_MEM_ID: &str = "sandy-mem";

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
