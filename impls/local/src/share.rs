//! The process profile's share transport: no virtio-fs, no daemon.

use std::{os::unix::fs::PermissionsExt, path::PathBuf};

use sandy::SECRET_MOUNT_TAG;
use sandy_api::{
    backend::BackendError,
    share::{GuestShareTransport, Placement, Presentation, ShareSpec},
};

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

    fn activate(&self, shares: &[ShareSpec]) -> Result<Vec<std::process::Child>, BackendError> {
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
fn set_dir_readonly(dir: &std::path::Path) -> Result<(), BackendError> {
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        // Fatal: if we cannot even enumerate the share dir, the RO step would be a
        // silent no-op — surface it rather than ship a silent gate.
        let entries = std::fs::read_dir(&current)
            .map_err(|e| BackendError::Spawn(format!("read share dir {}: {e}", current.display())))?;
        for entry in entries {
            let path = entry
                .map_err(|e| BackendError::Spawn(format!("read share entry in {}: {e}", current.display())))?
                .path();
            let meta = std::fs::symlink_metadata(&path)
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
                if let Err(err) = std::fs::set_permissions(&path, perms) {
                    tracing::warn!(path = %path.display(), %err, "failed to strip write from a read-only share file");
                }
            }
        }
    }
    Ok(())
}
