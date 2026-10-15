//! Share-staging policy shared by the backend implementations.
//!
//! [`plan_shares`] is the single home for the share-staging policy (which dirs are
//! shared under which tag, each share's read-only flag, the secret re-delivery
//! rule). The concrete per-hypervisor [`GuestShareTransport`](sandy_api::share::GuestShareTransport)
//! implementations live in the impl crates; this module is the staging the
//! backends share, plus the child-process reaper their daemon transports need.

use std::{
    path::{Path, PathBuf},
    process::Child,
};

use sandy_api::{
    backend::{BackendError, RunSpec},
    share::ShareSpec,
};

use crate::{INPUT_MOUNT_TAG, OUTPUT_MOUNT_TAG, SECRET_MOUNT_TAG, prepare_outputs, stage_inputs, stage_secrets};

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

/// Kill and reap a set of child processes, best-effort (the virtiofsd daemons at
/// teardown, or any already up when a later launch fails).
pub fn kill_children(children: &mut Vec<Child>) {
    for mut child in children.drain(..) {
        let _ = child.kill();
        let _ = child.wait();
    }
}
