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
    // A caller's dir is opened as it is and refused if it is not private; sandy's
    // own instance dir is created 0700 if missing, and refused, never repaired, if
    // it exists but is not private.
    let secret_dir = spec.secret_dir.unwrap_or(dirs.inst_dir);
    let owned = match spec.secret_dir {
        Some(dir) => sandy_fsutil::OwnedDir::open(dir),
        None => sandy_fsutil::OwnedDir::open_or_create(dirs.inst_dir),
    }
    .map_err(|e| BackendError::Spawn(e.to_string()))?;
    let staged_secrets = stage_secrets(spec.secrets, &owned)?;
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

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use sandy_api::backend::Grants;

    use super::*;

    const GRANTS: Grants = Grants {
        secrets: true,
        agent: false,
        shares: true,
    };

    fn spec<'a>(command: &'a [String], secret_dir: Option<&'a Path>) -> RunSpec<'a> {
        RunSpec {
            template: "t",
            command,
            inputs: &[],
            outputs: &[],
            secrets: &[],
            env: &[],
            cpu: None,
            mem: None,
            timeout_secs: 30,
            grants: &GRANTS,
            outcome_file: None,
            secret_dir,
        }
    }

    fn private_tempdir() -> std::io::Result<tempfile::TempDir> {
        tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
    }

    fn mode(path: &Path) -> std::io::Result<u32> {
        Ok(std::fs::metadata(path)?.permissions().mode() & 0o777)
    }

    /// #197: a caller-supplied secret dir (#49) that is group-writable is refused
    /// as it is, not narrowed to 0700 first and then accepted.
    #[test]
    fn a_wide_caller_secret_dir_is_refused_not_repaired() -> anyhow::Result<()> {
        let tmp = private_tempdir()?;
        let secret_dir = tmp.path().join("secret");
        std::fs::create_dir(&secret_dir)?;
        std::fs::set_permissions(&secret_dir, std::fs::Permissions::from_mode(0o775))?;
        let command = ["true".to_owned()];
        let dirs = ShareDirs {
            inst_dir: &tmp.path().join("inst"),
            inputs_dir: &tmp.path().join("inputs"),
            outputs_dir: &tmp.path().join("outputs"),
        };
        let err = plan_shares(&spec(&command, Some(&secret_dir)), &dirs)
            .expect_err("a 0775 caller secret dir must be refused");
        anyhow::ensure!(
            err.to_string().contains("group/world-writable"),
            "unexpected error: {err}"
        );
        anyhow::ensure!(mode(&secret_dir)? == 0o775, "the refused dir was silently repaired");
        Ok(())
    }

    /// #197: an existing group-writable instance dir is refused the same way.
    #[test]
    fn a_wide_existing_instance_dir_is_refused_not_repaired() -> anyhow::Result<()> {
        let tmp = private_tempdir()?;
        let inst_dir = tmp.path().join("inst");
        std::fs::create_dir(&inst_dir)?;
        std::fs::set_permissions(&inst_dir, std::fs::Permissions::from_mode(0o775))?;
        let command = ["true".to_owned()];
        let dirs = ShareDirs {
            inst_dir: &inst_dir,
            inputs_dir: &tmp.path().join("inputs"),
            outputs_dir: &tmp.path().join("outputs"),
        };
        let err = plan_shares(&spec(&command, None), &dirs).expect_err("a 0775 instance dir must be refused");
        anyhow::ensure!(
            err.to_string().contains("group/world-writable"),
            "unexpected error: {err}"
        );
        anyhow::ensure!(mode(&inst_dir)? == 0o775, "the refused dir was silently repaired");
        Ok(())
    }

    /// A missing instance dir is created 0700.
    #[test]
    fn a_missing_instance_dir_is_created_private() -> anyhow::Result<()> {
        let tmp = private_tempdir()?;
        let inst_dir = tmp.path().join("inst");
        let command = ["true".to_owned()];
        let dirs = ShareDirs {
            inst_dir: &inst_dir,
            inputs_dir: &tmp.path().join("inputs"),
            outputs_dir: &tmp.path().join("outputs"),
        };
        plan_shares(&spec(&command, None), &dirs)?;
        anyhow::ensure!(
            mode(&inst_dir)? == 0o700,
            "a created instance dir came out {:o}",
            mode(&inst_dir)?
        );
        Ok(())
    }
}
