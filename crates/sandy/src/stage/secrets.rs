//! Secret staging (E2, INV-1): each caller secret becomes a `0600` file written
//! by atomic rename under a `0700` per-instance dir, shared read-only into the
//! guest and wiped on teardown. The bytes never reach argv, env, or the store.

use std::{
    fs,
    io::Write,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use crate::backend::{BackendError, SecretRef, SecretSource};

/// Mode bits that would let group or other read a secret source (INV-1).
const GROUP_OTHER_READ: u32 = 0o044;

/// A secret that has been staged to disk for sharing into the guest.
///
/// Carries only the guest-visible name and the path the staged file is shared
/// in at — never the secret bytes (INV-1). The bytes live solely in the `0600`
/// file on disk, so this handle is safe to log, return, and keep.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagedSecret {
    /// The environment variable name the guest will see.
    pub name: String,
    /// The guest path the staged secret file is shared in at.
    pub guest_path: PathBuf,
}

/// Stage each secret's bytes into `inst_dir` as a `0600` file written by atomic
/// rename (temp → fsync → `rename`), under a freshly created `0700` directory.
///
/// Files are named `secret-<i>` by the secret's index in `secrets`. The bytes
/// travel this on-disk channel only — never argv, env, or the Nix store
/// (INV-1); the returned [`StagedSecret`]s retain no bytes.
///
/// # Errors
///
/// Returns [`BackendError`] when `inst_dir` cannot be prepared, a secret source
/// cannot be read, or a [`SecretSource::File`](crate::SecretSource::File) is
/// world-readable (its mode grants group/other read, e.g. `0644`) — a
/// world-readable source is rejected, not staged.
pub fn stage_secrets(secrets: &[SecretRef], inst_dir: &Path) -> Result<Vec<StagedSecret>, BackendError> {
    fs::create_dir_all(inst_dir).map_err(|e| spawn_err("create instance dir", inst_dir, &e))?;
    fs::set_permissions(inst_dir, fs::Permissions::from_mode(0o700))
        .map_err(|e| spawn_err("tighten instance dir to 0700", inst_dir, &e))?;

    let mut staged = Vec::with_capacity(secrets.len());
    for (i, secret) in secrets.iter().enumerate() {
        let bytes = read_source(&secret.source)?;
        let guest_path = inst_dir.join(format!("secret-{i}"));
        write_secret_file(inst_dir, &guest_path, &bytes)?;
        tracing::debug!(name = %secret.name, path = %guest_path.display(), "staged secret (0600)");
        staged.push(StagedSecret {
            name: secret.name.clone(),
            guest_path,
        });
    }
    Ok(staged)
}

/// Read a secret's bytes from its source, rejecting a world/group-readable file
/// (INV-1). The `Fd` channel needs an `unsafe` `File::from_raw_fd`, which this
/// crate forbids (`unsafe_code = forbid`), so it is rejected rather than read.
fn read_source(source: &SecretSource) -> Result<Vec<u8>, BackendError> {
    match source {
        SecretSource::File(path) => {
            let meta = fs::metadata(path).map_err(|e| spawn_err("stat secret source", path, &e))?;
            let mode = meta.permissions().mode() & 0o777;
            if mode & GROUP_OTHER_READ != 0 {
                return Err(BackendError::Spawn(format!(
                    "secret source {} is world/group-readable (mode {mode:#o}); refusing to stage (INV-1)",
                    path.display()
                )));
            }
            fs::read(path).map_err(|e| spawn_err("read secret source", path, &e))
        }
        SecretSource::Fd(fd) => Err(BackendError::Spawn(format!(
            "fd-sourced secrets (fd {fd}) are not supported without unsafe fd reads (INV-SAFE)"
        ))),
    }
}

/// Write `bytes` to `dest` as a `0600` file via temp-in-dir → sync → rename, then
/// fsync the directory so the rename is durable (INV-1).
fn write_secret_file(inst_dir: &Path, dest: &Path, bytes: &[u8]) -> Result<(), BackendError> {
    let tmp = dest.with_extension("tmp");
    let mut file = fs::File::create(&tmp).map_err(|e| spawn_err("create secret temp", &tmp, &e))?;
    file.write_all(bytes)
        .map_err(|e| spawn_err("write secret temp", &tmp, &e))?;
    file.sync_all().map_err(|e| spawn_err("sync secret temp", &tmp, &e))?;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))
        .map_err(|e| spawn_err("tighten secret to 0600", &tmp, &e))?;
    fs::rename(&tmp, dest).map_err(|e| spawn_err("rename secret into place", dest, &e))?;
    crate::fsync_dir(inst_dir).map_err(|e| spawn_err("fsync instance dir", inst_dir, &e))?;
    Ok(())
}

/// Build a [`BackendError::Spawn`] for an IO failure without leaking secret bytes.
fn spawn_err(action: &str, path: &Path, err: &std::io::Error) -> BackendError {
    BackendError::Spawn(format!("{action} at {}: {err}", path.display()))
}

/// Remove the staging directory and every secret file under it.
///
/// Called on teardown, including the crash/failure path after a partial
/// [`stage_secrets`]: it clears whatever was written so secret bytes never
/// outlive the run.
///
/// # Errors
///
/// Returns the underlying [`std::io::Error`] if the directory cannot be removed.
pub fn wipe(inst_dir: &Path) -> std::io::Result<()> {
    match fs::remove_dir_all(inst_dir) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use anyhow::Context;

    use super::*;
    use crate::backend::SecretSource;

    /// A `0600` host file holding `bytes`, created under `dir`.
    fn secret_source(dir: &Path, bytes: &[u8]) -> anyhow::Result<PathBuf> {
        let src = dir.join("source");
        std::fs::write(&src, bytes).context("write secret source")?;
        std::fs::set_permissions(&src, std::fs::Permissions::from_mode(0o600)).context("tighten source perms")?;
        Ok(src)
    }

    /// E2: a `File` secret is staged as a `0600` file, written via atomic rename,
    /// under a `0700` instance dir, with its contents intact.
    #[test]
    fn stages_secret_0600_atomic() -> anyhow::Result<()> {
        let tmp = tempfile::TempDir::new()?;
        let src = secret_source(tmp.path(), b"s3cr3t-marker")?;
        let inst_dir = tmp.path().join("inst");
        let secrets = [SecretRef {
            name: "TOK".to_string(),
            source: SecretSource::File(src),
        }];

        let staged = stage_secrets(&secrets, &inst_dir)?;

        assert_eq!(staged.len(), 1);
        let dir_mode = std::fs::metadata(&inst_dir)?.permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700, "instance dir must be 0700");

        let staged_file = inst_dir.join("secret-0");
        let file_mode = std::fs::metadata(&staged_file)?.permissions().mode() & 0o777;
        assert_eq!(file_mode, 0o600, "staged secret must be 0600");
        assert_eq!(
            std::fs::read(&staged_file)?,
            b"s3cr3t-marker",
            "contents must match the source"
        );
        Ok(())
    }

    /// INV-1: the staged handle names the secret and its path but never carries
    /// the bytes — the marker is absent from every returned value.
    #[test]
    fn secret_bytes_not_in_argv() -> anyhow::Result<()> {
        let marker = "s3cr3t-marker";
        let tmp = tempfile::TempDir::new()?;
        let src = secret_source(tmp.path(), marker.as_bytes())?;
        let inst_dir = tmp.path().join("inst");
        let secrets = [SecretRef {
            name: "TOK".to_string(),
            source: SecretSource::File(src),
        }];

        let staged = stage_secrets(&secrets, &inst_dir)?;

        let rendered = format!("{staged:?}");
        assert!(
            !rendered.contains(marker),
            "secret bytes must not appear in the staged handle"
        );
        Ok(())
    }

    /// Adversarial (INV-1): a world-readable (`0644`) source is rejected with a
    /// named [`BackendError`] and never staged.
    #[test]
    fn world_readable_source_rejected() -> anyhow::Result<()> {
        let tmp = tempfile::TempDir::new()?;
        let src = tmp.path().join("world-readable");
        std::fs::write(&src, b"marker")?;
        std::fs::set_permissions(&src, std::fs::Permissions::from_mode(0o644))?;
        let inst_dir = tmp.path().join("inst");
        let secrets = [SecretRef {
            name: "TOK".to_string(),
            source: SecretSource::File(src),
        }];

        let err = stage_secrets(&secrets, &inst_dir).expect_err("0644 source must be rejected");

        assert!(
            matches!(err, BackendError::Spawn(_)),
            "expected a named Spawn error, got {err:?}"
        );
        assert!(
            !inst_dir.join("secret-0").exists(),
            "a rejected source must not be staged"
        );
        Ok(())
    }

    /// E2 teardown: `wipe` removes the staging dir after a successful stage.
    #[test]
    fn wipe_removes_staging() -> anyhow::Result<()> {
        let tmp = tempfile::TempDir::new()?;
        let src = secret_source(tmp.path(), b"marker")?;
        let inst_dir = tmp.path().join("inst");
        let secrets = [SecretRef {
            name: "TOK".to_string(),
            source: SecretSource::File(src),
        }];

        stage_secrets(&secrets, &inst_dir)?;
        wipe(&inst_dir)?;

        assert!(!inst_dir.exists(), "wipe must remove the staging dir");
        Ok(())
    }

    /// Adversarial: on the crash path — a dir left with a partial temp file —
    /// `wipe` still clears everything so no secret bytes outlive the run.
    #[test]
    fn teardown_wipes_on_failure() -> anyhow::Result<()> {
        let tmp = tempfile::TempDir::new()?;
        let inst_dir = tmp.path().join("inst");
        std::fs::create_dir_all(&inst_dir)?;
        std::fs::write(inst_dir.join("secret-0.tmp"), b"partial")?;

        wipe(&inst_dir)?;

        assert!(!inst_dir.exists(), "wipe must clear a partially staged dir");
        Ok(())
    }
}
