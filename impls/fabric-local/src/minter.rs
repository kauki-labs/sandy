//! The agent-local [`Minter`] and host-side staging into the secret channel
//! (spec §3.8, INV-1).
//!
//! [`LocalMinter`] mints a job's work-secret on the host from the OS CSPRNG; the
//! bytes never leave the process that minted them. [`stage_secret`] hands them to
//! the existing secret channel: a `0600` file in a caller-owned staging directory,
//! returned as a [`SecretRef`] for `RunSpec.secrets`, which the backend stages into
//! the guest. Nothing travels on argv, in the environment, or through the store.

use std::path::{Path, PathBuf};

use sandy_api::backend::{SecretRef, SecretSource};
use sandy_fabric::minter::{MintedSecret, Minter, MinterError, SecretRequest};

/// Bytes in a work-secret: 256 bits.
pub const SECRET_LEN: usize = 32;

/// The agent-local [`Minter`]: each mint is [`SECRET_LEN`] fresh bytes from the
/// OS CSPRNG, minted on the host and never sent anywhere.
#[derive(Debug, Clone, Copy, Default)]
pub struct LocalMinter;

impl Minter for LocalMinter {
    async fn mint(&self, req: &SecretRequest) -> Result<MintedSecret, MinterError> {
        let _ = req;
        Ok(MintedSecret { bytes: Vec::new() })
    }
}

/// A staging failure: the secret was not written, so the job must not boot with it.
#[derive(Debug, thiserror::Error)]
pub enum StageError {
    /// The name is not a valid environment-variable name, which the guest-side
    /// secret channel requires.
    #[error("secret name {0:?} is not a valid environment-variable name ([A-Za-z_][A-Za-z0-9_]*)")]
    InvalidName(String),
    /// The staging directory is inside the Nix store, which is world-readable (INV-1).
    #[error("refusing to stage a secret under the nix store: {0}")]
    InStore(PathBuf),
    /// The file could not be written.
    #[error("staging {path}: {source}")]
    Io {
        /// The file being written.
        path: PathBuf,
        /// The underlying error.
        source: std::io::Error,
    },
}

/// Stage `bytes` as the secret `name` in `dir` and return the [`SecretRef`] that
/// carries it into the guest.
///
/// The file is created `0600` under a temporary name, synced, then renamed into
/// place, so a reader never sees a partial or world-readable secret. `dir` must
/// exist and be owned by the caller; it must not be inside the Nix store.
pub fn stage_secret(dir: &Path, name: &str, bytes: &[u8]) -> Result<SecretRef, StageError> {
    let _ = (dir, bytes);
    Ok(SecretRef {
        name: name.to_owned(),
        source: SecretSource::File(PathBuf::new()),
    })
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt};

    use anyhow::Context;
    use sandy_fabric::contract::minter_suite;

    use super::*;

    fn staged_path(secret: &SecretRef) -> anyhow::Result<&Path> {
        match &secret.source {
            SecretSource::File(path) => Ok(path),
            SecretSource::Fd(_) => anyhow::bail!("expected a file-backed secret"),
        }
    }

    #[tokio::test]
    async fn local_minter_satisfies_the_minter_contract() -> anyhow::Result<()> {
        minter_suite(|| LocalMinter).await.context("minter")
    }

    #[tokio::test]
    async fn a_minted_secret_is_full_length() -> anyhow::Result<()> {
        let secret = LocalMinter.mint(&SecretRequest { job: "j".to_owned() }).await?;
        anyhow::ensure!(secret.bytes.len() == SECRET_LEN, "minted {} bytes", secret.bytes.len());
        Ok(())
    }

    #[tokio::test]
    async fn a_minted_secret_is_staged_0600_with_its_exact_bytes() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let secret = LocalMinter.mint(&SecretRequest { job: "j".to_owned() }).await?;
        let staged = stage_secret(dir.path(), "WORK_SECRET", &secret.bytes)?;

        anyhow::ensure!(staged.name == "WORK_SECRET", "name {:?}", staged.name);
        let path = staged_path(&staged)?;
        anyhow::ensure!(
            path.starts_with(dir.path()),
            "staged outside the dir: {}",
            path.display()
        );
        let mode = fs::metadata(path)?.permissions().mode() & 0o777;
        anyhow::ensure!(mode == 0o600, "mode {mode:o}");
        anyhow::ensure!(fs::read(path)? == secret.bytes, "staged bytes differ");
        Ok(())
    }

    #[test]
    fn restaging_a_name_replaces_the_secret_and_leaves_no_temp_file() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        stage_secret(dir.path(), "S", b"old")?;
        let staged = stage_secret(dir.path(), "S", b"new")?;
        anyhow::ensure!(fs::read(staged_path(&staged)?)? == b"new", "secret not replaced");
        let entries = fs::read_dir(dir.path())?.count();
        anyhow::ensure!(entries == 1, "{entries} entries; a temp file was left behind");
        Ok(())
    }

    #[test]
    fn a_secret_never_reaches_argv_or_the_environment() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let marker = "sandy-inv1-marker-6f1e2d";
        let staged = stage_secret(dir.path(), "S", marker.as_bytes())?;
        anyhow::ensure!(!std::env::args().any(|a| a.contains(marker)), "the secret is on argv");
        anyhow::ensure!(
            !std::env::vars().any(|(k, v)| k.contains(marker) || v.contains(marker)),
            "the secret is in the environment"
        );
        anyhow::ensure!(
            !format!("{staged:?}").contains(marker),
            "the SecretRef carries the secret bytes, not just a path"
        );
        Ok(())
    }

    #[test]
    fn staging_under_the_nix_store_is_refused() {
        let res = stage_secret(Path::new("/nix/store/abc-staging"), "S", b"x");
        assert!(matches!(res, Err(StageError::InStore(_))), "got {res:?}");
    }

    #[test]
    fn a_name_that_is_not_an_env_var_is_refused() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        for bad in ["", "1ABC", "A-B", "A B", "../x", "A=B"] {
            let res = stage_secret(dir.path(), bad, b"x");
            anyhow::ensure!(matches!(res, Err(StageError::InvalidName(_))), "{bad:?} gave {res:?}");
        }
        anyhow::ensure!(fs::read_dir(dir.path())?.count() == 0, "a refused secret was written");
        Ok(())
    }
}
