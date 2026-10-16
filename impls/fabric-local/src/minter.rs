//! The agent-local [`Minter`] and host-side staging into the secret channel
//! (spec §3.8, INV-1).
//!
//! [`LocalMinter`] mints a job's work-secret on the host from the OS CSPRNG; the
//! bytes never leave the process that minted them. [`stage_secret`] hands them to
//! the existing secret channel: a `0600` file in a caller-owned staging directory,
//! returned as a [`SecretRef`] for `RunSpec.secrets`, which the backend stages into
//! the guest. Nothing travels on argv, in the environment, or through the store.

use std::{
    fs::{self, File},
    io::{self, Write},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

use rustix::fs::{AtFlags, Mode, OFlags};
use sandy_api::backend::{SecretRef, SecretSource};
use sandy_fabric::{
    capauth::{Cap, encode_cap},
    minter::{MintedSecret, Minter, MinterError, SecretRequest},
};

/// Bytes in a work-secret: 256 bits.
pub const SECRET_LEN: usize = 32;

/// The agent-local [`Minter`]: each mint is [`SECRET_LEN`] fresh bytes from the
/// OS CSPRNG, minted on the host and never sent anywhere.
#[derive(Debug, Clone, Copy, Default)]
pub struct LocalMinter;

impl Minter for LocalMinter {
    async fn mint(&self, req: &SecretRequest) -> Result<MintedSecret, MinterError> {
        let mut bytes = vec![0_u8; SECRET_LEN];
        getrandom::fill(&mut bytes)
            .map_err(|e| MinterError::Mint(format!("no OS entropy for job {:?}: {e}", req.job)))?;
        Ok(MintedSecret { bytes })
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
    /// The staging directory is not owned by this user, or is group- or
    /// world-writable, so another principal could swap the staged file.
    #[error("unsafe staging directory {0}: must be owned by this user and not group/world-writable")]
    UnsafeDir(PathBuf),
    /// The capability could not be encoded.
    #[error("encoding the channel cap: {0}")]
    Encode(String),
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
/// The file is created `0600` (never wider, not even briefly) under a unique
/// temporary name, synced, then renamed into place, so a reader never sees a
/// partial or world-readable secret. `dir` must exist, be owned by this user, and
/// not be group- or world-writable; otherwise another principal could replace the
/// staged file with a symlink to one of this user's files. It must not be inside
/// the Nix store.
///
/// `dir` is opened once and everything after is relative to that handle: the
/// owner and mode check, the create, the rename and the sync. A path swapped
/// after the check cannot redirect the write.
pub fn stage_secret(dir: &Path, name: &str, bytes: &[u8]) -> Result<SecretRef, StageError> {
    let mut chars = name.chars();
    let valid = chars.next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_');
    if !valid {
        return Err(StageError::InvalidName(name.to_owned()));
    }
    // Check the path as given before resolving it, then the resolved path, so a
    // symlink into the store is refused too.
    let store = Path::new("/nix/store");
    if dir.starts_with(store) {
        return Err(StageError::InStore(dir.to_owned()));
    }
    let io_err = |path: &Path| {
        let path = path.to_owned();
        move |source| StageError::Io { path, source }
    };
    let dir = fs::canonicalize(dir).map_err(io_err(dir))?;
    if dir.starts_with(store) {
        return Err(StageError::InStore(dir));
    }
    let handle: File = rustix::fs::open(
        &dir,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|e| StageError::Io {
        path: dir.clone(),
        source: e.into(),
    })?;
    let meta = handle.metadata().map_err(io_err(&dir))?;
    if meta.uid() != rustix::process::getuid().as_raw() || meta.mode() & 0o022 != 0 {
        return Err(StageError::UnsafeDir(dir));
    }

    let dest = dir.join(name);
    let tmp = format!(".{name}.{}.staging", unique_suffix().map_err(io_err(&dir))?);
    let discard_tmp = || {
        // Best effort: the original error is the one worth reporting.
        let _ = rustix::fs::unlinkat(&handle, tmp.as_str(), AtFlags::empty());
    };
    if let Err(source) = write_0600_at(&handle, &tmp, bytes) {
        discard_tmp();
        return Err(StageError::Io {
            path: dir.join(&tmp),
            source,
        });
    }
    if let Err(e) = rustix::fs::renameat(&handle, tmp.as_str(), &handle, name) {
        discard_tmp();
        return Err(StageError::Io {
            path: dest,
            source: e.into(),
        });
    }
    if let Err(source) = handle.sync_all() {
        // Not durable, and the caller gets no SecretRef to clean up with: remove it.
        let _ = rustix::fs::unlinkat(&handle, name, AtFlags::empty());
        return Err(StageError::Io { path: dir, source });
    }
    Ok(SecretRef {
        name: name.to_owned(),
        source: SecretSource::File(dest),
    })
}

/// Write a channel join capability as the `0600` file `name` in `dir`, as JSON,
/// and return its path (spec §3.8).
///
/// The cap is minted outside the sandbox by the orchestrator's
/// [`CapAuthority`](sandy_fabric::capauth::CapAuthority): this takes a minted
/// [`Cap`], never an authority, so nothing that can mint a cap is handed on. The
/// cap is written on its own; a work-secret is a separate secret, never bundled in.
///
/// It returns a path, not a [`SecretRef`], on purpose. `RunSpec.secrets` reaches
/// the job: the guest exports every staged secret into the job's environment. A
/// cap is the agent's, and the job must never hold it, so the bootstrap cap goes
/// to the agent out of band over its launch channel (#108, #109). Use this only
/// for a surface the job cannot read.
pub fn stage_cap(dir: &Path, name: &str, cap: &Cap) -> Result<PathBuf, StageError> {
    let encoded = encode_cap(cap).map_err(|e| StageError::Encode(e.to_string()))?;
    match stage_secret(dir, name, &encoded)?.source {
        SecretSource::File(path) => Ok(path),
        // stage_secret only ever stages to a file.
        SecretSource::Fd(_) => Err(StageError::Encode("staged cap is not a file".to_owned())),
    }
}

/// A random suffix so concurrent stagings of one name never share a temp file.
fn unique_suffix() -> io::Result<String> {
    let mut raw = [0_u8; 8];
    getrandom::fill(&mut raw).map_err(|e| io::Error::other(e.to_string()))?;
    Ok(raw.iter().map(|b| format!("{b:02x}")).collect())
}

/// Create `name` in the directory `dir` as a new `0600` file holding `bytes`,
/// synced to disk. `O_EXCL` with `O_NOFOLLOW` refuses anything already there,
/// including a planted symlink.
// SECURITY: keep in sync with `sandy::cred::write_secret_0600`; both move to one
// shared writer in #174.
fn write_0600_at(dir: &File, name: &str, bytes: &[u8]) -> io::Result<()> {
    let fd = rustix::fs::openat(
        dir,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )?;
    let mut file = File::from(fd);
    file.write_all(bytes)?;
    file.sync_all()
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
            path.starts_with(fs::canonicalize(dir.path())?),
            "staged outside the dir: {}",
            path.display()
        );
        let mode = fs::metadata(path)?.permissions().mode() & 0o777;
        anyhow::ensure!(mode == 0o600, "mode {mode:o}");
        anyhow::ensure!(fs::read(path)? == secret.bytes, "staged bytes differ");
        Ok(())
    }

    /// A 0700 temp dir: a safe staging dir (tempfile's default is already 0700).
    fn staging_dir() -> anyhow::Result<tempfile::TempDir> {
        let dir = tempfile::tempdir()?;
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700))?;
        Ok(dir)
    }

    #[test]
    fn restaging_over_a_wide_file_leaves_a_0600_secret_and_no_temp_file() -> anyhow::Result<()> {
        let dir = staging_dir()?;
        let old = dir.path().join("S");
        fs::write(&old, b"old")?;
        fs::set_permissions(&old, fs::Permissions::from_mode(0o644))?;
        let staged = stage_secret(dir.path(), "S", b"new")?;
        let path = staged_path(&staged)?;
        anyhow::ensure!(fs::read(path)? == b"new", "secret not replaced");
        let mode = fs::metadata(path)?.permissions().mode() & 0o777;
        anyhow::ensure!(mode == 0o600, "a pre-existing 0644 file kept its mode: {mode:o}");
        let entries = fs::read_dir(dir.path())?.count();
        anyhow::ensure!(entries == 1, "{entries} entries; a temp file was left behind");
        Ok(())
    }

    #[test]
    fn a_failed_rename_leaves_no_temp_file() -> anyhow::Result<()> {
        let dir = staging_dir()?;
        fs::create_dir(dir.path().join("S"))?;
        fs::write(dir.path().join("S").join("keep"), b"x")?;
        let res = stage_secret(dir.path(), "S", b"secret");
        anyhow::ensure!(matches!(res, Err(StageError::Io { .. })), "got {res:?}");
        let names: Vec<_> = fs::read_dir(dir.path())?
            .map(|e| e.map(|e| e.file_name()))
            .collect::<Result<_, _>>()?;
        anyhow::ensure!(names == ["S"], "left behind: {names:?}");
        Ok(())
    }

    #[test]
    fn a_symlink_planted_at_the_destination_never_touches_its_target() -> anyhow::Result<()> {
        let dir = staging_dir()?;
        let victim_dir = tempfile::tempdir()?;
        let victim = victim_dir.path().join("id_ed25519");
        fs::write(&victim, b"private key")?;
        std::os::unix::fs::symlink(&victim, dir.path().join("S"))?;
        let staged = stage_secret(dir.path(), "S", b"secret")?;
        anyhow::ensure!(
            fs::read(&victim)? == b"private key",
            "the symlink target was overwritten"
        );
        let path = staged_path(&staged)?;
        anyhow::ensure!(
            !fs::symlink_metadata(path)?.is_symlink(),
            "the staged secret is still a symlink"
        );
        anyhow::ensure!(fs::read(path)? == b"secret", "staged bytes differ");
        Ok(())
    }

    #[test]
    fn a_group_or_world_writable_staging_dir_is_refused() -> anyhow::Result<()> {
        for mode in [0o770, 0o707, 0o777] {
            let dir = staging_dir()?;
            fs::set_permissions(dir.path(), fs::Permissions::from_mode(mode))?;
            let res = stage_secret(dir.path(), "S", b"x");
            anyhow::ensure!(
                matches!(res, Err(StageError::UnsafeDir(_))),
                "mode {mode:o} gave {res:?}"
            );
            anyhow::ensure!(fs::read_dir(dir.path())?.count() == 0, "staged into an unsafe dir");
        }
        Ok(())
    }

    #[test]
    fn a_staging_dir_that_resolves_into_the_nix_store_is_refused() -> anyhow::Result<()> {
        let store = Path::new("/nix/store");
        if !store.is_dir() {
            return Ok(()); // no store on this host to resolve into
        }
        let dir = staging_dir()?;
        let link = dir.path().join("looks-local");
        std::os::unix::fs::symlink(store, &link)?;
        let res = stage_secret(&link, "S", b"x");
        anyhow::ensure!(matches!(res, Err(StageError::InStore(_))), "got {res:?}");
        Ok(())
    }

    /// INV-1: what reaches `RunSpec.secrets` is a path, never the bytes, so the
    /// secret cannot ride argv or env through the run.
    #[test]
    fn a_staged_secret_ref_carries_a_path_not_the_secret() -> anyhow::Result<()> {
        let dir = staging_dir()?;
        let marker = "sandy-inv1-marker-6f1e2d";
        let staged = stage_secret(dir.path(), "S", marker.as_bytes())?;
        anyhow::ensure!(
            !format!("{staged:?}").contains(marker),
            "the SecretRef carries the secret bytes, not just a path"
        );
        Ok(())
    }

    fn cap() -> Cap {
        use sandy_fabric::capauth::{CapRights, CapScope};
        Cap {
            scope: CapScope {
                peer: "agent".into(),
                channel: "orchestrator".into(),
                rights: CapRights {
                    post: true,
                    read: true,
                    invite: false,
                },
                expires_at: Some(4_102_444_800),
            },
            proof: vec![0xc0, 0xff, 0xee],
        }
    }

    #[test]
    fn a_channel_cap_is_staged_0600_and_reads_back_as_the_same_cap() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = stage_cap(dir.path(), "CHANNEL_CAP", &cap())?;
        let path = path.as_path();
        let mode = fs::metadata(path)?.permissions().mode() & 0o777;
        anyhow::ensure!(mode == 0o600, "mode {mode:o}");
        let read = sandy_fabric::capauth::decode_cap(&fs::read(path)?)?;
        // No `{:?}` on a Cap: its Debug prints the proof.
        anyhow::ensure!(read == cap(), "the staged cap differs from the minted one");
        Ok(())
    }

    #[tokio::test]
    async fn a_work_secret_is_staged_apart_from_the_join_cap() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let secret = LocalMinter.mint(&SecretRequest { job: "j".to_owned() }).await?;
        let cap_path = stage_cap(dir.path(), "CHANNEL_CAP", &cap())?;
        let secret_ref = stage_secret(dir.path(), "WORK_SECRET", &secret.bytes)?;
        let (cap_path, secret_path) = (cap_path.as_path(), staged_path(&secret_ref)?);
        anyhow::ensure!(cap_path != secret_path, "the cap and the work-secret share a file");
        let cap_bytes = fs::read(cap_path)?;
        anyhow::ensure!(
            !cap_bytes.windows(secret.bytes.len()).any(|w| w == secret.bytes),
            "the work-secret was bundled into the join cap"
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
