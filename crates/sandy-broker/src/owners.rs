//! The job-owner table: which client submitted which job, and the attach token
//! sandyd issued for it. The token never leaves this process (decision 3).

use std::{collections::HashMap, path::Path, sync::Mutex};

use base64::{Engine, engine::general_purpose::STANDARD};
use sandy_fsutil::OwnedDir;
use serde::{Deserialize, Serialize};

const FILE: &str = "owners.json";

#[derive(Clone, Serialize, Deserialize)]
struct Owned {
    client: String,
    /// Base64 of the attach token.
    token: String,
}

/// The persisted owner table. The file is 0600 and replaced atomically.
pub(crate) struct Owners {
    dir: OwnedDir,
    table: Mutex<HashMap<String, Owned>>,
}

/// The table could not be loaded or saved.
#[derive(Debug, thiserror::Error)]
pub enum OwnersError {
    /// The state directory or file is unsafe or unreadable.
    #[error("owner table: {0}")]
    Fs(#[from] sandy_fsutil::FsError),
    /// The stored file is not a valid table.
    #[error("owner table is corrupt: {0}")]
    Corrupt(#[from] serde_json::Error),
    /// Reading the file failed.
    #[error("read owner table: {0}")]
    Read(std::io::Error),
}

impl Owners {
    pub(crate) fn open(state_dir: &Path) -> Result<Self, OwnersError> {
        let dir = OwnedDir::open_or_create(state_dir)?;
        let table = match std::fs::read(dir.path().join(FILE)) {
            Ok(bytes) => serde_json::from_slice(&bytes)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => HashMap::new(),
            Err(e) => return Err(OwnersError::Read(e)),
        };
        Ok(Self {
            dir,
            table: Mutex::new(table),
        })
    }

    /// Records `job_id` as owned by `client` with `token`, and saves the table.
    pub(crate) fn insert(&self, job_id: &str, client: &str, token: &[u8]) -> Result<(), OwnersError> {
        let mut table = self.table.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        table.insert(
            job_id.to_owned(),
            Owned {
                client: client.to_owned(),
                token: STANDARD.encode(token),
            },
        );
        let saved = serde_json::to_vec(&*table)
            .map_err(OwnersError::from)
            .and_then(|bytes| self.dir.write_secret(FILE, &bytes).map(drop).map_err(OwnersError::from));
        if saved.is_err() {
            // Keep memory and disk equal: a later insert must not persist this entry.
            table.remove(job_id);
        }
        saved
    }

    /// The attach token of `job_id`, only when `client` owns it.
    pub(crate) fn token_for(&self, job_id: &str, client: &str) -> Option<Vec<u8>> {
        let table = self.table.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let owned = table.get(job_id).filter(|o| o.client == client)?;
        STANDARD.decode(&owned.token).ok()
    }

    /// Whether `client` owns `job_id`.
    pub(crate) fn owns(&self, job_id: &str, client: &str) -> bool {
        let table = self.table.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        table.get(job_id).is_some_and(|o| o.client == client)
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    #[test]
    fn ownership_and_the_token_survive_a_restart_and_the_file_is_private() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let state = dir.path().join("state");
        Owners::open(&state)?.insert("job-1", "a", b"\x00\xffsecret")?;
        let reopened = Owners::open(&state)?;
        assert_eq!(
            reopened.token_for("job-1", "a").as_deref(),
            Some(&b"\x00\xffsecret"[..])
        );
        assert!(
            reopened.token_for("job-1", "b").is_none(),
            "another client must not get the token"
        );
        assert!(!reopened.owns("job-2", "a"));
        let mode = std::fs::metadata(state.join(FILE))?.permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        Ok(())
    }
}
