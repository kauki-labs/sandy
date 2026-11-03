//! The owner table: which client submitted which job (with the attach token sandyd
//! issued for it) and which client created which environment. The attach token
//! never leaves this process (decision 3).

use std::{
    collections::HashMap,
    path::Path,
    sync::{Mutex, MutexGuard, PoisonError},
};

use base64::{Engine, engine::general_purpose::STANDARD};
use sandy_fsutil::OwnedDir;
use serde::{Deserialize, Serialize};

const FILE: &str = "owners.json";
const LOCK_FILE: &str = "owners.lock";

#[derive(Clone, Serialize, Deserialize)]
struct Owned {
    client: String,
    /// Base64 of the attach token.
    token: String,
}

/// Everything the file holds.
#[derive(Clone, Default, Serialize, Deserialize)]
struct Tables {
    #[serde(default)]
    jobs: HashMap<String, Owned>,
    /// Environment id to owning client.
    #[serde(default)]
    environments: HashMap<String, String>,
    /// `client` and request id to the environment that request created.
    #[serde(default)]
    keys: HashMap<String, String>,
}

/// The persisted owner table. The file is 0600 and replaced atomically.
pub(crate) struct Owners {
    dir: OwnedDir,
    tables: Mutex<Tables>,
    _lock: std::fs::File,
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
    /// Another broker holds this state directory.
    #[error("the state directory is in use by another broker")]
    Locked,
}

fn key_of(client: &str, request_id: &str) -> String {
    // Client ids are plain names and request ids never hold a newline, so the
    // join is unambiguous.
    format!("{client}\n{request_id}")
}

impl Owners {
    pub(crate) fn open(state_dir: &Path) -> Result<Self, OwnersError> {
        use std::os::unix::fs::OpenOptionsExt;

        use fs2::FileExt;

        let dir = OwnedDir::open_or_create(state_dir)?;
        // One broker per state dir: a second writer would clobber the table. The
        // lock lives as long as this value, and handlers hold it through their Arc.
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .mode(0o600)
            .open(dir.path().join(LOCK_FILE))
            .map_err(OwnersError::Read)?;
        lock.try_lock_exclusive().map_err(|_| OwnersError::Locked)?;
        let tables = match std::fs::read(dir.path().join(FILE)) {
            Ok(bytes) => serde_json::from_slice(&bytes)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Tables::default(),
            Err(e) => return Err(OwnersError::Read(e)),
        };
        Ok(Self {
            dir,
            tables: Mutex::new(tables),
            _lock: lock,
        })
    }

    fn lock(&self) -> MutexGuard<'_, Tables> {
        self.tables.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Applies `change` and saves. On a failed save the in-memory table goes back to
    /// what it was, so a later save cannot persist the failed change.
    fn update(&self, change: impl FnOnce(&mut Tables)) -> Result<(), OwnersError> {
        let mut tables = self.lock();
        let before = tables.clone();
        change(&mut tables);
        let saved = serde_json::to_vec(&*tables)
            .map_err(OwnersError::from)
            .and_then(|bytes| self.dir.write_secret(FILE, &bytes).map(drop).map_err(OwnersError::from));
        if saved.is_err() {
            *tables = before;
        }
        saved
    }

    /// Records `job_id` as owned by `client` with `token`, and saves the table.
    pub(crate) fn insert(&self, job_id: &str, client: &str, token: &[u8]) -> Result<(), OwnersError> {
        self.update(|t| {
            t.jobs.insert(
                job_id.to_owned(),
                Owned {
                    client: client.to_owned(),
                    token: STANDARD.encode(token),
                },
            );
        })
    }

    /// The attach token of `job_id`, only when `client` owns it.
    pub(crate) fn token_for(&self, job_id: &str, client: &str) -> Option<Vec<u8>> {
        let tables = self.lock();
        let owned = tables.jobs.get(job_id).filter(|o| o.client == client)?;
        STANDARD.decode(&owned.token).ok()
    }

    /// Whether `client` owns `job_id`.
    pub(crate) fn owns(&self, job_id: &str, client: &str) -> bool {
        self.lock().jobs.get(job_id).is_some_and(|o| o.client == client)
    }

    /// Records `environment_id` as created by `client` for `request_id`.
    pub(crate) fn record_environment(
        &self,
        environment_id: &str,
        client: &str,
        request_id: &str,
    ) -> Result<(), OwnersError> {
        self.update(|t| {
            t.environments.insert(environment_id.to_owned(), client.to_owned());
            t.keys.insert(key_of(client, request_id), environment_id.to_owned());
        })
    }

    /// Whether `client` owns `environment_id`.
    pub(crate) fn owns_environment(&self, environment_id: &str, client: &str) -> bool {
        self.lock()
            .environments
            .get(environment_id)
            .is_some_and(|c| c == client)
    }

    /// Whether `client` already created an environment for `request_id`.
    pub(crate) fn has_request(&self, client: &str, request_id: &str) -> bool {
        self.lock().keys.contains_key(&key_of(client, request_id))
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    #[test]
    fn a_second_broker_on_the_same_state_dir_is_refused_until_the_first_is_gone() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let first = Owners::open(dir.path())?;
        assert!(matches!(Owners::open(dir.path()), Err(OwnersError::Locked)));
        drop(first);
        Owners::open(dir.path())?;
        Ok(())
    }

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

    #[test]
    fn environment_ownership_and_request_ids_survive_a_restart_per_client() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        Owners::open(dir.path())?.record_environment("env-1", "a", "req")?;
        let reopened = Owners::open(dir.path())?;
        assert!(reopened.owns_environment("env-1", "a"));
        assert!(!reopened.owns_environment("env-1", "b"));
        assert!(reopened.has_request("a", "req"));
        assert!(!reopened.has_request("b", "req"), "request ids are per client");
        Ok(())
    }
}
