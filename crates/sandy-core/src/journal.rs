//! The per-job journal: one JSON record per job under `$SANDY_HOME/jobs/`.
//!
//! Records are written atomically (tmp + rename). Each job has a sibling flock
//! lockfile opened `O_CLOEXEC`; acquiring it proves the previous owner is
//! dead/absent and is the ONLY liveness authority — `writer_pid` is
//! informational (INV-3). `$SANDY_HOME` must be a local POSIX filesystem,
//! because flock is unreliable on virtiofs/networked FS (INV-5).

use std::{
    fs::{File, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    time::SystemTime,
};

use serde::{Deserialize, Serialize};

use crate::{CoreError, result::ResultEnvelope};

/// The schema version stamped into every journal record.
pub const JOURNAL_SCHEMA_VERSION: u32 = 1;

/// The lifecycle state of a job record. Terminal states carry the result
/// envelope (INV-6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    /// The box is (believed to be) running.
    Running,
    /// Reconcile found the owner gone before a terminal transition (INV-3).
    Crashed,
    /// The guest exited 0 and outputs were collected.
    Succeeded,
    /// A task or infra fault ended the job.
    Failed,
    /// The job was cancelled.
    Cancelled,
}

/// One job's journal record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobRecord {
    /// Schema version of this record.
    pub schema_version: u32,
    /// The job id.
    pub job_id: String,
    /// The box the job ran in, if one booted.
    pub box_id: Option<String>,
    /// The current lifecycle state.
    pub state: JobState,
    /// The pid that wrote this record — informational only (INV-3).
    pub writer_pid: u32,
    /// When the record was first created.
    pub started: SystemTime,
    /// The terminal result envelope, present once the job reaches a terminal
    /// state (INV-6).
    pub result: Option<ResultEnvelope>,
}

/// A held per-job flock. The lock is released when this value is dropped.
#[derive(Debug)]
pub struct JobLock {
    /// The job this lock guards.
    job_id: String,
    /// The locked file; held only for its RAII lifetime.
    #[allow(dead_code, reason = "held to keep the flock until drop")]
    file: std::fs::File,
}

impl JobLock {
    /// The job id this lock guards.
    #[must_use]
    pub fn job_id(&self) -> &str {
        &self.job_id
    }
}

/// The journal rooted at `$SANDY_HOME`.
#[derive(Debug, Clone)]
pub struct Journal {
    /// `$SANDY_HOME`.
    root: PathBuf,
}

impl Journal {
    /// A journal rooted at `sandy_home` (`$SANDY_HOME`). Performs no I/O; call
    /// [`Journal::ensure_dirs`] to create the layout.
    #[must_use]
    pub fn new(sandy_home: impl Into<PathBuf>) -> Self {
        Self {
            root: sandy_home.into(),
        }
    }

    /// The directory holding per-job records (`$SANDY_HOME/jobs`).
    #[must_use]
    pub fn jobs_dir(&self) -> PathBuf {
        self.root.join("jobs")
    }

    /// The record path for `job_id` (`$SANDY_HOME/jobs/<job_id>.json`).
    #[must_use]
    pub fn record_path(&self, job_id: &str) -> PathBuf {
        self.jobs_dir().join(format!("{job_id}.json"))
    }

    /// The lockfile path for `job_id` (`$SANDY_HOME/jobs/<job_id>.lock`).
    #[must_use]
    pub fn lock_path(&self, job_id: &str) -> PathBuf {
        self.jobs_dir().join(format!("{job_id}.lock"))
    }

    /// Create the journal directory layout.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Io`] if the directories cannot be created.
    pub fn ensure_dirs(&self) -> Result<(), CoreError> {
        std::fs::create_dir_all(self.jobs_dir())?;
        Ok(())
    }

    /// Write `record` atomically (tmp + fsync + rename).
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Io`] / [`CoreError::Serde`] on failure.
    pub fn write_record(&self, record: &JobRecord) -> Result<(), CoreError> {
        let dir = self.jobs_dir();
        let final_path = self.record_path(&record.job_id);
        let json = serde_json::to_vec_pretty(record)?;

        // Write into a same-directory temp file so the rename is atomic on one
        // filesystem; a unique suffix keeps concurrent writers from colliding.
        let tmp_path = dir.join(format!("{}.json.tmp.{}", record.job_id, uuid::Uuid::new_v4()));
        {
            let mut tmp = File::create(&tmp_path)?;
            tmp.write_all(&json)?;
            tmp.sync_all()?;
        }
        std::fs::rename(&tmp_path, &final_path)?;

        // fsync the directory so the rename itself survives a crash (INV-6).
        let dir_handle = File::open(&dir)?;
        dir_handle.sync_all()?;
        Ok(())
    }

    /// Read the record for `job_id`.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::NotFound`] when no record exists.
    pub fn read_record(&self, job_id: &str) -> Result<JobRecord, CoreError> {
        let path = self.record_path(job_id);
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(CoreError::NotFound(job_id.to_string()));
            }
            Err(e) => return Err(e.into()),
        };
        let record = serde_json::from_slice(&bytes)?;
        Ok(record)
    }

    /// List every job record.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Io`] / [`CoreError::Serde`] on failure.
    pub fn list(&self) -> Result<Vec<JobRecord>, CoreError> {
        let dir = self.jobs_dir();
        let mut records = Vec::new();
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(records),
            Err(e) => return Err(e.into()),
        };
        for entry in entries {
            let path = entry?.path();
            // Only committed records; skip `.lock` files and `.json.tmp.*` temps.
            if path.extension().and_then(|ext| ext.to_str()) == Some("json") {
                let bytes = std::fs::read(&path)?;
                let record: JobRecord = serde_json::from_slice(&bytes)?;
                records.push(record);
            }
        }
        Ok(records)
    }

    /// Block until the per-job flock is acquired (`O_CLOEXEC`).
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Io`] if the lockfile cannot be opened.
    pub fn lock_job(&self, job_id: &str) -> Result<JobLock, CoreError> {
        let file = self.open_lockfile(job_id)?;
        fs2::FileExt::lock_exclusive(&file)?;
        Ok(JobLock {
            job_id: job_id.to_string(),
            file,
        })
    }

    /// Try to acquire the per-job flock without blocking; `Ok(None)` if another
    /// writer holds it (proving the owner is live — INV-3).
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Io`] if the lockfile cannot be opened.
    pub fn try_lock_job(&self, job_id: &str) -> Result<Option<JobLock>, CoreError> {
        let file = self.open_lockfile(job_id)?;
        match fs2::FileExt::try_lock_exclusive(&file) {
            Ok(()) => Ok(Some(JobLock {
                job_id: job_id.to_string(),
                file,
            })),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Open (creating if absent) a job's lockfile with `O_CLOEXEC` so only the
    /// supervisor holds it — forked children must not inherit it, or reconcile
    /// would never fire (INV-3, D3).
    fn open_lockfile(&self, job_id: &str) -> Result<File, CoreError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .custom_flags(libc::O_CLOEXEC)
            .open(self.lock_path(job_id))?;
        Ok(file)
    }
}

/// Generate a fresh job id (UUID v4).
#[must_use]
pub fn new_job_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// Verify that `path` lives on a local POSIX filesystem, not virtiofs/NFS,
/// where flock is unreliable (INV-5).
///
/// # Errors
///
/// Returns [`CoreError::NonLocalFs`] when `path` is on a non-local filesystem.
pub fn ensure_local_posix_fs(path: &Path) -> Result<(), CoreError> {
    // A known-networked backing store is refused; anything else (local disk, or
    // an undetectable mount) is accepted, so the common local case never fails.
    if let Some(fstype) = detect_fs_type(path)
        && is_networked_fs(&fstype)
    {
        return Err(CoreError::NonLocalFs(format!(
            "{} is on a {fstype} filesystem; flock is unreliable there",
            path.display()
        )));
    }
    Ok(())
}

/// Return the filesystem type backing `path`, by matching it against the host's
/// mount table. `None` when it cannot be determined (then the caller accepts).
#[must_use]
pub fn detect_fs_type(path: &Path) -> Option<String> {
    let target = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    mount_table()
        .into_iter()
        .filter(|(mount_point, _)| target.starts_with(mount_point))
        .max_by_key(|(mount_point, _)| mount_point.as_os_str().len())
        .map(|(_, fstype)| fstype)
}

/// Mount points and their filesystem types, read from `/proc/mounts` on Linux.
#[cfg(target_os = "linux")]
fn mount_table() -> Vec<(PathBuf, String)> {
    let content = std::fs::read_to_string("/proc/mounts").unwrap_or_default();
    content
        .lines()
        .filter_map(|line| {
            // `<device> <mount-point> <fstype> <opts> <freq> <passno>`
            let mut fields = line.split_whitespace();
            let _device = fields.next()?;
            let mount_point = fields.next()?;
            let fstype = fields.next()?;
            Some((PathBuf::from(mount_point), fstype.to_string()))
        })
        .collect()
}

/// Mount points and their filesystem types, parsed from `mount(8)` elsewhere
/// (macOS and other BSDs have no `/proc/mounts`).
#[cfg(not(target_os = "linux"))]
fn mount_table() -> Vec<(PathBuf, String)> {
    let Ok(output) = std::process::Command::new("mount").output() else {
        return Vec::new();
    };
    let text = String::from_utf8_lossy(&output.stdout);
    text.lines()
        .filter_map(|line| {
            // `<device> on <mount-point> (<fstype>, <opts>...)`
            let (_device, rest) = line.split_once(" on ")?;
            let (mount_point, paren) = rest.rsplit_once(" (")?;
            let fstype = paren.trim_end_matches(')').split(',').next()?.trim();
            Some((PathBuf::from(mount_point), fstype.to_string()))
        })
        .collect()
}

/// Whether `fstype` names a networked / shared filesystem where flock cannot be
/// trusted (INV-5).
#[must_use]
pub fn is_networked_fs(fstype: &str) -> bool {
    const DENY: &[&str] = &[
        "nfs",
        "nfs4",
        "cifs",
        "smbfs",
        "smb",
        "afpfs",
        "webdav",
        "sshfs",
        "virtiofs",
        "9p",
        "ncpfs",
        "glusterfs",
        "lustre",
        "ceph",
        "fuse.sshfs",
        "fuse.glusterfs",
    ];
    let lower = fstype.to_ascii_lowercase();
    DENY.contains(&lower.as_str())
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use super::*;
    use crate::result::{Logs, OutputRef, Provenance, RESULT_SCHEMA_VERSION, Status};

    fn terminal_record() -> JobRecord {
        JobRecord {
            schema_version: JOURNAL_SCHEMA_VERSION,
            job_id: "job-1".to_string(),
            box_id: Some("box-1".to_string()),
            state: JobState::Succeeded,
            writer_pid: 4242,
            started: SystemTime::UNIX_EPOCH,
            result: Some(ResultEnvelope {
                result_schema_version: RESULT_SCHEMA_VERSION,
                job_id: "job-1".to_string(),
                box_id: Some("box-1".to_string()),
                status: Status::Succeeded,
                retryable: false,
                message: "ok".to_string(),
                exit_code: Some(0),
                outputs: vec![OutputRef {
                    path: "result.txt".to_string(),
                }],
                receipts: vec![],
                provenance: Provenance {
                    template_store_path: "/nix/store/xxx".to_string(),
                },
                logs: Logs { tail: String::new() },
            }),
        }
    }

    /// INV-6: a terminal record round-trips through the journal carrying the
    /// full result envelope and its `result_schema_version`.
    #[test]
    fn terminal_record_round_trips_with_result() -> anyhow::Result<()> {
        let tmp = tempfile::tempdir()?;
        let journal = Journal::new(tmp.path());
        journal.ensure_dirs()?;
        let record = terminal_record();
        journal.write_record(&record)?;
        let read = journal.read_record("job-1")?;
        let result = read.result.expect("terminal record carries a result");
        assert_eq!(result.result_schema_version, RESULT_SCHEMA_VERSION);
        assert_eq!(result.status, Status::Succeeded);
        Ok(())
    }

    /// INV-3: the per-job flock is single-writer — a second non-blocking
    /// acquire fails while the first is held.
    #[test]
    fn job_lock_is_single_writer() -> anyhow::Result<()> {
        let tmp = tempfile::tempdir()?;
        let journal = Journal::new(tmp.path());
        journal.ensure_dirs()?;
        let held = journal.lock_job("job-1")?;
        assert_eq!(held.job_id(), "job-1");
        assert!(
            journal.try_lock_job("job-1")?.is_none(),
            "a second writer must not acquire the held lock"
        );
        Ok(())
    }

    /// INV-5: a local POSIX `$SANDY_HOME` is accepted.
    #[test]
    fn local_posix_home_is_accepted() -> anyhow::Result<()> {
        let tmp = tempfile::tempdir()?;
        ensure_local_posix_fs(tmp.path())?;
        Ok(())
    }
}
