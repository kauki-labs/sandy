//! The process-backed, trusted-only [`EnvironmentBackend`].
//!
//! Each environment is one host process group started from a configured argv,
//! in its own private directory under the state dir. There is NO isolation: the
//! service runs as the daemon's user. What this module does guarantee:
//!
//! - the service gets a cleared environment (`PATH`, `HOME`, `LANG`, `TMPDIR` and only the variables the config names),
//!   never the daemon's;
//! - the pairing command's output goes to a `0600` file and is never logged, returned in a probe, or put in an error;
//! - `kill` ends the whole process group and removes the directory;
//! - an environment id cannot name a path outside the state dir.
//!
//! A hard-killed daemon cannot clean up. The next [`ProcessEnvironmentBackend::new`]
//! removes the stale directories and, on Linux, kills a recorded process group
//! only when the pid file's start time still matches the live process, so a
//! reused pid is never hit. A service that leaves its process group (`setsid`)
//! is not reached: there is no isolation here.
//!
//! One daemon owns a state dir at a time: `new` takes an exclusive lock on
//! `<state_dir>/.lock` before it sweeps, and refuses when it is held.

use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    process::{Command, ExitStatus, Stdio},
    sync::{Mutex, MutexGuard, PoisonError},
    time::{Duration, Instant, SystemTime},
};

use command_group::{CommandGroup, GroupChild};
use fs2::FileExt;
use sandy_api::{
    backend::{BackendError, BoxState},
    environment::{Endpoint, EnvironmentBackend, EnvironmentSpec, Launch, Probe},
};
use sandy_fsutil::OwnedDir;

/// The longest environment id accepted.
const MAX_ID: usize = 64;

/// Variables the backend sets itself; `pass_env` cannot override them.
const RESERVED_ENV: [&str; 4] = ["HOME", "PATH", "TMPDIR", "LANG"];

/// Why a [`ProcessConfig`] is unusable.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProcessConfigError {
    /// No service command was given, or its program is blank.
    #[error("the service command is empty")]
    Empty,
    /// A passed-through variable name is one the backend sets itself.
    #[error("{0} is set by the backend and cannot be passed through")]
    ReservedEnv(String),
}

/// How to run the service.
#[derive(Debug, Clone)]
pub struct ProcessConfig {
    /// The service argv. `{port}`, `{base_dir}` and `{environment_id}` are
    /// replaced in every element.
    pub command: Vec<String>,
    /// An optional argv run once after the service first answers; its stdout
    /// is written to `<base_dir>/pairing` (mode 0600) and never logged.
    pub pair_command: Option<Vec<String>>,
    /// Where each environment gets its own directory. Created `0700`; an
    /// existing one must already be private.
    pub state_dir: PathBuf,
    /// The `PATH` the service sees.
    pub path: String,
    /// Names of daemon environment variables passed through to the service.
    pub pass_env: Vec<String>,
    /// How long the pair command may run.
    pub pair_timeout: Duration,
}

impl ProcessConfig {
    /// Checks the config.
    ///
    /// # Errors
    /// [`ProcessConfigError::Empty`] when `command` is empty or its program is blank;
    /// [`ProcessConfigError::ReservedEnv`] when `pass_env` names a variable the backend sets.
    pub fn validate(&self) -> Result<(), ProcessConfigError> {
        match self.command.first() {
            Some(program) if !program.trim().is_empty() => {}
            _ => return Err(ProcessConfigError::Empty),
        }
        match self.pass_env.iter().find(|n| RESERVED_ENV.contains(&n.as_str())) {
            Some(name) => Err(ProcessConfigError::ReservedEnv(name.clone())),
            None => Ok(()),
        }
    }
}

struct Running {
    child: GroupChild,
    port: u16,
    dir: PathBuf,
    started: SystemTime,
    paired: bool,
}

/// Runs each environment as a host process group.
pub struct ProcessEnvironmentBackend {
    config: ProcessConfig,
    base: OwnedDir,
    /// Holds the state dir's exclusive lock for this backend's life.
    _lock: fs::File,
    running: Mutex<BTreeMap<String, Running>>,
}

impl std::fmt::Debug for ProcessEnvironmentBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProcessEnvironmentBackend")
            .field("state_dir", &self.config.state_dir)
            .finish_non_exhaustive()
    }
}

fn spawn_err(message: impl Into<String>) -> BackendError {
    BackendError::Spawn(message.into())
}

/// 1 to [`MAX_ID`] bytes of letters, digits, `-`, `_` and `.`, and not all dots.
fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_ID
        && !id.bytes().all(|b| b == b'.')
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

fn substitute(argv: &[String], port: u16, dir: &Path, id: &str) -> Vec<String> {
    argv.iter()
        .map(|a| {
            a.replace("{port}", &port.to_string())
                .replace("{base_dir}", &dir.display().to_string())
                .replace("{environment_id}", id)
        })
        .collect()
}

fn free_port() -> std::io::Result<u16> {
    Ok(TcpListener::bind(("127.0.0.1", 0))?.local_addr()?.port())
}

/// The HTTP status the service answers on `/`, or `None` if nothing answers.
fn http_status(port: u16) -> Option<u16> {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_millis(500)).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(1))).ok()?;
    stream.set_write_timeout(Some(Duration::from_secs(1))).ok()?;
    stream
        .write_all(b"GET / HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .ok()?;
    // "HTTP/1.x NNN" is 12 bytes; a service may send it in several segments.
    let mut buf = [0u8; 12];
    let mut filled = 0;
    while filled < buf.len() {
        match stream.read(&mut buf[filled..]) {
            Ok(0) | Err(_) => break,
            Ok(n) => filled += n,
        }
    }
    let line = std::str::from_utf8(&buf[..filled]).ok()?;
    let rest = line.strip_prefix("HTTP/1.")?;
    rest.get(2..5)?.parse().ok()
}

/// Takes the state dir's exclusive lock, or says another daemon holds it.
fn lock_state_dir(base: &OwnedDir) -> Result<fs::File, BackendError> {
    let path = base.path().join(".lock");
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits().cast_signed())
        .open(&path)
        .map_err(|e| spawn_err(format!("open {}: {e}", path.display())))?;
    file.try_lock_exclusive().map_err(|_| {
        spawn_err(format!(
            "state dir {} is in use by another process",
            base.path().display()
        ))
    })?;
    Ok(file)
}

impl ProcessEnvironmentBackend {
    /// A backend over `config`. Removes stale environment directories left by
    /// an earlier daemon (and kills their process groups where it can tell
    /// they are ours).
    ///
    /// # Errors
    /// [`BackendError::Spawn`] if the config is invalid or the state dir cannot be prepared.
    pub fn new(config: ProcessConfig) -> Result<Self, BackendError> {
        config.validate().map_err(|e| spawn_err(e.to_string()))?;
        let base = OwnedDir::open_or_create(&config.state_dir).map_err(|e| spawn_err(format!("state dir: {e}")))?;
        let lock = lock_state_dir(&base)?;
        sweep_stale(base.path());
        Ok(Self {
            config,
            base,
            _lock: lock,
            running: Mutex::new(BTreeMap::new()),
        })
    }

    fn lock(&self) -> MutexGuard<'_, BTreeMap<String, Running>> {
        self.running.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A command with a cleared environment: only what the config allows.
    fn command(&self, argv: &[String], dir: &Path) -> Command {
        let mut cmd = Command::new(&argv[0]);
        cmd.args(&argv[1..])
            .env_clear()
            .env("PATH", &self.config.path)
            .env("HOME", dir)
            .env("LANG", "C.UTF-8")
            .env("TMPDIR", dir)
            .current_dir(dir)
            .stdin(Stdio::null());
        for name in &self.config.pass_env {
            if let Some(value) = std::env::var_os(name) {
                cmd.env(name, value);
            }
        }
        cmd
    }

    /// Run the pair command once; its stdout goes to `<dir>/pairing` (0600).
    /// The error text never carries the command's output.
    fn pair(&self, running: &Running, argv: &[String], id: &str) -> Result<(), String> {
        let argv = substitute(argv, running.port, &running.dir, id);
        if argv.first().is_none_or(|p| p.trim().is_empty()) {
            return Err("the pairing command is empty".to_owned());
        }
        let path = running.dir.join("pairing");
        let out = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .map_err(|e| format!("could not create the pairing file: {e}"))?;
        let mut child = match self
            .command(&argv, &running.dir)
            .stdout(Stdio::from(out))
            .stderr(Stdio::null())
            .group_spawn()
        {
            Ok(child) => child,
            Err(e) => {
                let _ = fs::remove_file(&path);
                return Err(format!("could not start the pairing command: {e}"));
            }
        };
        let deadline = Instant::now() + self.config.pair_timeout;
        let status: ExitStatus = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(50)),
                Ok(None) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = fs::remove_file(&path);
                    return Err("the pairing command timed out".to_owned());
                }
                Err(e) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = fs::remove_file(&path);
                    return Err(format!("could not wait for the pairing command: {e}"));
                }
            }
        };
        if status.success() {
            Ok(())
        } else {
            let _ = fs::remove_file(&path);
            Err(format!("the pairing command failed ({status})"))
        }
    }
}

impl Drop for ProcessEnvironmentBackend {
    fn drop(&mut self) {
        let mut running = self.lock();
        for (_, mut r) in std::mem::take(&mut *running) {
            let _ = r.child.kill();
            let _ = r.child.wait();
            let _ = fs::remove_dir_all(&r.dir);
        }
    }
}

/// The start time (clock ticks since boot) of `pid`, from `/proc/<pid>/stat`.
/// It tells a live process from a later one that reused the pid.
#[cfg(target_os = "linux")]
fn start_time(pid: i32) -> Option<u64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // Field 2 (comm) may hold spaces and parentheses; the fields after the last ')' start at field 3.
    let after = &stat[stat.rfind(')')? + 1..];
    after.split_whitespace().nth(19)?.parse().ok()
}

/// What the pid file records: the leader pid and, on Linux, its start time.
fn pid_record(pid: u32) -> String {
    #[cfg(target_os = "linux")]
    if let Some(start) = i32::try_from(pid).ok().and_then(start_time) {
        return format!("{pid} {start}");
    }
    pid.to_string()
}

/// Kills the process group a pid file names, only when the file's start time
/// still matches the live process.
#[cfg(target_os = "linux")]
fn kill_recorded_group(record: &str) {
    let mut fields = record.split_whitespace();
    let (Some(pid), Some(start), None) = (fields.next(), fields.next(), fields.nth(0)) else {
        return;
    };
    let (Ok(pid), Ok(start)) = (pid.parse::<i32>(), start.parse::<u64>()) else {
        return;
    };
    if pid <= 1 || start_time(pid) != Some(start) {
        return;
    }
    if let Some(pid) = rustix::process::Pid::from_raw(pid) {
        let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
    }
}

/// Remove stale environment directories, killing a recorded process group first
/// (Linux only; see [`kill_recorded_group`]). Symlinks and plain files are left alone.
fn sweep_stale(state_dir: &Path) {
    let Ok(entries) = fs::read_dir(state_dir) else { return };
    for entry in entries.flatten() {
        if !entry.file_type().is_ok_and(|t| t.is_dir()) {
            continue;
        }
        let dir = entry.path();
        #[cfg(target_os = "linux")]
        if let Ok(record) = fs::read_to_string(dir.join("pid")) {
            kill_recorded_group(&record);
        }
        if let Err(e) = fs::remove_dir_all(&dir) {
            tracing::warn!(dir = %dir.display(), error = %e, "could not remove a stale environment directory");
        }
    }
}

impl EnvironmentBackend for ProcessEnvironmentBackend {
    fn launch(&self, spec: &EnvironmentSpec) -> Result<Launch, BackendError> {
        let id = spec.environment_id.as_str();
        if !valid_id(id) {
            return Err(spawn_err(format!("invalid environment id {id:?}")));
        }
        let mut running = self.lock();
        if running.contains_key(id) {
            return Ok(Launch::AlreadyRunning);
        }
        let dir = self.base.path().join(id);
        // A directory left by an earlier attempt that could not clean up.
        let _ = fs::remove_dir_all(&dir);
        let owned = self
            .base
            .create_private_dir(id)
            .map_err(|e| spawn_err(format!("create the environment dir: {e}")))?;
        let started = (|| -> Result<(GroupChild, u16), BackendError> {
            let port = free_port().map_err(|e| spawn_err(format!("no free port: {e}")))?;
            let argv = substitute(&self.config.command, port, &dir, id);
            let log = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(dir.join("service.log"))
                .map_err(|e| spawn_err(format!("create the service log: {e}")))?;
            let log_err = log
                .try_clone()
                .map_err(|e| spawn_err(format!("clone the service log: {e}")))?;
            let mut child = self
                .command(&argv, &dir)
                .stdout(Stdio::from(log))
                .stderr(Stdio::from(log_err))
                .group_spawn()
                .map_err(|e| spawn_err(format!("spawn `{}`: {e}", argv[0])))?;
            if let Err(e) = owned.write_secret("pid", pid_record(child.id()).as_bytes()) {
                let _ = child.kill();
                let _ = child.wait();
                return Err(spawn_err(format!("record the pid: {e}")));
            }
            Ok((child, port))
        })();
        match started {
            Ok((child, port)) => {
                running.insert(
                    id.to_owned(),
                    Running {
                        child,
                        port,
                        dir,
                        started: SystemTime::now(),
                        paired: false,
                    },
                );
                Ok(Launch::Started)
            }
            Err(e) => {
                let _ = fs::remove_dir_all(&dir);
                Err(e)
            }
        }
    }

    fn probe(&self, environment_id: &str) -> Result<Probe, BackendError> {
        let mut running = self.lock();
        let Some(r) = running.get_mut(environment_id) else {
            return Ok(Probe::NotRunning);
        };
        match r.child.try_wait() {
            Ok(Some(status)) => {
                return Ok(Probe::Failed {
                    step: "process".to_owned(),
                    reason: format!("the service exited with {status}"),
                });
            }
            Ok(None) => {}
            Err(e) => return Err(BackendError::Transport(format!("wait for the service: {e}"))),
        }
        match http_status(r.port) {
            None => Ok(Probe::Starting {
                step: "boot".to_owned(),
            }),
            Some(status) if status >= 500 => Ok(Probe::Starting {
                step: "starting".to_owned(),
            }),
            Some(_) => {
                if !r.paired {
                    if let Some(pair) = &self.config.pair_command
                        && let Err(reason) = self.pair(r, pair, environment_id)
                    {
                        return Ok(Probe::Failed {
                            step: "pair".to_owned(),
                            reason,
                        });
                    }
                    r.paired = true;
                }
                Ok(Probe::Ready {
                    endpoint: Endpoint {
                        host: "127.0.0.1".to_owned(),
                        port: r.port,
                    },
                })
            }
        }
    }

    fn kill(&self, environment_id: &str) -> Result<(), BackendError> {
        let mut running = self.lock();
        if let Some(mut r) = running.remove(environment_id) {
            // An already-exited group is not an error.
            let _ = r.child.kill();
            let _ = r.child.wait();
        }
        // Also clears a directory an earlier kill could not remove.
        if valid_id(environment_id) {
            let dir = self.base.path().join(environment_id);
            match fs::remove_dir_all(&dir) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(BackendError::Transport(format!("remove {}: {e}", dir.display()))),
            }
        }
        Ok(())
    }

    fn boxes(&self) -> Result<Vec<BoxState>, BackendError> {
        Ok(self
            .lock()
            .iter()
            .map(|(id, r)| BoxState {
                box_id: id.clone(),
                box_name: id.clone(),
                pid: r.child.id(),
                started: r.started,
                rvport: None,
            })
            .collect())
    }
}
