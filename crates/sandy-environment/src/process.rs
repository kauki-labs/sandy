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
//! only after checking that its command line names the directory.

use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, ExitStatus, Stdio},
    sync::{Mutex, MutexGuard, PoisonError},
    time::{Duration, Instant, SystemTime},
};

use command_group::{CommandGroup, GroupChild};
use sandy_api::{
    backend::{BackendError, BoxState},
    environment::{Endpoint, EnvironmentBackend, EnvironmentSpec, Launch, Probe},
};

/// The longest environment id accepted.
const MAX_ID: usize = 64;

/// Why a [`ProcessConfig`] is unusable.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProcessConfigError {
    /// No service command was given, or its program is blank.
    #[error("the service command is empty")]
    Empty,
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
    /// [`ProcessConfigError::Empty`] when `command` is empty or its program is blank.
    pub fn validate(&self) -> Result<(), ProcessConfigError> {
        match self.command.first() {
            Some(program) if !program.trim().is_empty() => Ok(()),
            _ => Err(ProcessConfigError::Empty),
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
    let mut buf = [0u8; 32];
    let n = stream.read(&mut buf).ok()?;
    let line = std::str::from_utf8(&buf[..n]).ok()?;
    let rest = line.strip_prefix("HTTP/1.")?;
    rest.get(2..5)?.parse().ok()
}

fn private_dir(path: &Path) -> Result<(), BackendError> {
    match fs::metadata(path) {
        Ok(meta) if meta.is_dir() => {
            if meta.permissions().mode() & 0o077 != 0 {
                return Err(spawn_err(format!(
                    "state dir {} must be private (mode 0700), not {:o}",
                    path.display(),
                    meta.permissions().mode() & 0o777
                )));
            }
            Ok(())
        }
        Ok(_) => Err(spawn_err(format!("state dir {} is not a directory", path.display()))),
        Err(_) => fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)
            .map_err(|e| spawn_err(format!("create state dir {}: {e}", path.display()))),
    }
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
        private_dir(&config.state_dir)?;
        sweep_stale(&config.state_dir);
        Ok(Self {
            config,
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
        let Some(program) = argv.first().filter(|p| !p.trim().is_empty()) else {
            return Err("the pairing command is empty".to_owned());
        };
        let _ = program;
        let path = running.dir.join("pairing");
        let out = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)
            .map_err(|e| format!("could not create the pairing file: {e}"))?;
        let mut child = self
            .command(&argv, &running.dir)
            .stdout(Stdio::from(out))
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("could not start the pairing command: {e}"))?;
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
                Err(e) => return Err(format!("could not wait for the pairing command: {e}")),
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

/// Remove stale environment directories. A recorded process group is killed
/// only on Linux and only when its command line names the directory, so a
/// reused pid is never hit.
fn sweep_stale(state_dir: &Path) {
    let Ok(entries) = fs::read_dir(state_dir) else { return };
    for entry in entries.flatten() {
        let dir = entry.path();
        if !dir.is_dir() {
            continue;
        }
        #[cfg(target_os = "linux")]
        if let Some(pid) = fs::read_to_string(dir.join("pid"))
            .ok()
            .and_then(|s| s.trim().parse::<i32>().ok())
        {
            let ours = fs::read(format!("/proc/{pid}/cmdline"))
                .map(|raw| String::from_utf8_lossy(&raw).contains(&dir.display().to_string()))
                .unwrap_or(false);
            if let (true, Some(pid)) = (ours, rustix::process::Pid::from_raw(pid)) {
                let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
            }
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
        let dir = self.config.state_dir.join(id);
        // A directory left by an earlier attempt that could not clean up.
        let _ = fs::remove_dir_all(&dir);
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&dir)
            .map_err(|e| spawn_err(format!("create {}: {e}", dir.display())))?;
        let started = (|| -> Result<(GroupChild, u16), BackendError> {
            let port = free_port().map_err(|e| spawn_err(format!("no free port: {e}")))?;
            let argv = substitute(&self.config.command, port, &dir, id);
            let log = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(dir.join("service.log"))
                .map_err(|e| spawn_err(format!("create the service log: {e}")))?;
            let log_err = log
                .try_clone()
                .map_err(|e| spawn_err(format!("clone the service log: {e}")))?;
            let child = self
                .command(&argv, &dir)
                .stdout(Stdio::from(log))
                .stderr(Stdio::from(log_err))
                .group_spawn()
                .map_err(|e| spawn_err(format!("spawn `{}`: {e}", argv[0])))?;
            fs::write(dir.join("pid"), child.id().to_string())
                .map_err(|e| spawn_err(format!("record the pid: {e}")))?;
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
                    if let Some(pair) = &self.config.pair_command {
                        if let Err(reason) = self.pair(r, pair, environment_id) {
                            return Ok(Probe::Failed {
                                step: "pair".to_owned(),
                                reason,
                            });
                        }
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
        let removed = self.lock().remove(environment_id);
        if let Some(mut r) = removed {
            // An already-exited group is not an error.
            let _ = r.child.kill();
            let _ = r.child.wait();
            fs::remove_dir_all(&r.dir)
                .map_err(|e| BackendError::Transport(format!("remove {}: {e}", r.dir.display())))?;
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
