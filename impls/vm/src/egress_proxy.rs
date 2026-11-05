//! The per-launch egress proxy (#404, `docs/decisions/egress-proxy.md` decisions 1 and 2).
//!
//! In proxy mode the guest has no NIC. The backend runs one `sandy-egress-proxy` per launch
//! attempt and wraps the job in `sandy-agent egress-relay` so the guest reaches the proxy over vsock.
//! How the proxy listens depends on the host ([`ProxyListen`]):
//!
//! - qemu (#404): a random host vsock port, scoped to the CID that attempt claimed.
//! - vfkit (#405): a unix socket in the private staging base. vfkit dials it for each guest connection to the constant
//!   guest port [`EGRESS_VSOCK_PORT`].
//!
//! - [`ProxyHandle::start`] spawns the proxy with a sanitized environment, writes the policy on stdin, and waits for
//!   its `READY` line.
//! - [`egress_relay_argv`] builds the guest-side wrapper command, and [`console_command`] nests it around the agent.
//! - [`ProxyHandle::exited`] tells a proxy that died from one the backend is about to kill.

use std::{
    io::{BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex, mpsc},
    time::Duration,
};

use sandy::BackendError;
use sandy_api::{agent::AGENT_VSOCK_PORT, egress::AllowList};
use uuid::Uuid;

use crate::agent::agent_command_argv;

/// Names the proxy binary, like `SANDY_VIRTIOFSD_BIN` names virtiofsd.
const PROXY_BIN_ENV: &str = "SANDY_EGRESS_PROXY_BIN";
/// The proxy binary looked up on `PATH` when [`PROXY_BIN_ENV`] is unset.
const PROXY_BIN_DEFAULT: &str = "sandy-egress-proxy";
/// The vsock port the guest relay dials under vfkit: constant, since the port space is per VM (#405).
pub(crate) const EGRESS_VSOCK_PORT: u32 = 5001;
/// How long the proxy has to print `READY` (decision 2).
pub(crate) const READY_DEADLINE: Duration = Duration::from_secs(5);
/// Ports tried before the launch fails: the vsock port space is shared by every VM on the host.
const PORT_ATTEMPTS: usize = 8;
/// The lowest port a launch picks (above the well-known and registered ranges).
const PORT_MIN: u32 = 49152;
/// The highest vsock port a launch picks (`2^31 - 1`).
const PORT_MAX: u32 = 0x7FFF_FFFF;
/// Bytes of proxy stderr kept for a start-failure diagnostic.
const STDERR_CAP: usize = 16 * 1024;
/// The text a failed bind prints; the proxy writes the OS error verbatim.
const ADDR_IN_USE: &str = "Address already in use";
/// How long to wait for a proxy that closed stdout to be reaped, and for its stderr to reach EOF.
const REAP_GRACE: Duration = Duration::from_secs(1);

/// How the proxy listens for the guest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ProxyListen {
    /// A random host vsock port (retried when taken), serving only the guest that claimed `cid` (qemu).
    Vsock {
        /// The CID this attempt claimed for the guest: the only peer the proxy serves.
        cid: u32,
    },
    /// A unix socket vfkit dials for each guest connection. It lives in the 0700 private staging base, so only this
    /// VM's vfkit can reach it.
    Unix {
        /// The socket path, short enough for `sun_path`.
        socket: PathBuf,
    },
}

/// What the backend needs to start the proxy for one launch attempt.
#[derive(Debug, Clone)]
pub(crate) struct EgressLaunch<'a> {
    /// The allow-list the proxy enforces.
    pub(crate) policy: &'a AllowList,
    /// How the proxy listens.
    pub(crate) listen: ProxyListen,
    /// The image's `sandy-agent`, which runs the relay in the guest.
    pub(crate) relay_program: &'a Path,
    /// The proxy binary.
    pub(crate) bin: PathBuf,
    /// How long the proxy has to print `READY`.
    pub(crate) ready_deadline: Duration,
}

impl<'a> EgressLaunch<'a> {
    /// A vsock launch (qemu) with the production binary resolution and the 5 s `READY` deadline.
    pub(crate) fn new(policy: &'a AllowList, cid: u32, relay_program: &'a Path) -> Self {
        Self::with_listen(policy, ProxyListen::Vsock { cid }, relay_program)
    }

    /// A unix-socket launch (vfkit) with the production binary resolution and the 5 s `READY` deadline.
    pub(crate) fn new_unix(policy: &'a AllowList, socket: PathBuf, relay_program: &'a Path) -> Self {
        Self::with_listen(policy, ProxyListen::Unix { socket }, relay_program)
    }

    fn with_listen(policy: &'a AllowList, listen: ProxyListen, relay_program: &'a Path) -> Self {
        let bin = std::env::var_os(PROXY_BIN_ENV).map_or_else(|| PathBuf::from(PROXY_BIN_DEFAULT), PathBuf::from);
        Self {
            policy,
            listen,
            relay_program,
            bin,
            ready_deadline: READY_DEADLINE,
        }
    }

    /// The proxy's unix socket, when it listens on one.
    pub(crate) fn unix_socket(&self) -> Option<&Path> {
        match &self.listen {
            ProxyListen::Unix { socket } => Some(socket),
            ProxyListen::Vsock { .. } => None,
        }
    }

    /// Start the proxy for this attempt.
    ///
    /// # Errors
    /// [`BackendError::Spawn`] (band 3) when the proxy does not reach `READY`.
    pub(crate) fn start(&self) -> Result<ProxyHandle, BackendError> {
        ProxyHandle::start(self)
    }
}

/// A running proxy. Dropping it kills the process, so no path leaks one.
#[derive(Debug)]
pub(crate) struct ProxyHandle {
    child: Child,
    port: u32,
}

/// Why one start attempt failed.
enum StartFailure {
    /// The vsock port is taken; retry another.
    AddrInUse(String),
    /// Anything else; do not retry.
    Other(String),
}

impl ProxyHandle {
    /// The proxy's process id, for the box record (#666).
    pub(crate) fn pid(&self) -> u32 {
        self.child.id()
    }

    /// The vsock port the guest relay dials: the random host port (qemu) or [`EGRESS_VSOCK_PORT`] (vfkit).
    pub(crate) fn port(&self) -> u32 {
        self.port
    }

    /// `Some(code)` when the proxy has already exited (`code` is `None` for a signal). Call it BEFORE
    /// [`kill`](Self::kill), so the backend's own kill is never read as a proxy death.
    pub(crate) fn exited(&mut self) -> Option<Option<i32>> {
        match self.child.try_wait() {
            Ok(Some(status)) => Some(status.code()),
            Ok(None) | Err(_) => None,
        }
    }

    /// Kill the proxy and reap it. Best effort: it may already be gone.
    pub(crate) fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }

    fn start(launch: &EgressLaunch<'_>) -> Result<Self, BackendError> {
        let policy = serde_json::to_vec(launch.policy)
            .map_err(|err| BackendError::Spawn(format!("egress proxy did not start: encode policy: {err}")))?;
        let cid = match &launch.listen {
            ProxyListen::Vsock { cid } => *cid,
            // A bind failure on the unix socket is not a port clash: no retry.
            ProxyListen::Unix { socket } => {
                let args = ["--unix".to_owned(), socket.to_string_lossy().into_owned()];
                return match start_once(launch, &args, EGRESS_VSOCK_PORT, &policy) {
                    Ok(handle) => Ok(handle),
                    Err(StartFailure::AddrInUse(why) | StartFailure::Other(why)) => {
                        Err(BackendError::Spawn(format!("egress proxy did not start: {why}")))
                    }
                };
            }
        };
        let mut last = String::new();
        for attempt in 1..=PORT_ATTEMPTS {
            let port = random_proxy_port();
            let args = [
                "--vsock-port".to_owned(),
                port.to_string(),
                "--peer-cid".to_owned(),
                cid.to_string(),
            ];
            match start_once(launch, &args, port, &policy) {
                Ok(handle) => return Ok(handle),
                Err(StartFailure::AddrInUse(why)) => {
                    tracing::debug!(attempt, port, "egress proxy port in use; retrying");
                    last = why;
                }
                Err(StartFailure::Other(why)) => {
                    return Err(BackendError::Spawn(format!("egress proxy did not start: {why}")));
                }
            }
        }
        Err(BackendError::Spawn(format!(
            "egress proxy did not start: no free vsock port after {PORT_ATTEMPTS} attempts: {last}"
        )))
    }
}

impl Drop for ProxyHandle {
    fn drop(&mut self) {
        self.kill();
    }
}

/// A random vsock port in `49152..=2^31-1`.
fn random_proxy_port() -> u32 {
    #[allow(clippy::cast_possible_truncation, reason = "any 32 random bits will do")]
    let bits = Uuid::new_v4().as_u128() as u32;
    PORT_MIN + bits % (PORT_MAX - PORT_MIN + 1)
}

/// The guest command in proxy mode: the relay wrapper around `rest` (the job, or the agent-mode
/// invocation).
pub(crate) fn egress_relay_argv(program: &Path, port: u32, rest: &[String]) -> Vec<String> {
    let mut argv = vec![
        program.to_string_lossy().into_owned(),
        "egress-relay".to_owned(),
        "--vsock-port".to_owned(),
        port.to_string(),
        "--".to_owned(),
    ];
    argv.extend(rest.iter().cloned());
    argv
}

/// The guest command: the job, behind the agent in agent mode, behind the egress relay in proxy mode
/// (outermost, so the relay's variables reach the agent and the job).
pub(crate) fn console_command(
    job: &[String],
    env: &[(String, String)],
    agent: Option<&Path>,
    relay: Option<(&Path, u32)>,
) -> Vec<String> {
    let inner = match agent {
        Some(program) => agent_command_argv(program, AGENT_VSOCK_PORT, job, env),
        None => job.to_vec(),
    };
    match relay {
        Some((program, port)) => egress_relay_argv(program, port, &inner),
        None => inner,
    }
}

/// Spawn the proxy with `args` (the `--vsock-port`/`--peer-cid` or `--unix` listen flags), report `port` as the
/// relay's port, and wait for `READY`.
fn start_once(
    launch: &EgressLaunch<'_>,
    args: &[String],
    port: u32,
    policy: &[u8],
) -> Result<ProxyHandle, StartFailure> {
    let mut command = Command::new(&launch.bin);
    // Sanitized environment: PATH only, never the forge token or any other secret.
    command.env_clear();
    if let Some(path) = std::env::var_os("PATH") {
        command.env("PATH", path);
    }
    let child = command
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| StartFailure::Other(format!("spawn `{}`: {err}", launch.bin.display())))?;
    let mut handle = ProxyHandle { child, port };

    // The policy goes on stdin, then stdin closes (the thread owns it and drops it): the proxy waits
    // for EOF. The write runs on a thread so the READY deadline bounds a proxy that never reads it:
    // a policy bigger than the pipe buffer would otherwise block `write_all` here for good. Killing
    // the proxy closes the pipe and ends the thread.
    if let Some(mut stdin) = handle.child.stdin.take() {
        let policy = policy.to_vec();
        std::thread::spawn(move || {
            if let Err(err) = stdin.write_all(&policy) {
                // A proxy that died at once surfaces below with its own stderr.
                tracing::debug!(%err, "write egress policy to proxy stdin");
            }
        });
    }

    let stderr = Arc::new(Mutex::new(Vec::new()));
    let (stderr_done, stderr_eof) = mpsc::channel();
    if let Some(pipe) = handle.child.stderr.take() {
        let sink = Arc::clone(&stderr);
        std::thread::spawn(move || {
            drain_stderr(pipe, &sink);
            let _ = stderr_done.send(());
        });
    }
    let (line_tx, line_rx) = mpsc::channel();
    if let Some(pipe) = handle.child.stdout.take() {
        std::thread::spawn(move || {
            let mut reader = BufReader::new(pipe);
            let mut line = String::new();
            let first = reader.read_line(&mut line).map(|n| (n > 0).then_some(line));
            let _ = line_tx.send(first);
            // Keep draining so the proxy never blocks or takes SIGPIPE on a later write.
            let _ = std::io::copy(&mut reader, &mut std::io::sink());
        });
    }

    let tail = || {
        let _ = stderr_eof.recv_timeout(REAP_GRACE);
        let buf = stderr.lock().map(|b| b.clone()).unwrap_or_default();
        String::from_utf8_lossy(&buf).trim().to_owned()
    };
    match line_rx.recv_timeout(launch.ready_deadline) {
        Ok(Ok(Some(line))) if line.trim() == "READY" => Ok(handle),
        Ok(Ok(Some(line))) => {
            handle.kill();
            Err(StartFailure::Other(format!(
                "expected READY, got `{}`; stderr: {}",
                line.trim(),
                tail()
            )))
        }
        Ok(Ok(None) | Err(_)) | Err(mpsc::RecvTimeoutError::Disconnected) => {
            // Stdout closed with no READY: the proxy exited (or closed its stdout).
            let status = wait_briefly(&mut handle.child);
            let why = tail();
            handle.kill();
            if why.contains(ADDR_IN_USE) {
                Err(StartFailure::AddrInUse(why))
            } else {
                Err(StartFailure::Other(format!(
                    "exited ({status}) before READY; stderr: {why}"
                )))
            }
        }
        Err(mpsc::RecvTimeoutError::Timeout) => {
            handle.kill();
            Err(StartFailure::Other(format!(
                "no READY within {:?}; stderr: {}",
                launch.ready_deadline,
                tail()
            )))
        }
    }
}

/// Wait up to [`REAP_GRACE`] for `child` to exit; describe its status.
fn wait_briefly(child: &mut Child) -> String {
    let deadline = std::time::Instant::now() + REAP_GRACE;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                return status
                    .code()
                    .map_or_else(|| "killed by a signal".to_owned(), |c| format!("exit status {c}"));
            }
            Ok(None) if std::time::Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            Ok(None) => return "still running".to_owned(),
            Err(err) => return format!("wait failed: {err}"),
        }
    }
}

/// Read `pipe` to EOF, logging each line at debug level and keeping the last [`STDERR_CAP`] bytes in
/// `sink`. Draining also stops a chatty proxy from blocking on a full pipe.
fn drain_stderr(pipe: impl Read, sink: &Mutex<Vec<u8>>) {
    let mut reader = BufReader::new(pipe);
    let mut line = Vec::new();
    while reader.read_until(b'\n', &mut line).is_ok_and(|n| n > 0) {
        tracing::debug!(target: "sandy_egress_proxy", "{}", String::from_utf8_lossy(&line).trim_end());
        if let Ok(mut buf) = sink.lock() {
            buf.extend_from_slice(&line);
            if buf.len() > STDERR_CAP {
                let excess = buf.len() - STDERR_CAP;
                buf.drain(..excess);
            }
        }
        line.clear();
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::os::unix::fs::PermissionsExt;

    use anyhow::Context;
    use sandy_api::egress::EgressRule;

    use super::*;

    /// How long a stub that prints READY at once may take to start (#624). Generous on purpose: the wait ends the
    /// moment READY arrives, so it costs nothing on a quiet host and keeps a loaded one from failing the test.
    pub(crate) const PROXY_STARTS: Duration = Duration::from_secs(30);

    /// The READY deadline of a stub that never prints READY (#624). The stub writes its pid file as its first act, and
    /// the test reads it after the start fails, so the deadline must outlast a loaded host's shell start-up: at 300 ms
    /// the proxy was killed before the pid file existed and the read failed with ENOENT.
    pub(crate) const NEVER_READY: Duration = Duration::from_secs(3);

    /// Write an executable `/bin/sh` stub into `dir`.
    pub(crate) fn stub(dir: &Path, name: &str, body: &str) -> anyhow::Result<PathBuf> {
        let path = dir.join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).context("write stub")?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).context("chmod stub")?;
        Ok(path)
    }

    fn policy() -> AllowList {
        AllowList {
            rules: vec![EgressRule {
                host: "github.com".to_owned(),
                port: 443,
            }],
        }
    }

    pub(crate) fn launch<'a>(policy: &'a AllowList, bin: PathBuf, deadline: Duration) -> EgressLaunch<'a> {
        EgressLaunch {
            policy,
            listen: ProxyListen::Vsock { cid: 42 },
            relay_program: Path::new("/nix/store/x-sandy-agent/bin/sandy-agent"),
            bin,
            ready_deadline: deadline,
        }
    }

    fn alive(pid: &str) -> bool {
        Command::new("kill")
            .args(["-0", pid])
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    }

    #[test]
    fn the_proxy_port_stays_in_the_dynamic_range() {
        for _ in 0..10_000 {
            let port = random_proxy_port();
            assert!((PORT_MIN..=PORT_MAX).contains(&port), "port {port}");
        }
    }

    #[test]
    fn the_relay_wraps_the_rest_as_one_flat_argv() {
        let rest = ["sh".to_owned(), "-c".to_owned(), "echo hi".to_owned()];
        assert_eq!(
            egress_relay_argv(Path::new("/p/sandy-agent"), 50000, &rest),
            [
                "/p/sandy-agent",
                "egress-relay",
                "--vsock-port",
                "50000",
                "--",
                "sh",
                "-c",
                "echo hi"
            ]
        );
    }

    /// The proxy gets the policy as JSON on stdin, `--vsock-port`/`--peer-cid` on argv, and an
    /// environment holding PATH only.
    #[test]
    fn the_proxy_gets_the_policy_on_stdin_and_a_sanitized_environment() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let seen = dir.path().join("seen");
        let bin = stub(
            dir.path(),
            "proxy",
            &format!(
                "cat > {seen}.stdin; echo \"$@\" > {seen}.args; env | sort > {seen}.env; echo READY; exec sleep 30",
                seen = seen.display()
            ),
        )?;
        let allow = policy();
        let mut handle = launch(&allow, bin, PROXY_STARTS).start()?;
        let port = handle.port();
        assert_eq!(handle.exited(), None, "a live proxy has not exited");
        handle.kill();
        let stdin = std::fs::read_to_string(dir.path().join("seen.stdin"))?;
        assert_eq!(serde_json::from_str::<AllowList>(&stdin).context("policy json")?, allow);
        let args = std::fs::read_to_string(dir.path().join("seen.args"))?;
        assert_eq!(args.trim(), format!("--vsock-port {port} --peer-cid 42"));
        let env = std::fs::read_to_string(dir.path().join("seen.env"))?;
        for line in env.lines() {
            let name = line.split('=').next().unwrap_or_default();
            assert!(
                matches!(name, "PATH" | "PWD" | "SHLVL" | "_" | "OLDPWD"),
                "unexpected variable in the proxy environment: {line}"
            );
        }
        Ok(())
    }

    /// The `READY` deadline bounds the WHOLE start, including the policy write: a proxy that never
    /// reads stdin, given a policy bigger than the pipe buffer, must fail as "no READY", not block
    /// the launch thread in `write_all` forever (decisions 2 and 3).
    #[test]
    fn a_proxy_that_never_reads_stdin_is_still_bounded_by_the_ready_deadline() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let pidfile = dir.path().join("pid");
        // Never reads stdin and never prints READY.
        let bin = stub(
            dir.path(),
            "proxy",
            &format!("echo $$ > {}; exec sleep 30", pidfile.display()),
        )?;
        // ~450 KiB of JSON, several times a 64 KiB pipe buffer.
        let huge: &'static AllowList = Box::leak(Box::new(AllowList {
            rules: (0..4000)
                .map(|i| EgressRule {
                    host: format!("{i:0>100}.example"),
                    port: 443,
                })
                .collect(),
        }));
        let launch = launch(huge, bin, NEVER_READY);
        // Run the start on its own thread so a regression fails this test instead of hanging it.
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(launch.start().err());
        });
        let err = rx
            .recv_timeout(Duration::from_secs(20))
            .context("start() blocked past the READY deadline: the policy write is not bounded")?;
        let Some(BackendError::Spawn(message)) = err else {
            anyhow::bail!("expected Spawn, got {err:?}");
        };
        assert!(
            message.starts_with("egress proxy did not start: no READY within"),
            "{message}"
        );
        let pid = std::fs::read_to_string(&pidfile)?;
        assert!(!alive(pid.trim()), "the stuck proxy must be killed");
        Ok(())
    }

    #[test]
    fn no_ready_in_time_is_a_spawn_error_and_the_proxy_is_killed() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let pidfile = dir.path().join("pid");
        let bin = stub(
            dir.path(),
            "proxy",
            &format!("echo $$ > {}; cat >/dev/null; exec sleep 30", pidfile.display()),
        )?;
        let allow = policy();
        let started = std::time::Instant::now();
        let err = launch(&allow, bin, NEVER_READY).start().err();
        let Some(BackendError::Spawn(message)) = err else {
            anyhow::bail!("expected Spawn, got {err:?}");
        };
        assert!(started.elapsed() < Duration::from_secs(10));
        assert!(
            message.starts_with("egress proxy did not start: no READY within"),
            "{message}"
        );
        let pid = std::fs::read_to_string(&pidfile)?;
        assert!(!alive(pid.trim()), "the stuck proxy must be killed");
        Ok(())
    }

    #[test]
    fn a_malformed_policy_exit_is_a_spawn_error_with_the_proxy_stderr() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let bin = stub(dir.path(), "proxy", "cat >/dev/null; echo 'bad policy' >&2; exit 2")?;
        let allow = policy();
        let err = launch(&allow, bin, PROXY_STARTS).start().err();
        let Some(BackendError::Spawn(message)) = err else {
            anyhow::bail!("expected Spawn, got {err:?}");
        };
        assert!(message.contains("exit status 2"), "{message}");
        assert!(message.contains("bad policy"), "{message}");
        Ok(())
    }

    #[test]
    fn a_missing_binary_is_a_spawn_error() -> anyhow::Result<()> {
        let allow = policy();
        let err = launch(&allow, PathBuf::from("/nonexistent/sandy-egress-proxy"), READY_DEADLINE)
            .start()
            .err();
        let Some(BackendError::Spawn(message)) = err else {
            anyhow::bail!("expected Spawn, got {err:?}");
        };
        assert!(message.starts_with("egress proxy did not start: spawn"), "{message}");
        Ok(())
    }

    /// EADDRINUSE retries with a new port: the stub refuses the first two ports, then serves.
    #[test]
    fn a_taken_port_is_retried_with_a_new_one() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let count = dir.path().join("count");
        let bin = stub(
            dir.path(),
            "proxy",
            &format!(
                "cat >/dev/null; echo x >> {c}; if [ $(wc -l < {c}) -le 2 ]; then echo 'Address already in use (os \
                 error 98)' >&2; exit 2; fi; echo READY; exec sleep 30",
                c = count.display()
            ),
        )?;
        let allow = policy();
        let mut handle = launch(&allow, bin, PROXY_STARTS).start()?;
        handle.kill();
        assert_eq!(std::fs::read_to_string(&count)?.lines().count(), 3);
        Ok(())
    }

    #[test]
    fn eight_taken_ports_give_up() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let count = dir.path().join("count");
        let bin = stub(
            dir.path(),
            "proxy",
            &format!(
                "cat >/dev/null; echo x >> {}; echo 'Address already in use' >&2; exit 2",
                count.display()
            ),
        )?;
        let allow = policy();
        let err = launch(&allow, bin, PROXY_STARTS).start().err();
        let Some(BackendError::Spawn(message)) = err else {
            anyhow::bail!("expected Spawn, got {err:?}");
        };
        assert!(message.contains("no free vsock port after 8 attempts"), "{message}");
        assert_eq!(std::fs::read_to_string(&count)?.lines().count(), PORT_ATTEMPTS);
        Ok(())
    }

    /// #405: the vfkit variant listens on a unix socket, has no CID or vsock port, and reports the constant
    /// relay port.
    #[test]
    fn a_unix_proxy_gets_the_socket_flag_only_and_reports_the_constant_port() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let seen = dir.path().join("seen");
        let bin = stub(
            dir.path(),
            "proxy",
            &format!(
                "cat > {seen}.stdin; echo \"$@\" > {seen}.args; echo READY; exec sleep 30",
                seen = seen.display()
            ),
        )?;
        let allow = policy();
        let socket = dir.path().join("eg-0123456789ab.sock");
        let mut launch = launch(&allow, bin, PROXY_STARTS);
        launch.listen = ProxyListen::Unix { socket: socket.clone() };
        assert_eq!(launch.unix_socket(), Some(socket.as_path()));
        let mut handle = launch.start()?;
        assert_eq!(handle.port(), EGRESS_VSOCK_PORT);
        assert_eq!(handle.port(), 5001);
        handle.kill();
        let args = std::fs::read_to_string(dir.path().join("seen.args"))?;
        assert_eq!(args.trim(), format!("--unix {}", socket.display()));
        let stdin = std::fs::read_to_string(dir.path().join("seen.stdin"))?;
        assert_eq!(serde_json::from_str::<AllowList>(&stdin).context("policy json")?, allow);
        Ok(())
    }

    /// #405: a bind failure on the unix socket is not retried like a vsock port clash, even when its
    /// stderr says "Address already in use" (a stale socket file prints it too).
    #[test]
    fn a_unix_bind_failure_is_not_retried() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let count = dir.path().join("count");
        let bin = stub(
            dir.path(),
            "proxy",
            &format!(
                "cat >/dev/null; echo x >> {}; echo 'bind /x.sock: Address already in use' >&2; exit 2",
                count.display()
            ),
        )?;
        let allow = policy();
        let mut launch = launch(&allow, bin, PROXY_STARTS);
        launch.listen = ProxyListen::Unix {
            socket: dir.path().join("eg.sock"),
        };
        let err = launch.start().err();
        let Some(BackendError::Spawn(message)) = err else {
            anyhow::bail!("expected Spawn, got {err:?}");
        };
        assert!(message.starts_with("egress proxy did not start:"), "{message}");
        assert!(message.contains("Address already in use"), "{message}");
        assert_eq!(std::fs::read_to_string(&count)?.lines().count(), 1, "one attempt only");
        Ok(())
    }

    /// #404: the console command in console-only proxy mode is the relay wrapper around the job.
    #[test]
    fn the_console_command_wraps_a_console_only_job_in_the_relay() {
        let job = [
            "sh".to_string(),
            "-c".to_string(),
            "curl https://github.com".to_string(),
        ];
        let program = Path::new("/nix/store/a-sandy-agent/bin/sandy-agent");
        assert_eq!(
            console_command(&job, &[], None, Some((program, 50123))),
            [
                "/nix/store/a-sandy-agent/bin/sandy-agent",
                "egress-relay",
                "--vsock-port",
                "50123",
                "--",
                "sh",
                "-c",
                "curl https://github.com"
            ]
        );
    }

    /// #404: in agent mode the relay is outermost and the agent invocation is its `<rest>`.
    #[test]
    fn the_console_command_wraps_the_agent_invocation_in_the_relay() {
        let job = ["sh".to_string(), "-c".to_string(), "env".to_string()];
        let program = Path::new("/nix/store/a-sandy-agent/bin/sandy-agent");
        assert_eq!(
            console_command(&job, &[], Some(program), Some((program, 50123))),
            [
                "/nix/store/a-sandy-agent/bin/sandy-agent",
                "egress-relay",
                "--vsock-port",
                "50123",
                "--",
                "/nix/store/a-sandy-agent/bin/sandy-agent",
                "--vsock-listen",
                "5000",
                "--",
                "sh",
                "-c",
                "env"
            ]
        );
        let env = [("SANDY_HISTORY_LINES".to_string(), "250".to_string())];
        assert_eq!(
            console_command(&job, &env, Some(program), None)[..2],
            ["env", "SANDY_HISTORY_LINES=250"],
            "the job env reaches the agent through the console command"
        );
        assert_eq!(
            console_command(&job, &[], None, None),
            job,
            "no agent, no proxy: the job unchanged"
        );
    }

    #[test]
    fn an_exited_proxy_reports_its_status_and_a_live_one_does_not() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let bin = stub(dir.path(), "proxy", "cat >/dev/null; echo READY; exit 3")?;
        let allow = policy();
        let mut handle = launch(&allow, bin, PROXY_STARTS).start()?;
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let status = loop {
            if let Some(status) = handle.exited() {
                break status;
            }
            anyhow::ensure!(std::time::Instant::now() < deadline, "proxy never exited");
            std::thread::sleep(Duration::from_millis(10));
        };
        assert_eq!(status, Some(3));
        Ok(())
    }
}
