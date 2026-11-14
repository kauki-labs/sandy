//! Live pipeline through the daemon (#858, slice 1): a `sandyd` and a `sandy-host-executor` the test starts itself
//! (mutual-TLS keys, ports and temp dirs of its own), then `sandy run` / `daemon submit` / `wait` / `kill` / `gc`
//! against them with a real qemu boot. It re-proves the kpi rows K1, K2 and K3 through the daemon (INV-S9).
//!
//! Tier-3, behind the `live` feature. Linux with KVM only. The guest runner is built first, from the packaged guest
//! flake the executor resolves, because the executor boots a guest and does not build one.
//!
//!   SANDY_LIVE=1 SANDY_HOST_EXECUTOR_BIN=<store>/bin/sandy-host-executor SANDY_AGENT_PATH=<store>/bin/sandy-agent \
//!     SANDY_GUEST_WRAPPER=<store of sandy-guest-wrapper> \
//!     nix shell nixpkgs#qemu nixpkgs#virtiofsd -c cargo nextest run -p sandy-cli --features live \
//!     --test live_daemon_pipeline
//!
//! The three variables name the packaged executor, agent and guest wrapper (`nix build .#sandy-host-executor
//! .#sandy-agent .#sandy-guest-wrapper`). `SANDYD_BIN` points at a prebuilt `sandyd`; without it the test builds one.
//! Every spawned command has a timeout; the harness kills only the processes it started, matched by pid and start
//! time, and removes its own temp dir on every exit path.
#![cfg(feature = "live")]
#![cfg(target_os = "linux")]

use std::{
    collections::BTreeSet,
    net::TcpListener,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use anyhow::{Context, bail, ensure};
use serde_json::Value;

mod common;
use common::require_live;

const TEMPLATE: &str = "topologies.x86_64-linux.qemu";
/// A cold guest build plus a boot, and the longest a single `sandy` call may take.
const BUILD_SECS: u64 = 1500;
const CALL_SECS: u64 = 600;

/// `(parent pid, start time)` of a process, from `/proc/<pid>/stat`.
fn parent_and_start(pid: u32) -> Option<(u32, u64)> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // The command name may hold spaces and parentheses; the fields after it start past the last `)`.
    let rest: Vec<&str> = stat.get(stat.rfind(')')? + 1..)?.split_whitespace().collect();
    Some((rest.get(1)?.parse().ok()?, rest.get(19)?.parse().ok()?))
}

fn signal(name: &str, pid: u32) {
    let _ = Command::new("kill")
        .arg(format!("-{name}"))
        .arg(pid.to_string())
        .status();
}

/// The direct children of `parent` with their start times and command lines, from `/proc`.
fn children_of(parent: u32) -> Vec<(u32, u64, String)> {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|entry| {
            let pid: u32 = entry.file_name().to_str()?.parse().ok()?;
            let (ppid, start) = parent_and_start(pid)?;
            (ppid == parent).then(|| {
                let cmdline = std::fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
                (pid, start, String::from_utf8_lossy(&cmdline).replace('\0', " "))
            })
        })
        .collect()
}

/// A process the test started. On drop: TERM, then KILL after a grace period, then KILL of every child it had that is
/// still the same process (pid and start time), so a failed run leaves no qemu or virtiofsd behind. Another session's
/// processes on the shared host are never touched.
struct Proc(Child);

impl Drop for Proc {
    fn drop(&mut self) {
        let owned = children_of(self.0.id());
        signal("TERM", self.0.id());
        let deadline = Instant::now() + Duration::from_secs(15);
        while !matches!(self.0.try_wait(), Ok(Some(_))) {
            if Instant::now() > deadline {
                let _ = self.0.kill();
                let _ = self.0.wait();
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        for (pid, start, _) in owned {
            if parent_and_start(pid).is_some_and(|(_, t)| t == start) {
                signal("KILL", pid);
            }
        }
    }
}

/// Run `cmd` to its end or kill it after `secs`, with its output in files so a large result cannot fill a pipe.
fn run_timeout(mut cmd: Command, dir: &Path, label: &str, secs: u64) -> anyhow::Result<(i32, String, String)> {
    let (out, err) = (dir.join(format!("{label}.out")), dir.join(format!("{label}.err")));
    let mut child = cmd
        .stdout(Stdio::from(std::fs::File::create(&out)?))
        .stderr(Stdio::from(std::fs::File::create(&err)?))
        .spawn()
        .with_context(|| format!("spawn {label}"))?;
    let deadline = Instant::now() + Duration::from_secs(secs);
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            bail!("{label} did not finish within {secs}s");
        }
        std::thread::sleep(Duration::from_millis(200));
    };
    Ok((
        status.code().unwrap_or(-1),
        std::fs::read_to_string(&out)?,
        std::fs::read_to_string(&err)?,
    ))
}

fn env_path(name: &str) -> anyhow::Result<PathBuf> {
    std::env::var_os(name)
        .map(PathBuf::from)
        .with_context(|| format!("{name} is required: see the doc comment of this file"))
}

fn sandyd_bin() -> anyhow::Result<PathBuf> {
    if let Some(path) = std::env::var_os("SANDYD_BIN") {
        return Ok(PathBuf::from(path));
    }
    let sandy = PathBuf::from(env!("CARGO_BIN_EXE_sandy"));
    let status = Command::new(env!("CARGO"))
        .args(["build", "-p", "sandyd", "--bin", "sandyd"])
        .arg("--manifest-path")
        .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/../../Cargo.toml"))
        .status()
        .context("build sandyd")?;
    ensure!(status.success(), "cargo build -p sandyd failed");
    Ok(sandy.parent().context("sandy's binary has no parent")?.join("sandyd"))
}

/// A free loopback port. The listener is dropped before the port is used; a collision fails the start, not a result.
fn free_port() -> anyhow::Result<u16> {
    Ok(TcpListener::bind("127.0.0.1:0")?.local_addr()?.port())
}

fn private_dir(path: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

/// `sandyd` and `sandy-host-executor`, registered with each other, and the env a `sandy` call needs.
struct Stack {
    dir: tempfile::TempDir,
    sock: PathBuf,
    client_tmp: PathBuf,
    executor_pid: u32,
    _executor: Proc,
    _daemon: Proc,
}

impl Stack {
    fn start() -> anyhow::Result<Self> {
        require_live()?;
        let executor_bin = env_path("SANDY_HOST_EXECUTOR_BIN")?;
        let agent = env_path("SANDY_AGENT_PATH")?;
        let wrapper = env_path("SANDY_GUEST_WRAPPER")?;
        // Under `/tmp`, not `$TMPDIR`: a nix shell's is long, and the sockets below live under this dir.
        let dir = tempfile::Builder::new()
            .prefix("s")
            .tempdir_in("/tmp")
            .context("temp dir under /tmp")?;
        let base = dir.path();
        for sub in ["d", "e", "dt", "et", "ct"] {
            private_dir(&base.join(sub))?;
        }
        let sandy = PathBuf::from(env!("CARGO_BIN_EXE_sandy"));

        let mut build = Command::new("nix");
        build.args(["build", "--no-link"]).arg(format!(
            "path:{}?dir=nix/guest#packages.x86_64-linux.guest-runner",
            wrapper.display()
        ));
        let (code, _, err) = run_timeout(build, base, "guest-build", BUILD_SECS)?;
        ensure!(code == 0, "nix build of the guest runner failed: {err}");

        let fingerprint = |name: &str| -> anyhow::Result<String> {
            let mut cmd = Command::new(&sandy);
            cmd.args(["mesh", "key", "generate"]).arg(base.join(name).join("tls"));
            let (code, out, err) = run_timeout(cmd, base, &format!("key-{name}"), 60)?;
            ensure!(code == 0, "mesh key generate failed: {err}");
            Ok(out.trim().to_owned())
        };
        let (daemon_fp, executor_fp) = (fingerprint("d")?, fingerprint("e")?);

        let sock = base.join("d.sock");
        let (mesh, link) = (free_port()?, free_port()?);
        let daemon = Proc(
            Command::new(sandyd_bin()?)
                .env("SANDY_SOCK", &sock)
                .env("SANDY_DB", base.join("d.db"))
                .env("TMPDIR", base.join("dt"))
                .env("SANDY_MESH_LISTEN", format!("127.0.0.1:{mesh}"))
                .env("SANDY_MESH_ALLOWLIST", format!("127.0.0.1={executor_fp}"))
                .env("SANDY_MESH_AGENT_LINK_LISTEN", format!("127.0.0.1:{link}"))
                .env("SANDY_MESH_TLS_IDENTITY_DIR", base.join("d/tls"))
                .stdout(Stdio::from(std::fs::File::create(base.join("d.log"))?))
                .stderr(Stdio::from(std::fs::File::create(base.join("d.err"))?))
                .spawn()
                .context("spawn sandyd")?,
        );
        let deadline = Instant::now() + Duration::from_secs(15);
        while std::os::unix::net::UnixStream::connect(&sock).is_err() {
            ensure!(Instant::now() < deadline, "sandyd never accepted on {}", sock.display());
            std::thread::sleep(Duration::from_millis(50));
        }

        let executor = Proc(
            Command::new(executor_bin)
                .env("SANDY_HOST_EXECUTOR_ID", "live-858")
                .env("SANDY_HOST_EXECUTOR_ORCHESTRATOR", format!("127.0.0.1:{mesh}"))
                .env("SANDY_HOST_EXECUTOR_ORCHESTRATOR_FINGERPRINT", &daemon_fp)
                .env("SANDY_HOST_EXECUTOR_TLS_IDENTITY_DIR", base.join("e/tls"))
                .env("SANDY_AGENT_PATH", &agent)
                .env("SANDY_GUEST_WRAPPER", &wrapper)
                .env("SANDY_HOST_SHARES_SUBMITTER_FS", "1")
                .env("TMPDIR", base.join("et"))
                .stdout(Stdio::from(std::fs::File::create(base.join("e.log"))?))
                .stderr(Stdio::from(std::fs::File::create(base.join("e.err"))?))
                .spawn()
                .context("spawn sandy-host-executor")?,
        );
        let executor_pid = executor.0.id();
        // The executor logs "registered with the orchestrator" once the daemon has accepted it.
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let log = std::fs::read_to_string(base.join("e.err")).unwrap_or_default()
                + &std::fs::read_to_string(base.join("e.log")).unwrap_or_default();
            if log.contains("registered with the orchestrator") {
                break;
            }
            ensure!(Instant::now() < deadline, "the executor never registered: {log}");
            std::thread::sleep(Duration::from_millis(200));
        }
        Ok(Self {
            sock,
            client_tmp: base.join("ct"),
            executor_pid,
            dir,
            _executor: executor,
            _daemon: daemon,
        })
    }

    /// A `sandy` call against this daemon, with the client's own `TMPDIR` (the shared staging base may not be ours).
    fn sandy(&self, label: &str, args: &[&str]) -> anyhow::Result<(i32, Value)> {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_sandy"));
        cmd.env("SANDY_SOCK", &self.sock)
            .env("TMPDIR", &self.client_tmp)
            .args(["-o", "json"])
            .args(args);
        let (code, out, err) = run_timeout(cmd, self.dir.path(), label, CALL_SECS)?;
        // The JSON is the first top-level value; notes the CLI prints go to stderr.
        let json = serde_json::Deserializer::from_str(&out)
            .into_iter::<Value>()
            .next()
            .transpose()
            .with_context(|| format!("{label}: stdout is not JSON: {out} / {err}"))?
            .unwrap_or(Value::Null);
        Ok((code, json))
    }

    /// Children of the executor that are the guest itself: a long-lived qemu with a boot drive, not a `--version`
    /// probe.
    fn guest_qemus(&self) -> Vec<(u32, u64)> {
        children_of(self.executor_pid)
            .into_iter()
            .filter(|(_, _, cmd)| cmd.contains("qemu-system") && cmd.contains("-drive"))
            .map(|(pid, start, _)| (pid, start))
            .collect()
    }
}

fn str_at<'a>(v: &'a Value, path: &[&str]) -> &'a str {
    path.iter()
        .try_fold(v, |v, k| v.get(k))
        .and_then(Value::as_str)
        .unwrap_or("")
}

/// K1: a dispatched job boots the guest, runs the command, collects declared outputs and returns `succeeded` / 0.
/// The guest is proved by its hostname (`sandy`, never the host's), so a run that fell back to a host process fails.
#[test]
fn a_job_boots_runs_and_collects_its_outputs_through_the_daemon() -> anyhow::Result<()> {
    let stack = Stack::start()?;
    let out = stack.dir.path().join("outdir");
    let out_arg = out.to_string_lossy().into_owned();

    let (code, envelope) = stack.sandy(
        "k1-true",
        &[
            "run",
            "--out",
            &out_arg,
            TEMPLATE,
            "--",
            "sh",
            "-c",
            "hostname > /run/sandy/outputs/h; echo out-bytes > /run/sandy/outputs/o",
        ],
    )?;
    ensure!(code == 0, "sandy run exited {code}: {envelope}");
    ensure!(str_at(&envelope, &["result", "status"]) == "succeeded", "{envelope}");
    ensure!(envelope["exit_code"] == 0, "{envelope}");
    let hostname = std::fs::read_to_string(out.join("h")).context("the hostname output was not collected")?;
    ensure!(
        hostname.trim() == "sandy",
        "the job did not run in the guest: hostname {hostname:?}"
    );
    ensure!(
        std::fs::read_to_string(out.join("o")).context("the declared output was not collected")? == "out-bytes\n",
        "the output bytes differ"
    );
    let names: BTreeSet<&str> = envelope["result"]["outputs"]
        .as_array()
        .map(|a| a.iter().filter_map(|o| o["path"].as_str()).collect())
        .unwrap_or_default();
    ensure!(names == BTreeSet::from(["h", "o"]), "the envelope lists {names:?}");
    Ok(())
}

/// K2: a nonzero guest exit is a task fault: `failed`, the guest's code, not retryable, and the CLI exits 1 (an
/// infrastructure fault would be 3 and retryable).
#[test]
fn a_nonzero_guest_exit_is_a_task_fault_not_an_infrastructure_one() -> anyhow::Result<()> {
    let stack = Stack::start()?;

    let (code, envelope) = stack.sandy("k2-exit7", &["run", TEMPLATE, "--", "sh", "-c", "exit 7"])?;

    ensure!(code == 1, "a task fault exits 1, got {code}: {envelope}");
    ensure!(str_at(&envelope, &["result", "status"]) == "failed", "{envelope}");
    ensure!(envelope["result"]["exit_code"] == 7, "{envelope}");
    ensure!(
        envelope["result"]["retryable"] == false,
        "a task fault is not retryable: {envelope}"
    );
    ensure!(
        envelope["result"]["receipt"]["guest_reported"]["exit_code"] == 7,
        "the guest did not report its own exit: {envelope}"
    );
    Ok(())
}

/// K3: `ls`, `status`, `wait`, `kill` and `gc` operate over a real running job and reconcile it. After `kill` the
/// guest's qemu is gone, and `gc` removes the terminal record.
#[test]
fn the_lifecycle_verbs_operate_on_a_real_running_job() -> anyhow::Result<()> {
    let stack = Stack::start()?;
    let (code, submitted) = stack.sandy(
        "k3-submit",
        &[
            "daemon",
            "submit",
            TEMPLATE,
            "--isolation-class",
            "untrusted",
            "--",
            "sleep",
            "600",
        ],
    )?;
    ensure!(code == 0, "submit exited {code}: {submitted}");
    let id = str_at(&submitted, &["job_id"]).to_owned();
    ensure!(!id.is_empty(), "no job id: {submitted}");

    // The job reads Running before the guest boots: wait for the guest's own qemu, which proves a real boot.
    let deadline = Instant::now() + Duration::from_secs(CALL_SECS);
    let guest = loop {
        if let Some(guest) = stack.guest_qemus().into_iter().next() {
            break guest;
        }
        ensure!(Instant::now() < deadline, "no guest qemu appeared under the executor");
        std::thread::sleep(Duration::from_millis(500));
    };

    let (_, listed) = stack.sandy("k3-ls", &["ls"])?;
    ensure!(
        listed
            .as_array()
            .is_some_and(|l| l.iter().any(|j| str_at(j, &["job_id"]) == id)),
        "ls does not list the job: {listed}"
    );
    let (_, status) = stack.sandy("k3-status", &["status", &id])?;
    ensure!(str_at(&status, &["status"]) == "JOB_STATUS_RUNNING", "{status}");
    let (code, _) = stack.sandy("k3-wait", &["wait", "--wait-timeout", "5", &id])?;
    ensure!(code == 3, "a wait that times out exits 3, got {code}");

    let (code, killed) = stack.sandy("k3-kill", &["kill", &id])?;
    ensure!(code == 0 && killed["cancelled"] == true, "kill: {code} {killed}");
    let (_, ended) = stack.sandy("k3-wait-after", &["wait", "--wait-timeout", "120", &id])?;
    ensure!(str_at(&ended, &["status"]) == "JOB_STATUS_CANCELLED", "{ended}");

    let gone = Instant::now() + Duration::from_secs(60);
    while parent_and_start(guest.0).is_some_and(|(_, t)| t == guest.1) {
        ensure!(Instant::now() < gone, "the guest's qemu {} outlived kill", guest.0);
        std::thread::sleep(Duration::from_millis(250));
    }

    let (code, collected) = stack.sandy("k3-gc", &["gc", "--keep-last", "0"])?;
    ensure!(code == 0, "gc: {collected}");
    ensure!(
        collected["evicted"]
            .as_array()
            .is_some_and(|e| e.iter().any(|j| j == id.as_str())),
        "gc did not evict the job: {collected}"
    );
    let (_, after) = stack.sandy("k3-ls-after", &["ls"])?;
    ensure!(after.as_array().is_some_and(Vec::is_empty), "ls after gc: {after}");
    Ok(())
}
