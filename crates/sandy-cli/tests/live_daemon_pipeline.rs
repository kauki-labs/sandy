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
//! Every spawned command has a timeout. On a normal end, a panic or an `Err`, `Drop` stops the processes the test
//! started (matched by pid and start time) and removes its temp dir. `Drop` does not run when a signal ends the test
//! process (a nextest timeout, Ctrl-C, `kill -9`), so each stack also starts a watchdog: a `sh` in its own process
//! group that waits for the test's pid to go, then kills every process whose environment names this stack's temp dir
//! (an exact `TMPDIR=<dir>` or `TMPDIR=<dir>/...` entry, inherited by `sandyd`, the executor and qemu, or an exact
//! `SANDY_LIVE_STACK=<dir>` entry, which every setup helper carries: the guest build, the key generation, the
//! fallback `sandyd` build) and removes the dir. It reads no command line and touches nothing from another session;
//! a decoy test and a guard test pin that.
//!
//! Not covered here: that virtiofsd inherits `TMPDIR` is unchecked (the signal proof showed no survivor, but did not
//! name the virtiofsd processes), and the egress proxy clears its environment. A later `--allow` slice that boots a
//! proxy must re-check that the watchdog still reaches it.
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
/// The fallback `cargo build -p sandyd` when `SANDYD_BIN` is unset: long enough for a cold build, short enough that
/// a wait on a cargo lock cannot hang the start.
const SANDYD_BUILD_SECS: u64 = 900;
/// Every helper the stack runs gets this variable with the stack's dir, so the watchdog reaches a helper whose own
/// environment has no `TMPDIR` under the dir (the guest build, the key generation, the `sandyd` build).
const STACK_MARKER: &str = "SANDY_LIVE_STACK";
/// The guest's qemu appears within a minute of the job reading Running (about 20 s on ws01).
const GUEST_SECS: u64 = 120;

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
    use std::os::unix::process::CommandExt as _;
    let (out, err) = (dir.join(format!("{label}.out")), dir.join(format!("{label}.err")));
    // Its own process group, so a timeout kills the helper and what it started (cargo's rustc), and the marker
    // lets the watchdog reach it if the test dies first.
    let mut child = cmd
        .env(STACK_MARKER, dir)
        .process_group(0)
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
            let _ = Command::new("kill")
                .args(["-KILL", "--"])
                .arg(format!("-{}", child.id()))
                .status();
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

fn sandyd_bin(base: &Path) -> anyhow::Result<PathBuf> {
    if let Some(path) = std::env::var_os("SANDYD_BIN") {
        return Ok(PathBuf::from(path));
    }
    let sandy = PathBuf::from(env!("CARGO_BIN_EXE_sandy"));
    let mut build = Command::new(env!("CARGO"));
    build
        .args(["build", "-p", "sandyd", "--bin", "sandyd"])
        .arg("--manifest-path")
        .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/../../Cargo.toml"));
    let (code, _, err) = run_timeout(build, base, "sandyd-build", SANDYD_BUILD_SECS)?;
    ensure!(code == 0, "cargo build -p sandyd failed: {err}");
    Ok(sandy.parent().context("sandy's binary has no parent")?.join("sandyd"))
}

/// Two distinct free loopback ports. Both listeners are held until both ports are known, so the kernel cannot hand
/// out one port twice; they drop before the ports are used, so a collision with another process fails the start.
fn two_free_ports() -> anyhow::Result<(u16, u16)> {
    let (a, b) = (TcpListener::bind("127.0.0.1:0")?, TcpListener::bind("127.0.0.1:0")?);
    Ok((a.local_addr()?.port(), b.local_addr()?.port()))
}

/// Waits for the owner process to go (pid and start time, so a reused pid does not keep it), then kills every process
/// whose environment has an entry that is exactly `TMPDIR=<base>`, `SANDY_LIVE_STACK=<base>`, or one of those two
/// followed by `/...`, and removes `base`. Runs as `sh` in its own process group: a group signal to the test (a nextest
/// timeout) does not reach it.
///
/// Guards, all checked before any kill and again before the removal: five non-empty arguments (`set -u`), `base` is
/// `/tmp/s` plus six alphanumerics (the shape of the test's own temp dir), and it is still the directory the test
/// created (a real directory, not a link, with the inode and birth time the test passed). The environment match is per
/// NUL-delimited entry (`grep -z -x`), never a substring, so `XTMPDIR=<base>/x` and `TMPDIR=<base>x/...` do not match.
/// A pid's start ticks are read before the match and checked again right before the signal, so a pid reused in
/// between is not signalled. It reads no command line and matches no name.
const WATCHDOG: &str = r#"
set -u
[ $# -eq 5 ] || exit 1
pid=$1; start=$2; base=$3; ino=$4; birth=$5
for v in "$pid" "$start" "$base" "$ino" "$birth"; do [ -n "$v" ] || exit 1; done
case "$base" in /tmp/s[A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9]) ;; *) exit 1 ;; esac
ticks() { sed 's/.*) //' "/proc/$1/stat" 2>/dev/null | cut -d' ' -f20; }
same_dir() { [ -d "$base" ] && [ ! -L "$base" ] && [ "$(stat -c %i:%W "$base")" = "$ino:$birth" ]; }
same_dir || exit 1
alive() { [ -r "/proc/$pid/stat" ] && [ "$(ticks "$pid")" = "$start" ]; }
while alive; do sleep 1; done
for round in 1 2 3; do
  same_dir || exit 1
  for p in /proc/[0-9]*; do
    n=${p#/proc/}
    [ "$n" = "$$" ] && continue
    t0=$(ticks "$n")
    [ -n "$t0" ] || continue
    if grep -qzxE "(TMPDIR|SANDY_LIVE_STACK)=$base(/.*)?" "$p/environ" 2>/dev/null; then
      [ "$(ticks "$n")" = "$t0" ] && kill -KILL "$n" 2>/dev/null
    fi
  done
  sleep 1
done
same_dir && rm -rf "$base"
"#;

/// Run the [`WATCHDOG`] with exactly these arguments. Its stdio is null and its environment holds no marker for `base`.
/// The tests pass wrong arguments to pin the guards; `start_watchdog` passes the right ones.
fn spawn_watchdog(owner: u32, owner_start: u64, base: &str, ino: u64, birth: u64) -> anyhow::Result<Child> {
    use std::os::unix::process::CommandExt as _;
    Command::new("sh")
        .args(["-c", WATCHDOG, "watchdog"])
        .args([owner.to_string(), owner_start.to_string()])
        .args([base.to_owned(), ino.to_string(), birth.to_string()])
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("spawn the watchdog")
}

/// The inode and birth time (whole seconds, 0 when the filesystem has none) of `path`, as the watchdog's `stat -c
/// %i:%W` reads them.
fn dir_identity(path: &Path) -> anyhow::Result<(u64, u64)> {
    use std::os::unix::fs::MetadataExt as _;
    let meta = std::fs::metadata(path).context("stat the temp dir")?;
    let birth = meta
        .created()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_secs());
    Ok((meta.ino(), birth))
}

/// Start the [`WATCHDOG`] for `base`, to reap once `owner` (a pid of this host) is gone.
fn start_watchdog(owner: u32, base: &Path) -> anyhow::Result<Child> {
    let (_, start) = parent_and_start(owner).context("read the owner's start time")?;
    let (ino, birth) = dir_identity(base)?;
    spawn_watchdog(owner, start, &base.to_string_lossy(), ino, birth)
}

fn private_dir(path: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

/// `sandyd` and `sandy-host-executor`, registered with each other, and the env a `sandy` call needs.
struct Stack {
    sock: PathBuf,
    client_tmp: PathBuf,
    executor_pid: u32,
    // Fields drop in order: the processes stop before the directory they use is removed.
    _executor: Proc,
    _daemon: Proc,
    dir: tempfile::TempDir,
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
        start_watchdog(std::process::id(), base)?;
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
        let (mesh, link) = two_free_ports()?;
        let daemon = Proc(
            Command::new(sandyd_bin(base)?)
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
    let deadline = Instant::now() + Duration::from_secs(GUEST_SECS);
    let guest = loop {
        if let Some(guest) = stack.guest_qemus().into_iter().next() {
            break guest;
        }
        ensure!(
            Instant::now() < deadline,
            "no guest qemu (a `qemu-system` child with `-drive`) appeared under the executor within {GUEST_SECS}s; \
             its children are: {:?}",
            children_of(stack.executor_pid)
                .into_iter()
                .map(|(pid, _, cmd)| format!("{pid}: {}", cmd.chars().take(80).collect::<String>()))
                .collect::<Vec<_>>()
        );
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

/// Cleanup that runs when it drops, so it is in place before the next step that can fail: it kills and reaps the
/// children the test holds a handle for, and removes the directories it was given. Register a child or a dir the
/// moment it exists.
#[derive(Default)]
struct Cleanup {
    children: Vec<Child>,
    dirs: Vec<PathBuf>,
}

impl Cleanup {
    /// A `sleep 600` whose environment holds `key=value`; the index of its handle in `children`.
    fn sleeper(&mut self, key: &str, value: &str) -> anyhow::Result<usize> {
        let child = Command::new("sleep")
            .arg("600")
            .env(key, value)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("spawn a sleeper")?;
        self.children.push(child);
        Ok(self.children.len() - 1)
    }

    fn is_alive(&mut self, index: usize) -> anyhow::Result<bool> {
        Ok(self.children[index].try_wait()?.is_none())
    }
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        for child in &mut self.children {
            let _ = child.kill();
            let _ = child.wait();
        }
        for dir in &self.dirs {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

/// Wait for `child` to end, or kill it after `secs`.
fn wait_exit(child: &mut Child, secs: u64, label: &str) -> anyhow::Result<std::process::ExitStatus> {
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            bail!("{label} did not finish within {secs}s");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// The watchdog kills a process whose environment names its dir exactly, and nothing else. Two positive controls must
/// die: `TMPDIR=<dir>/dt` and the setup helpers' `SANDY_LIVE_STACK=<dir>`. Four decoys must live: a dir whose name only
/// starts like this one (`TMPDIR=<dir>x/dt`), an entry that only ends like it (`XTMPDIR=<dir>/dt`,
/// `XSANDY_LIVE_STACK=<dir>`) and an unrelated `TMPDIR`. The owner is a short-lived child, so no VM is needed (and
/// `require_live` is not called, on purpose). Every child and dir is registered with [`Cleanup`] as soon as it exists,
/// so a failed step cannot leak the ones before it.
#[test]
fn the_watchdog_kills_only_processes_that_name_its_own_dir() -> anyhow::Result<()> {
    let mut cleanup = Cleanup::default();
    let dir = tempfile::Builder::new()
        .prefix("s")
        .tempdir_in("/tmp")
        .context("temp dir under /tmp")?;
    let base = dir.path().to_string_lossy().into_owned();
    let longer = PathBuf::from(format!("{base}x"));
    std::fs::create_dir(&longer).context("a dir whose name starts like the stack's")?;
    cleanup.dirs.push(longer.clone());

    let dies = [
        cleanup.sleeper("TMPDIR", &format!("{base}/dt"))?,
        cleanup.sleeper(STACK_MARKER, &base)?,
    ];
    let lives = [
        cleanup.sleeper("TMPDIR", &format!("{base}x/dt"))?,
        cleanup.sleeper("XTMPDIR", &format!("{base}/dt"))?,
        cleanup.sleeper(&format!("X{STACK_MARKER}"), &base)?,
        cleanup.sleeper("TMPDIR", "/tmp/unrelated-858")?,
    ];
    let owner = {
        let child = Command::new("sleep").arg("1").spawn().context("spawn the owner")?;
        cleanup.children.push(child);
        cleanup.children.len() - 1
    };
    let mut watchdog = start_watchdog(cleanup.children[owner].id(), dir.path())?;
    cleanup.children[owner].wait().context("the owner ends")?;

    let status = wait_exit(&mut watchdog, 30, "the watchdog")?;
    ensure!(status.success(), "the watchdog exited {status}");
    for i in dies {
        ensure!(
            !cleanup.is_alive(i)?,
            "a process of the stack's dir survived the watchdog"
        );
    }
    ensure!(!dir.path().exists(), "the watchdog did not remove its dir");
    for (n, i) in lives.into_iter().enumerate() {
        ensure!(cleanup.is_alive(i)?, "decoy {n} was killed");
    }
    ensure!(longer.exists(), "the dir that only starts like the stack's was touched");
    Ok(())
}

/// Each guard of the watchdog pins one wrong argument: it must exit 1 before it kills anything or removes anything.
/// For every case a sleeper whose `TMPDIR` is `<base>/dt` is the would-be victim, and the owner is already gone (its
/// start time never matches), so a loosened guard would reach the kill within a second and fail this test.
///
/// Every path the cases need lives inside one unique, random `anchor` dir, so two runs never collide and nothing is
/// left in `/tmp` if the test is killed: the anchor has its own watchdog (the real one), which removes it and kills
/// the sleepers (their `TMPDIR` names the anchor) once this process is gone. The cases that name `/tmp` itself or a
/// name directly under it are left out on purpose: a loosened guard would then act on a shared path.
///
/// Pinned: a wrong inode, a wrong birth time, a base with a trailing slash, a base nested below a dir of the right
/// shape, an empty base and a missing argument. Not pinned: the `[ ! -L ]` link check (the inode check already
/// refuses a link, because `stat` without `-L` reads the link's own inode), and the length and character class of the
/// name (they would need names directly under `/tmp`).
#[test]
fn the_watchdog_refuses_anything_but_the_dir_the_test_made() -> anyhow::Result<()> {
    let mut cleanup = Cleanup::default();
    let me = std::process::id();
    let anchor = tempfile::Builder::new()
        .prefix("s")
        .tempdir_in("/tmp")
        .context("a unique dir under /tmp")?;
    start_watchdog(me, anchor.path())?;
    let (ino, birth) = dir_identity(anchor.path())?;
    let anchor_path = anchor.path().to_string_lossy().into_owned();
    // A dir of the right name shape below the anchor: a real directory, but a base that is not `/tmp/s` + six.
    let nested = anchor.path().join("s654321");
    std::fs::create_dir(&nested).context("a nested dir")?;
    let (nested_ino, nested_birth) = dir_identity(&nested)?;

    // (case, base as the watchdog is told it, inode, birth time)
    let cases: Vec<(&str, String, u64, u64)> = vec![
        ("a wrong inode", anchor_path.clone(), ino + 1, birth),
        ("a wrong birth time", anchor_path.clone(), ino, birth + 1),
        ("a trailing slash", format!("{anchor_path}/"), ino, birth),
        (
            "a dir nested below one of the right shape",
            nested.to_string_lossy().into_owned(),
            nested_ino,
            nested_birth,
        ),
    ];
    for (case, base, i, b) in cases {
        let victim = cleanup.sleeper("TMPDIR", &format!("{base}/dt"))?;
        let mut watchdog = spawn_watchdog(me, 0, &base, i, b)?;
        let status = wait_exit(&mut watchdog, 30, case)?;
        ensure!(status.code() == Some(1), "{case}: the watchdog exited {status}, not 1");
        ensure!(cleanup.is_alive(victim)?, "{case}: the process was killed");
        ensure!(Path::new(&base).exists(), "{case}: the dir was removed");
    }
    ensure!(anchor.path().exists(), "the anchor dir was removed");

    // An empty base, and a missing argument, exit 1 too (`set -u` and the argument check).
    let mut empty = spawn_watchdog(me, 0, "", ino, birth)?;
    ensure!(
        wait_exit(&mut empty, 30, "an empty base")?.code() == Some(1),
        "an empty base was accepted"
    );
    let mut short = Command::new("sh")
        .args(["-c", WATCHDOG, "watchdog", "1", "0", &anchor_path, &ino.to_string()])
        .stdin(Stdio::null())
        .spawn()
        .context("spawn a watchdog with four arguments")?;
    ensure!(
        wait_exit(&mut short, 30, "four arguments")?.code() == Some(1),
        "four arguments were accepted"
    );
    Ok(())
}
