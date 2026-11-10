//! Live broker gate (#585 step 5, tier-3): the conformance script of `conformance/script.json` runs over stdio
//! against the real stack: `sandyd` (`SANDY_ENV_BACKEND=vm-qemu`), `sandy-broker` on loopback with a bearer
//! token, and the real `sandy-mcp` binary. The target overrides `fixtures` only and reads no broker state.
//!
//! Written for: AT-1 (idempotent spawn, one VM), AT-2 (Provisioning with no connection, then Ready), AT-4 and
//! AT-6 (cancel during Provisioning, idempotent delete), AT-9 (request id conflict), AT-10 (secret-shaped
//! arguments refused), and the API-credential half of AT-11. Every test here is `#[ignore]`d with its reason:
//! the main scenario is red on the base guest, the others are blocked rows.
//!
//! The guest is the generic base guest (`topologies.x86_64-linux.qemu`) running `socat` as `nobody`: sandy core
//! names no service. Tier-3, behind the `live` feature like the other live suites (INV-S9). Linux with KVM and
//! `/dev/vhost-vsock` only. Build the sibling binaries first, so no cargo build runs mid-test:
//!
//!   cargo build -p sandyd -p sandy-broker -p sandy-mcp
//!   SANDY_LIVE=1 nix shell nixpkgs#qemu -c cargo nextest run -p sandy-mcp --features live --test live_broker
//! --no-capture
//!
//! `SANDYD_BIN` and `BROKER_BIN` override the sibling binaries. Every wait is bounded, and the stack guard
//! stops what the test started: only a qemu that is a direct child of this test's own `sandyd` is ever killed.
#![cfg(feature = "live")]
#![cfg(target_os = "linux")]

mod common;

use std::{
    collections::BTreeSet,
    io::Read,
    net::TcpListener,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail, ensure};
use common::mcp_client::{BIN, Mcp, SCRIPT, credential_file, run_script};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// A cold boot plus the service probe; the daemon's provision timeout and the script's Ready timeout.
const PROVISION_SECS: u64 = 240;
/// The generic service: a TCP listener from the base guest's own `socat`, as a non-root account the guest has.
const SERVICE_COMMAND: &str = "socat TCP-LISTEN:{port},bind=127.0.0.1,fork,reuseaddr PIPE";
const SERVICE_PORT: &str = "9000";
const SERVICE_USER: &str = "nobody";

fn require_live() -> Result<()> {
    ensure!(
        std::env::var("SANDY_LIVE").ok().as_deref() == Some("1"),
        "refusing: this is a live gate, set SANDY_LIVE=1 on a Linux/KVM host (INV-S9)"
    );
    ensure!(
        std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
            .any(|d| d.join("qemu-system-x86_64").is_file()),
        "refusing: qemu-system-x86_64 is not on PATH, run under `nix shell nixpkgs#qemu`"
    );
    Ok(())
}

fn guest_flake() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../nix/guest")
}

/// A sibling binary of `sandy-mcp` in the cargo target directory, or the override in `var`.
fn sibling(name: &str, var: &str) -> Result<PathBuf> {
    let path = match std::env::var_os(var) {
        Some(p) => PathBuf::from(p),
        None => Path::new(BIN).with_file_name(name),
    };
    ensure!(
        path.is_file(),
        "{} is missing: run `cargo build -p sandyd -p sandy-broker -p sandy-mcp` or set {var}",
        path.display()
    );
    Ok(path)
}

/// Runs `cmd` to completion within `secs`; kills it and fails past that.
fn run_bounded(cmd: &mut Command, secs: u64, what: &str) -> Result<()> {
    let mut child = cmd.spawn().with_context(|| format!("spawn {what}"))?;
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        if let Some(status) = child.try_wait().context("wait")? {
            ensure!(status.success(), "{what} failed: {status}");
            return Ok(());
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            bail!("{what} took more than {secs} s");
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn signal(name: &str, pid: u32) {
    let _ = Command::new("kill")
        .arg(format!("-{name}"))
        .arg(pid.to_string())
        .status();
}

/// `(parent pid, start time)` of a process, from `/proc/<pid>/stat`.
fn parent_and_start(pid: u32) -> Option<(u32, u64)> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // The command name may hold spaces and parentheses; the fields after it start past the last `)`.
    let rest: Vec<&str> = stat.get(stat.rfind(')')? + 1..)?.split_whitespace().collect();
    Some((rest.get(1)?.parse().ok()?, rest.get(19)?.parse().ok()?))
}

/// Process ids of every running qemu, from `/proc`.
fn qemu_pids() -> BTreeSet<u32> {
    let Ok(proc) = std::fs::read_dir("/proc") else {
        return BTreeSet::new();
    };
    proc.flatten()
        .filter_map(|e| {
            let pid = e.file_name().to_str()?.parse::<u32>().ok()?;
            let comm = std::fs::read_to_string(e.path().join("comm")).ok()?;
            // The nix-wrapped binary reports `.qemu-system-x8`.
            comm.trim().trim_start_matches('.').starts_with("qemu").then_some(pid)
        })
        .collect()
}

/// `(pid, start time)` of every qemu that is a direct child of `parent`. The host is shared: another session's
/// VM is never counted or killed.
fn qemu_children(parent: u32) -> Vec<(u32, u64)> {
    qemu_pids()
        .into_iter()
        .filter_map(|pid| {
            parent_and_start(pid)
                .filter(|(ppid, _)| *ppid == parent)
                .map(|(_, t)| (pid, t))
        })
        .collect()
}

/// Every `/tmp/sandy-*` entry and its direct children.
fn sandy_tmp_entries() -> BTreeSet<PathBuf> {
    let mut found = BTreeSet::new();
    let Ok(tmp) = std::fs::read_dir("/tmp") else {
        return found;
    };
    for entry in tmp.flatten() {
        if entry.file_name().to_string_lossy().starts_with("sandy-") {
            found.insert(entry.path());
            if let Ok(children) = std::fs::read_dir(entry.path()) {
                found.extend(children.flatten().map(|c| c.path()));
            }
        }
    }
    found
}

fn private_file(path: &Path, text: &str) -> Result<()> {
    std::fs::write(path, text).with_context(|| format!("write {}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

fn free_port() -> Result<u16> {
    Ok(TcpListener::bind("127.0.0.1:0")
        .context("bind a free port")?
        .local_addr()?
        .port())
}

/// A bearer token that doubles as the AT-11 canary: unique per run, and grep-able.
fn canary_token() -> Result<String> {
    let mut bytes = [0u8; 16];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(format!(
        "canary-{}",
        bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
    ))
}

/// The running stack. Dropping it stops the broker, then `sandyd` with SIGTERM (SIGKILL after 15 s), then any
/// qemu that was a direct child of that `sandyd` (a killed daemon leaves its VM running, decision 34).
struct Stack {
    dir: tempfile::TempDir,
    sandyd: Child,
    broker: Option<Child>,
    api_url: String,
    token: String,
    credential: PathBuf,
}

impl Drop for Stack {
    fn drop(&mut self) {
        if let Some(broker) = self.broker.as_mut() {
            let _ = broker.kill();
            let _ = broker.wait();
        }
        let owned = qemu_children(self.sandyd.id());
        signal("TERM", self.sandyd.id());
        let deadline = Instant::now() + Duration::from_secs(15);
        while !matches!(self.sandyd.try_wait(), Ok(Some(_))) {
            if Instant::now() > deadline {
                let _ = self.sandyd.kill();
                let _ = self.sandyd.wait();
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        for (pid, start) in owned {
            if parent_and_start(pid).is_some_and(|(_, t)| t == start) {
                signal("KILL", pid);
            }
        }
    }
}

impl Stack {
    fn start() -> Result<Self> {
        let flake = guest_flake();
        run_bounded(
            Command::new("nix")
                .args(["build", "--no-link"])
                .arg(format!("{}#packages.x86_64-linux.guest-runner", flake.display())),
            3600,
            "nix build of the base guest runner",
        )?;
        let dir = tempfile::tempdir().context("temp dir")?;
        let token = canary_token()?;
        let credential = credential_file(dir.path(), &token)?;
        let sock = dir.path().join("sandyd.sock");

        let profiles = dir.path().join("profiles.json");
        let entry =
            |name: &str| json!({"name": name, "credential": "live", "targets": ["o/r"], "capabilities": ["read_code"]});
        private_file(
            &profiles,
            &json!({"profiles": [entry("harness"), entry("other")]}).to_string(),
        )?;
        let clients = dir.path().join("clients.json");
        private_file(
            &clients,
            &json!([{
                "id": "live",
                "token_sha256": Sha256::digest(token.as_bytes()).iter().map(|b| format!("{b:02x}")).collect::<String>(),
                "max_isolation_class": "untrusted",
                "max_environments": 4,
                "profiles": ["harness", "other"],
            }])
            .to_string(),
        )?;

        let sandyd = Command::new(sibling("sandyd", "SANDYD_BIN")?)
            .env("SANDY_SOCK", &sock)
            .env("SANDY_DB", dir.path().join("sandyd.db"))
            .env("SANDY_PROFILES", &profiles)
            .env("RUST_LOG", "debug")
            .env("SANDY_ENV_BACKEND", "vm-qemu")
            .env(
                "SANDY_ENV_VM_TEMPLATE",
                format!("{}#topologies.x86_64-linux.qemu", flake.display()),
            )
            .env("SANDY_ENV_VM_COMMAND", SERVICE_COMMAND)
            .env("SANDY_ENV_VM_SERVICE_PORT", SERVICE_PORT)
            .env("SANDY_ENV_VM_SERVICE_USER", SERVICE_USER)
            // The provision timeout may not be below the boot budget (default 600 s).
            .env("SANDY_ENV_VM_BOOT_TIMEOUT_SECS", "100")
            .env("SANDY_ENV_PROVISION_TIMEOUT_SECS", PROVISION_SECS.to_string())
            .stdout(Stdio::from(std::fs::File::create(dir.path().join("sandyd.out"))?))
            .stderr(Stdio::from(std::fs::File::create(dir.path().join("sandyd.log"))?))
            .spawn()
            .context("spawn sandyd")?;
        // From here the guard owns the daemon, so a failed start still stops it.
        let mut stack = Self {
            dir,
            sandyd,
            broker: None,
            api_url: String::new(),
            token,
            credential,
        };
        // sandyd evaluates the guest template and sweeps orphans before it serves.
        let deadline = Instant::now() + Duration::from_secs(120);
        while std::os::unix::net::UnixStream::connect(&sock).is_err() {
            if Instant::now() > deadline || stack.sandyd.try_wait()?.is_some() {
                stack.dump_logs();
                bail!("sandyd never accepted on {}", sock.display());
            }
            std::thread::sleep(Duration::from_millis(50));
        }

        let port = free_port()?;
        let state_dir = stack.dir.path().join("broker");
        std::fs::create_dir(&state_dir)?;
        std::fs::set_permissions(&state_dir, std::fs::Permissions::from_mode(0o700))?;
        let broker = Command::new(sibling("sandy-broker", "BROKER_BIN")?)
            .arg("--control-socket")
            .arg(&sock)
            .arg("--state-dir")
            .arg(&state_dir)
            .arg("--clients-file")
            .arg(&clients)
            .arg("--bind")
            .arg(format!("127.0.0.1:{port}"))
            .stdout(Stdio::null())
            .stderr(Stdio::from(std::fs::File::create(stack.dir.path().join("broker.log"))?))
            .spawn()
            .context("spawn sandy-broker")?;
        let broker = stack.broker.insert(broker);
        stack.api_url = format!("http://127.0.0.1:{port}");
        let deadline = Instant::now() + Duration::from_secs(15);
        while std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
            ensure!(Instant::now() < deadline, "sandy-broker never listened on {port}");
            ensure!(broker.try_wait()?.is_none(), "sandy-broker exited at start");
            std::thread::sleep(Duration::from_millis(50));
        }
        Ok(stack)
    }

    fn mcp(&self) -> Result<Mcp> {
        let mut mcp = Mcp::spawn(&self.api_url, &self.credential)?;
        mcp.initialize()?;
        Ok(mcp)
    }

    /// Prints the tail of the daemon and broker logs, for a failed run.
    fn dump_logs(&self) {
        for name in ["sandyd.log", "sandyd.out", "broker.log"] {
            let text = std::fs::read_to_string(self.dir.path().join(name)).unwrap_or_default();
            // The client polls once per 100 ms; each poll logs a connection.
            let tail: Vec<&str> = text
                .lines()
                .filter(|l| !l.contains("control connection opened"))
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .take(150)
                .collect();
            eprintln!(
                "--- {name} (last {} lines)\n{}",
                tail.len(),
                tail.into_iter().rev().collect::<Vec<_>>().join("\n")
            );
        }
    }

    /// Command lines of this stack's qemu children, for a failed run.
    fn dump_vms(&self) {
        for (pid, _) in self.vms() {
            let args = std::fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
            eprintln!("--- qemu {pid}: {}", String::from_utf8_lossy(&args).replace('\0', " "));
        }
    }

    /// qemu processes that are direct children of this stack's `sandyd`.
    fn vms(&self) -> Vec<(u32, u64)> {
        qemu_children(self.sandyd.id())
    }

    /// Fails unless no VM of this stack runs within `secs`.
    fn wait_no_vm(&self, secs: u64) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(secs);
        while !self.vms().is_empty() {
            ensure!(
                Instant::now() < deadline,
                "VM {:?} still runs {secs} s later",
                self.vms()
            );
            std::thread::sleep(Duration::from_millis(250));
        }
        Ok(())
    }
}

fn get_environment(mcp: &mut Mcp, id: &str) -> Result<Value> {
    let (is_err, got) = mcp.call("get_environment", &json!({"environment_id": id}))?;
    ensure!(!is_err, "get_environment failed: {got}");
    Ok(got)
}

/// Polls until `state` is `want`; fails fast on `failed`. Returns the elapsed time.
fn wait_state(mcp: &mut Mcp, id: &str, want: &str, secs: u64) -> Result<(Value, Duration)> {
    let start = Instant::now();
    loop {
        let got = get_environment(mcp, id)?;
        match got["state"].as_str() {
            Some(s) if s == want => return Ok((got, start.elapsed())),
            Some("failed") => bail!("environment {id} failed while waiting for {want}: {got}"),
            _ => {}
        }
        ensure!(
            start.elapsed() < Duration::from_secs(secs),
            "environment {id} never reached {want}: {got}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn spawn_args(request_id: &str, task: &str) -> Value {
    json!({"request_id": request_id, "profile": "harness",
           "lifetime": {"kind": "ephemeral", "ttl_secs": 3600}, "task_ref": task})
}

/// Every file under `root` (bounded size) that holds `needle`, except `skip`.
fn files_holding(root: &Path, needle: &str, skip: &Path) -> Vec<PathBuf> {
    let mut hits = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(p) = stack.pop() {
        let Ok(meta) = std::fs::symlink_metadata(&p) else {
            continue;
        };
        if meta.is_dir() {
            stack.extend(std::fs::read_dir(&p).into_iter().flatten().flatten().map(|e| e.path()));
        } else if meta.is_file()
            && meta.len() < 64 * 1024 * 1024
            && p != skip
            && std::fs::read(&p).is_ok_and(|b| b.windows(needle.len()).any(|w| w == needle.as_bytes()))
        {
            hits.push(p);
        }
    }
    hits
}

/// The canary never reaches the host process table: `ps` shows every argv on the box.
fn ps_holds(needle: &str) -> Result<bool> {
    let out = Command::new("ps")
        .args(["-eww", "-o", "args="])
        .output()
        .context("ps")?;
    Ok(String::from_utf8_lossy(&out.stdout).contains(needle))
}

// Red on ws01 (2026-11-10): the vm-qemu environment on the base guest boots and the agent link comes up, then
// the service probe (TCP 9000, `socat` as `nobody`) never passes and the driver fails the environment at its
// provision timeout (step `provision`, "link I/O: Connection reset by peer"). `live_agent` boots the same guest
// fine, so the fault is in the service path: the base guest has no service account and the example guest
// (`qemu-t3`) is the only guest KENV20 ever ran on. Run with `--run-ignored all` once a generic service guest exists.
#[test]
#[ignore = "red: a vm-qemu service on the base guest never reaches Ready (probe times out); needs a generic service \
            guest"]
fn the_conformance_script_passes_against_the_real_stack_and_leaves_nothing() -> Result<()> {
    require_live()?;
    let tmp_before = sandy_tmp_entries();
    let stack = Stack::start()?;
    // A failure prints the daemon and broker logs first: the temp dir goes with the guard.
    scenario(&stack, &tmp_before).inspect_err(|_| {
        stack.dump_logs();
        stack.dump_vms();
    })?;
    drop(stack);
    // A new staging base is the only thing a first run may add: no run directory under it, no stray entry.
    let strays: Vec<_> = sandy_tmp_entries()
        .difference(&tmp_before)
        .filter(|p| p.parent() != Some(Path::new("/tmp")) || std::fs::read_dir(p).is_ok_and(|mut d| d.next().is_some()))
        .cloned()
        .collect();
    ensure!(strays.is_empty(), "left behind in /tmp: {strays:?}");
    Ok(())
}

fn scenario(stack: &Stack, tmp_before: &BTreeSet<PathBuf>) -> Result<()> {
    // AT-1, AT-2 and the boot-to-Ready time, over a bare spawn, so a broken backend fails on the first boot.
    let mut mcp = stack.mcp()?;
    let spawn = spawn_args("live-first", "bare");
    let (is_err, first) = mcp.call("spawn_environment", &spawn)?;
    ensure!(!is_err, "spawn failed: {first}");
    let spawned_at = Instant::now();
    let id = first["environment_id"].as_str().context("environment_id")?.to_owned();
    let (_, again) = mcp.call("spawn_environment", &spawn)?;
    assert_eq!(
        again["environment_id"],
        json!(id),
        "AT-1: a retry returns the same environment"
    );
    let early = get_environment(&mut mcp, &id)?;
    assert_eq!(
        early["state"],
        json!("provisioning"),
        "AT-2: not Ready straight after spawn: {early}"
    );
    assert!(
        early.get("connection").is_none(),
        "AT-2: no connection before Ready: {early}"
    );
    let (ready, _) = wait_state(&mut mcp, &id, "ready", PROVISION_SECS + 60)?;
    let boot = spawned_at.elapsed();
    eprintln!("KPI boot-to-Ready (spawn call to Ready, base guest, MCP polling every 100 ms): {boot:?}");
    assert!(
        ready["connection"]["url"].is_string(),
        "AT-2: Ready carries the connection: {ready}"
    );
    assert_eq!(
        stack.vms().len(),
        1,
        "AT-1: two spawns of one request id run exactly one VM"
    );

    // AT-11, API-credential half: the bearer token (a unique canary) is in the credential file and nowhere else
    // the host or the MCP shows: not `ps`, not a log, not the journal, not any file the stack made.
    assert!(!ps_holds(&stack.token)?, "AT-11: the canary is in `ps` output");
    let leaked = files_holding(stack.dir.path(), &stack.token, &stack.credential);
    assert!(leaked.is_empty(), "AT-11: the canary is in {leaked:?}");
    let new_tmp: Vec<_> = sandy_tmp_entries().difference(tmp_before).cloned().collect();
    for p in &new_tmp {
        let leaked = files_holding(p, &stack.token, &stack.credential);
        assert!(leaked.is_empty(), "AT-11: the canary is in {leaked:?}");
    }

    // AT-10: a secret-shaped argument is refused by the real binary and creates nothing.
    let mut bad = spawn_args("live-secret", "secret");
    bad["token"] = json!("x");
    let (refused, why) = mcp.call("spawn_environment", &bad)?;
    assert!(refused, "AT-10: a `token` field must be refused: {why}");
    let (_, listed) = mcp.call("list_environments", &json!({}))?;
    let count = listed["environments"].as_array().map(Vec::len);
    assert_eq!(count, Some(1), "AT-10: the refused call made no environment: {listed}");

    let (is_err, deleted) = mcp.call("delete_environment", &json!({"environment_id": id}))?;
    ensure!(!is_err, "delete failed: {deleted}");
    stack.wait_no_vm(120)?;

    // AT-4: cancel while Provisioning ends Deleted and leaves no VM. Cancel only once this stack's qemu exists
    // and the state is still Provisioning, so a fast boot cannot make the assertion vacuous.
    let (_, c) = mcp.call("spawn_environment", &spawn_args("live-cancel", "cancel"))?;
    let cid = c["environment_id"].as_str().context("environment_id")?.to_owned();
    let deadline = Instant::now() + Duration::from_secs(120);
    while stack.vms().is_empty() {
        ensure!(Instant::now() < deadline, "no VM ever started for {cid}");
        std::thread::sleep(Duration::from_millis(20));
    }
    let now = get_environment(&mut mcp, &cid)?;
    assert_eq!(
        now["state"],
        json!("provisioning"),
        "AT-4: cancelled too late to test, state is {now}"
    );
    let (is_err, cancelled) = mcp.call("cancel_environment", &json!({"environment_id": cid}))?;
    ensure!(!is_err, "cancel failed: {cancelled}");
    assert_eq!(cancelled["state"], json!("deleted"), "AT-4: {cancelled}");
    stack.wait_no_vm(120)?;
    // AT-6: delete after cancel is the same terminal result, not an error.
    let (is_err, again) = mcp.call("delete_environment", &json!({"environment_id": cid}))?;
    ensure!(!is_err && again["state"] == json!("deleted"), "AT-6: {again}");
    let _ = mcp.finish()?;

    // The shared script (AT-6, AT-9 and the rest) over a fresh MCP, with the Ready wait sized for a boot.
    let mut script: Value = serde_json::from_str(SCRIPT)?;
    script["fixtures"]["ready_timeout_ms"] = json!((PROVISION_SECS + 60) * 1000);
    script["fixtures"]["ready_poll_ms"] = json!(250);
    let mut mcp = stack.mcp()?;
    run_script(&mut mcp, &script)?;
    let (clean_exit, output) = mcp.finish()?;
    assert!(clean_exit, "sandy-mcp must exit cleanly when stdin closes");
    assert!(
        !output.contains(&stack.token),
        "AT-11: the canary is in the MCP's stdout or stderr"
    );

    // After the run: no non-terminal environment through the API, no VM of ours, nothing new in /tmp/sandy-*.
    stack.wait_no_vm(120)?;
    let mut mcp = stack.mcp()?;
    let (_, listed) = mcp.call("list_environments", &json!({}))?;
    let live: Vec<_> = listed["environments"]
        .as_array()
        .context("environments")?
        .iter()
        .filter(|e| !matches!(e["state"].as_str(), Some("deleted" | "failed")))
        .collect();
    assert!(live.is_empty(), "non-terminal environments after the run: {live:?}");
    let (_, jobs) = mcp.call("list", &json!({}))?;
    let running: Vec<_> = jobs["jobs"]
        .as_array()
        .context("jobs")?
        .iter()
        .filter(|j| {
            !matches!(
                j["state"].as_str(),
                Some("cancelled" | "succeeded" | "failed" | "timed_out")
            )
        })
        .collect();
    assert!(running.is_empty(), "non-terminal jobs after the run: {running:?}");
    let (clean_exit, output) = mcp.finish()?;
    assert!(clean_exit && !output.contains(&stack.token));
    Ok(())
}

#[test]
#[ignore = "blocked on #706: no profile secret reaches the guest yet (#705 stages the values, #706 owns the lease)"]
fn a_profile_secret_canary_is_absent_everywhere_but_the_guest_secret_path() {
    // AT-11, profile-secret half: a unique canary in a profile secret must be absent from every MCP result and
    // stderr, the journal, host `ps` and the console log, and present at the guest secret path only. The API
    // credential half runs in the test above.
}

#[test]
#[ignore = "owner decision on #585: sandy core has no T3 internals, so AT-7 (delegate_task round trip) has no live row \
            here"]
fn a_stand_in_primary_runs_a_delegate_task_in_the_guest() {}

#[test]
#[ignore = "owner decision on #585 and open point 1: no external unlink interface, so AT-8 (parent ends after delete) \
            is blocked"]
fn the_parent_task_ends_failed_within_60_seconds_of_a_delete() {}

#[test]
#[ignore = "owner decision on #585 and open point 1: pairing and link are T3-specific, so AT-17 (pairing code absent) \
            is blocked"]
fn a_pairing_code_is_absent_from_every_result_and_log() {}
