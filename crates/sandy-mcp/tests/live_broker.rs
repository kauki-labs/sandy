//! Live broker gate (#585 step 5, tier-3): the conformance script of `conformance/script.json` runs over stdio
//! against the real stack: `sandyd` (`SANDY_ENV_BACKEND=vm-qemu`), `sandy-broker` on loopback with a bearer
//! token, and the real `sandy-mcp` binary. The target overrides `fixtures` only and reads no broker state.
//!
//! Written for: AT-1 (idempotent spawn, one VM), AT-2 (Provisioning with no connection, then Ready), AT-4 and
//! AT-6 (cancel during Provisioning, idempotent delete), AT-9 (request id conflict), AT-10 (secret-shaped
//! arguments refused), the API-credential half of AT-11, and the forge credential bracket (#706) through the stub
//! trust root (#733). The main scenario runs; the other tests here are `#[ignore]`d blocked rows, each with its
//! reason.
//!
//! The guest is the generic base guest (`topologies.x86_64-linux.qemu`) running `socat` as `nobody`: sandy core
//! names no service. The service is a plain TCP echo, and the daemon runs with the connect host check (#732), so Ready
//! means the service port accepted a connection. Tier-3, behind the `live` feature like the other live suites (INV-S9).
//! Linux with KVM and `/dev/vhost-vsock` only. Build the sibling binaries first, so no cargo build runs mid-test.
//! `sandyd` needs the `stub-trust-root` feature: every vm environment mints from a registered trust root, and no real
//! one exists on a test host. Without the feature the daemon refuses to start and says so.
//!
//! ```text
//! cargo build -p sandyd -p sandy-broker -p sandy-mcp --features sandyd/stub-trust-root
//! SANDY_LIVE=1 nix shell nixpkgs#qemu nixpkgs#virtiofsd -c \
//!   cargo nextest run -p sandy-mcp --features live --test live_broker --no-capture
//! ```
//!
//! The daemon runs with `SANDYD_STUB_TRUST_ROOT=live` and a call log in the test's own directory. The profiles
//! name that trust root. The stub's token is staged at `<TMPDIR>/sandy/env-cred-<id>/GITHUB_TOKEN`, the host side
//! of the guest's secret share, and must be nowhere else: not in `ps`, an MCP result, a log or any other file. Every
//! `mint` in the call log must have its `revoke`, and no staged directory may remain.
//!
//! `SANDYD_BIN` and `BROKER_BIN` override the sibling binaries. Every wait is bounded, and the stack guard
//! stops what the test started: only descendants of this test's own `sandyd` and the members of its own process group,
//! matched by pid and start time, are ever killed (qemu, virtiofsd, the egress proxy). The daemon runs with `TMPDIR`
//! set to a directory inside the test's own temp dir, so the staging base (`<TMPDIR>/sandy`, with the secret share,
//! console log and sockets) is scanned for the canary and removed with that directory. Nothing outside it is ever
//! deleted; a new `/tmp/sandy*` entry made by another session is only reported.
#![cfg(feature = "live")]
#![cfg(target_os = "linux")]

mod common;

use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
    net::TcpListener,
    os::unix::{fs::PermissionsExt, process::CommandExt as _},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail, ensure};
use common::{
    mcp_client::{BIN, Mcp, SCRIPT, credential_file, run_script},
    procs::{
        descendants_in, files_holding, foreign_new_entries, group_members_in, is_vm_part, parse_pgrp, parse_stat,
        run_dirs_left, sandy_entries, stat_is_live,
    },
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// A cold boot plus the service probe; the daemon's provision timeout and the script's Ready timeout.
const PROVISION_SECS: u64 = 240;
/// The generic service: a TCP echo from the base guest's own `socat`, as a non-root account the guest has. It speaks no
/// HTTP, so the daemon runs with the connect host check (`SANDY_ENV_VM_HOST_CHECK=connect`, #732): Ready means the
/// service port accepted a connection through the bridge.
const SERVICE_COMMAND: &str = "socat TCP-LISTEN:{port},bind=127.0.0.1,fork,reuseaddr PIPE";
/// The stub trust root's name (#733): the profiles' `credential` and `SANDYD_STUB_TRUST_ROOT`.
/// The longest daemon `TMPDIR` the run's sockets still fit under. The longest socket name found in `impls/vm` is
/// virtiofsd's `vfsd-sandy-secrets.sock` (23 bytes), so `/sandy/<36-char run id>/vfsd-sandy-secrets.sock` adds 67, and
/// `sun_path` holds 107 plus the NUL. 38 leaves 2 bytes of margin.
const MAX_TMP_BYTES: usize = 38;
const STUB_ROOT: &str = "live";
const SERVICE_PORT: &str = "9000";
const SERVICE_USER: &str = "nobody";

fn require_live() -> Result<()> {
    ensure!(
        std::env::var("SANDY_LIVE").ok().as_deref() == Some("1"),
        "refusing: this is a live gate, set SANDY_LIVE=1 on a Linux/KVM host (INV-S9)"
    );
    let on_path = |name: &str| {
        std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()).any(|d| d.join(name).is_file())
    };
    ensure!(
        on_path("qemu-system-x86_64") || std::env::var_os("SANDY_QEMU_BIN").is_some(),
        "refusing: qemu-system-x86_64 is not on PATH and SANDY_QEMU_BIN is unset, run under `nix shell nixpkgs#qemu \
         nixpkgs#virtiofsd`"
    );
    // The forge credential is staged on a virtiofs share (#706), so every environment starts a `virtiofsd`.
    ensure!(
        on_path("virtiofsd") || std::env::var_os("SANDY_VIRTIOFSD_BIN").is_some(),
        "refusing: virtiofsd is not on PATH, run under `nix shell nixpkgs#qemu nixpkgs#virtiofsd`"
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

/// True while `pid` is a live process, from `/proc/<pid>/stat`.
fn process_alive(pid: u32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|stat| stat_is_live(&stat))
}

/// `(parent pid, start time)` of a process, from `/proc/<pid>/stat`.
fn parent_and_start(pid: u32) -> Option<(u32, u64)> {
    parse_stat(&std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?)
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

/// `(pid, start time)` of every descendant of `root`, from `/proc`. Take it before `root` is signalled; see
/// [`descendants_in`] for what the walk cannot reach.
fn descendants(root: u32) -> Vec<(u32, u64)> {
    let Ok(proc) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    let table: Vec<(u32, u32, u64)> = proc
        .flatten()
        .filter_map(|e| {
            let pid = e.file_name().to_str()?.parse::<u32>().ok()?;
            let (ppid, start) = parent_and_start(pid)?;
            Some((pid, ppid, start))
        })
        .collect();
    descendants_in(&table, root)
}

/// `(pid, start time)` of every process in the process group `pgid`, from `/proc`, `pgid` itself included. The test
/// starts `sandyd` as the leader of its own group, so this reaches a child that was re-parented or double-forked,
/// which the parent walk in [`descendants`] cannot (#734). A process that calls `setsid` or `setpgid` leaves the
/// group; `vm_parts_using` covers those by their command line.
fn group_members(pgid: u32) -> Vec<(u32, u64)> {
    let Ok(proc) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    let table: Vec<(u32, u32, u64)> = proc
        .flatten()
        .filter_map(|e| {
            let pid = e.file_name().to_str()?.parse::<u32>().ok()?;
            let stat = std::fs::read_to_string(e.path().join("stat")).ok()?;
            let (_, start) = parse_stat(&stat)?;
            Some((pid, parse_pgrp(&stat)?, start))
        })
        .collect();
    group_members_in(&table, pgid)
}

/// The processes of this daemon's tree that are part of a VM: qemu, virtiofsd and the egress proxy. Its descendants
/// and the members of its process group, so a re-parented one still counts.
fn vm_parts(root: u32) -> Vec<(u32, u64)> {
    let mut parts: Vec<(u32, u64)> = descendants(root)
        .into_iter()
        .chain(group_members(root))
        .filter(|(pid, _)| std::fs::read_to_string(format!("/proc/{pid}/comm")).is_ok_and(|comm| is_vm_part(&comm)))
        .collect();
    parts.sort_unstable();
    parts.dedup();
    parts
}

/// `(pid, start time)` of every VM part whose command line names `base`: the test daemon's own `TMPDIR`, unique to
/// this run, so another session's VMs never match. For a daemon that is already dead, whose children the walk from
/// its pid cannot reach.
/// Best effort: a part whose argv does not name the base (the egress proxy, if it is not launched with a path under it)
/// is not found here.
fn vm_parts_using(base: &Path) -> Vec<(u32, u64)> {
    let needle = base.to_string_lossy().into_owned();
    let Ok(proc) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    proc.flatten()
        .filter_map(|e| {
            let pid = e.file_name().to_str()?.parse::<u32>().ok()?;
            let comm = std::fs::read_to_string(e.path().join("comm")).ok()?;
            let cmdline = std::fs::read(e.path().join("cmdline")).ok()?;
            let named = String::from_utf8_lossy(&cmdline).contains(&needle);
            (is_vm_part(&comm) && named).then_some(())?;
            parent_and_start(pid).map(|(_, start)| (pid, start))
        })
        .collect()
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
    /// The stub trust root's call log (#733): one `mint`, `refresh` or `revoke` line per call, never a token.
    stub_log: PathBuf,
    /// Every stub token seen so far, each with the staged file it was read from. Kept after the file is gone, so a
    /// revoked token is still scanned for.
    stub_tokens: Arc<Mutex<BTreeMap<String, PathBuf>>>,
    /// Set by the sampler thread when any `ps` sample held a stub token.
    ps_stub_hit: Arc<AtomicBool>,
    /// The daemon's `TMPDIR`, inside `dir`: its staging base is `<tmp>/sandy`.
    tmp: PathBuf,
    /// The host's sandy-named `/tmp` entries before this run, for the report of foreign new ones.
    host_before: BTreeSet<PathBuf>,
    /// Set once teardown ran, so the guard does not repeat it.
    torn_down: bool,
    /// Set by the sampler thread when any `ps` sample held the canary.
    ps_hit: Arc<AtomicBool>,
    /// `ps` samples that failed or timed out: the canary could not be checked then.
    ps_errors: Arc<AtomicUsize>,
    sampler_stop: Arc<AtomicBool>,
    sampler: Option<std::thread::JoinHandle<()>>,
}

impl Drop for Stack {
    fn drop(&mut self) {
        // A path that skipped `shutdown` (a failed start, a panic) still stops everything. No assert here: it
        // would replace the real error.
        for finding in self.teardown() {
            eprintln!("teardown finding: {finding}");
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
        let host_before = sandy_entries(&std::env::temp_dir());
        // Under `/tmp`, not `$TMPDIR`: a nix shell's `TMPDIR` is long, and a run's socket paths live under this dir.
        let dir = tempfile::Builder::new()
            .prefix("s")
            .tempdir_in("/tmp")
            .context("temp dir under /tmp")?;
        let tmp = dir.path().join("t");
        ensure!(
            tmp.as_os_str().len() <= MAX_TMP_BYTES,
            "the daemon's TMPDIR {} is {} bytes, over {MAX_TMP_BYTES}: a run's socket under it could pass the \
             108-byte `sun_path` limit",
            tmp.display(),
            tmp.as_os_str().len()
        );
        std::fs::create_dir(&tmp)?;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o700))?;
        let token = canary_token()?;
        let credential = credential_file(dir.path(), &token)?;
        let sock = dir.path().join("sandyd.sock");
        let stub_log = dir.path().join("stub-calls.log");

        let profiles = dir.path().join("profiles.json");
        let entry = |name: &str| json!({"name": name, "credential": STUB_ROOT, "targets": ["o/r"], "capabilities": ["read_code"]});
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
            .env("TMPDIR", &tmp)
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
            .env("SANDY_ENV_VM_HOST_CHECK", "connect")
            .env("SANDY_ENV_VM_SERVICE_USER", SERVICE_USER)
            .env("SANDYD_STUB_TRUST_ROOT", STUB_ROOT)
            .env("SANDYD_STUB_CALL_LOG", &stub_log)
            // The provision timeout may not be below the boot budget (default 600 s).
            .env("SANDY_ENV_VM_BOOT_TIMEOUT_SECS", "100")
            .env("SANDY_ENV_PROVISION_TIMEOUT_SECS", PROVISION_SECS.to_string())
            .stdout(Stdio::from(std::fs::File::create(dir.path().join("sandyd.out"))?))
            .stderr(Stdio::from(std::fs::File::create(dir.path().join("sandyd.log"))?))
            // Its own process group: teardown finds a re-parented child of the daemon by the group (#734).
            .process_group(0)
            .spawn()
            .context("spawn sandyd")?;
        // From here the guard owns the daemon, so a failed start still stops it.
        let mut stack = Self {
            dir,
            sandyd,
            broker: None,
            api_url: String::new(),
            tmp,
            host_before,
            torn_down: false,
            ps_hit: Arc::new(AtomicBool::new(false)),
            ps_errors: Arc::new(AtomicUsize::new(0)),
            sampler_stop: Arc::new(AtomicBool::new(false)),
            sampler: None,
            token,
            credential,
            stub_log,
            stub_tokens: Arc::new(Mutex::new(BTreeMap::new())),
            ps_stub_hit: Arc::new(AtomicBool::new(false)),
        };
        // Sample `ps` for the whole run: one snapshot can miss a short-lived argv. The stub's forge tokens (#733) are
        // checked on every tick too: a helper that put one in its argv between two checkpoints is caught here.
        let (hit, stub_hit, errors, stop, canary, tokens, tmp) = (
            Arc::clone(&stack.ps_hit),
            Arc::clone(&stack.ps_stub_hit),
            Arc::clone(&stack.ps_errors),
            Arc::clone(&stack.sampler_stop),
            stack.token.clone(),
            Arc::clone(&stack.stub_tokens),
            stack.tmp.clone(),
        );
        stack.sampler = Some(std::thread::spawn(move || {
            while !stop.load(Ordering::SeqCst) {
                match ps_holds(&canary) {
                    Ok(true) => hit.store(true, Ordering::SeqCst),
                    Ok(false) => {}
                    Err(_) => {
                        errors.fetch_add(1, Ordering::SeqCst);
                    }
                }
                for (token, _) in staged_stub_tokens(&tmp, &tokens) {
                    match ps_holds(&token) {
                        Ok(true) => stub_hit.store(true, Ordering::SeqCst),
                        Ok(false) => {}
                        Err(_) => {
                            errors.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                }
                std::thread::sleep(Duration::from_millis(500));
            }
        }));
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

    /// The one canary scan every checkpoint uses: the `ps` sampler's verdict plus a fresh `ps` sample, and every
    /// file under the stack's directory except the credential file. The daemon's staging base is under that
    /// directory, so the run's secret share, console log and sockets are covered. `at` names the checkpoint.
    fn canary_leaks(&self, at: &str) -> Result<()> {
        ensure!(
            self.ps_errors.load(Ordering::SeqCst) == 0,
            "AT-11 ({at}): a `ps` sample failed, so the canary could not be checked"
        );
        ensure!(
            !self.ps_hit.load(Ordering::SeqCst) && !ps_holds(&self.token)?,
            "AT-11 ({at}): the canary is in `ps` output"
        );
        let leaked = files_holding(self.dir.path(), &self.token, &self.credential)
            .context("AT-11: the canary scan could not read every file")?;
        ensure!(leaked.is_empty(), "AT-11 ({at}): the canary is in {leaked:?}");
        // The stub's forge tokens (#733): each only in the file the guest's secret share is staged from.
        ensure!(
            !self.ps_stub_hit.load(Ordering::SeqCst),
            "AT-11 ({at}): a stub forge token was in `ps` output (seen by the sampler)"
        );
        for (token, staged) in self.refresh_stub_tokens() {
            ensure!(!ps_holds(&token)?, "AT-11 ({at}): a stub forge token is in `ps` output");
            let leaked = files_holding(self.dir.path(), &token, &staged)
                .context("AT-11: the stub token scan could not read every file")?;
            ensure!(
                leaked.is_empty(),
                "AT-11 ({at}): a stub forge token is outside its staged file, in {leaked:?}"
            );
        }
        Ok(())
    }

    /// The staged stub tokens now on disk (`<tmp>/sandy/env-cred-<id>/GITHUB_TOKEN`), added to the ones seen before.
    /// Returns all of them, with the staged file each came from.
    fn refresh_stub_tokens(&self) -> Vec<(String, PathBuf)> {
        staged_stub_tokens(&self.tmp, &self.stub_tokens)
    }

    /// The stub's call log, one line per call.
    fn stub_calls(&self) -> Result<Vec<String>> {
        Ok(std::fs::read_to_string(&self.stub_log)
            .context("the stub trust root wrote no call log: was sandyd built with --features sandyd/stub-trust-root?")?
            .lines()
            .map(str::to_owned)
            .collect())
    }

    /// [`Stack::stub_bracket_is_balanced`], retried for up to `secs`: the driver revokes in the pass after the kill, so
    /// the last `revoke` can land a moment after the VM is gone. The last failure is the error.
    fn wait_stub_bracket_balanced(&self, at: &str, secs: u64) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(secs);
        loop {
            match self.stub_bracket_is_balanced(at) {
                Ok(()) => return Ok(()),
                Err(e) if Instant::now() > deadline => return Err(e),
                Err(_) => std::thread::sleep(Duration::from_millis(250)),
            }
        }
    }

    /// Every `mint` has its `revoke`, no revoke is for a handle never minted, no staged directory remains, and no
    /// stub token is in any of the places the canary scan covers (the staged file is gone).
    fn stub_bracket_is_balanced(&self, at: &str) -> Result<()> {
        let calls = self.stub_calls()?;
        let handles = |verb: &str| -> BTreeSet<String> {
            calls
                .iter()
                .filter_map(|l| l.strip_prefix(verb).and_then(|h| h.strip_prefix(' ')))
                .map(str::to_owned)
                .collect()
        };
        let (minted, revoked) = (handles("mint"), handles("revoke"));
        ensure!(!minted.is_empty(), "stub bracket ({at}): nothing was minted: {calls:?}");
        ensure!(
            minted == revoked,
            "stub bracket ({at}): minted {minted:?} but revoked {revoked:?}"
        );
        let left: Vec<_> = std::fs::read_dir(self.tmp.join("sandy"))
            .map(|d| {
                d.flatten()
                    .map(|e| e.path())
                    .filter(|p| {
                        p.file_name()
                            .is_some_and(|n| n.to_string_lossy().starts_with("env-cred-"))
                    })
                    .collect()
            })
            .unwrap_or_default();
        ensure!(
            left.is_empty(),
            "stub bracket ({at}): staged directories left: {left:?}"
        );
        Ok(())
    }

    /// A finished MCP session: it exited cleanly and neither its stdout nor its stderr held the canary.
    fn check_session(&self, mcp: Mcp, at: &str) -> Result<()> {
        let (clean_exit, output) = mcp.finish()?;
        ensure!(clean_exit, "{at}: sandy-mcp must exit cleanly when stdin closes");
        ensure!(
            !output.contains(&self.token),
            "AT-11 ({at}): the canary is in the MCP's stdout or stderr"
        );
        for (token, _) in self.refresh_stub_tokens() {
            ensure!(
                !output.contains(&token),
                "AT-11 ({at}): a stub forge token is in the MCP's stdout or stderr"
            );
        }
        Ok(())
    }

    /// Stops everything this stack started and returns what it found wrong. Idempotent.
    ///
    /// The descendants of `sandyd` are listed before it is signalled, since a child of a dead parent is
    /// re-parented and the walk no longer reaches it. A process that outlives `sandyd` is a finding, then
    /// SIGKILLed. Pid plus start time guards against pid reuse. A run directory left under this run's own
    /// staging base is a finding too; the base goes with the test's temp dir. Entries other sessions made in the
    /// host's `/tmp` are reported, never touched.
    fn teardown(&mut self) -> Vec<String> {
        if self.torn_down {
            return Vec::new();
        }
        self.torn_down = true;
        let mut findings = Vec::new();
        if let Some(broker) = self.broker.as_mut() {
            let _ = broker.kill();
            let _ = broker.wait();
        }
        let sandyd_pid = self.sandyd.id();
        let mut owned = descendants(sandyd_pid);
        // Also the members of the daemon's process group: a child that was re-parented before this walk is not a
        // descendant any more, and is still in the group (#734).
        owned.extend(
            group_members(sandyd_pid)
                .into_iter()
                .filter(|(pid, _)| *pid != sandyd_pid),
        );
        // A daemon that already exited died during the run: its children were re-parented, and every "no VM left"
        // answer since was blind. The status is reaped here, so it is reported once, and the pid is never signalled
        // (it may belong to another process now). The walk finds nothing, so the VM parts are found by the staging
        // base in their command lines instead.
        let already_exited = match self.sandyd.try_wait() {
            Ok(Some(status)) => {
                findings.push(format!("sandyd had already exited during the run: {status}"));
                owned = vm_parts_using(&self.tmp);
                owned.extend(
                    group_members(sandyd_pid)
                        .into_iter()
                        .filter(|(pid, _)| *pid != sandyd_pid),
                );
                owned.sort_unstable();
                owned.dedup();
                true
            }
            _ => false,
        };
        if !already_exited {
            signal("TERM", self.sandyd.id());
        }
        let deadline = Instant::now() + Duration::from_secs(15);
        while !already_exited && !matches!(self.sandyd.try_wait(), Ok(Some(_))) {
            if Instant::now() > deadline {
                findings.push("sandyd ignored SIGTERM for 15 s and was SIGKILLed".to_owned());
                let _ = self.sandyd.kill();
                let _ = self.sandyd.wait();
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let alive = |owned: &[(u32, u64)]| -> Vec<(u32, u64)> {
            owned
                .iter()
                .filter(|(pid, start)| parent_and_start(*pid).is_some_and(|(_, t)| t == *start))
                .copied()
                .collect()
        };
        let deadline = Instant::now() + Duration::from_secs(10);
        while !alive(&owned).is_empty() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(200));
        }
        let left = alive(&owned);
        if !left.is_empty() {
            findings.push(format!(
                "descendants of sandyd outlived it and were SIGKILLed: {left:?}"
            ));
            for (pid, _) in &left {
                signal("KILL", *pid);
            }
        }
        self.sampler_stop.store(true, Ordering::SeqCst);
        if let Some(sampler) = self.sampler.take() {
            let _ = sampler.join();
        }
        if let Err(e) = self.canary_leaks("after teardown") {
            findings.push(e.to_string());
        }
        match run_dirs_left(&self.tmp) {
            Ok(strays) if strays.is_empty() => {}
            Ok(strays) => findings.push(format!("run directories left under the staging base: {strays:?}")),
            Err(e) => findings.push(format!("the staging base could not be checked: {e:#}")),
        }
        let foreign = foreign_new_entries(&self.host_before, &sandy_entries(&std::env::temp_dir()), &self.tmp);
        if !foreign.is_empty() {
            eprintln!("new sandy entries in the host temp dir, not ours and left alone: {foreign:?}");
        }
        findings
    }

    /// Tears the stack down and returns the findings; the scan and checks run while the files still exist.
    fn shutdown(mut self) -> Vec<String> {
        self.teardown()
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
    ///
    /// A dead `sandyd` is an error: its VM parts are re-parented, so the walk finds none and the wait would pass
    /// with the VMs still running.
    fn wait_no_vm(&self, secs: u64) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(secs);
        loop {
            ensure!(
                process_alive(self.sandyd.id()),
                "sandyd (pid {}) is not running, so \"no VM left\" proves nothing",
                self.sandyd.id()
            );
            if vm_parts(self.sandyd.id()).is_empty() {
                return Ok(());
            }
            ensure!(
                Instant::now() < deadline,
                "VM parts {:?} still run {secs} s later",
                vm_parts(self.sandyd.id())
            );
            std::thread::sleep(Duration::from_millis(250));
        }
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

/// The stub tokens staged under `<tmp>/sandy/env-cred-<id>/GITHUB_TOKEN` now, added to `seen`, which keeps a token
/// after its file is gone so a revoked token is still looked for. Returns every token seen, with its staged file.
fn staged_stub_tokens(tmp: &Path, seen: &Mutex<BTreeMap<String, PathBuf>>) -> Vec<(String, PathBuf)> {
    let mut seen = seen.lock().unwrap_or_else(PoisonError::into_inner);
    if let Ok(base) = std::fs::read_dir(tmp.join("sandy")) {
        for entry in base.flatten() {
            if !entry.file_name().to_string_lossy().starts_with("env-cred-") {
                continue;
            }
            let staged = entry.path().join("GITHUB_TOKEN");
            if let Ok(text) = std::fs::read_to_string(&staged) {
                let token = text.trim().to_owned();
                if !token.is_empty() {
                    seen.entry(token).or_insert(staged);
                }
            }
        }
    }
    seen.iter().map(|(t, p)| (t.clone(), p.clone())).collect()
}

/// The canary never reaches the host process table: `ps` shows every argv on the box. `timeout` bounds it, and a
/// `ps` that fails or times out is an error, not a clean sample.
fn ps_holds(needle: &str) -> Result<bool> {
    let out = Command::new("timeout")
        .args(["10", "ps", "-eww", "-o", "args="])
        .output()
        .context("ps")?;
    ensure!(out.status.success(), "ps did not finish: {}", out.status);
    Ok(String::from_utf8_lossy(&out.stdout).contains(needle))
}

#[test]
fn the_conformance_script_passes_against_the_real_stack_and_leaves_nothing() -> Result<()> {
    require_live()?;
    let stack = Stack::start()?;
    // A failure prints the daemon and broker logs first: the temp dir goes with the stack.
    let outcome = scenario(&stack).inspect_err(|_| {
        stack.dump_logs();
        stack.dump_vms();
    });
    // Teardown, the last canary scan and the stray check run on failure too. A finding never replaces the
    // scenario's own error: it is printed, and fails the test only when the scenario passed.
    let findings = stack.shutdown();
    for finding in &findings {
        eprintln!("teardown finding: {finding}");
    }
    outcome?;
    ensure!(findings.is_empty(), "teardown findings: {findings:#?}");
    Ok(())
}

fn scenario(stack: &Stack) -> Result<()> {
    // AT-1, AT-2 and the boot-to-Ready time, over a bare spawn, so a broken backend fails on the first boot.
    let mut mcp = stack.mcp()?;
    let spawn = spawn_args("live-first", "bare");
    let (is_err, first) = mcp.call("spawn_environment", &spawn)?;
    ensure!(!is_err, "spawn failed: {first}");
    let spawned_at = Instant::now();
    let id = first["environment_id"].as_str().context("environment_id")?.to_owned();
    let (_, again) = mcp.call("spawn_environment", &spawn)?;
    ensure!(
        again["environment_id"] == json!(id),
        "AT-1: a retry returns the same environment: {again}"
    );
    let early = get_environment(&mut mcp, &id)?;
    ensure!(
        early["state"] == json!("provisioning"),
        "AT-2: not Ready straight after spawn: {early}"
    );
    ensure!(
        early.get("connection").is_none(),
        "AT-2: no connection before Ready: {early}"
    );
    let (ready, _) = wait_state(&mut mcp, &id, "ready", PROVISION_SECS + 60)?;
    let boot = spawned_at.elapsed();
    eprintln!("KPI boot-to-Ready (spawn call to Ready, base guest, MCP polling every 100 ms): {boot:?}");
    ensure!(
        ready["connection"]["url"].is_string(),
        "AT-2: Ready carries the connection: {ready}"
    );
    ensure!(
        stack.vms().len() == 1,
        "AT-1: two spawns of one request id run exactly one VM: {:?}",
        stack.vms()
    );

    // The forge credential bracket (#706), through the stub (#733): minted before the boot and staged once, at the
    // host side of the guest's secret share.
    let staged_tokens = stack.refresh_stub_tokens();
    ensure!(
        staged_tokens.len() == 1,
        "a Ready environment has exactly one staged stub token: {}",
        staged_tokens.len()
    );
    let calls = stack.stub_calls()?;
    ensure!(
        calls.len() == 1 && calls[0].starts_with("mint stub-"),
        "the bracket minted once before Ready and revoked nothing yet: {calls:?}"
    );
    ensure!(
        staged_tokens[0].0.starts_with("stub-token-"),
        "the staged token is the stub's, not a real forge token"
    );

    // AT-11, API-credential half: the bearer token (a unique canary) is in the credential file and nowhere else
    // the host or the MCP shows. The same scan runs again after the script and after teardown.
    stack.canary_leaks("after Ready")?;

    // AT-10: a secret-shaped argument is refused by the real binary and creates nothing.
    let mut bad = spawn_args("live-secret", "secret");
    bad["token"] = json!("x");
    let (refused, why) = mcp.call("spawn_environment", &bad)?;
    ensure!(refused, "AT-10: a `token` field must be refused: {why}");
    let (_, listed) = mcp.call("list_environments", &json!({}))?;
    let count = listed["environments"].as_array().map(Vec::len);
    ensure!(
        count == Some(1),
        "AT-10: the refused call made no environment: {listed}"
    );

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
    ensure!(
        now["state"] == json!("provisioning"),
        "AT-4: cancelled too late to test, state is {now}"
    );
    let (is_err, cancelled) = mcp.call("cancel_environment", &json!({"environment_id": cid}))?;
    ensure!(!is_err, "cancel failed: {cancelled}");
    ensure!(cancelled["state"] == json!("deleted"), "AT-4: {cancelled}");
    stack.wait_no_vm(120)?;
    // AT-6: delete after cancel is the same terminal result, not an error.
    let (is_err, again) = mcp.call("delete_environment", &json!({"environment_id": cid}))?;
    ensure!(!is_err && again["state"] == json!("deleted"), "AT-6: {again}");
    stack.check_session(mcp, "first session")?;
    stack.canary_leaks("after the first session")?;

    // The shared script (AT-6, AT-9 and the rest) over a fresh MCP, with the Ready wait sized for a boot.
    let mut script: Value = serde_json::from_str(SCRIPT)?;
    ensure!(
        script["fixtures"].get("skip_tools").is_none(),
        "the shipped script must not carry `skip_tools`: the live tier adds it, so tier-2 runs every tool"
    );
    script["fixtures"]["ready_timeout_ms"] = json!((PROVISION_SECS + 60) * 1000);
    script["fixtures"]["ready_poll_ms"] = json!(250);
    // The live stack has only the vm environment backend and no job host, so a job submit is refused by design.
    // `link_environment` is service-specific and answers `unsupported` on a real broker until open point 1 of #585 is
    // decided (AT-8 and AT-17 are the blocked rows below). All of them stay covered at tier-2 against the fake.
    script["fixtures"]["skip_tools"] = json!(["submit", "status", "attach", "cancel", "link_environment"]);
    let mut mcp = stack.mcp()?;
    run_script(&mut mcp, &script)?;
    stack.check_session(mcp, "script session")?;
    stack.canary_leaks("after the script")?;

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
    ensure!(live.is_empty(), "non-terminal environments after the run: {live:?}");
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
    ensure!(running.is_empty(), "non-terminal jobs after the run: {running:?}");
    stack.check_session(mcp, "final session")?;
    stack.canary_leaks("after the final listing")?;
    stack.wait_stub_bracket_balanced("after the final listing", 60)
}

#[test]
#[ignore = "blocked on #706: no profile secret reaches the guest yet (#705 stages the values, #706 owns the lease)"]
fn a_profile_secret_canary_is_absent_everywhere_but_the_guest_secret_path() {
    // AT-11, profile-secret half: a unique canary in a profile secret must be absent from every MCP result and
    // stderr, the journal, host `ps` and the console log, and present at the guest secret path only. The API
    // credential half runs in the test above.
    unimplemented!("AT-11 profile-secret half is blocked on #706");
}

#[test]
#[ignore = "owner decision on #585: sandy core has no service-specific internals, so AT-7 (delegate_task round trip) \
            has no live row here"]
fn a_stand_in_primary_runs_a_delegate_task_in_the_guest() {
    unimplemented!("AT-7 is blocked, see the ignore reason");
}

#[test]
#[ignore = "owner decision on #585 and open point 1: no external unlink interface, so AT-8 (parent ends after delete) \
            is blocked"]
fn the_parent_task_ends_failed_within_60_seconds_of_a_delete() {
    unimplemented!("AT-8 is blocked, see the ignore reason");
}

#[test]
#[ignore = "owner decision on #585 and open point 1: pairing and link are service-specific, so AT-17 (pairing code \
            absent) is blocked"]
fn a_pairing_code_is_absent_from_every_result_and_log() {
    unimplemented!("AT-17 is blocked, see the ignore reason");
}
