//! Live qemu confinement gate (#392, audit NV-02).
//!
//! Tier-3 (behind the `live` feature): a real qemu process, started by a real `sandy run`, must run under a
//! seccomp filter. Without one, a qemu escape has the full syscall surface of the sandy user. The test reads
//! `/proc/<pid>/status` of the qemu process while the guest job runs, so it proves the kernel enforces the filter,
//! not just that the flag is in the argv.
//!
//! Run it on a Linux/KVM host:
//!   nix shell nixpkgs#qemu nixpkgs#virtiofsd -c \
//!     env SANDY_LIVE=1 cargo nextest run -p sandy-cli --features live --test live_qemu_sandbox
#![cfg(all(feature = "live", target_os = "linux"))]

use std::{
    collections::HashSet,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

use anyhow::Context;

mod common;
use common::{build_guest, guest_flake, require_live};

/// How long the guest job sleeps: long enough to poll `/proc` while the VM is up.
const JOB_SECS: &str = "20";
/// How long to wait for the qemu process to appear under the `sandy` process.
const APPEAR_WITHIN: Duration = Duration::from_secs(90);

/// `(pid, parent pid, comm)` of every process, from `/proc`.
fn processes() -> Vec<(u32, u32, String)> {
    let Ok(dir) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    dir.filter_map(|entry| {
        let pid: u32 = entry.ok()?.file_name().to_str()?.parse().ok()?;
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        // `pid (comm) state ppid ...`: comm may hold spaces and parentheses, so split at the last `)`.
        let (head, tail) = stat.rsplit_once(')')?;
        let comm = head.split_once('(')?.1.to_string();
        let ppid: u32 = tail.split_whitespace().nth(1)?.parse().ok()?;
        Some((pid, ppid, comm))
    })
    .collect()
}

/// The first argv element of `pid` (its executable path as launched), or empty when unreadable.
fn argv0(pid: u32) -> String {
    std::fs::read(format!("/proc/{pid}/cmdline"))
        .ok()
        .and_then(|bytes| {
            bytes
                .split(|b| *b == 0)
                .next()
                .map(|s| String::from_utf8_lossy(s).into_owned())
        })
        .unwrap_or_default()
}

/// Every process descended from `root`, as `(pid, comm, argv0)`. Nix wraps qemu, so the executable's name is
/// matched through `argv0` as well as `comm` (a wrapper's `comm` can be `.qemu-system-x86`).
fn descendants(root: u32) -> Vec<(u32, String, String)> {
    let all = processes();
    let mut family: HashSet<u32> = HashSet::from([root]);
    // A few passes cover any nesting (a wrapper between sandy and qemu).
    for _ in 0..4 {
        for (pid, ppid, _) in &all {
            if family.contains(ppid) {
                family.insert(*pid);
            }
        }
    }
    all.into_iter()
        .filter(|(pid, ..)| family.contains(pid) && *pid != root)
        .map(|(pid, _, comm)| (pid, comm, argv0(pid)))
        .collect()
}

/// The pid of a qemu process descended from `root`, if one exists now.
fn qemu_under(root: u32) -> Option<u32> {
    descendants(root)
        .into_iter()
        .find(|(_, comm, argv0)| comm.contains("qemu-system") || argv0.contains("qemu-system"))
        .map(|(pid, ..)| pid)
}

/// The `Seccomp:` mode of `pid`: 0 off, 1 strict, 2 filter.
fn seccomp_mode(pid: u32) -> anyhow::Result<u32> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).context("read /proc status")?;
    let line = status
        .lines()
        .find_map(|l| l.strip_prefix("Seccomp:"))
        .context("no Seccomp line in /proc status")?;
    line.trim().parse().context("parse the Seccomp mode")
}

/// A VM run's qemu process has a seccomp filter installed (mode 2) while the guest runs.
#[test]
fn the_qemu_process_runs_under_a_seccomp_filter() -> anyhow::Result<()> {
    let target = require_live()?;
    build_guest(&target)?;
    let home = tempfile::tempdir().context("temp SANDY_HOME")?;
    let attr = format!("{}#{}", guest_flake().display(), target.topology_attr);

    let mut sandy = Command::new(env!("CARGO_BIN_EXE_sandy"))
        .env("SANDY_HOME", home.path())
        .args(["-o", "json", "run", &attr, "--timeout", "120", "--", "sleep", JOB_SECS])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("spawn sandy run")?;

    // The mode is read once the process exists and its filter is installed; qemu installs it early, so poll the
    // mode, not only the pid. The run is always waited for below, so no qemu is left behind.
    let deadline = Instant::now() + APPEAR_WITHIN;
    let mut seen = None;
    let mut last_family = Vec::new();
    while Instant::now() < deadline && seen != Some(2) {
        last_family = descendants(sandy.id());
        if let Some(pid) = qemu_under(sandy.id()) {
            seen = seccomp_mode(pid).ok();
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    let output = sandy.wait_with_output().context("wait for sandy run")?;

    assert_eq!(
        seen,
        Some(2),
        "the qemu process must run with a seccomp filter (None = never saw a qemu process); last descendants (pid, \
         comm, argv0): {last_family:?}; sandy stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.status.code(), Some(0), "the sandboxed run must still succeed");
    Ok(())
}
