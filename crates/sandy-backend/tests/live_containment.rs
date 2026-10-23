//! Live containment — the tier-3 gate that proves the real hole #135 exists for
//! actually closes: a descendant that escapes its process group via `setsid` is
//! reaped by the cgroup scope, where the backend's process-group kill would leave
//! it a host orphan.
//!
//! Linux only (cgroup v2) and behind the `live` feature (off by default, so CI and
//! `nix flake check` never run it), and it needs a real user `systemd` instance.
//! Per INV-S9 it is never counted green from a fake: `SANDY_LIVE=1` must be set, and
//! the host's containment must actually report Available — an unavailable live host
//! fails loudly rather than skip-and-greening.
//!
//! Run it on a Linux host:
//!   SANDY_LIVE=1 cargo nextest run -p sandy-backend --features live --test live_containment
#![cfg(all(feature = "live", target_os = "linux"))]

use std::{process::Command, time::Duration};

use sandy::{Containment, ContainmentStatus, Grants, Input, RunControl, RunSpec, VmBackend};
use sandy_backend::{ProcessBackend, SystemdRunContainment};

fn no_grants() -> Grants {
    Grants {
        secrets: false,
        agent: false,
        shares: false,
    }
}

/// Build a contained backend, refusing the run off-matrix (INV-S9): `SANDY_LIVE`
/// must be set and the host's containment must report Available.
fn live_contained_backend() -> ProcessBackend {
    assert!(
        std::env::var("SANDY_LIVE").is_ok(),
        "set SANDY_LIVE=1 to run the live containment gate (INV-S9: never green from a fake)"
    );
    let containment = SystemdRunContainment::detect();
    assert!(
        matches!(containment.status(), ContainmentStatus::Available { .. }),
        "the live host must provide cgroup reaping (user systemd + cgroup v2); got {:?}",
        containment.status()
    );
    ProcessBackend::with_containment(Box::new(containment))
}

/// Build a backend whose containment also confines the filesystem (bwrap + userns,
/// #142). Refuses off-matrix: the #142 live rows need bubblewrap and unprivileged
/// user namespaces, so a host without them fails loudly rather than skip-greening.
fn live_confining_backend() -> ProcessBackend {
    assert!(
        std::env::var("SANDY_LIVE").is_ok(),
        "set SANDY_LIVE=1 to run the live containment gate (INV-S9: never green from a fake)"
    );
    let containment = SystemdRunContainment::detect();
    assert!(
        matches!(containment.status(), ContainmentStatus::Available { .. }),
        "the live host must provide cgroup reaping; got {:?}",
        containment.status()
    );
    assert!(
        containment.confines_filesystem(),
        "#142 live rows need bwrap + unprivileged user namespaces; this host provides neither"
    );
    ProcessBackend::with_containment(Box::new(containment))
}

/// Run one job with a single read-only input staged, returning the outcome. Keeps the
/// #142 confinement tests terse.
fn run_with_input(backend: &ProcessBackend, input: &std::path::Path, script: &str) -> anyhow::Result<sandy::Outcome> {
    let inputs = [Input {
        host: input.to_path_buf(),
        name: "data".to_string(),
        guest_path: None,
    }];
    let grants = no_grants();
    let command = ["sh".to_string(), "-c".to_string(), script.to_string()];
    let control = RunControl::with_timeout_secs(30);
    let spec = RunSpec {
        template: "process",
        command: &command,
        inputs: &inputs,
        outputs: &[],
        secrets: &[],
        env: &[],
        cpu: None,
        mem: None,
        timeout_secs: 30,
        grants: &grants,
        outcome_file: None,
        secret_dir: None,
        control: &control,
    };
    Ok(backend.run(&spec)?)
}

/// #142 path fidelity: a confined job reads the input at the VM-faithful FIXED path
/// `/run/sandy/inputs/data` (not just via `SANDY_INPUTS_DIR`), because bwrap binds it
/// there.
#[test]
fn a_confined_job_reads_the_faithful_run_sandy_path() -> anyhow::Result<()> {
    let backend = live_confining_backend();
    let src = tempfile::TempDir::new()?;
    std::fs::write(src.path().join("data"), b"faithful-path-input")?;

    let outcome = run_with_input(&backend, &src.path().join("data"), "cat /run/sandy/inputs/data")?;

    assert_eq!(outcome.guest_exit, Some(0), "the job read the fixed path");
    assert!(
        outcome.console.contains("faithful-path-input"),
        "job read /run/sandy/inputs/data, got {:?}",
        outcome.console
    );
    Ok(())
}

/// #142 hard read-only: a write to a read-only share fails at the KERNEL (a
/// read-only mount), not merely because the staged file is `chmod a-w`. The job first
/// tries to restore write permission and only then writes: under cooperative RO
/// (writable mount + `a-w` file) the `chmod` would succeed and the write go through
/// (WROTE); under a real `--ro-bind` the mount rejects both, so it stays DENIED and
/// the host source is untouched. This is what distinguishes hard RO from the
/// cooperative fallback.
#[test]
fn a_write_to_a_read_only_share_is_denied_by_the_mount() -> anyhow::Result<()> {
    let backend = live_confining_backend();
    let src = tempfile::TempDir::new()?;
    let data = src.path().join("data");
    std::fs::write(&data, b"original")?;

    let outcome = run_with_input(
        &backend,
        &data,
        "chmod u+w /run/sandy/inputs/data 2>/dev/null; if echo tampered > /run/sandy/inputs/data 2>/dev/null; then \
         echo WROTE; else echo DENIED; fi",
    )?;

    assert!(
        outcome.console.contains("DENIED") && !outcome.console.contains("WROTE"),
        "a read-only MOUNT must reject the write even after chmod u+w (not cooperative), got {:?}",
        outcome.console
    );
    assert_eq!(std::fs::read(&data)?, b"original", "the host source must be unchanged");
    Ok(())
}

/// #142 user-bus isolation: inside the namespace the session bus is gone — the env
/// pointer is unset and `systemctl --user` cannot reach the user manager, so the job
/// cannot spawn units outside the scope (the CWE-269 escape is closed for the confined
/// path).
#[test]
fn the_user_bus_is_unreachable_in_the_namespace() -> anyhow::Result<()> {
    let backend = live_confining_backend();
    let src = tempfile::TempDir::new()?;
    std::fs::write(src.path().join("data"), b"x")?;

    let outcome = run_with_input(
        &backend,
        &src.path().join("data"),
        "echo xdg=${XDG_RUNTIME_DIR:-UNSET}; if systemctl --user is-system-running >/dev/null 2>&1; then echo \
         BUS_REACHABLE; else echo BUS_BLOCKED; fi",
    )?;

    assert!(
        outcome.console.contains("xdg=UNSET"),
        "XDG_RUNTIME_DIR must be unset in the namespace, got {:?}",
        outcome.console
    );
    assert!(
        outcome.console.contains("BUS_BLOCKED") && !outcome.console.contains("BUS_REACHABLE"),
        "the user bus must be unreachable in the namespace, got {:?}",
        outcome.console
    );
    Ok(())
}

/// A `setsid`-escaped descendant is reaped by the containment scope. Without the
/// cgroup reap this sleeper would survive the run as a host orphan (a `killpg`
/// misses it); `reap()` (`systemctl --user stop` of the scope's cgroup) kills it.
#[test]
fn a_setsid_escaped_descendant_is_reaped_by_the_cgroup() -> anyhow::Result<()> {
    let backend = live_contained_backend();
    let grants = no_grants();
    // A unique sleep duration so pgrep matches ONLY this test's sleeper, never a
    // stale orphan from an earlier/concurrent run. The job spawns it in a NEW session
    // (setsid → escapes the process group), then blocks past the 1s budget so the run
    // tears down via timeout → reap(scope). `sleep <int>.<pid>` is a valid float
    // duration and a unique marker at once.
    let marker = format!("3141.{}", std::process::id());
    let script = format!("setsid sleep {marker} & echo spawned; sleep 300");
    let command = ["sh".to_string(), "-c".to_string(), script];
    let control = RunControl::with_timeout_secs(1);
    let spec = RunSpec {
        template: "process",
        command: &command,
        inputs: &[],
        outputs: &[],
        secrets: &[],
        env: &[],
        cpu: None,
        mem: None,
        timeout_secs: 1,
        grants: &grants,
        outcome_file: None,
        secret_dir: None,
        control: &control,
    };

    let outcome = backend.run(&spec)?;
    assert!(outcome.timed_out, "the job exceeded its 1s budget");

    // Poll pgrep briefly to absorb the reap race; the escaped sleeper must be gone.
    let pattern = format!("sleep {marker}");
    let gone = (0..50).any(|_| {
        let found = Command::new("pgrep")
            .args(["-f", &pattern])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if found {
            std::thread::sleep(Duration::from_millis(40));
            false
        } else {
            true
        }
    });
    assert!(
        gone,
        "the setsid-escaped sleeper must be reaped by the cgroup scope, not orphaned (pattern {pattern:?})"
    );
    Ok(())
}

/// A contained job still reads its staged input via `SANDY_INPUTS_DIR`: the env the
/// backend sets reaches the job THROUGH the `systemd-run --scope` wrapper. This
/// closes the gap the reaping test alone leaves — a run that reaps correctly but
/// whose env never reached the job would be a silently broken Available path.
#[test]
fn a_contained_job_reads_its_input_through_the_scope() -> anyhow::Result<()> {
    let backend = live_contained_backend();
    let src = tempfile::TempDir::new()?;
    std::fs::write(src.path().join("data"), b"contained-input")?;
    let inputs = [Input {
        host: src.path().join("data"),
        name: "data".to_string(),
        guest_path: None,
    }];
    let grants = no_grants();
    let command = [
        "sh".to_string(),
        "-c".to_string(),
        "cat \"$SANDY_INPUTS_DIR/data\"".to_string(),
    ];
    let control = RunControl::with_timeout_secs(30);
    let spec = RunSpec {
        template: "process",
        command: &command,
        inputs: &inputs,
        outputs: &[],
        secrets: &[],
        env: &[],
        cpu: None,
        mem: None,
        timeout_secs: 30,
        grants: &grants,
        outcome_file: None,
        secret_dir: None,
        control: &control,
    };

    let outcome = backend.run(&spec)?;
    assert_eq!(outcome.guest_exit, Some(0), "the contained job ran");
    assert!(
        outcome.console.contains("contained-input"),
        "the job read SANDY_INPUTS_DIR through the scope wrapper, got {:?}",
        outcome.console
    );
    Ok(())
}
