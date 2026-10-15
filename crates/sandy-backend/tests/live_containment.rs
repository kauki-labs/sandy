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

use sandy::{Containment, ContainmentStatus, Grants, Input, RunSpec, VmBackend};
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
        matches!(containment.status(), ContainmentStatus::Available),
        "the live host must provide real containment (user systemd + cgroup v2); got {:?}",
        containment.status()
    );
    ProcessBackend::with_containment(Box::new(containment))
}

/// A `setsid`-escaped descendant is reaped by the containment scope. Without the
/// cgroup reap this sleeper would survive the run as a host orphan (a `killpg`
/// misses it); `reap()` (`systemctl --user stop` of the scope's cgroup) kills it.
#[test]
fn a_setsid_escaped_descendant_is_reaped_by_the_cgroup() -> anyhow::Result<()> {
    let backend = live_contained_backend();
    let grants = no_grants();
    // A unique marker so pgrep finds only this test's sleeper. The job spawns it in
    // a NEW session (setsid → escapes the process group), then blocks past the 1s
    // budget so the run tears down via timeout → reap(scope).
    let marker = format!("sandy-live-135-{}", std::process::id());
    let script = format!("setsid sleep 3141 & echo {marker}; sleep 300");
    let command = ["sh".to_string(), "-c".to_string(), script];
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
    };

    let outcome = backend.run(&spec)?;
    assert!(outcome.timed_out, "the job exceeded its 1s budget");

    // Poll pgrep briefly to absorb the reap race; the escaped sleeper must be gone.
    let pattern = "sleep 3141";
    let gone = (0..50).any(|_| {
        let found = Command::new("pgrep")
            .args(["-f", pattern])
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
