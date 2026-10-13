//! Live acceptance for mid-run credential refresh re-delivery (#49).
//!
//! The one check the subprocess `live_boot` gate can't cover: that a rotated token
//! reaches a RUNNING guest mid-job. It drives the library path directly
//! ([`run_job_with_credential`] + the real host backend) with a test-local rotating
//! provider that mints a fresh token each call, so it proves the `secret_dir` seam,
//! the refresh thread, the live virtiofs rewrite, and the in-guest file read end to
//! end on a real boot, with no GitHub App (the live `GithubAdapter` is covered
//! separately by `sandy/tests/cred_github_live.rs`).
//!
//! Behind the `live` feature (CI never builds it) and refuses off-matrix (INV-S9).
//! Run on a live host with the refresh loop forced to fire inside a short job:
//!
//! ```sh
//! SANDY_LIVE=1 SANDY_REFRESH_MARGIN_SECS=100000 SANDY_REFRESH_TICK_SECS=2 \
//!   nix develop -c cargo nextest run -p sandy-cli --features live \
//!   --test live_refresh --no-capture
//! ```
#![cfg(feature = "live")]

mod common;

use std::{
    sync::{Mutex, PoisonError},
    time::{Duration, SystemTime},
};

use anyhow::{Context, bail};
use common::{build_guest, guest_flake, require_live};
use sandy::{
    AllowList, CredError, CredentialHandle, CredentialProvider, EgressOs, FakeApplier, Grants, Journal, Lease,
    MAX_TTL_SECS, Minted, Scope, Status,
};
use sandy_cli::{plan::JobPlan, supervisor::run_job_with_credential};

/// A provider whose every mint and refresh yields a fresh, distinct token, so the
/// guest can observe the staged file change across a refresh without a real forge.
/// Revoke is a no-op: this test is about re-delivery into the guest, not the
/// adversarial revoke path (covered by the unit tests).
struct RotatingProvider {
    counter: Mutex<u32>,
}

impl RotatingProvider {
    fn new() -> Self {
        Self { counter: Mutex::new(0) }
    }

    fn next(&self) -> Minted {
        let mut n = self.counter.lock().unwrap_or_else(PoisonError::into_inner);
        *n += 1;
        Minted::new(
            format!("live-rot-tok-{n}"),
            SystemTime::now() + Duration::from_secs(u64::from(MAX_TTL_SECS)),
            CredentialHandle { id: format!("h-{n}") },
        )
    }
}

impl CredentialProvider for RotatingProvider {
    fn mint(&self, _scope: &Scope, _ttl: Duration) -> Result<Minted, CredError> {
        Ok(self.next())
    }

    fn revoke(&self, _lease: &Lease) -> Result<(), CredError> {
        Ok(())
    }

    fn refresh(&self, _lease: &Lease) -> Result<Minted, CredError> {
        Ok(self.next())
    }
}

#[cfg(target_os = "macos")]
fn host_backend() -> sandy_backend::VfkitBackend {
    let vfkit_bin = std::env::var("SANDY_VFKIT_BIN").unwrap_or_else(|_| "vfkit".to_string());
    sandy_backend::VfkitBackend::new(vfkit_bin)
}

#[cfg(not(target_os = "macos"))]
fn host_backend() -> sandy_backend::QemuBackend {
    sandy_backend::QemuBackend::new()
}

const EGRESS_OS: EgressOs = if cfg!(target_os = "macos") {
    EgressOs::MacOs
} else {
    EgressOs::Linux
};

/// A credentialed job that reads its token file twice across a sleep spanning
/// several refresh ticks sees the value CHANGE: the refresh thread re-minted and
/// re-staged over the live guest share each tick. Proves the `secret_dir` seam + the
/// mid-run refresh reach a running guest.
#[test]
fn a_refreshed_token_reaches_the_running_guest() -> anyhow::Result<()> {
    let target = require_live()?;

    // The refresh loop must fire during a short job: a margin past the token TTL
    // (always due) and a short tick. Refuse on defaults (300s/60s) so a misconfigured
    // run is RED, never a silent pass (INV-S9). `run_job_with_credential` reads these
    // from the environment; the test cannot set them (edition-2024 `set_var` is
    // `unsafe`, forbidden by the workspace lint).
    for key in ["SANDY_REFRESH_MARGIN_SECS", "SANDY_REFRESH_TICK_SECS"] {
        if std::env::var(key).is_err() {
            bail!(
                "set {key} to force a mid-run refresh (e.g. SANDY_REFRESH_MARGIN_SECS=100000 \
                 SANDY_REFRESH_TICK_SECS=2)"
            );
        }
    }

    build_guest(&target)?;
    let home = tempfile::tempdir().context("temp SANDY_HOME")?;
    let journal = Journal::new(home.path());
    journal.ensure_dirs().context("ensure_dirs")?;
    let cred_dir = tempfile::tempdir().context("temp cred dir")?;

    // Read the token file twice across a sleep longer than two ticks. The comparison
    // is in-guest, so neither token value reaches argv or the console. No refresh
    // (unchanged file) fails the `!=` guard with exit 7.
    let probe = r#"f=/run/sandy/secrets/GITHUB_TOKEN; a=$(cat "$f"); sleep 6; b=$(cat "$f"); [ -n "$a" ] && [ "$a" != "$b" ] && exit 0 || exit 7"#;

    let plan = JobPlan {
        template: format!("{}#{}", guest_flake().display(), target.topology_attr),
        command: vec![probe.to_string()],
        inputs: vec![],
        secrets: vec![],
        env: vec![],
        allow: AllowList::default(),
        cpu: None,
        mem: None,
        timeout_secs: 120,
        grants: Grants {
            secrets: false,
            agent: false,
            shares: false,
        },
        secret_dir: None,
    };

    let provider = RotatingProvider::new();
    let report = run_job_with_credential(
        &host_backend(),
        &journal,
        plan,
        &FakeApplier::new(),
        EGRESS_OS,
        None,
        &provider,
        &Scope::default(),
        "GITHUB_TOKEN",
        cred_dir.path(),
        MAX_TTL_SECS,
    )
    .context("run_job_with_credential")?;

    let env = &report.envelope;
    assert_eq!(
        env.status,
        Status::Succeeded,
        "the guest must observe the token change mid-run; envelope: {env:?}"
    );
    assert_eq!(
        env.exit_code,
        Some(0),
        "exit 7 means the token did not change — no refresh reached the guest; envelope: {env:?}"
    );

    // INV-1: no token value in the captured console (the probe compares in-guest).
    assert!(
        !env.logs.tail.contains("live-rot-tok-"),
        "a token value leaked into the console; tail: {}",
        env.logs.tail
    );
    Ok(())
}
