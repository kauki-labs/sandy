//! Credential end-to-end scenarios (#49 domain): the full credential flow as one
//! guest-observable workflow, not a single leg.
//!
//! The focused `live_*` tests each prove one piece (the share mounts, the helper
//! serves a staged file, a refresh re-stages). This exercises the whole flow
//! together: a credentialed run mints and stages a scoped token, the guest reads it
//! **through the git credential helper** (#70) the way a real `git push` would, a
//! mid-run refresh (#49) rotates it so the helper serves the new token on the next
//! operation, and the superseded plus final tokens are revoked at teardown.
//!
//! Library tier: a rotating fake provider stands in for the trust root, so this runs
//! on any live host (vfkit or qemu/KVM) without a GitHub App. The real-App flow
//! (`sandy cred github register` → real `GithubAdapter` mint) stays operator-gated in
//! `sandy/tests/cred_github_live.rs`.
//!
//! Behind the `live` feature (CI never builds it) and refuses off-matrix (INV-S9).
//! Run with the refresh loop forced to fire inside a short job:
//!
//! ```sh
//! SANDY_LIVE=1 SANDY_REFRESH_MARGIN_SECS=100000 SANDY_REFRESH_TICK_SECS=2 \
//!   nix develop -c cargo nextest run -p sandy-cli --features live --test live_cred --no-capture
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
    AllowList, CredError, CredentialHandle, CredentialProvider, EgressOs, FakeApplier, FakeProvider, Grants, Input,
    Journal, Lease, MAX_TTL_SECS, Minted, Output, Scope, SecretRef, SecretSource, Status,
};
use sandy_cli::{plan::JobPlan, supervisor::run_job_with_credential};

/// A provider whose every mint/refresh yields a fresh, distinct token, and that
/// records every revoked handle, so the e2e can assert the guest saw the token
/// change (via the helper) and that revoke fired at teardown, all without a real
/// forge.
struct RotatingProvider {
    counter: Mutex<u32>,
    revoked: Mutex<Vec<String>>,
}

impl RotatingProvider {
    fn new() -> Self {
        Self {
            counter: Mutex::new(0),
            revoked: Mutex::new(Vec::new()),
        }
    }

    fn revoked(&self) -> Vec<String> {
        self.revoked.lock().unwrap_or_else(PoisonError::into_inner).clone()
    }

    fn next(&self) -> Minted {
        let mut n = self.counter.lock().unwrap_or_else(PoisonError::into_inner);
        *n += 1;
        Minted::new(
            format!("live-e2e-tok-{n}"),
            SystemTime::now() + Duration::from_secs(u64::from(MAX_TTL_SECS)),
            CredentialHandle { id: format!("h-{n}") },
        )
    }
}

impl CredentialProvider for RotatingProvider {
    fn mint(&self, _scope: &Scope, _ttl: Duration) -> Result<Minted, CredError> {
        Ok(self.next())
    }

    fn revoke(&self, lease: &Lease) -> Result<(), CredError> {
        self.revoked
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(lease.handle.id.clone());
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

/// The whole credential flow as one scenario: a credentialed run delivers a scoped
/// token the guest reads through the **git credential helper**, a mid-run refresh
/// rotates it (so a later `git credential fill` serves a different token), and the
/// provider's tokens are revoked at teardown.
#[test]
fn credential_flows_through_git_helper_and_refreshes_midrun() -> anyhow::Result<()> {
    let target = require_live()?;

    // The refresh loop must fire during a short job: a margin past the token TTL and
    // a short tick. Refuse on defaults so a misconfigured run is RED, not a silent
    // pass (INV-S9). `run_job_with_credential` reads these from the environment; the
    // test cannot set them (edition-2024 `set_var` is `unsafe`, forbidden by lint).
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

    // Read the token the way a real git remote op does: through the guest's git
    // credential helper (`git credential fill` for github.com), sampled repeatedly
    // over the job so the refresh is observed even when VM contention slows the
    // host-side refresh cadence (a single fixed-sleep A!=B is too timing-tight when
    // tests run in parallel). Pass iff the helper served a non-empty token and that
    // token changed at least once (a refresh reached the helper). The comparison is
    // in-guest, so no token value reaches argv or the console. No token or no change
    // → exit 7.
    let probe = r#"f() { printf 'protocol=https\nhost=github.com\n\n' | git credential fill 2>/dev/null | sed -n 's/^password=//p'; }; prev=""; changed=0; i=0; while [ $i -lt 12 ]; do cur=$(f); if [ -n "$prev" ] && [ -n "$cur" ] && [ "$cur" != "$prev" ]; then changed=$((changed+1)); fi; prev="$cur"; i=$((i+1)); sleep 1; done; [ -n "$prev" ] && [ $changed -ge 1 ] && exit 0 || exit 7"#;

    let plan = JobPlan {
        template: format!("{}#{}", guest_flake().display(), target.topology_attr),
        command: vec![probe.to_string()],
        secrets: vec![],
        inputs: vec![],
        outputs: vec![],
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
        "git credential fill must serve a token that changes mid-run; envelope: {env:?}"
    );
    assert_eq!(
        env.exit_code,
        Some(0),
        "exit 7 means the helper served no token or the same token twice (no refresh); envelope: {env:?}"
    );

    // Revoke fired at teardown (and for each superseded token on refresh): the
    // credential does not outlive the run.
    assert!(
        !provider.revoked().is_empty(),
        "the credential must be revoked at teardown"
    );

    // INV-1: no token value in the captured console (the probe compares in-guest).
    // `logs.tail` is a bounded rolling buffer (the last ConsoleTail::CAP = 64 KiB),
    // so a leak early in a long console could be evicted before this check. Assert
    // the tail holds the complete console first (this short probe's output is far
    // under the cap), so the no-leak check sees everything rather than passing by
    // truncation.
    assert!(
        env.logs.tail.len() < 64 * 1024,
        "console tail is at the 64 KiB cap, so the no-leak check may be incomplete; tail len {}",
        env.logs.tail.len()
    );
    assert!(
        !env.logs.tail.contains("live-e2e-tok-"),
        "a token value leaked into the console; tail: {}",
        env.logs.tail
    );
    Ok(())
}

/// The "everything" scenario: a credential token + a plain plan secret + an input +
/// an output all compose in one guest run. The cred leg (`run_job_with_credential` +
/// a fake provider minting `GITHUB_TOKEN`) is the #49 domain; the I/O legs and their
/// assertions come from the #34 owner's skeleton. Proves `$GITHUB_TOKEN` (from the
/// credential bracket) and `$TOK` (a plain plan secret) both export via the shared
/// secret dir, the input is readable, and the output is collected to the host and
/// recorded in the envelope, with no secret or token leaking.
#[test]
fn credential_secret_input_output_all_compose() -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let target = require_live()?;
    build_guest(&target)?;
    let home = tempfile::tempdir().context("temp SANDY_HOME")?;
    let journal = Journal::new(home.path());
    journal.ensure_dirs().context("ensure_dirs")?;
    let cred_dir = tempfile::tempdir().context("temp cred dir")?;
    let staging = tempfile::tempdir().context("temp staging")?;

    std::fs::create_dir_all(staging.path().join("in")).context("mk input dir")?;
    std::fs::write(staging.path().join("in/f"), b"INPUT-MARKER").context("write input")?;
    let tok = staging.path().join("tok");
    std::fs::write(&tok, b"SECRET-VALUE").context("write secret")?;
    std::fs::set_permissions(&tok, std::fs::Permissions::from_mode(0o600)).context("chmod secret")?;
    let out_dest = staging.path().join("collected");

    // One job: the credential token is present AND the plan secret matches AND the
    // input is readable, then write the output for the host to collect.
    let job = r#"[ -n "$GITHUB_TOKEN" ] && [ "$TOK" = SECRET-VALUE ] && grep -q INPUT-MARKER /run/sandy/inputs/data/f && printf done > /run/sandy/outputs/result/out"#;

    let plan = JobPlan {
        template: format!("{}#{}", guest_flake().display(), target.topology_attr),
        command: vec![job.to_string()],
        secrets: vec![SecretRef {
            name: "TOK".to_string(),
            source: SecretSource::File(tok),
        }],
        inputs: vec![Input {
            host: staging.path().join("in"),
            name: "data".to_string(),
        }],
        outputs: vec![Output {
            name: Some("result".to_string()),
            dest: out_dest.clone(),
        }],
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

    // Cred leg: a fixed fake provider minting GITHUB_TOKEN into the guest.
    let provider = FakeProvider::returning("e2e-everything-token");
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
        "cred token + plan secret + input + output must all compose; envelope: {env:?}"
    );
    assert_eq!(env.exit_code, Some(0), "one leg failed in-guest; envelope: {env:?}");
    assert_eq!(
        std::fs::read(out_dest.join("out")).context("read collected output")?,
        b"done",
        "the guest's output must be collected to the host dest"
    );
    assert!(
        env.outputs.iter().any(|o| o.path == "result/out"),
        "the collected output must be recorded in the envelope; outputs: {:?}",
        env.outputs
    );
    // The leak check sees the complete console only while the tail is under its
    // 64 KiB cap (ConsoleTail::CAP); assert that before trusting the no-leak scan.
    assert!(
        env.logs.tail.len() < 64 * 1024,
        "console tail is at the 64 KiB cap, so the no-leak check may be incomplete; tail len {}",
        env.logs.tail.len()
    );
    assert!(
        !env.logs.tail.contains("SECRET-VALUE") && !env.logs.tail.contains("e2e-everything-token"),
        "no secret or token value may leak into the console; tail: {}",
        env.logs.tail
    );
    Ok(())
}
