//! Live credential end-to-end gate: the GitHub credential provider against a
//! real, registered trust root.
//!
//! Tier-3 (network to GitHub, no VM) and behind the `live` feature, so CI and
//! `nix flake check` never run it. It is the "did we break the cred flow?"
//! regression check: `verify` drives the whole path — build the App-JWT adapter
//! from the trust root, read the installation's permissions (ceiling), dry-run
//! mint a scoped token, and revoke it. A failure means register/import or the
//! adapter regressed.
//!
//! Precondition: a trust root is configured on this host, e.g.
//!   sandy cred github register sandy-runner --org <org> \
//!     --capability write-code --capability write-pr --repo <owner>/<repo>
//! then run:
//!   SANDY_LIVE=1 cargo nextest run -p sandy-cli --features live --test cred_e2e
//! Override the handle / capabilities with SANDY_CRED_HANDLE / SANDY_CRED_CAPS
//! (comma-separated, default `sandy-runner` / `write-code,write-pr`).
//!
//! The `sandy run --credential` leg (a scoped mint injected into a live guest) is
//! a separate gate on the run-path side; it binds in here once the guest-side
//! secret consumption (#50) lands.
#![cfg(feature = "live")]

use std::{path::PathBuf, process::Command};

use anyhow::{Context, Result, bail};

/// The live gate: `SANDY_LIVE=1` and a configured trust root. Returns the handle
/// and the capabilities to verify. Refuses (never skip-and-greens) otherwise.
fn require_cred_live() -> Result<(String, Vec<String>)> {
    if std::env::var("SANDY_LIVE").ok().as_deref() != Some("1") {
        bail!("refusing: this is a live gate — set SANDY_LIVE=1 on the host that holds the trust root");
    }
    let handle = std::env::var("SANDY_CRED_HANDLE").unwrap_or_else(|_| "sandy-runner".to_string());
    let caps = std::env::var("SANDY_CRED_CAPS").unwrap_or_else(|_| "write-code,write-pr".to_string());
    let config = trust_root_config(&handle);
    if !config.exists() {
        bail!(
            "no trust root at {} — register it first: `sandy cred github register {handle} …`",
            config.display()
        );
    }
    Ok((handle, caps.split(',').map(str::to_string).collect()))
}

/// The config path for a trust root of the given name (mirrors the CLI's
/// `$XDG_CONFIG_HOME`/`~/.config` resolution).
fn trust_root_config(handle: &str) -> PathBuf {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .unwrap_or_default();
    base.join("sandy").join("trust-roots").join(format!("{handle}.json"))
}

/// Run the built `sandy` binary, returning its exit code and combined output.
fn run_sandy(args: &[&str]) -> Result<(i32, String)> {
    let out = Command::new(env!("CARGO_BIN_EXE_sandy"))
        .args(args)
        .output()
        .context("spawn sandy")?;
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    Ok((out.status.code().unwrap_or(-1), combined))
}

/// The GitHub credential flow works end to end against the live App: `verify`
/// mints a scoped token, the installation grants the requested capabilities, and
/// the probe token is revoked. Exit 0 and a "Verified" line.
#[test]
fn cred_github_verify_mints_and_revokes() -> Result<()> {
    let (handle, caps) = require_cred_live()?;

    let mut args = vec!["cred", "github", "verify", handle.as_str()];
    for cap in &caps {
        args.push("--capability");
        args.push(cap);
    }

    let (code, out) = run_sandy(&args)?;
    assert_eq!(code, 0, "`sandy cred github verify` failed (exit {code}):\n{out}");
    assert!(out.contains("Verified"), "unexpected output:\n{out}");
    Ok(())
}
