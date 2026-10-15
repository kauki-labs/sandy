//! Live GitHub adapter smoke test (tier-3, #49).
//!
//! Runs only when `SANDY_CRED_LIVE_TRUST_ROOT` points at a real GitHub App
//! `TrustRoot` JSON; otherwise it skips (no creds, e.g. in CI). Plain HTTPS to
//! GitHub, no VM. It mints a scoped installation token, proves it can read the
//! scoped repo, checks the installation-permission ceiling, revokes, and proves
//! the token is then rejected.
//!
//! Run it:
//! ```text
//! SANDY_CRED_LIVE_TRUST_ROOT=~/.config/sandy/trust-roots/sandy-runner.json \
//!   cargo nextest run -p sandy --test cred_github_live --no-capture
//! ```

use std::path::PathBuf;

use anyhow::Context;
use sandy::{
    Capability, CredentialProvider, GithubAdapter, Scope, SecretSource, Target, TrustRoot, TrustRootIo, mint_lease,
    render_github_permissions,
};

/// Reachability of `GET /repos/{owner}/{repo}` with `token`: true on 200, false on
/// an auth failure. A plain octocrab call, not through the adapter.
fn repo_readable(token: &str, repo: &str) -> anyhow::Result<bool> {
    let (owner, name) = repo.split_once('/').context("repo must be owner/name")?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("tokio runtime")?;
    // Build the client inside the runtime (octocrab's Buffer needs an active reactor).
    Ok(runtime.block_on(async {
        match octocrab::Octocrab::builder()
            .build()
            .and_then(|c| c.user_access_token(token.to_string()))
        {
            Ok(client) => client.repos(owner, name).get().await.is_ok(),
            Err(_) => false,
        }
    }))
}

#[test]
fn live_mint_probe_ceiling_revoke() -> anyhow::Result<()> {
    let Some(path) = std::env::var_os("SANDY_CRED_LIVE_TRUST_ROOT").map(PathBuf::from) else {
        eprintln!("skipping: set SANDY_CRED_LIVE_TRUST_ROOT to a GitHub App TrustRoot JSON to run this live test");
        return Ok(());
    };

    let root = TrustRoot::load(&path).context("load trust root")?;
    let repo = match &root {
        TrustRoot::Github { targets, .. } => targets.first().map(|t| t.0.clone()),
        TrustRoot::Gitlab { .. } => None,
    }
    .context("trust root has no target repo")?;
    let adapter = GithubAdapter::from_trust_root(&root).context("build adapter")?;

    let scope = Scope {
        targets: vec![Target(repo.clone())],
        capabilities: vec![Capability::ReadCode, Capability::ReadPr],
    };

    // Ceiling: the installation must actually grant every permission we render, or
    // the mint would be a silent under-grant.
    let granted = adapter.installation_permissions().context("installation permissions")?;
    for (name, _level) in render_github_permissions(&scope.capabilities) {
        anyhow::ensure!(
            granted.contains_key(&name),
            "installation does not grant {name}; granted = {granted:?}"
        );
    }

    // Mint through the seam (stages a 0600 secret), read the token back, probe it.
    let tmp = tempfile::tempdir().context("temp dir")?;
    let lease = mint_lease(&adapter, &scope, 600, "GH_TOKEN", tmp.path()).context("mint_lease")?;
    let SecretSource::File(token_path) = &lease.secret_ref.source else {
        anyhow::bail!("expected a file-sourced secret");
    };
    let token = std::fs::read_to_string(token_path).context("read staged token")?;
    anyhow::ensure!(!token.trim().is_empty(), "minted token is empty");

    anyhow::ensure!(
        repo_readable(&token, &repo).context("probe before revoke")?,
        "a scoped token must read {repo}"
    );

    // Revoke, then the same token must be rejected.
    adapter.revoke(&lease).context("revoke")?;
    anyhow::ensure!(
        !repo_readable(&token, &repo).context("probe after revoke")?,
        "after revoke the token must be rejected for {repo}"
    );
    Ok(())
}
