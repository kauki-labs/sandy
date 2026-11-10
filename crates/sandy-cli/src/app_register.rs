//! `sandy cred github register` / `sandy cred github deregister`: the in-code trust-root
//! installer (docs/providers/github/).
//!
//! The provider-neutral pipeline and its invariants live in the `sandy` library
//! (`register` / `deregister` / `Provisioner`); this module is the GitHub
//! `Provisioner` and the thin CLI wiring. GitHub has no API to create or install
//! an App, so two browser clicks (Create, Install) are irreducible in every path;
//! everything around them is automated here: the manifest is pre-filled, the
//! redirect is caught on a localhost listener, and the private key + ids are
//! captured and written to the trust-root config with no hand-copying.
//!
//! The manifest conversion (`POST /app-manifests/{code}/conversions`) is
//! unauthenticated, so registration needs no App-JWT. `verify` (a dry-run mint +
//! ceiling check) and `deregister`'s forge uninstall run through the credential
//! seam's live [`sandy::GithubAdapter`]; `register` verifies by default, and
//! `--skip-verify` is the explicit (never default) escape for a key-only bootstrap.

use std::{
    collections::HashMap,
    io,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use sandy::{
    Capability, CredentialProvider, GithubAdapter, InstallError, Provisioner, RegistrationPlan, RevokeOutcome, Scope,
    Target, TrustRoot, TrustRootIo, mint_lease, render_github_permissions,
};
use serde::{Deserialize, Serialize};
use tiny_http::{Header, Response, Server};

/// `sandy cred github register`'s result. Paths only: the key itself is never
/// part of any output (INV-1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredRegistered {
    /// The App's name at the forge.
    pub app_name: String,
    /// The forge's App id.
    pub app_id: String,
    /// The installation the trust root points at.
    pub installation_id: u64,
    /// The trust-root config written.
    pub trust_root: PathBuf,
    /// The `0600` private-key file written.
    pub private_key: PathBuf,
}

/// `sandy cred github import`'s result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredImported {
    /// The imported App's id.
    pub app_id: String,
    /// The installation the trust root points at.
    pub installation_id: u64,
    /// The trust-root config written.
    pub trust_root: PathBuf,
}

/// `sandy cred github verify`'s result: the probe minted a scoped token and
/// the installation grants the requested capabilities. A failed probe is an
/// error, never a `verified: false` value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredVerified {
    /// Always `true` on success.
    pub verified: bool,
}

/// `sandy cred github deregister`'s result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredDeregistered {
    /// Whether the App was uninstalled at the forge.
    pub uninstalled: bool,
    /// Where the operator removes what the API cannot (the App registration, or
    /// the installation when the key was unavailable), if anything is left.
    pub registration_residue: Option<String>,
    /// The trust-root config removed along with the shredded local key.
    pub trust_root: PathBuf,
}

/// Where the account the App is registered under lives.
#[derive(Debug, Clone)]
pub enum Owner {
    /// The authenticated user's own account.
    User,
    /// An organization, by login.
    Org(String),
}

/// A one-shot localhost catcher for the manifest-flow redirects. Binds
/// `127.0.0.1` on a random port; serves the auto-submitting manifest form, then
/// catches the redirect GitHub makes back to it, matching a single-use `state`
/// nonce so another local process cannot complete the handshake.
pub struct RedirectCatcher {
    server: Server,
    addr: SocketAddr,
}

impl RedirectCatcher {
    /// Bind the catcher on a random loopback port.
    ///
    /// # Errors
    /// [`io::Error`] if the listener cannot bind.
    pub fn bind() -> io::Result<Self> {
        let server = Server::http("127.0.0.1:0").map_err(|e| io::Error::other(e.to_string()))?;
        let addr = server
            .server_addr()
            .to_ip()
            .ok_or_else(|| io::Error::other("redirect catcher did not bind an IP address"))?;
        Ok(Self { server, addr })
    }

    /// The `http://127.0.0.1:<port>/` URL GitHub redirects back to.
    #[must_use]
    pub fn redirect_url(&self) -> String {
        format!("http://{}/", self.addr)
    }

    /// Serve the auto-submitting manifest form, then catch the create redirect and
    /// return its query params (e.g. `code`). The first no-query GET is answered
    /// with the form (which POSTs the manifest to GitHub); the matching
    /// `?...&state=<state>` redirect that follows is captured.
    ///
    /// # Errors
    /// [`io::Error`] if the listener closes before a matching redirect.
    pub fn serve_and_catch(
        &self,
        new_app_url: &str,
        manifest_json: &str,
        state: &str,
        params: &[&str],
    ) -> io::Result<HashMap<String, String>> {
        for request in self.server.incoming_requests() {
            let query = parse_query(request.url());
            if query.is_empty() {
                let page = manifest_form_page(new_app_url, manifest_json, state);
                let _ = request.respond(Response::from_string(page).with_header(html_header()));
            } else if query.get("state").map(String::as_str) == Some(state) {
                let picked = pick(&query, params);
                let _ = request.respond(Response::from_string(CLOSE_PAGE).with_header(html_header()));
                return Ok(picked);
            } else {
                let _ = request.respond(Response::from_string("unexpected state").with_status_code(400));
            }
        }
        Err(io::Error::other("redirect catcher closed before the create redirect"))
    }

    /// Catch the post-install redirect GitHub makes to the App's `setup_url`,
    /// returning its query params (e.g. `installation_id`). The install redirect
    /// carries no `state`, so it is matched by the presence of `installation_id`.
    ///
    /// # Errors
    /// [`io::Error`] if the listener closes before the install redirect.
    pub fn catch_install(&self) -> io::Result<HashMap<String, String>> {
        for request in self.server.incoming_requests() {
            let query = parse_query(request.url());
            if query.contains_key("installation_id") {
                let picked = pick(&query, &["installation_id", "setup_action"]);
                let _ = request.respond(Response::from_string(CLOSE_PAGE).with_header(html_header()));
                return Ok(picked);
            }
            let _ = request.respond(Response::from_string("waiting for the installation").with_status_code(400));
        }
        Err(io::Error::other("redirect catcher closed before the install redirect"))
    }
}

const CLOSE_PAGE: &str =
    "<!doctype html><title>sandy</title><p>Captured. Return to the terminal; you can close this tab.</p>";

fn html_header() -> Header {
    // `text/html` is a valid header; the fallback keeps this total without an unwrap.
    Header::from_bytes(&b"Content-Type"[..], &b"text/html; charset=utf-8"[..])
        .unwrap_or_else(|()| Header::from_bytes(&b"X-Content"[..], &b"html"[..]).expect("static header"))
}

/// Pick the named keys out of a parsed query, dropping absent ones.
fn pick(query: &HashMap<String, String>, keys: &[&str]) -> HashMap<String, String> {
    keys.iter()
        .filter_map(|k| query.get(*k).map(|v| ((*k).to_string(), v.clone())))
        .collect()
}

/// Parse a request target's query string into key/value pairs. The values we read
/// (`code`, `state`, `installation_id`) are URL-safe, so no percent-decoding is
/// applied.
fn parse_query(url: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    if let Some((_, qs)) = url.split_once('?') {
        for pair in qs.split('&') {
            if let Some((key, value)) = pair.split_once('=') {
                out.insert(key.to_string(), value.to_string());
            }
        }
    }
    out
}

/// The local page that auto-POSTs the manifest to GitHub's new-App endpoint.
fn manifest_form_page(new_app_url: &str, manifest_json: &str, state: &str) -> String {
    let action = format!("{new_app_url}?state={state}");
    let manifest_attr = html_attr_escape(manifest_json);
    format!(
        "<!doctype html><title>sandy</title><form id=\"f\" method=\"post\" action=\"{action}\"><input type=\"hidden\" \
         name=\"manifest\" \
         value=\"{manifest_attr}\"></form><script>document.getElementById('f').submit()</script><p>Submitting the \
         GitHub App manifest…</p>"
    )
}

/// Escape a string for an HTML double-quoted attribute value.
fn html_attr_escape(raw: &str) -> String {
    raw.replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// The GitHub `Provisioner`: drives the manifest flow and captures the trust root.
pub struct GithubProvisioner {
    /// The local handle: the stem of the `<handle>.json` / `<handle>.pem` files.
    /// Stable and predictable, independent of the (possibly suffixed) App name.
    pub handle: String,
    /// The App name as registered on GitHub (globally unique; may carry a random
    /// suffix). Used only in the manifest.
    pub app_name: String,
    /// The App homepage URL.
    pub homepage_url: String,
    /// The web base, e.g. `https://github.com` or a GitHub Enterprise Server host.
    pub web_base: String,
    /// The owner the App is registered under.
    pub owner: Owner,
    /// Repositories the credential may be scoped to.
    pub targets: Vec<Target>,
}

impl GithubProvisioner {
    /// The `.../settings/apps/new` endpoint the manifest is POSTed to.
    fn new_app_url(&self) -> String {
        match &self.owner {
            Owner::User => format!("{}/settings/apps/new", self.web_base),
            Owner::Org(org) => format!("{}/organizations/{org}/settings/apps/new", self.web_base),
        }
    }

    /// The API base for the manifest conversion: GitHub.com uses octocrab's
    /// default; a GHES host uses `<web_base>/api/v3`.
    fn api_base(&self) -> Option<String> {
        derived_api_base(&self.web_base)
    }

    /// `base_url` stored in the trust root (`None` for github.com).
    fn trust_root_base_url(&self) -> Option<String> {
        self.api_base()
    }
}

/// The API base a GitHub Enterprise Server `web_base` implies (`<web base>/api/v3`); `None` for github.com.
fn derived_api_base(web_base: &str) -> Option<String> {
    if web_base == "https://github.com" {
        None
    } else {
        Some(format!("{web_base}/api/v3"))
    }
}

/// Refuse an API base the App's JWT must not go to (#736), by field and rule and never the value.
fn check_api_base(base: Option<&str>) -> Result<(), InstallError> {
    base.map_or(Ok(()), sandy::validate_api_base)
        .map_err(|reason| InstallError::Capture(format!("base_url is not allowed: {reason}")))
}

/// The subset of the manifest-conversion response the installer needs.
#[derive(serde::Deserialize)]
struct Conversion {
    id: u64,
    slug: String,
    pem: String,
}

impl Provisioner for GithubProvisioner {
    fn plan(&self, _capabilities: &[Capability]) -> RegistrationPlan {
        RegistrationPlan {
            open_url: String::new(), // filled with the live catcher URL at capture time
            steps: vec![
                "A browser tab opens pre-filled; click \"Create GitHub App\".".to_string(),
                "Then click \"Install\" and pick the repositories the App may touch.".to_string(),
                "The key and ids are captured here automatically; no copying.".to_string(),
            ],
        }
    }

    fn capture(&self, capabilities: &[Capability]) -> Result<TrustRoot, InstallError> {
        let catcher = RedirectCatcher::bind().map_err(|e| InstallError::Capture(e.to_string()))?;
        let state = new_nonce();
        let mut manifest = sandy::github_app_manifest(&self.app_name, &self.homepage_url, capabilities);
        inject(&mut manifest, "redirect_url", &catcher.redirect_url());
        inject(&mut manifest, "setup_url", &catcher.redirect_url());
        let manifest_json = manifest.to_string();

        eprintln!(
            "Open {} in your browser, then click \"Create GitHub App\".",
            catcher.redirect_url()
        );
        let created = catcher
            .serve_and_catch(&self.new_app_url(), &manifest_json, &state, &["code"])
            .map_err(|e| InstallError::Capture(e.to_string()))?;
        let code = created
            .get("code")
            .ok_or_else(|| InstallError::Capture("the create redirect carried no code".to_string()))?;

        let conversion = convert_manifest(self.api_base().as_deref(), code)?;
        let key_path = write_pem(&self.handle, &conversion.pem)?;

        eprintln!(
            "App created. Open {}/apps/{}/installations/new, click \"Install\", and pick the repositories.",
            self.web_base, conversion.slug
        );
        let installed = catcher
            .catch_install()
            .map_err(|e| InstallError::Capture(e.to_string()))?;
        let installation_id = installed
            .get("installation_id")
            .and_then(|s| s.parse::<u64>().ok())
            .ok_or_else(|| InstallError::Capture("the install redirect carried no installation_id".to_string()))?;

        Ok(TrustRoot::Github {
            base_url: self.trust_root_base_url(),
            app_id: conversion.id.to_string(),
            private_key_path: key_path,
            installation_id,
            targets: self.targets.clone(),
        })
    }

    fn verify(&self, root: &TrustRoot, capabilities: &[Capability]) -> Result<(), InstallError> {
        let adapter =
            GithubAdapter::from_trust_root(root).map_err(|e| InstallError::Verify(format!("build adapter: {e}")))?;

        // Ceiling check: the installation must grant at least what the requested
        // capabilities render to (an under-scoped install would mint too narrow a
        // token). Compared through the SAME renderer the manifest used, so it can't
        // drift.
        let granted = adapter
            .installation_permissions()
            .map_err(|e| InstallError::Verify(format!("read installation permissions: {e}")))?;
        for (perm, level) in render_github_permissions(capabilities) {
            if !grant_satisfies(granted.get(&perm).map(String::as_str), &level) {
                return Err(InstallError::Verify(format!(
                    "installation grant is too narrow: `{perm}` needs `{level}`, installation has {:?}",
                    granted.get(&perm)
                )));
            }
        }

        // Dry-run mint: prove the App mints a scoped token end-to-end, then revoke
        // it. A successful scoped mint is GitHub confirming the App + installation +
        // scope are all valid.
        let scope = Scope {
            targets: github_targets(root),
            capabilities: capabilities.to_vec(),
        };
        let probe_dir = verify_tmp_dir()?;
        let outcome = match mint_lease(&adapter, &scope, 60, "SANDY_VERIFY_PROBE", &probe_dir) {
            Ok(lease) => adapter
                .revoke(&lease)
                .map_err(|e| InstallError::Verify(format!("revoke probe token: {e}"))),
            Err(e) => Err(InstallError::Verify(format!("dry-run mint failed: {e}"))),
        };
        let _ = std::fs::remove_dir_all(&probe_dir);
        outcome
    }

    fn revoke(&self, root: &TrustRoot) -> Result<RevokeOutcome, InstallError> {
        // Uninstall needs an App JWT, which only the live `.pem` can sign (App JWTs
        // live <=10 min, so none can be pre-made). With the key present, uninstall
        // via the adapter; the App *registration* shell can't be deleted via API, so
        // report where to remove it by hand. With the key gone, don't block the
        // local teardown — point to the UI instead.
        match GithubAdapter::from_trust_root(root) {
            Ok(adapter) => {
                adapter
                    .uninstall()
                    .map_err(|e| InstallError::Revoke(format!("uninstall: {e}")))?;
                Ok(RevokeOutcome {
                    uninstalled: true,
                    registration_residue: Some(app_registration_url(&self.web_base, root)),
                })
            }
            Err(e) => {
                eprintln!("note: can't sign the App JWT to uninstall ({e}); do it in the GitHub UI.");
                Ok(RevokeOutcome {
                    uninstalled: false,
                    registration_residue: Some(manual_uninstall_url(&self.web_base, root)),
                })
            }
        }
    }
}

/// Whether an installation's granted permission level satisfies a required one
/// (`write` dominates `read`; absent satisfies nothing).
fn grant_satisfies(have: Option<&str>, need: &str) -> bool {
    matches!((have, need), (Some("write"), _) | (Some("read"), "read"))
}

/// The repositories a GitHub trust root is scoped to.
fn github_targets(root: &TrustRoot) -> Vec<Target> {
    match root {
        TrustRoot::Github { targets, .. } => targets.clone(),
        TrustRoot::Gitlab { .. } => Vec::new(),
    }
}

/// A `0700` temp dir for the verify probe's short-lived staged token, removed
/// after the probe.
fn verify_tmp_dir() -> Result<PathBuf, InstallError> {
    sandy_fsutil::private_staging_dir("verify")
        .map(|dir| dir.path().to_path_buf())
        .map_err(|e| InstallError::Verify(format!("create verify temp dir: {e}")))
}

/// After uninstall the installation is gone, but the App *registration* shell
/// remains (no delete API). Point to the owner's Developer-settings Apps page to
/// remove it by hand; the org is read best-effort from the first target.
fn app_registration_url(web_base: &str, root: &TrustRoot) -> String {
    let org = github_targets(root)
        .first()
        .and_then(|target| target.0.split('/').next().map(str::to_string));
    match org {
        Some(org) => format!("{web_base}/organizations/{org}/settings/apps"),
        None => format!("{web_base}/settings/apps"),
    }
}

/// The GitHub UI URL at which the user uninstalls the App by hand (no `.pem`
/// needed — it uses their account login).
fn manual_uninstall_url(web_base: &str, root: &TrustRoot) -> String {
    match root {
        TrustRoot::Github { installation_id, .. } => {
            format!("{web_base}/settings/installations/{installation_id}")
        }
        TrustRoot::Gitlab { .. } => format!("{web_base}/-/profile/personal_access_tokens"),
    }
}

/// Insert a string field into a manifest JSON object.
fn inject(manifest: &mut serde_json::Value, key: &str, value: &str) {
    if let Some(object) = manifest.as_object_mut() {
        object.insert(key.to_string(), serde_json::Value::String(value.to_string()));
    }
}

/// POST the manifest code to the conversion endpoint (unauthenticated) and return
/// the App id, slug, and private key.
fn convert_manifest(api_base: Option<&str>, code: &str) -> Result<Conversion, InstallError> {
    let api_base = api_base.map(str::to_string);
    let route = format!("/app-manifests/{code}/conversions");
    let runtime = tokio::runtime::Runtime::new().map_err(|e| InstallError::Capture(e.to_string()))?;
    // Build the client INSIDE the runtime: octocrab's tower service needs a live
    // Tokio reactor, so a client built outside block_on panics ("no reactor running").
    runtime.block_on(async move {
        let mut builder = octocrab::Octocrab::builder();
        if let Some(base) = &api_base {
            builder = builder
                .base_uri(base)
                .map_err(|e| InstallError::Capture(format!("GHES base {base}: {e}")))?;
        }
        let octo = builder.build().map_err(|e| InstallError::Capture(e.to_string()))?;
        octo.post::<(), Conversion>(route, None)
            .await
            .map_err(|e| InstallError::Capture(format!("manifest conversion: {e}")))
    })
}

/// Write the captured PEM to a `0600` file under the default trust-roots dir.
fn write_pem(stem: &str, pem: &str) -> Result<PathBuf, InstallError> {
    let dir = trust_roots_dir().map_err(|e| InstallError::Capture(e.to_string()))?;
    write_pem_in(&dir, stem, pem)
}

/// Write the PEM to a `0600` `<dir>/<stem>.pem` file, returning its path. The dir
/// is a parameter so this is testable without touching the real config dir.
fn write_pem_in(dir: &Path, stem: &str, pem: &str) -> Result<PathBuf, InstallError> {
    Ok(sandy::write_trust_secret(dir, &format!("{stem}.pem"), pem.as_bytes())?)
}

/// The `<config>/sandy/trust-roots` directory (`XDG_CONFIG_HOME` or `~/.config`).
pub fn trust_roots_dir() -> io::Result<PathBuf> {
    sandy::trust_roots_dir()
}

/// The config file path for a trust root of the given name.
#[must_use]
pub fn config_path(dir: &std::path::Path, name: &str) -> PathBuf {
    dir.join(format!("{name}.json"))
}

/// A single-use state nonce for the redirect handshake.
fn new_nonce() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

/// The GitHub App name to register. With `override_name` it is used verbatim;
/// otherwise it is `<handle>-<owner>-<random>` (the org is folded in so the name
/// says whose App it is), and `<handle>-<random>` for a user account — the
/// account login isn't known before the App is created, so it is omitted (pass
/// `--name-override` to include it). The handle stays the local file stem
/// regardless; the random suffix keeps the name unique in GitHub's global
/// App namespace.
#[must_use]
pub fn github_app_name(handle: &str, owner: &Owner, override_name: Option<&str>) -> String {
    if let Some(name) = override_name {
        return name.to_string();
    }
    // Deterministic, not random: in the one-shared-org-App model every member must
    // resolve to the SAME App name, and the duplicate check must be able to find it.
    // `<org>` makes it globally unique (org logins are unique).
    match owner {
        Owner::Org(org) => format!("{handle}-{org}"),
        Owner::User => handle.to_string(),
    }
}

/// `sandy cred github register`: register a GitHub App trust root in-code. Prints the
/// one-line disclosure (contacts only the forge, captures locally, writes `0600`,
/// ships no secret), drives the two browser clicks, and writes the trust root.
/// With `skip_verify`, the scope-check probe is skipped (explicit pilot bootstrap).
///
/// # Errors
/// Any [`InstallError`] from capture, verify, or the config write.
#[allow(clippy::too_many_arguments)]
pub fn run_register(
    handle: &str,
    github_app_name: &str,
    homepage_url: &str,
    owner: Owner,
    web_base: &str,
    capabilities: &[Capability],
    targets: Vec<Target>,
    skip_verify: bool,
    force: bool,
) -> Result<CredRegistered, InstallError> {
    sandy::validate_trust_root_name(handle)?;
    // Before the browser, the forge or any file: the web base decides where the App's secrets are sent.
    check_api_base(derived_api_base(web_base).as_deref())?;
    let dir = trust_roots_dir().map_err(|e| InstallError::Capture(e.to_string()))?;
    let cfg = config_path(&dir, handle);
    if !force {
        // One-shared-org-App model: don't create a second sandy App. Reuse the
        // existing one via `sandy cred github import` with the shared key instead.
        check_no_existing_sandy_app(handle, web_base, &owner)?;
    }
    let provisioner = GithubProvisioner {
        handle: handle.to_string(),
        app_name: github_app_name.to_string(),
        homepage_url: homepage_url.to_string(),
        web_base: web_base.to_string(),
        owner,
        targets,
    };

    eprintln!(
        "sandy cred github register: contacts only {web_base}; the key is captured on this machine and written 0600; \
         no shared secret, no sandy server in the path."
    );

    let root = if skip_verify {
        eprintln!("--skip-verify: writing the trust root WITHOUT the live scope-check probe (pilot bootstrap).");
        sandy::register_skip_verify(&provisioner, capabilities, &cfg)?
    } else {
        sandy::register(&provisioner, capabilities, &cfg)?
    };

    let TrustRoot::Github {
        app_id,
        installation_id,
        private_key_path,
        ..
    } = root
    else {
        return Err(InstallError::Capture(format!(
            "registration finished and {} is written, but it is not a GitHub trust root; run `sandy cred github \
             verify {handle}`",
            cfg.display()
        )));
    };
    Ok(CredRegistered {
        app_name: github_app_name.to_string(),
        app_id,
        installation_id,
        trust_root: cfg,
        private_key: private_key_path,
    })
}

/// `sandy cred github deregister`: uninstall the App at the forge, then shred
/// the local secret and remove the config. `keep_remote` shreds locally only.
///
/// # Errors
/// Any [`InstallError`] from loading, the forge revoke, or the local removal.
pub fn run_deregister(name: &str, keep_remote: bool) -> Result<CredDeregistered, InstallError> {
    sandy::validate_trust_root_name(name)?;
    let dir = trust_roots_dir().map_err(|e| InstallError::Capture(e.to_string()))?;
    let cfg = config_path(&dir, name);
    // Unchecked: `deregister` checks the base itself where the forge is called, so a root with a bad stored base can
    // still be removed locally with --keep-remote (#736).
    let root = TrustRoot::load_unchecked(&cfg)?;
    let provisioner = provisioner_for(&root, name);

    let outcome = sandy::deregister(&provisioner, &cfg, keep_remote)?;

    Ok(CredDeregistered {
        uninstalled: outcome.uninstalled,
        registration_residue: outcome.registration_residue,
        trust_root: cfg,
    })
}

/// Build a [`GithubProvisioner`] from a loaded trust root, for the deregister
/// revoke. Only `revoke` is called on it, and that uses the root, not these
/// registration fields, so the owner/homepage are placeholders.
fn provisioner_for(root: &TrustRoot, name: &str) -> GithubProvisioner {
    let web_base = match root {
        TrustRoot::Github {
            base_url: Some(api), ..
        } => api.strip_suffix("/api/v3").unwrap_or(api).to_string(),
        _ => "https://github.com".to_string(),
    };
    GithubProvisioner {
        handle: name.to_string(),
        app_name: name.to_string(),
        homepage_url: String::new(),
        web_base,
        owner: Owner::User,
        targets: Vec::new(),
    }
}

/// Best-effort check for an existing shared sandy App on the target owner, via
/// the user's `gh` auth: list the owner's app installations and look for one
/// whose slug starts with the handle. Returns an error to BLOCK a duplicate
/// registration (the one-shared-org-App model). If `gh` is unavailable or the
/// owner is not github.com, it skips with a note rather than blocking (re-run
/// with `--force` to skip it deliberately).
fn check_no_existing_sandy_app(handle: &str, web_base: &str, owner: &Owner) -> Result<(), InstallError> {
    if web_base != "https://github.com" {
        eprintln!("note: existing-App check is only automated for github.com; skipping.");
        return Ok(());
    }
    let endpoint = match owner {
        Owner::Org(org) => format!("/orgs/{org}/installations"),
        Owner::User => "/user/installations".to_string(),
    };
    let output = std::process::Command::new("gh")
        .args(["api", &endpoint, "--jq", ".installations[].app_slug"])
        .output();
    let output = match output {
        Ok(out) if out.status.success() => out,
        Ok(out) => {
            eprintln!(
                "note: couldn't check for an existing sandy App ({}); proceeding. --force skips this check.",
                String::from_utf8_lossy(&out.stderr).trim()
            );
            return Ok(());
        }
        Err(_) => {
            eprintln!("note: `gh` not found, so can't check for an existing sandy App; proceeding.");
            return Ok(());
        }
    };
    let slugs = String::from_utf8_lossy(&output.stdout);
    let existing: Vec<&str> = slugs
        .lines()
        .map(str::trim)
        .filter(|slug| slug.starts_with(handle))
        .collect();
    if existing.is_empty() {
        Ok(())
    } else {
        Err(InstallError::Capture(format!(
            "a sandy App is already installed on this owner: {}. This org shares one App, so don't create another: \
             get its key from the shared store and run `sandy cred github import`, or pass --force to override.",
            existing.join(", ")
        )))
    }
}

/// `sandy cred github import`: set up this controller from an EXISTING shared App's
/// credentials (the one-shared-org-App model), no registration, no browser.
/// Members 2..N obtain the App's private key from the shared secret store and
/// point sandy at it; this writes the trust root the credential adapter reads.
///
/// # Errors
/// [`InstallError::AlreadyExists`] if a trust root of this name is already
/// configured, or an I/O / parse error reading the key or writing the config.
pub fn run_import(
    handle: &str,
    app_id: &str,
    installation_id: u64,
    pem_source: &Path,
    base_url: Option<String>,
    targets: Vec<Target>,
) -> Result<CredImported, InstallError> {
    sandy::validate_trust_root_name(handle)?;
    let dir = trust_roots_dir().map_err(|e| InstallError::Capture(e.to_string()))?;
    import_into(&dir, handle, app_id, installation_id, pem_source, base_url, targets)
}

/// `sandy cred github verify`: re-run the verify probe against an existing trust root —
/// dry-run mint a token scoped to the given capabilities and confirm the
/// installation grants them. Handy to re-check a shared App after an import.
///
/// # Errors
/// [`InstallError::Verify`] if the probe fails, or a config/load error.
pub fn run_verify(handle: &str, capabilities: &[Capability]) -> Result<CredVerified, InstallError> {
    sandy::validate_trust_root_name(handle)?;
    let dir = trust_roots_dir().map_err(|e| InstallError::Capture(e.to_string()))?;
    let cfg = config_path(&dir, handle);
    let root = TrustRoot::load(&cfg)?;
    provisioner_for(&root, handle).verify(&root, capabilities)?;
    Ok(CredVerified { verified: true })
}

/// Core of [`run_import`], with the trust-roots dir as a parameter so it is
/// testable without the real config dir. Returns the command's result.
fn import_into(
    dir: &Path,
    handle: &str,
    app_id: &str,
    installation_id: u64,
    pem_source: &Path,
    base_url: Option<String>,
    targets: Vec<Target>,
) -> Result<CredImported, InstallError> {
    // Before the key is read or anything is written.
    check_api_base(base_url.as_deref())?;
    let cfg = config_path(dir, handle);
    if cfg.exists() {
        return Err(InstallError::AlreadyExists { path: cfg });
    }
    let pem = std::fs::read_to_string(pem_source).map_err(|source| InstallError::Io {
        action: "read the shared private key",
        path: pem_source.to_path_buf(),
        source,
    })?;
    if !pem.contains("PRIVATE KEY") {
        return Err(InstallError::Capture(format!(
            "{} does not look like a PEM private key",
            pem_source.display()
        )));
    }
    let key_path = write_pem_in(dir, handle, &pem)?;
    let root = TrustRoot::Github {
        base_url,
        app_id: app_id.to_string(),
        private_key_path: key_path,
        installation_id,
        targets,
    };
    root.write(&cfg)?;
    Ok(CredImported {
        app_id: app_id.to_string(),
        installation_id,
        trust_root: cfg,
    })
}

#[cfg(test)]
mod tests {
    use std::{io::Write, net::TcpStream};

    use super::*;

    /// #736: an API base that would send the App's JWT in the clear or off host is refused at import, before the key
    /// is read or any file is written.
    #[test]
    fn import_refuses_a_bad_api_base_and_writes_nothing() -> anyhow::Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()?;
        let pem = dir.path().join("shared.pem");
        std::fs::write(&pem, "-----BEGIN PRIVATE KEY-----")?;
        for bad in [
            "http://ghe.example.com/api/v3",
            "https://user:hunter2@ghe.example.com",
            "https://ghe.example.com#x",
        ] {
            let err = import_into(dir.path(), "acme", "1", 2, &pem, Some(bad.to_string()), Vec::new()).expect_err(bad);
            let text = err.to_string();
            assert!(text.contains("base_url"), "{bad}: {text}");
            assert!(
                !text.contains("hunter2"),
                "the refusal must not repeat the value: {text}"
            );
        }
        assert!(!config_path(dir.path(), "acme").exists(), "nothing was written");
        assert!(!dir.path().join("acme.pem").exists(), "no key was copied");
        Ok(())
    }

    /// #736: `register` derives the API base from the web base for a GitHub Enterprise Server. A web base that would be
    /// refused as an API base is refused before the browser or the forge is touched.
    #[test]
    fn register_refuses_a_bad_web_base_before_contacting_anything() {
        for bad in [
            "http://ghe.example.com",
            "https://user:hunter2@ghe.example.com",
            "https://ghe.example.com?x=1",
        ] {
            let err = run_register(
                "acme",
                "acme-app",
                "https://example.com",
                Owner::User,
                bad,
                &[],
                Vec::new(),
                true,
                true,
            )
            .expect_err(bad);
            let text = err.to_string();
            assert!(text.contains("base_url"), "{bad}: {text}");
            assert!(
                !text.contains("hunter2"),
                "the refusal must not repeat the value: {text}"
            );
        }
    }

    /// The default web base stays github.com and needs no API base.
    #[test]
    fn the_default_web_base_derives_no_api_base() {
        assert_eq!(derived_api_base("https://github.com"), None);
        assert_eq!(
            derived_api_base("https://ghe.example.com").as_deref(),
            Some("https://ghe.example.com/api/v3")
        );
    }

    /// #194: rewriting the App key over an existing 0644 file leaves it 0600. The
    /// old writer opened with `truncate`, which kept the old mode.
    #[test]
    fn rewriting_the_app_key_over_a_wide_file_leaves_it_0600() -> anyhow::Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()?;
        let key = dir.path().join("acme.pem");
        std::fs::write(&key, "old")?;
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644))?;
        let written = write_pem_in(dir.path(), "acme", "-----BEGIN KEY-----")?;
        let mode = std::fs::metadata(&written)?.permissions().mode() & 0o777;
        anyhow::ensure!(mode == 0o600, "the App key came out {mode:o}");
        Ok(())
    }

    /// #194: a symlink at the App key path is replaced, never written through.
    #[test]
    fn the_app_key_is_never_written_through_a_symlink() -> anyhow::Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()?;
        let victim = dir.path().join("victim");
        std::fs::write(&victim, "untouched")?;
        std::os::unix::fs::symlink(&victim, dir.path().join("acme.pem"))?;
        let key = write_pem_in(dir.path(), "acme", "-----BEGIN KEY-----")?;
        anyhow::ensure!(
            std::fs::read_to_string(&victim)? == "untouched",
            "the key was written through a symlink"
        );
        anyhow::ensure!(
            std::fs::symlink_metadata(&key)?.is_file(),
            "the key path is still a symlink"
        );
        anyhow::ensure!(
            std::fs::read_to_string(&key)? == "-----BEGIN KEY-----",
            "the key was not written"
        );
        Ok(())
    }

    /// #193: the verify probe stages an installation token, so its dir must be
    /// 0700 from creation under any umask, freshly named (never a pre-created
    /// path), and under the validated staging base. The old dir was created at the
    /// umask's mode and narrowed by a chmod whose failure was discarded.
    /// The umask is process-wide; nextest runs each test in its own process.
    #[test]
    fn the_verify_probe_dir_is_private_from_creation() -> anyhow::Result<()> {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let previous = rustix::process::umask(rustix::fs::Mode::from_raw_mode(0o002));
        let made = (verify_tmp_dir(), verify_tmp_dir());
        rustix::process::umask(previous);
        let (first, second) = (made.0?, made.1?);
        let cleanup = || {
            let _ = std::fs::remove_dir_all(&first);
            let _ = std::fs::remove_dir_all(&second);
        };

        let meta = std::fs::metadata(&first)?;
        let mode = meta.permissions().mode() & 0o777;
        let checks = [
            (mode == 0o700, format!("the probe dir came out {mode:o}, not 0700")),
            (
                meta.uid() == rustix::process::getuid().as_raw(),
                "the probe dir is not this user's".to_owned(),
            ),
            (first != second, "two probes shared a dir name".to_owned()),
            (
                first.starts_with(sandy_fsutil::ensure_sandy_staging_base()?),
                format!("{} is outside the staging base", first.display()),
            ),
        ];
        cleanup();
        for (ok, why) in checks {
            anyhow::ensure!(ok, "{why}");
        }
        Ok(())
    }

    fn get(addr: &SocketAddr, target: &str) {
        let mut stream = TcpStream::connect(addr).expect("connect to catcher");
        write!(
            stream,
            "GET {target} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
        )
        .expect("send GET");
    }

    #[test]
    fn the_catcher_returns_the_named_params_for_a_matching_state() {
        let catcher = RedirectCatcher::bind().expect("bind");
        let addr = catcher.addr;
        let worker = std::thread::spawn(move || get(&addr, "/?code=abc123&state=nonce-xyz"));

        let got = catcher
            .serve_and_catch("https://github.com/settings/apps/new", "{}", "nonce-xyz", &["code"])
            .expect("catch");

        worker.join().expect("worker");
        assert_eq!(got.get("code").map(String::as_str), Some("abc123"));
    }

    #[test]
    fn the_catcher_rejects_a_foreign_state_and_waits_for_the_real_one() {
        let catcher = RedirectCatcher::bind().expect("bind");
        let addr = catcher.addr;
        let worker = std::thread::spawn(move || {
            get(&addr, "/?code=evil&state=wrong");
            get(&addr, "/?code=good&state=right");
        });

        let got = catcher
            .serve_and_catch("https://github.com/settings/apps/new", "{}", "right", &["code"])
            .expect("catch");

        worker.join().expect("worker");
        assert_eq!(
            got.get("code").map(String::as_str),
            Some("good"),
            "the foreign state is ignored"
        );
    }

    #[test]
    fn an_html_attribute_value_is_escaped() {
        assert_eq!(html_attr_escape(r#"a"b&c<d"#), "a&quot;b&amp;c&lt;d");
    }

    #[test]
    fn the_github_app_name_is_deterministic_from_the_owner() {
        // Deterministic, so every member resolves to the same shared App and the
        // duplicate check can find it by name.
        assert_eq!(
            github_app_name("sandy-runner", &Owner::Org("kauki-labs".to_string()), None),
            "sandy-runner-kauki-labs"
        );
        assert_eq!(github_app_name("sandy-runner", &Owner::User, None), "sandy-runner");
        assert_eq!(
            github_app_name("sandy-runner", &Owner::User, Some("exact-name")),
            "exact-name"
        );
    }

    #[test]
    fn the_config_path_is_the_named_json_under_the_dir() {
        let path = config_path(std::path::Path::new("/cfg/trust-roots"), "sandy-runner");
        assert_eq!(path, PathBuf::from("/cfg/trust-roots/sandy-runner.json"));
    }

    #[test]
    fn import_writes_a_trust_root_from_a_shared_pem_and_refuses_a_non_key() -> anyhow::Result<()> {
        let tmp = tempfile::TempDir::new()?;
        let roots = tmp.path().join("trust-roots");
        let pem = tmp.path().join("shared.pem");
        std::fs::write(
            &pem,
            "-----BEGIN RSA PRIVATE KEY-----\nx\n-----END RSA PRIVATE KEY-----\n",
        )?;

        let imported = import_into(
            &roots,
            "sandy-runner",
            "5285548",
            170_585_018,
            &pem,
            None,
            vec![Target("kauki-labs/sandy-pilot-test".to_string())],
        )
        .map_err(|e| anyhow::anyhow!("{e}"))?;

        match TrustRoot::load(&imported.trust_root)? {
            TrustRoot::Github {
                app_id,
                installation_id,
                ..
            } => {
                assert_eq!(app_id, "5285548");
                assert_eq!(installation_id, 170_585_018);
            }
            TrustRoot::Gitlab { .. } => panic!("expected a github trust root"),
        }

        // A second import of the same handle is refused (no clobber).
        assert!(
            matches!(
                import_into(&roots, "sandy-runner", "9", 9, &pem, None, Vec::new()),
                Err(InstallError::AlreadyExists { .. })
            ),
            "re-import of the same handle must be refused"
        );

        // A non-PEM file is refused.
        let not_a_key = tmp.path().join("bad");
        std::fs::write(&not_a_key, "not a key")?;
        assert!(
            import_into(&roots, "other", "1", 2, &not_a_key, None, Vec::new()).is_err(),
            "a non-PEM file is refused"
        );
        Ok(())
    }

    /// INV-1: importing a key with a known secret value prints neither the key
    /// body nor its source path's contents in plain or JSON.
    #[test]
    fn import_never_prints_the_key_in_either_format() -> anyhow::Result<()> {
        use crate::output::{OutputFormat, emit_to};

        let tmp = tempfile::TempDir::new()?;
        let pem = tmp.path().join("shared.pem");
        std::fs::write(
            &pem,
            "-----BEGIN RSA PRIVATE KEY-----\nsentinel-secret-0451\n-----END RSA PRIVATE KEY-----\n",
        )?;
        let imported = import_into(
            &tmp.path().join("roots"),
            "sandy-runner",
            "1",
            2,
            &pem,
            None,
            Vec::new(),
        )
        .map_err(|e| anyhow::anyhow!("{e}"))?;
        for format in [OutputFormat::Plain, OutputFormat::Json] {
            let mut out = Vec::new();
            emit_to(&imported, format, &mut out)?;
            let rendered = String::from_utf8(out)?;
            anyhow::ensure!(
                !rendered.contains("sentinel-secret-0451") && !rendered.contains("PRIVATE KEY"),
                "{format:?} output leaked the key: {rendered}"
            );
        }
        Ok(())
    }
}
