//! The mesh-join setup and teardown sequencer for one environment (#671, slice 1).
//!
//! Pure ordering logic over seams: a coordination server (headscale), the guest
//! secrets directory, the VM boot, the service readiness check and the delegator
//! link. It runs no network call itself, so the whole sequence is tier-2 testable
//! over fakes. Every seam call is bounded by a timeout.
//!
//! A join key is a credential. [`JoinKey`] never prints its value, and every
//! string this module returns or logs passes through the exact-key replace plus
//! [`redact`].
//!
//! # Cancellation
//! The caller picks the node name and passes it to [`setup`]. If the setup
//! future is dropped midway, the caller runs [`teardown`] with that name and no
//! key: the node (if it joined) is deleted by name, and an unused key is
//! short-lived (`key_ttl`) and single-use.

use std::{fmt, future::Future, time::Duration};

/// Secrets file holding the pre-auth join key.
pub const KEY_FILE: &str = "tailscale-authkey";
/// Secrets file holding the node name the guest sets as its hostname.
pub const HOSTNAME_FILE: &str = "hostname";
/// Marker the guest waits for. Written last, removed first.
pub const READY_FILE: &str = ".ready";
const REDACTED: &str = "[redacted]";

/// A single-use pre-auth key. Debug and Display never show the value.
#[derive(Clone, PartialEq, Eq)]
pub struct JoinKey(String);

impl JoinKey {
    /// Wrap a key value.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// The raw value. Only the secrets writer should call this.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for JoinKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("JoinKey(<redacted>)")
    }
}

impl fmt::Display for JoinKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// Mask `hskey-auth-...` and `tskey-...` tokens in `text`, ignoring case.
#[must_use]
pub fn redact(text: &str) -> String {
    const PREFIXES: [&str; 2] = ["hskey-auth-", "tskey-"];
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    loop {
        // ASCII lowercasing keeps byte offsets, so indexes carry over to `rest`.
        let lower = rest.to_ascii_lowercase();
        let Some(at) = PREFIXES.iter().filter_map(|p| lower.find(p)).min() else {
            break;
        };
        out.push_str(&rest[..at]);
        out.push_str(REDACTED);
        let tail = &rest[at..];
        let end = tail
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == '_'))
            .unwrap_or(tail.len());
        rest = &tail[end..];
    }
    out.push_str(rest);
    out
}

/// Replace the exact value of `key`, then mask key-shaped tokens.
fn scrub(text: &str, key: Option<&JoinKey>) -> String {
    match key {
        Some(k) if !k.expose().is_empty() => redact(&text.replace(k.expose(), REDACTED)),
        _ => redact(text),
    }
}

/// A seam failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct SeamError(String);

impl SeamError {
    /// Build an error. The module scrubs the exact key at every exit; this
    /// constructor only masks key-shaped tokens.
    pub fn new(message: impl AsRef<str>) -> Self {
        Self(redact(message.as_ref()))
    }
}

/// Source of random bytes, injected so names are deterministic in tests.
pub trait RandomBytes {
    /// Fill `buf` with random bytes.
    fn fill(&mut self, buf: &mut [u8]);
}

/// `sandbox-<16 hex>` from 8 random bytes.
pub fn sandbox_name(rng: &mut impl RandomBytes) -> String {
    let mut bytes = [0u8; 8];
    rng.fill(&mut bytes);
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!("sandbox-{hex}")
}

/// The coordination server (headscale) the guest joins.
pub trait Coordination: Send + Sync {
    /// Mint a single-use, ephemeral pre-auth key for `tag`, valid for `ttl`.
    fn mint_join_key(&self, tag: &str, ttl: Duration) -> impl Future<Output = Result<JoinKey, SeamError>> + Send;
    /// Delete the node `name`. Idempotent: an absent node counts as success.
    fn delete_node(&self, name: &str) -> impl Future<Output = Result<(), SeamError>> + Send;
    /// Expire `key` so it can no longer join. Idempotent: an absent or already
    /// expired key counts as success.
    fn expire_key(&self, key: &JoinKey) -> impl Future<Output = Result<(), SeamError>> + Send;
    /// Whether the node `name` is online.
    fn node_online(&self, name: &str) -> impl Future<Output = Result<bool, SeamError>> + Send;
}

/// The guest secrets directory.
pub trait GuestDelivery: Send + Sync {
    /// Make the directory ready to receive files, with no stale content.
    fn prepare(&self) -> impl Future<Output = Result<(), SeamError>> + Send;
    /// Write `files`, removing [`READY_FILE`] first and writing it last.
    fn deliver(&self, files: &[(&str, &[u8])]) -> impl Future<Output = Result<(), SeamError>> + Send;
    /// Remove the directory and everything in it. Idempotent.
    fn remove_secrets(&self) -> impl Future<Output = Result<(), SeamError>> + Send;
}

/// Boots the guest VM named `name`.
pub trait VmBoot: Send + Sync {
    /// Start the VM.
    fn boot(&self, name: &str) -> impl Future<Output = Result<(), SeamError>> + Send;
}

/// Readiness of the guest service: `GET /` answers below 500.
pub trait ServiceReady: Send + Sync {
    /// One probe of the service on node `name`.
    fn ready(&self, name: &str) -> impl Future<Output = Result<bool, SeamError>> + Send;
}

/// The delegator link (`t3 environment link`).
pub trait Linker: Send + Sync {
    /// Link node `name` with `access`.
    fn link(&self, name: &str, access: LinkAccess) -> impl Future<Output = Result<(), SeamError>> + Send;
}

/// Steps teardown runs before the key expiry and node delete.
pub trait TeardownSteps: Send + Sync {
    /// Unlink the delegator link. A failure fails teardown after the rest runs.
    fn unlink(&self) -> impl Future<Output = Result<(), SeamError>> + Send;
    /// Revoke the environment's sessions. A failure fails teardown after the rest runs.
    fn revoke_sessions(&self) -> impl Future<Output = Result<(), SeamError>> + Send;
    /// `tailscale logout` in the guest. Best effort: a failure only logs.
    fn tailscale_logout(&self) -> impl Future<Output = Result<(), SeamError>> + Send;
}

/// File operations behind a [`SecretsDir`]. Removal is idempotent.
pub trait FileSink: Send + Sync {
    /// Create the directory.
    fn ensure_dir(&self) -> Result<(), SeamError>;
    /// Remove every file in the directory, keeping the directory.
    fn clear_dir(&self) -> Result<(), SeamError>;
    /// Write one file.
    fn write_file(&self, name: &str, bytes: &[u8]) -> Result<(), SeamError>;
    /// Remove one file; absent is fine.
    fn remove_file(&self, name: &str) -> Result<(), SeamError>;
    /// Remove the directory tree.
    fn remove_dir_all(&self) -> Result<(), SeamError>;
}

/// [`GuestDelivery`] over a [`FileSink`], enforcing the `.ready` ordering and
/// the required, non-empty `hostname` file.
pub struct SecretsDir<S>(S);

impl<S: FileSink> SecretsDir<S> {
    /// Wrap a sink.
    pub fn new(sink: S) -> Self {
        Self(sink)
    }
}

impl<S: FileSink> GuestDelivery for SecretsDir<S> {
    async fn prepare(&self) -> Result<(), SeamError> {
        self.0.ensure_dir()
    }

    async fn deliver(&self, files: &[(&str, &[u8])]) -> Result<(), SeamError> {
        match files.iter().find(|(n, _)| *n == HOSTNAME_FILE) {
            None => {
                return Err(SeamError::new(
                    "missing hostname file: the guest would keep its default name",
                ));
            }
            Some((_, b)) if b.is_empty() => {
                return Err(SeamError::new("empty hostname file"));
            }
            Some(_) => {}
        }
        if files.iter().any(|(n, _)| *n == READY_FILE) {
            return Err(SeamError::new("the ready marker is written by delivery, not passed in"));
        }
        self.0.remove_file(READY_FILE)?;
        for (name, bytes) in files {
            self.0.write_file(name, bytes)?;
        }
        self.0.write_file(READY_FILE, b"")
    }

    async fn remove_secrets(&self) -> Result<(), SeamError> {
        self.0.remove_dir_all()
    }
}

/// Access mode of the delegator link (`t3 environment link --access`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkAccess {
    /// `read-only`.
    ReadOnly,
    /// `approval-required`, the CLI default.
    ApprovalRequired,
    /// `auto-accept-edits`.
    AutoAccept,
    /// `auto`.
    Auto,
    /// `full-access`, the only mode a sandbox VM accepts.
    FullAccess,
}

impl fmt::Display for LinkAccess {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ReadOnly => "read-only",
            Self::ApprovalRequired => "approval-required",
            Self::AutoAccept => "auto-accept-edits",
            Self::Auto => "auto",
            Self::FullAccess => "full-access",
        })
    }
}

/// The mode the sequencer's link step uses.
pub const LINK_ACCESS: LinkAccess = LinkAccess::FullAccess;

/// A link made with a lower mode than the VM needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("runtime_mode_escalation_denied: link access {0} is lower than full-access")]
pub struct LinkModeError(pub LinkAccess);

/// Reject a link mode lower than full access, at link time.
///
/// # Errors
/// [`LinkModeError`] for any mode but [`LinkAccess::FullAccess`].
pub fn check_link_access(access: LinkAccess) -> Result<(), LinkModeError> {
    if access == LinkAccess::FullAccess {
        return Ok(());
    }
    Err(LinkModeError(access))
}

/// Knobs for [`setup`].
#[derive(Debug, Clone)]
pub struct SetupConfig<'a> {
    /// ACL tag the node joins under.
    pub tag: &'a str,
    /// Lifetime of the pre-auth key.
    pub key_ttl: Duration,
    /// Probes before the node or service counts as not coming up. At least 1.
    pub poll_attempts: u32,
    /// Pause between probes.
    pub poll_interval: Duration,
    /// Bound on every seam call.
    pub call_timeout: Duration,
    /// Mode of the delegator link; [`LINK_ACCESS`] unless a test says otherwise.
    pub link_access: LinkAccess,
}

/// A setup step, named in a failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetupStep {
    /// Rejecting a bad [`SetupConfig`].
    Config,
    /// Preparing the secrets directory.
    Prepare,
    /// Minting the join key.
    MintKey,
    /// Booting the VM.
    Boot,
    /// Writing the secret files.
    Deliver,
    /// Waiting for the node to join.
    JoinOnline,
    /// Waiting for the service to answer.
    ServiceReady,
    /// Linking the delegator.
    Link,
}

impl fmt::Display for SetupStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Config => "config",
            Self::Prepare => "prepare",
            Self::MintKey => "mint_key",
            Self::Boot => "boot",
            Self::Deliver => "deliver",
            Self::JoinOnline => "join_online",
            Self::ServiceReady => "service_ready",
            Self::Link => "link",
        })
    }
}

/// Setup failed at `step`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("setup failed at {step}: {reason}")]
pub struct SetupError {
    /// The step that failed.
    pub step: SetupStep,
    /// The node name, so the caller can run teardown for a node that may exist.
    pub name: String,
    /// Scrubbed reason.
    pub reason: String,
    /// The minted key, if any. Pass it to [`teardown`]: when `key_burned` is
    /// false its expiry failed and it may still be live.
    pub key: Option<JoinKey>,
    /// True only when a key was minted and its expiry succeeded.
    pub key_burned: bool,
}

/// What an environment row shows after setup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvStatus {
    /// Node online and service answering.
    Ready,
    /// Setup failed; the scrubbed reason.
    Failed {
        /// Scrubbed reason, naming the step.
        reason: String,
    },
}

impl From<&SetupError> for EnvStatus {
    fn from(e: &SetupError) -> Self {
        Self::Failed { reason: e.to_string() }
    }
}

/// A joined, serving environment. The key is kept so teardown can expire it.
#[derive(Debug)]
pub struct Provisioned {
    /// The node name.
    pub name: String,
    /// The (used) join key.
    pub key: JoinKey,
}

/// Bound one seam call by `limit`.
async fn bounded<T>(limit: Duration, call: impl Future<Output = Result<T, SeamError>>) -> Result<T, SeamError> {
    tokio::time::timeout(limit, call)
        .await
        .unwrap_or_else(|_| Err(SeamError::new(format!("timed out after {limit:?}"))))
}

/// Run setup for the node `name`: prepare, mint key, boot, deliver, node
/// online, service ready, link. Choose `name` with [`sandbox_name`].
///
/// # Errors
/// [`SetupError`] naming the failed step. A key minted before the failure is
/// expired; if that expiry fails the error carries the key with
/// `key_burned == false` and the caller must pass it to [`teardown`].
pub async fn setup<C, G, B, S, L>(
    coord: &C,
    guest: &G,
    vm: &B,
    service: &S,
    linker: &L,
    name: &str,
    cfg: &SetupConfig<'_>,
) -> Result<Provisioned, SetupError>
where
    C: Coordination,
    G: GuestDelivery,
    B: VmBoot,
    S: ServiceReady,
    L: Linker,
{
    let _ = (coord, guest, vm, service, linker, name, cfg);
    unimplemented!("setup")
}

#[allow(clippy::too_many_arguments, reason = "internal step runner over the seams")]
async fn join<C, G, B, S, L>(
    coord: &C,
    guest: &G,
    vm: &B,
    service: &S,
    linker: &L,
    name: &str,
    key: &JoinKey,
    cfg: &SetupConfig<'_>,
) -> Result<(), (SetupStep, SeamError)>
where
    C: Coordination,
    G: GuestDelivery,
    B: VmBoot,
    S: ServiceReady,
    L: Linker,
{
    let t = cfg.call_timeout;
    bounded(t, vm.boot(name)).await.map_err(|e| (SetupStep::Boot, e))?;
    let files: [(&str, &[u8]); 2] = [(KEY_FILE, key.expose().as_bytes()), (HOSTNAME_FILE, name.as_bytes())];
    bounded(t, guest.deliver(&files))
        .await
        .map_err(|e| (SetupStep::Deliver, e))?;
    if !poll(cfg, || coord.node_online(name))
        .await
        .map_err(|e| (SetupStep::JoinOnline, e))?
    {
        return Err((
            SetupStep::JoinOnline,
            SeamError::new(format!(
                "node {name} not online after {} probes: the key may be expired, reused or refused",
                cfg.poll_attempts
            )),
        ));
    }
    if !poll(cfg, || service.ready(name))
        .await
        .map_err(|e| (SetupStep::ServiceReady, e))?
    {
        return Err((
            SetupStep::ServiceReady,
            SeamError::new(format!(
                "service on {name} did not answer below 500 after {} probes",
                cfg.poll_attempts
            )),
        ));
    }
    check_link_access(cfg.link_access).map_err(|e| (SetupStep::Link, SeamError::new(e.to_string())))?;
    bounded(t, linker.link(name, cfg.link_access))
        .await
        .map_err(|e| (SetupStep::Link, e))
}

/// Probe until `f` answers `true` or the attempts run out.
async fn poll<F, Fut>(cfg: &SetupConfig<'_>, mut f: F) -> Result<bool, SeamError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<bool, SeamError>>,
{
    for attempt in 0..cfg.poll_attempts {
        if attempt > 0 {
            tokio::time::sleep(cfg.poll_interval).await;
        }
        if bounded(cfg.call_timeout, f()).await? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Teardown did not finish cleanly. The caller keeps the environment record.
/// Each reason lists every failed step, scrubbed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TeardownError {
    /// The node delete failed; the node may still exist.
    #[error("node {name} is still present: {reason}")]
    NodeStillPresent {
        /// The node name.
        name: String,
        /// Scrubbed reason.
        reason: String,
    },
    /// The node is gone but the key or secrets could not be removed.
    #[error("node {name} deleted but residue remains: {reason}")]
    Residue {
        /// The node name.
        name: String,
        /// Scrubbed reason.
        reason: String,
    },
    /// Everything was removed but unlink or session revocation failed.
    #[error("node {name} deleted but a teardown step failed: {reason}")]
    HookFailed {
        /// The node name.
        name: String,
        /// Scrubbed reason.
        reason: String,
    },
}

/// Run teardown: unlink, revoke sessions, tailscale logout, expire key, delete
/// node, remove secrets. Every step runs whatever an earlier one did. The key
/// expires before the node delete so a guest that is still up cannot rejoin.
/// Logout is best effort; every other failure fails teardown. A node that
/// setup never finished (a dropped future) is torn down with `key == None`.
///
/// # Errors
/// [`TeardownError`], never `Ok` while the node may exist or a key may be live.
pub async fn teardown<C, G, T>(
    coord: &C,
    guest: &G,
    steps: &T,
    name: &str,
    key: Option<&JoinKey>,
    call_timeout: Duration,
) -> Result<(), TeardownError>
where
    C: Coordination,
    G: GuestDelivery,
    T: TeardownSteps,
{
    let _ = (coord, guest, steps, name, key, call_timeout);
    unimplemented!("teardown")
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        sync::{Arc, Mutex, MutexGuard, PoisonError},
    };

    use anyhow::{Context, Result, bail};

    use super::*;

    #[derive(Clone, Copy, Default, PartialEq)]
    enum Logout {
        #[default]
        Ok,
        Fail,
        Hang,
    }

    #[derive(Default)]
    struct State {
        log: Vec<String>,
        minted: u32,
        mint_value: Option<String>,
        files: BTreeMap<String, Vec<u8>>,
        written: Vec<(String, Vec<u8>)>,
        online: bool,
        service_down: bool,
        boot_error: Option<String>,
        boot_hangs: bool,
        write_fail: Option<String>,
        secrets_fail: Option<String>,
        delete_error: Option<String>,
        expire_error: Option<String>,
        unlink_fails: bool,
        revoke_fails: bool,
        logout: Logout,
        link_fails: bool,
        expired: Vec<String>,
        deleted: Vec<String>,
        linked: Vec<(String, LinkAccess)>,
    }

    #[derive(Clone, Default)]
    struct World(Arc<Mutex<State>>);

    impl World {
        fn online() -> Self {
            let w = Self::default();
            w.st().online = true;
            w
        }

        fn st(&self) -> MutexGuard<'_, State> {
            self.0.lock().unwrap_or_else(PoisonError::into_inner)
        }

        fn log(&self) -> Vec<String> {
            self.st().log.clone()
        }

        fn push(&self, line: impl Into<String>) {
            self.st().log.push(line.into());
        }

        fn ran(&self, line: &str) -> bool {
            self.log().iter().any(|l| l == line)
        }
    }

    impl Coordination for World {
        async fn mint_join_key(&self, _tag: &str, _ttl: Duration) -> Result<JoinKey, SeamError> {
            self.push("mint_key");
            let mut s = self.st();
            s.minted += 1;
            let value = s
                .mint_value
                .clone()
                .unwrap_or_else(|| format!("hskey-auth-abc{}", s.minted));
            Ok(JoinKey::new(value))
        }

        async fn delete_node(&self, name: &str) -> Result<(), SeamError> {
            self.push("delete_node");
            let mut s = self.st();
            s.deleted.push(name.to_owned());
            match s.delete_error.clone() {
                Some(e) => Err(SeamError::new(e)),
                None => Ok(()),
            }
        }

        async fn expire_key(&self, key: &JoinKey) -> Result<(), SeamError> {
            self.push("expire_key");
            let mut s = self.st();
            s.expired.push(key.expose().to_owned());
            match s.expire_error.clone() {
                Some(e) => Err(SeamError::new(e)),
                None => Ok(()),
            }
        }

        async fn node_online(&self, _name: &str) -> Result<bool, SeamError> {
            self.push("node_online");
            Ok(self.st().online)
        }
    }

    impl FileSink for World {
        fn ensure_dir(&self) -> Result<(), SeamError> {
            self.push("ensure_dir");
            Ok(())
        }

        fn clear_dir(&self) -> Result<(), SeamError> {
            self.push("clear_dir");
            self.st().files.clear();
            Ok(())
        }

        fn write_file(&self, name: &str, bytes: &[u8]) -> Result<(), SeamError> {
            self.push(format!("write {name}"));
            let mut s = self.st();
            if s.write_fail.as_deref() == Some(name) {
                return Err(SeamError::new(format!("disk full writing {name}")));
            }
            s.files.insert(name.into(), bytes.to_vec());
            s.written.push((name.into(), bytes.to_vec()));
            Ok(())
        }

        fn remove_file(&self, name: &str) -> Result<(), SeamError> {
            self.push(format!("remove {name}"));
            self.st().files.remove(name);
            Ok(())
        }

        fn remove_dir_all(&self) -> Result<(), SeamError> {
            self.push("remove_secrets");
            let mut s = self.st();
            if let Some(e) = s.secrets_fail.clone() {
                return Err(SeamError::new(e));
            }
            s.files.clear();
            Ok(())
        }
    }

    impl VmBoot for World {
        async fn boot(&self, _name: &str) -> Result<(), SeamError> {
            self.push("boot");
            let (err, hangs) = {
                let s = self.st();
                (s.boot_error.clone(), s.boot_hangs)
            };
            if hangs {
                std::future::pending::<()>().await;
            }
            match err {
                Some(e) => Err(SeamError::new(e)),
                None => Ok(()),
            }
        }
    }

    impl ServiceReady for World {
        async fn ready(&self, _name: &str) -> Result<bool, SeamError> {
            self.push("service_ready");
            Ok(!self.st().service_down)
        }
    }

    impl Linker for World {
        async fn link(&self, name: &str, access: LinkAccess) -> Result<(), SeamError> {
            self.push("link");
            let mut s = self.st();
            s.linked.push((name.to_owned(), access));
            if s.link_fails {
                return Err(SeamError::new("link refused"));
            }
            Ok(())
        }
    }

    impl TeardownSteps for World {
        async fn unlink(&self) -> Result<(), SeamError> {
            self.push("unlink");
            if self.st().unlink_fails {
                return Err(SeamError::new("unlink refused"));
            }
            Ok(())
        }

        async fn revoke_sessions(&self) -> Result<(), SeamError> {
            self.push("revoke_sessions");
            if self.st().revoke_fails {
                return Err(SeamError::new("revoke refused"));
            }
            Ok(())
        }

        async fn tailscale_logout(&self) -> Result<(), SeamError> {
            self.push("tailscale_logout");
            let mode = self.st().logout;
            match mode {
                Logout::Ok => Ok(()),
                Logout::Fail => Err(SeamError::new("logout refused")),
                Logout::Hang => {
                    std::future::pending::<()>().await;
                    Ok(())
                }
            }
        }
    }

    struct Fixed;
    impl RandomBytes for Fixed {
        fn fill(&mut self, buf: &mut [u8]) {
            for (i, b) in buf.iter_mut().enumerate() {
                *b = 0xa0 + u8::try_from(i).unwrap_or(0);
            }
        }
    }

    const NAME: &str = "sandbox-test";
    const T: Duration = Duration::from_secs(1);
    const CFG: SetupConfig<'static> = SetupConfig {
        tag: "tag:t3",
        key_ttl: Duration::from_secs(60),
        poll_attempts: 3,
        poll_interval: Duration::ZERO,
        call_timeout: T,
        link_access: LINK_ACCESS,
    };

    async fn run_with(w: &World, cfg: &SetupConfig<'_>) -> Result<Provisioned, SetupError> {
        setup(w, &SecretsDir::new(w.clone()), w, w, w, NAME, cfg).await
    }

    async fn run_setup(w: &World) -> Result<Provisioned, SetupError> {
        run_with(w, &CFG).await
    }

    async fn run_teardown(w: &World, key: Option<&JoinKey>, limit: Duration) -> Result<(), TeardownError> {
        teardown(w, &SecretsDir::new(w.clone()), w, NAME, key, limit).await
    }

    #[test]
    fn the_name_is_sandbox_and_sixteen_hex_digits() {
        assert_eq!(sandbox_name(&mut Fixed), "sandbox-a0a1a2a3a4a5a6a7");
    }

    #[tokio::test]
    async fn setup_runs_its_steps_in_order_and_mints_the_key_between_prepare_and_boot() -> Result<()> {
        let w = World::online();
        let p = run_setup(&w).await.context("setup")?;
        assert_eq!(p.name, NAME);
        assert_eq!(
            w.log(),
            [
                "ensure_dir",
                "clear_dir",
                "mint_key",
                "boot",
                "remove .ready",
                "write tailscale-authkey",
                "write hostname",
                "write .ready",
                "node_online",
                "service_ready",
                "link",
            ]
        );
        assert_eq!(w.st().linked, [(NAME.to_owned(), LinkAccess::FullAccess)]);
        Ok(())
    }

    #[tokio::test]
    async fn a_reinject_removes_ready_first_and_writes_it_last() -> Result<()> {
        let w = World::default();
        let dir = SecretsDir::new(w.clone());
        let files: [(&str, &[u8]); 2] = [(KEY_FILE, b"k2"), (HOSTNAME_FILE, b"sandbox-x")];
        dir.deliver(&files).await.context("first")?;
        dir.deliver(&files).await.context("second")?;
        let log = w.log();
        let second = &log[4..];
        assert_eq!(second.first().map(String::as_str), Some("remove .ready"));
        assert_eq!(second.last().map(String::as_str), Some("write .ready"));
        assert_eq!(second.iter().filter(|l| *l == "write .ready").count(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn a_delivery_without_a_usable_hostname_or_with_a_ready_file_is_rejected() -> Result<()> {
        let bad: [Vec<(&str, &[u8])>; 3] = [
            vec![(KEY_FILE, b"k".as_slice())],
            vec![(KEY_FILE, b"k".as_slice()), (HOSTNAME_FILE, b"".as_slice())],
            vec![(HOSTNAME_FILE, b"n".as_slice()), (READY_FILE, b"".as_slice())],
        ];
        for files in bad {
            let w = World::default();
            let Err(e) = SecretsDir::new(w.clone()).deliver(&files).await else {
                bail!("delivery of {files:?} must fail");
            };
            assert!(!e.to_string().is_empty());
            assert!(w.st().files.is_empty(), "nothing may be written");
        }
        let w = World::default();
        let Err(e) = SecretsDir::new(w).deliver(&[(KEY_FILE, b"k".as_slice())]).await else {
            bail!("must fail");
        };
        assert!(e.to_string().contains("hostname"), "{e}");
        Ok(())
    }

    #[tokio::test]
    async fn prepare_clears_a_stale_marker_key_and_hostname_from_a_reused_dir() -> Result<()> {
        let w = World::default();
        let dir = SecretsDir::new(w.clone());
        dir.deliver(&[(KEY_FILE, b"old".as_slice()), (HOSTNAME_FILE, b"old-name".as_slice())])
            .await
            .context("first delivery")?;
        assert!(w.st().files.contains_key(READY_FILE));
        dir.prepare().await.context("prepare")?;
        assert!(w.st().files.is_empty(), "{:?}", w.st().files.keys());
        Ok(())
    }

    #[tokio::test]
    async fn an_expired_key_fails_the_environment_and_no_retry_reuses_it() -> Result<()> {
        let w = World::default();
        let Err(e) = run_setup(&w).await else {
            bail!("a node that never joins must fail setup");
        };
        assert_eq!(e.step, SetupStep::JoinOnline);
        assert!(e.key_burned);
        assert!(matches!(EnvStatus::from(&e), EnvStatus::Failed { .. }));
        let first_key = w.st().written[0].1.clone();
        assert_eq!(w.st().expired, [String::from_utf8(first_key.clone())?]);

        w.st().online = true;
        run_setup(&w).await.context("retry")?;
        let retry_key = w
            .st()
            .written
            .iter()
            .rfind(|(n, _)| n == KEY_FILE)
            .context("key")?
            .1
            .clone();
        assert_ne!(first_key, retry_key, "a retry must mint a fresh key");
        assert_eq!(w.st().minted, 2);
        Ok(())
    }

    #[tokio::test]
    async fn every_failing_step_after_the_mint_expires_the_minted_key() -> Result<()> {
        let cases: [(SetupStep, fn(&mut State)); 4] = [
            (SetupStep::Boot, |s| s.boot_error = Some("no kvm".into())),
            (SetupStep::Deliver, |s| s.write_fail = Some(HOSTNAME_FILE.into())),
            (SetupStep::ServiceReady, |s| s.service_down = true),
            (SetupStep::Link, |s| s.link_fails = true),
        ];
        for (step, knob) in cases {
            let w = World::online();
            knob(&mut w.st());
            let Err(e) = run_setup(&w).await else {
                bail!("{step} must fail setup");
            };
            assert_eq!(e.step, step);
            assert!(e.key_burned, "{step}");
            assert_eq!(w.st().expired, ["hskey-auth-abc1"], "{step}");
        }
        Ok(())
    }

    #[tokio::test]
    async fn a_failed_expiry_is_not_burned_and_teardown_will_not_succeed_while_the_key_lives() -> Result<()> {
        let w = World::online();
        {
            let mut s = w.st();
            s.write_fail = Some(HOSTNAME_FILE.into());
            s.expire_error = Some("headscale 500".into());
        }
        let Err(e) = run_setup(&w).await else {
            bail!("deliver failure must fail setup");
        };
        assert_eq!(e.step, SetupStep::Deliver);
        assert!(!e.key_burned, "an unexpired key is not burned");
        assert!(e.reason.contains("key expiry failed"), "{}", e.reason);
        let key = e.key.clone().context("the error must carry the key")?;

        let r = run_teardown(&w, Some(&key), T).await;
        assert!(matches!(r, Err(TeardownError::Residue { .. })), "{r:?}");

        w.st().expire_error = None;
        run_teardown(&w, Some(&key), T).await.context("retry")?;
        assert_eq!(w.st().expired.last().map(String::as_str), Some(key.expose()));
        Ok(())
    }

    #[tokio::test]
    async fn a_dropped_setup_future_leaves_a_node_teardown_deletes_by_name() -> Result<()> {
        let w = World::online();
        w.st().boot_hangs = true;
        let r = tokio::time::timeout(Duration::from_millis(30), run_setup(&w)).await;
        assert!(r.is_err(), "setup must still be waiting on the boot");
        run_teardown(&w, None, T).await.context("teardown")?;
        assert_eq!(w.st().deleted, [NAME]);
        Ok(())
    }

    #[tokio::test]
    async fn a_key_without_the_prefix_never_leaves_the_module_on_setup_or_teardown() -> Result<()> {
        let w = World::online();
        {
            let mut s = w.st();
            s.mint_value = Some("plainsecret99".into());
            s.boot_error = Some("dial with plainsecret99 failed".into());
        }
        let Err(e) = run_setup(&w).await else {
            bail!("boot failure must fail setup");
        };
        for text in [e.to_string(), format!("{e:?}"), format!("{:?}", EnvStatus::from(&e))] {
            assert!(!text.contains("plainsecret99"), "{text}");
        }

        let key = JoinKey::new("plainsecret99");
        let w = World::online();
        {
            let mut s = w.st();
            s.delete_error = Some("rm node plainsecret99 failed".into());
            s.secrets_fail = Some("rm dir plainsecret99 failed".into());
            s.expire_error = Some("expire plainsecret99 failed".into());
        }
        let r = run_teardown(&w, Some(&key), T).await;
        let Err(err) = r else { bail!("must fail") };
        for text in [err.to_string(), format!("{err:?}")] {
            assert!(!text.contains("plainsecret99"), "{text}");
        }
        w.st().delete_error = None;
        let Err(err) = run_teardown(&w, Some(&key), T).await else {
            bail!("residue must fail")
        };
        assert!(matches!(err, TeardownError::Residue { .. }));
        assert!(!format!("{err}{err:?}").contains("plainsecret99"));
        Ok(())
    }

    #[test]
    fn redaction_masks_key_shaped_tokens_in_any_case_and_the_key_type_prints_nothing() {
        assert_eq!(redact("x tskey-auth-k1_Z9 y"), "x [redacted] y");
        assert_eq!(redact("x HSKEY-AUTH-AbC9 y TsKey-q"), "x [redacted] y [redacted]");
        let key = JoinKey::new("hskey-auth-abc");
        assert!(!format!("{key:?}{key}").contains("abc"));
    }

    #[tokio::test]
    async fn a_join_key_never_shows_in_debug_display_or_errors() -> Result<()> {
        let w = World::online();
        w.st().boot_error = Some("run: tailscale up --auth-key=hskey-auth-abc1 --reset".into());
        let Err(e) = run_setup(&w).await else {
            bail!("a failed boot must fail setup");
        };
        for text in [format!("{e}"), format!("{e:?}")] {
            assert!(!text.contains("hskey-auth-abc"), "{text}");
        }
        assert_eq!(e.step, SetupStep::Boot);
        let ok = World::online();
        let p = run_setup(&ok).await.context("setup")?;
        assert!(!format!("{p:?}").contains("hskey-auth-abc"));
        Ok(())
    }

    #[tokio::test]
    async fn teardown_runs_in_order_expiring_the_key_before_the_node_delete() -> Result<()> {
        let w = World::online();
        let key = JoinKey::new("hskey-auth-abc1");
        run_teardown(&w, Some(&key), T).await.context("teardown")?;
        assert_eq!(
            w.log(),
            [
                "unlink",
                "revoke_sessions",
                "tailscale_logout",
                "expire_key",
                "delete_node",
                "remove_secrets",
            ]
        );
        assert_eq!(w.st().expired, ["hskey-auth-abc1"]);
        assert_eq!(w.st().deleted, [NAME]);
        Ok(())
    }

    #[tokio::test]
    async fn a_failed_node_delete_reports_the_node_present_and_still_cleans_up() -> Result<()> {
        let w = World::online();
        {
            let mut s = w.st();
            s.delete_error = Some("headscale 500".into());
            s.secrets_fail = Some("busy".into());
        }
        let key = JoinKey::new("hskey-auth-abc1");
        let r = run_teardown(&w, Some(&key), T).await;
        let Err(TeardownError::NodeStillPresent { reason, .. }) = r else {
            bail!("expected NodeStillPresent, got {r:?}");
        };
        assert!(
            reason.contains("headscale 500") && reason.contains("secrets: busy"),
            "{reason}"
        );
        assert!(w.ran("expire_key") && w.ran("remove_secrets"));
        Ok(())
    }

    #[tokio::test]
    async fn a_failed_key_expiry_or_secrets_removal_after_the_delete_is_residue() -> Result<()> {
        for knob in [
            (|s: &mut State| s.expire_error = Some("nope".into())) as fn(&mut State),
            |s| s.secrets_fail = Some("busy".into()),
        ] {
            let w = World::online();
            knob(&mut w.st());
            let key = JoinKey::new("hskey-auth-abc1");
            let r = run_teardown(&w, Some(&key), T).await;
            assert!(matches!(r, Err(TeardownError::Residue { .. })), "{r:?}");
            assert!(w.ran("delete_node"));
        }
        Ok(())
    }

    #[tokio::test]
    async fn a_failed_unlink_or_revoke_fails_teardown_after_the_rest_ran_but_logout_does_not() -> Result<()> {
        let w = World::online();
        w.st().unlink_fails = true;
        let r = run_teardown(&w, None, T).await;
        assert!(matches!(r, Err(TeardownError::HookFailed { .. })), "{r:?}");
        for step in ["revoke_sessions", "tailscale_logout", "delete_node", "remove_secrets"] {
            assert!(w.ran(step), "{step} must still run");
        }

        let w = World::online();
        w.st().revoke_fails = true;
        assert!(matches!(
            run_teardown(&w, None, T).await,
            Err(TeardownError::HookFailed { .. })
        ));

        let w = World::online();
        w.st().logout = Logout::Fail;
        run_teardown(&w, None, T).await.context("logout is best effort")?;

        let w = World::online();
        {
            let mut s = w.st();
            s.logout = Logout::Fail;
            s.unlink_fails = true;
        }
        assert!(
            run_teardown(&w, None, T).await.is_err(),
            "a failing best-effort step must not mask a real failure"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_hanging_logout_times_out_and_does_not_block_the_node_delete() -> Result<()> {
        let w = World::online();
        w.st().logout = Logout::Hang;
        run_teardown(&w, None, Duration::from_millis(20))
            .await
            .context("teardown")?;
        assert_eq!(w.st().deleted, [NAME]);
        Ok(())
    }

    #[tokio::test]
    async fn zero_poll_attempts_is_a_config_error_and_mints_nothing() -> Result<()> {
        let w = World::online();
        let cfg = SetupConfig {
            poll_attempts: 0,
            ..CFG
        };
        let Err(e) = run_with(&w, &cfg).await else {
            bail!("zero attempts must be rejected");
        };
        assert_eq!(e.step, SetupStep::Config);
        assert!(w.log().is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn setup_refuses_a_link_below_full_access_and_never_calls_the_linker() -> Result<()> {
        let w = World::online();
        let cfg = SetupConfig {
            link_access: LinkAccess::ApprovalRequired,
            ..CFG
        };
        let Err(e) = run_with(&w, &cfg).await else {
            bail!("a lower link mode must fail setup");
        };
        assert_eq!(e.step, SetupStep::Link);
        assert!(e.reason.contains("runtime_mode_escalation_denied"), "{}", e.reason);
        assert!(e.reason.contains("approval-required"), "{}", e.reason);
        assert!(w.st().linked.is_empty());
        assert!(e.key_burned);
        Ok(())
    }

    #[test]
    fn a_link_below_full_access_is_denied_with_the_cli_spelling() {
        assert_eq!(LINK_ACCESS, LinkAccess::FullAccess);
        assert!(check_link_access(LinkAccess::FullAccess).is_ok());
        for (lower, spelling) in [
            (LinkAccess::ReadOnly, "read-only"),
            (LinkAccess::ApprovalRequired, "approval-required"),
            (LinkAccess::AutoAccept, "auto-accept-edits"),
            (LinkAccess::Auto, "auto"),
        ] {
            let e = check_link_access(lower)
                .err()
                .map(|e| e.to_string())
                .unwrap_or_default();
            assert!(e.contains("runtime_mode_escalation_denied"), "{e}");
            assert!(e.contains(&format!("link access {spelling} is")), "{e}");
        }
        assert_eq!(LinkAccess::FullAccess.to_string(), "full-access");
    }
}
