//! The mesh-join setup and teardown sequencer for one environment (#671, slice 1).
//!
//! Pure ordering logic over seams: a coordination server (headscale), the guest
//! secrets directory, the VM boot, and the service readiness check. It runs no
//! network call itself, so the whole sequence is tier-2 testable over fakes.
//!
//! A join key is a credential. [`JoinKey`] never prints its value, and every
//! error string this module returns passes through [`redact`].

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

/// Mask `hskey-auth-...` and `tskey-...` tokens in `text`.
#[must_use]
pub fn redact(text: &str) -> String {
    unimplemented!("redact({text})")
}

/// A seam failure. The message is redacted when the value is built.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct SeamError(String);

impl SeamError {
    /// Build an error, masking any key in `message`.
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
    let _ = rng;
    unimplemented!("sandbox_name")
}

/// The coordination server (headscale) the guest joins.
pub trait Coordination: Send + Sync {
    /// Mint a single-use, ephemeral pre-auth key for `tag`, valid for `ttl`.
    fn mint_join_key(&self, tag: &str, ttl: Duration) -> impl Future<Output = Result<JoinKey, SeamError>> + Send;
    /// Delete the node `name`.
    fn delete_node(&self, name: &str) -> impl Future<Output = Result<(), SeamError>> + Send;
    /// Expire `key` so it can no longer join.
    fn expire_key(&self, key: &JoinKey) -> impl Future<Output = Result<(), SeamError>> + Send;
    /// Whether the node `name` is online.
    fn node_online(&self, name: &str) -> impl Future<Output = Result<bool, SeamError>> + Send;
}

/// The guest secrets directory.
pub trait GuestDelivery: Send + Sync {
    /// Make the directory ready to receive files.
    fn prepare(&self) -> impl Future<Output = Result<(), SeamError>> + Send;
    /// Write `files`, removing [`READY_FILE`] first and writing it last.
    fn deliver(&self, files: &[(&str, &[u8])]) -> impl Future<Output = Result<(), SeamError>> + Send;
    /// Remove the directory and everything in it.
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

/// Guest-side and orchestrator-side steps teardown runs before the node delete.
pub trait TeardownSteps: Send + Sync {
    /// Unlink the delegator link. A hook: its logic is out of scope here.
    fn unlink(&self) -> impl Future<Output = Result<(), SeamError>> + Send;
    /// Revoke the environment's sessions. A hook: its logic is out of scope here.
    fn revoke_sessions(&self) -> impl Future<Output = Result<(), SeamError>> + Send;
    /// `tailscale logout` in the guest, best effort.
    fn tailscale_logout(&self) -> impl Future<Output = Result<(), SeamError>> + Send;
}

/// File operations behind a [`SecretsDir`]. Removal is idempotent.
pub trait FileSink: Send + Sync {
    /// Create the directory.
    fn ensure_dir(&self) -> Result<(), SeamError>;
    /// Write one file.
    fn write_file(&self, name: &str, bytes: &[u8]) -> Result<(), SeamError>;
    /// Remove one file; absent is fine.
    fn remove_file(&self, name: &str) -> Result<(), SeamError>;
    /// Remove the directory tree.
    fn remove_dir_all(&self) -> Result<(), SeamError>;
}

/// [`GuestDelivery`] over a [`FileSink`], enforcing the `.ready` ordering and
/// the required `hostname` file.
pub struct SecretsDir<S>(S);

impl<S: FileSink> SecretsDir<S> {
    /// Wrap a sink.
    pub fn new(sink: S) -> Self {
        Self(sink)
    }
}

impl<S: FileSink> GuestDelivery for SecretsDir<S> {
    async fn prepare(&self) -> Result<(), SeamError> {
        unimplemented!("prepare {}", std::any::type_name::<S>())
    }

    async fn deliver(&self, files: &[(&str, &[u8])]) -> Result<(), SeamError> {
        unimplemented!("deliver {}", files.len())
    }

    async fn remove_secrets(&self) -> Result<(), SeamError> {
        unimplemented!("remove_secrets")
    }
}

/// Where setup gives up, and the knobs it polls with.
#[derive(Debug, Clone)]
pub struct SetupConfig<'a> {
    /// ACL tag the node joins under.
    pub tag: &'a str,
    /// Lifetime of the pre-auth key.
    pub key_ttl: Duration,
    /// Probes before the node or service counts as not coming up.
    pub poll_attempts: u32,
    /// Pause between probes.
    pub poll_interval: Duration,
}

/// A setup step, named in a failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetupStep {
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
}

impl fmt::Display for SetupStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Prepare => "prepare",
            Self::MintKey => "mint_key",
            Self::Boot => "boot",
            Self::Deliver => "deliver",
            Self::JoinOnline => "join_online",
            Self::ServiceReady => "service_ready",
        };
        f.write_str(name)
    }
}

/// Setup failed at `step`. The key, if one was minted, is burned.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("setup failed at {step}: {reason}")]
pub struct SetupError {
    /// The step that failed.
    pub step: SetupStep,
    /// The node name, so the caller can run teardown for a node that may exist.
    pub name: String,
    /// Redacted reason.
    pub reason: String,
    /// Whether a key was minted and is now expired and never reusable.
    pub key_burned: bool,
}

/// What an environment row shows after setup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvStatus {
    /// Node online and service answering.
    Ready,
    /// Setup failed; the redacted reason.
    Failed {
        /// Redacted reason, naming the step.
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

/// Run setup: name, prepare, mint key, boot, deliver, node online, service ready.
///
/// # Errors
/// [`SetupError`] naming the failed step. A key minted before the failure is
/// expired and never reused.
pub async fn setup<C, G, B, S>(
    coord: &C,
    guest: &G,
    vm: &B,
    service: &S,
    rng: &mut impl RandomBytes,
    cfg: &SetupConfig<'_>,
) -> Result<Provisioned, SetupError>
where
    C: Coordination,
    G: GuestDelivery,
    B: VmBoot,
    S: ServiceReady,
{
    let _ = (coord, guest, vm, service, rng, cfg);
    unimplemented!("setup")
}

/// Teardown did not finish cleanly. The caller keeps the environment record.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TeardownError {
    /// The node delete failed; the node may still exist.
    #[error("node {name} is still present: {reason}")]
    NodeStillPresent {
        /// The node name.
        name: String,
        /// Redacted reason.
        reason: String,
    },
    /// The node is gone but the key or secrets could not be removed.
    #[error("node {name} deleted but residue remains: {reason}")]
    Residue {
        /// The node name.
        name: String,
        /// Redacted reason.
        reason: String,
    },
}

/// Run teardown: unlink, revoke sessions, tailscale logout, delete node,
/// expire key, remove secrets. Unlink, revoke and logout are best effort.
///
/// # Errors
/// [`TeardownError::NodeStillPresent`] when the node delete fails; never `Ok`
/// while the node may exist. Key expiry and secrets removal still run.
pub async fn teardown<C, G, T>(
    coord: &C,
    guest: &G,
    steps: &T,
    name: &str,
    key: Option<&JoinKey>,
) -> Result<(), TeardownError>
where
    C: Coordination,
    G: GuestDelivery,
    T: TeardownSteps,
{
    let _ = (coord, guest, steps, name, key);
    unimplemented!("teardown")
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

/// The mode the sequencer's link step uses.
pub const LINK_ACCESS: LinkAccess = LinkAccess::FullAccess;

/// A link made with a lower mode than the VM needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("runtime_mode_escalation_denied: link access {0:?} is lower than full-access")]
pub struct LinkModeError(pub LinkAccess);

/// Reject a link mode lower than full access, at link time.
///
/// # Errors
/// [`LinkModeError`] for any mode but [`LinkAccess::FullAccess`].
pub fn check_link_access(access: LinkAccess) -> Result<(), LinkModeError> {
    let _ = access;
    unimplemented!("check_link_access")
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

    use anyhow::{Context, Result, bail};

    use super::*;

    #[derive(Default)]
    struct State {
        log: Vec<String>,
        minted: u32,
        written: Vec<(String, Vec<u8>)>,
        online: bool,
        boot_error: Option<String>,
        delete_fails: bool,
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

        fn pos(&self, line: &str) -> Result<usize> {
            self.log()
                .iter()
                .position(|l| l == line)
                .with_context(|| format!("{line} missing from {:?}", self.log()))
        }
    }

    impl Coordination for World {
        async fn mint_join_key(&self, _tag: &str, _ttl: Duration) -> Result<JoinKey, SeamError> {
            self.push("mint_key");
            let mut s = self.st();
            s.minted += 1;
            Ok(JoinKey::new(format!("hskey-auth-abc{}", s.minted)))
        }

        async fn delete_node(&self, _name: &str) -> Result<(), SeamError> {
            self.push("delete_node");
            if self.st().delete_fails {
                return Err(SeamError::new("headscale 500"));
            }
            Ok(())
        }

        async fn expire_key(&self, _key: &JoinKey) -> Result<(), SeamError> {
            self.push("expire_key");
            Ok(())
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

        fn write_file(&self, name: &str, bytes: &[u8]) -> Result<(), SeamError> {
            self.push(format!("write {name}"));
            self.st().written.push((name.into(), bytes.to_vec()));
            Ok(())
        }

        fn remove_file(&self, name: &str) -> Result<(), SeamError> {
            self.push(format!("remove {name}"));
            Ok(())
        }

        fn remove_dir_all(&self) -> Result<(), SeamError> {
            self.push("remove_secrets");
            Ok(())
        }
    }

    impl VmBoot for World {
        async fn boot(&self, _name: &str) -> Result<(), SeamError> {
            self.push("boot");
            match self.st().boot_error.clone() {
                Some(e) => Err(SeamError::new(e)),
                None => Ok(()),
            }
        }
    }

    impl ServiceReady for World {
        async fn ready(&self, _name: &str) -> Result<bool, SeamError> {
            self.push("service_ready");
            Ok(true)
        }
    }

    impl TeardownSteps for World {
        async fn unlink(&self) -> Result<(), SeamError> {
            self.push("unlink");
            Ok(())
        }

        async fn revoke_sessions(&self) -> Result<(), SeamError> {
            self.push("revoke_sessions");
            Ok(())
        }

        async fn tailscale_logout(&self) -> Result<(), SeamError> {
            self.push("tailscale_logout");
            Ok(())
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

    const CFG: SetupConfig<'static> = SetupConfig {
        tag: "tag:t3",
        key_ttl: Duration::from_secs(60),
        poll_attempts: 3,
        poll_interval: Duration::ZERO,
    };

    async fn run_setup(w: &World) -> Result<Provisioned, SetupError> {
        setup(w, &SecretsDir::new(w.clone()), w, w, &mut Fixed, &CFG).await
    }

    #[test]
    fn the_name_is_sandbox_and_sixteen_hex_digits() {
        assert_eq!(sandbox_name(&mut Fixed), "sandbox-a0a1a2a3a4a5a6a7");
    }

    #[tokio::test]
    async fn setup_runs_its_steps_in_order_and_mints_the_key_between_prepare_and_boot() -> Result<()> {
        let w = World::online();
        let p = run_setup(&w).await.context("setup")?;
        assert_eq!(p.name, "sandbox-a0a1a2a3a4a5a6a7");
        assert_eq!(
            w.log(),
            [
                "ensure_dir",
                "mint_key",
                "boot",
                "remove .ready",
                "write tailscale-authkey",
                "write hostname",
                "write .ready",
                "node_online",
                "service_ready",
            ]
        );
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
    async fn a_missing_hostname_file_is_reported_and_nothing_is_marked_ready() -> Result<()> {
        let w = World::default();
        let dir = SecretsDir::new(w.clone());
        let Err(e) = dir.deliver(&[(KEY_FILE, b"k".as_slice())]).await else {
            bail!("delivery without a hostname file must fail");
        };
        assert!(e.to_string().contains("hostname"), "{e}");
        assert!(!w.log().iter().any(|l| l == "write .ready"));
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
        assert!(w.pos("expire_key")? > w.pos("write .ready")?);
        let first_key = w.st().written[0].1.clone();

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
    async fn a_join_key_never_shows_in_debug_display_or_errors() -> Result<()> {
        let w = World::online();
        w.st().boot_error = Some("run: tailscale up --auth-key=hskey-auth-abc1 --reset".into());
        let Err(e) = run_setup(&w).await else {
            bail!("a failed boot must fail setup");
        };
        let status = EnvStatus::from(&e);
        for text in [format!("{e}"), format!("{e:?}"), format!("{status:?}")] {
            assert!(!text.contains("hskey-auth-abc"), "{text}");
        }
        assert_eq!(e.step, SetupStep::Boot);

        let key = JoinKey::new("hskey-auth-abc");
        assert!(!format!("{key:?}{key}").contains("abc"));
        assert_eq!(redact("x tskey-auth-k1_Z9 y"), "x [redacted] y");
        let ok = World::online();
        let p = run_setup(&ok).await.context("setup")?;
        assert!(!format!("{p:?}").contains("hskey-auth-abc"));
        Ok(())
    }

    #[tokio::test]
    async fn teardown_runs_in_order_and_ends_with_the_secrets_gone() -> Result<()> {
        let w = World::online();
        let key = JoinKey::new("hskey-auth-abc1");
        teardown(&w, &SecretsDir::new(w.clone()), &w, "n", Some(&key))
            .await
            .context("teardown")?;
        assert_eq!(
            w.log(),
            [
                "unlink",
                "revoke_sessions",
                "tailscale_logout",
                "delete_node",
                "expire_key",
                "remove_secrets",
            ]
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_failed_node_delete_reports_the_node_present_and_never_succeeds() -> Result<()> {
        let w = World::online();
        w.st().delete_fails = true;
        let r = teardown(&w, &SecretsDir::new(w.clone()), &w, "n", None).await;
        assert!(matches!(r, Err(TeardownError::NodeStillPresent { .. })), "{r:?}");
        assert!(w.log().contains(&"remove_secrets".to_string()));
        Ok(())
    }

    #[test]
    fn a_link_below_full_access_is_denied_at_link_time() {
        assert_eq!(LINK_ACCESS, LinkAccess::FullAccess);
        assert!(check_link_access(LinkAccess::FullAccess).is_ok());
        for lower in [
            LinkAccess::ReadOnly,
            LinkAccess::ApprovalRequired,
            LinkAccess::AutoAccept,
            LinkAccess::Auto,
        ] {
            let e = check_link_access(lower)
                .err()
                .map(|e| e.to_string())
                .unwrap_or_default();
            assert!(e.contains("runtime_mode_escalation_denied"), "{e}");
        }
    }
}
