//! The mesh-join setup and teardown sequencer for one environment (#671, slice 1).
//!
//! Pure ordering logic over seams: a coordination server (headscale), the guest
//! secrets directory, the VM boot, the service readiness check and guest hooks. It runs no network call itself, so the
//! whole sequence is tier-2 testable over fakes. Every seam call is bounded by a timeout
//! (for [`SecretsDir`] the file work runs on the blocking pool so the timeout can fire).
//!
//! A join key is a credential. [`JoinKey`] never prints its value, and every
//! string this module returns or logs passes through the exact-key replace plus
//! [`redact`].
//!
//! # Cancellation and failure
//! The caller picks the node name and a [`KeySlot`] and passes both to
//! [`setup`]. If the setup future is dropped midway, or setup returns a
//! [`SetupError`] from [`SetupStep::Boot`] onward, the caller must run
//! [`teardown`] with the same name and slot: setup only expires the key, so a
//! joined node and a running VM (for example after a failed `after_ready` hook)
//! are left for teardown. A failure at [`SetupStep::Prepare`] or
//! [`SetupStep::MintKey`] removes the prepared secrets directory itself. The slot
//! must be empty at setup; a clean teardown empties it, so teardown can be retried
//! until it returns `Ok`. A mint that timed out can leave a server-side key
//! that only its TTL expires; the slot cannot hold it.

use std::{
    fmt,
    future::Future,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

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
        Some(k) if !k.expose().is_empty() => redact(&replace_ignore_case(text, k.expose())),
        _ => redact(text),
    }
}

/// Replace every ASCII-case-insensitive occurrence of `needle` with the mask.
fn replace_ignore_case(text: &str, needle: &str) -> String {
    let (lt, ln) = (text.to_ascii_lowercase(), needle.to_ascii_lowercase());
    let mut out = String::with_capacity(text.len());
    let mut at = 0;
    while let Some(i) = lt[at..].find(&ln) {
        out.push_str(&text[at..at + i]);
        out.push_str(REDACTED);
        at += i + ln.len();
    }
    out.push_str(&text[at..]);
    out
}

/// Turn a panic in `fut` into a [`SeamError`] so a hook cannot unwind the sequencer.
async fn contained<T>(fut: impl Future<Output = Result<T, SeamError>>) -> Result<T, SeamError> {
    use std::{
        panic::{AssertUnwindSafe, catch_unwind},
        task::Poll,
    };
    let mut fut = Box::pin(fut);
    std::future::poll_fn(|cx| match catch_unwind(AssertUnwindSafe(|| fut.as_mut().poll(cx))) {
        Ok(poll) => poll,
        Err(_) => Poll::Ready(Err(SeamError::new("hook panicked"))),
    })
    .await
}

/// A seam failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct SeamError {
    message: String,
    busy: bool,
}

impl SeamError {
    /// Build an error. The module scrubs the exact key at every exit; this
    /// constructor only masks key-shaped tokens.
    pub fn new(message: impl AsRef<str>) -> Self {
        Self {
            message: redact(message.as_ref()),
            busy: false,
        }
    }

    /// The refusal of an operation while another one on the same resource is
    /// still running. Nothing was started, so the caller may retry later.
    fn busy(message: impl AsRef<str>) -> Self {
        Self {
            busy: true,
            ..Self::new(message)
        }
    }

    /// Whether this is the refusal of an operation while another one is still
    /// running ([`SecretsDir`]): nothing was started and a retry may succeed.
    #[must_use]
    pub fn is_busy(&self) -> bool {
        self.busy
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

/// Boots and stops the guest VM named `name`.
pub trait VmBoot: Send + Sync {
    /// Start the VM.
    fn boot(&self, name: &str) -> impl Future<Output = Result<(), SeamError>> + Send;
    /// Stop the VM so a guest still joining cannot register. Idempotent: a VM
    /// that is not running counts as success.
    fn stop(&self, name: &str) -> impl Future<Output = Result<(), SeamError>> + Send;
}

/// Readiness of the guest service: `GET /` answers below 500.
pub trait ServiceReady: Send + Sync {
    /// One probe of the service on node `name`.
    fn ready(&self, name: &str) -> impl Future<Output = Result<bool, SeamError>> + Send;
}

/// Deployment-specific steps around the generic sequence. Sandy does not know
/// what they do: an example guest or a deployment step supplies them. Both
/// default to a no-op.
pub trait GuestHooks: Send + Sync {
    /// Runs after the service answers. A failure fails setup (the key is expired).
    /// A hook error is a hook failure, so make it idempotent: a retried setup runs it again.
    fn after_ready(&self, name: &str) -> impl Future<Output = Result<(), SeamError>> + Send {
        let _ = name;
        async { Ok(()) }
    }
    /// Runs first in teardown, while the guest still runs. A failure fails
    /// teardown after the rest ran. Teardown skips it when the VM never booted
    /// (setup failed at [`SetupStep::Boot`] or earlier), once it succeeded, and once
    /// the VM is stopped, so a retry never aims it at a stopped VM. A hook that
    /// failed runs again on a retry while the VM is still up. A caller that
    /// retries until `Ok` can lose an earlier `HookFailed` when the stop then
    /// succeeds, so it must record a `HookFailed` from any attempt.
    fn before_teardown(&self, name: &str) -> impl Future<Output = Result<(), SeamError>> + Send {
        let _ = name;
        async { Ok(()) }
    }
}

/// The hooks that do nothing.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoHooks;

impl GuestHooks for NoHooks {}

/// The mesh step teardown runs in the guest.
pub trait TeardownSteps: Send + Sync {
    /// `tailscale logout` in the guest of node `name`. Best effort: a failure only logs.
    fn tailscale_logout(&self, name: &str) -> impl Future<Output = Result<(), SeamError>> + Send;
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
///
/// Each operation runs on the blocking pool, so a wedged sink cannot stop the
/// caller's timeout from firing. A timed-out operation keeps its thread until
/// the sink returns, so at most one operation is in flight per directory: while
/// one runs, a new one answers [`SeamError::is_busy`] at once and spawns
/// nothing. A straggler therefore never acts after a later delivery, and a
/// retry loop against a wedged sink holds one blocking-pool thread, not one per
/// timeout. A caller retries after a pause. Teardown that meets `Busy` leaves
/// its slot set and is retried the same way. A sink that never returns keeps
/// the directory busy for good, as it kept the old gate held. A failed setup's
/// clean-up that meets `Busy` leaves the prepared directory, which holds no key
/// yet, until the next `prepare` clears it.
pub struct SecretsDir<S>(std::sync::Arc<Gated<S>>);

struct Gated<S> {
    sink: S,
    in_flight: AtomicBool,
}

/// Holds the directory's one in-flight place until dropped. It moves into the
/// blocking closure, so the place frees when the sink call returns, not when
/// the caller's future is dropped on a timeout.
struct InFlight<S>(std::sync::Arc<Gated<S>>);

impl<S> Drop for InFlight<S> {
    fn drop(&mut self) {
        self.0.in_flight.store(false, Ordering::SeqCst);
    }
}

impl<S: FileSink + 'static> SecretsDir<S> {
    /// Wrap a sink.
    pub fn new(sink: S) -> Self {
        Self(std::sync::Arc::new(Gated {
            sink,
            in_flight: AtomicBool::new(false),
        }))
    }

    async fn blocking<T: Send + 'static>(
        &self,
        op: impl FnOnce(&S) -> Result<T, SeamError> + Send + 'static,
    ) -> Result<T, SeamError> {
        if self
            .0
            .in_flight
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err(SeamError::busy(
                "another file operation on the secrets directory is still running",
            ));
        }
        let turn = InFlight(std::sync::Arc::clone(&self.0));
        tokio::task::spawn_blocking(move || {
            let result = op(&turn.0.sink);
            drop(turn);
            result
        })
        .await
        .unwrap_or_else(|e| Err(SeamError::new(format!("file operation did not finish: {e}"))))
    }
}

impl<S: FileSink + 'static> GuestDelivery for SecretsDir<S> {
    async fn prepare(&self) -> Result<(), SeamError> {
        self.blocking(|s| {
            s.ensure_dir()?;
            s.clear_dir()
        })
        .await
    }

    async fn deliver(&self, files: &[(&str, &[u8])]) -> Result<(), SeamError> {
        match files.iter().find(|(n, _)| *n == HOSTNAME_FILE) {
            None => {
                return Err(SeamError::new(
                    "missing hostname file: the guest would keep its default name",
                ));
            }
            Some((_, [])) => {
                return Err(SeamError::new("empty hostname file"));
            }
            Some(_) => {}
        }
        if files.iter().any(|(n, _)| *n == READY_FILE) {
            return Err(SeamError::new("the ready marker is written by delivery, not passed in"));
        }
        let files: Vec<(String, Vec<u8>)> = files.iter().map(|(n, b)| ((*n).to_owned(), b.to_vec())).collect();
        self.blocking(move |s| {
            s.remove_file(READY_FILE)?;
            for (name, bytes) in &files {
                s.write_file(name, bytes)?;
            }
            s.write_file(READY_FILE, b"")
        })
        .await
    }

    async fn remove_secrets(&self) -> Result<(), SeamError> {
        self.blocking(|s| s.remove_dir_all()).await
    }
}

/// Caller-owned record of one environment's mesh state: the join key and which
/// teardown steps already ran. [`setup`] fills it right after the mint, before
/// any further await, so a dropped setup future still leaves the key where
/// [`teardown`] finds it. [`setup`] refuses a slot that is not empty and a
/// clean [`teardown`] empties it.
#[derive(Debug, Default)]
pub struct KeySlot {
    key: std::sync::Mutex<Option<JoinKey>>,
    booted: AtomicBool,
    vm_stopped: AtomicBool,
    hook_done: AtomicBool,
}

impl KeySlot {
    /// An empty slot.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn set(&self, key: JoinKey) {
        *self.key.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Some(key);
    }

    /// The key, if one was minted.
    #[must_use]
    pub fn get(&self) -> Option<JoinKey> {
        self.key
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn clear(&self) {
        *self.key.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        for flag in [&self.booted, &self.vm_stopped, &self.hook_done] {
            flag.store(false, Ordering::SeqCst);
        }
    }
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
    /// Bound on every seam call. Must be non-zero.
    pub call_timeout: Duration,
}

/// A setup step, named in a failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetupStep {
    /// Rejecting a bad [`SetupConfig`].
    Config,
    /// Refusing a [`KeySlot`] that still holds a key.
    SlotInUse,
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
    /// Running the `after_ready` hook.
    AfterReady,
}

impl fmt::Display for SetupStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Config => "config",
            Self::SlotInUse => "slot_in_use",
            Self::Prepare => "prepare",
            Self::MintKey => "mint_key",
            Self::Boot => "boot",
            Self::Deliver => "deliver",
            Self::JoinOnline => "join_online",
            Self::ServiceReady => "service_ready",
            Self::AfterReady => "after_ready",
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
    /// The minted key, if any. When `key_burned` is false its expiry failed and
    /// it may still be live; the same key is in the caller's [`KeySlot`], which
    /// [`teardown`] reads.
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
/// online, service ready, `after_ready` hook. Choose `name` with [`sandbox_name`].
///
/// The minted key goes into `slot` before anything else awaits. A caller that
/// drops this future must run [`teardown`] with the same `name` and `slot`:
/// Setup must finish or be dropped before teardown starts; a teardown during an
/// in-flight setup is not supported. Once the key is in the guest it is only safe when the VM is stopped or the
/// key is expired.
///
/// A seam error while polling counts as one failed probe, not an abort, so a
/// transient blip does not fail a join that is about to succeed.
///
/// # Errors
/// [`SetupError`] naming the failed step. A key minted before the failure is
/// expired; if that expiry fails the error carries the key with
/// `key_burned == false`. Run [`teardown`] after any error from boot onward.
#[allow(
    clippy::too_many_arguments,
    reason = "one parameter per seam plus name, slot and config"
)]
pub async fn setup<C, G, B, S, H>(
    coord: &C,
    guest: &G,
    vm: &B,
    service: &S,
    hooks: &H,
    name: &str,
    slot: &KeySlot,
    cfg: &SetupConfig<'_>,
) -> Result<Provisioned, SetupError>
where
    C: Coordination,
    G: GuestDelivery,
    B: VmBoot,
    S: ServiceReady,
    H: GuestHooks,
{
    let t = cfg.call_timeout;
    let err = |step, key: Option<&JoinKey>, burned, reason: &str| SetupError {
        step,
        name: name.to_owned(),
        reason: scrub(reason, key),
        key: key.cloned(),
        key_burned: burned,
    };
    if cfg.poll_attempts == 0 {
        return Err(err(SetupStep::Config, None, false, "poll_attempts must be at least 1"));
    }
    if cfg.call_timeout.is_zero() {
        return Err(err(SetupStep::Config, None, false, "call_timeout must be non-zero"));
    }
    if cfg.key_ttl.is_zero() {
        return Err(err(SetupStep::Config, None, false, "key_ttl must be non-zero"));
    }
    if name.is_empty() {
        return Err(err(SetupStep::Config, None, false, "the node name must not be empty"));
    }
    if slot.get().is_some() {
        return Err(err(
            SetupStep::SlotInUse,
            None,
            false,
            "the key slot still holds a key: run teardown before another setup",
        ));
    }
    // Nothing of this environment exists yet on a prepare or mint failure, so
    // the directory prepare made is removed here; teardown has no key to find.
    let clean_up = |step, e: SeamError| async move {
        if let Err(x) = bounded(t, guest.remove_secrets()).await {
            tracing::warn!(error = %scrub(&x.to_string(), None), "removing the prepared secrets directory failed");
        }
        err(step, None, false, &e.to_string())
    };
    if let Err(e) = bounded(t, guest.prepare()).await {
        return Err(clean_up(SetupStep::Prepare, e).await);
    }
    let key = match bounded(t, coord.mint_join_key(cfg.tag, cfg.key_ttl)).await {
        Ok(key) => key,
        Err(e) => return Err(clean_up(SetupStep::MintKey, e).await),
    };
    slot.set(key.clone());
    if let Err((step, e)) = join(coord, guest, vm, service, hooks, name, &key, slot, cfg).await {
        let mut reason = e.to_string();
        let burned = match bounded(t, coord.expire_key(&key)).await {
            Ok(()) => true,
            Err(x) => {
                reason.push_str(&format!("; key expiry failed: {x}"));
                false
            }
        };
        return Err(err(step, Some(&key), burned, &reason));
    }
    Ok(Provisioned {
        name: name.to_owned(),
        key,
    })
}

#[allow(clippy::too_many_arguments, reason = "internal step runner over the seams")]
async fn join<C, G, B, S, H>(
    coord: &C,
    guest: &G,
    vm: &B,
    service: &S,
    hooks: &H,
    name: &str,
    key: &JoinKey,
    slot: &KeySlot,
    cfg: &SetupConfig<'_>,
) -> Result<(), (SetupStep, SeamError)>
where
    C: Coordination,
    G: GuestDelivery,
    B: VmBoot,
    S: ServiceReady,
    H: GuestHooks,
{
    let t = cfg.call_timeout;
    bounded(t, vm.boot(name)).await.map_err(|e| (SetupStep::Boot, e))?;
    slot.booted.store(true, Ordering::SeqCst);
    let files: [(&str, &[u8]); 2] = [(KEY_FILE, key.expose().as_bytes()), (HOSTNAME_FILE, name.as_bytes())];
    bounded(t, guest.deliver(&files))
        .await
        .map_err(|e| (SetupStep::Deliver, e))?;
    let (online, last) = poll(cfg, || coord.node_online(name)).await;
    if !online {
        return Err((
            SetupStep::JoinOnline,
            SeamError::new(format!(
                "node {name} not online after {} probes: the key may be expired, reused or refused{}",
                cfg.poll_attempts,
                last_error(last.as_ref())
            )),
        ));
    }
    let (ready, last) = poll(cfg, || service.ready(name)).await;
    if !ready {
        return Err((
            SetupStep::ServiceReady,
            SeamError::new(format!(
                "service on {name} did not answer below 500 after {} probes{}",
                cfg.poll_attempts,
                last_error(last.as_ref())
            )),
        ));
    }
    bounded(t, contained(hooks.after_ready(name)))
        .await
        .map_err(|e| (SetupStep::AfterReady, e))
}

fn last_error(last: Option<&SeamError>) -> String {
    last.map_or_else(String::new, |e| format!("; last probe error: {e}"))
}

/// Probe until `f` answers `true` or the attempts run out. A probe that errors
/// or times out uses up one attempt; the last such error is returned.
async fn poll<F, Fut>(cfg: &SetupConfig<'_>, mut f: F) -> (bool, Option<SeamError>)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<bool, SeamError>>,
{
    let mut last = None;
    for attempt in 0..cfg.poll_attempts {
        if attempt > 0 {
            tokio::time::sleep(cfg.poll_interval).await;
        }
        match bounded(cfg.call_timeout, f()).await {
            Ok(true) => return (true, None),
            Ok(false) => {}
            Err(e) => last = Some(e),
        }
    }
    (false, last)
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
    /// The VM could not be stopped; a guest may still be joining.
    #[error("vm for node {name} may still run: {reason}")]
    VmStillRunning {
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
    /// Everything was removed but the `before_teardown` hook failed.
    #[error("node {name} deleted but a teardown step failed: {reason}")]
    HookFailed {
        /// The node name.
        name: String,
        /// Scrubbed reason.
        reason: String,
    },
}

/// Run teardown: `before_teardown` hook, tailscale logout, stop the VM, expire
/// the key in `slot`, delete the node, remove secrets. Every step runs whatever
/// an earlier one did, except the hook (see [`GuestHooks::before_teardown`]).
/// `slot` records the steps done, so a retry after an error is safe; an `Ok`
/// result empties it. The VM stops and the key expires before the node delete,
/// so a guest still joining cannot register afterwards. Logout is best effort;
/// every other failure fails teardown. Works after a dropped [`setup`] future:
/// pass the same `name` and `slot`.
///
/// # Errors
/// [`TeardownError`]; a failed VM stop is reported as `VmStillRunning` even when the
/// node delete failed too. Never `Ok` while the node may exist, the VM may run or a
/// key in `slot` may be live. A key whose mint timed out is not in the slot.
#[allow(
    clippy::too_many_arguments,
    reason = "one parameter per seam plus name, slot and timeout"
)]
pub async fn teardown<C, G, B, T, H>(
    coord: &C,
    guest: &G,
    steps: &T,
    vm: &B,
    hooks: &H,
    name: &str,
    slot: &KeySlot,
    call_timeout: Duration,
) -> Result<(), TeardownError>
where
    C: Coordination,
    G: GuestDelivery,
    B: VmBoot,
    T: TeardownSteps,
    H: GuestHooks,
{
    let t = call_timeout;
    let key = slot.get();
    let key = key.as_ref();
    let mut hook = Vec::new();
    let mut residue = Vec::new();
    // The hook talks to the guest: run it only while a booted VM is still up
    // and it has not succeeded, so a retry never aims it at a stopped VM.
    if slot.booted.load(Ordering::SeqCst)
        && !slot.vm_stopped.load(Ordering::SeqCst)
        && !slot.hook_done.load(Ordering::SeqCst)
    {
        match bounded(t, contained(hooks.before_teardown(name))).await {
            Ok(()) => slot.hook_done.store(true, Ordering::SeqCst),
            Err(e) => hook.push(format!("before_teardown: {e}")),
        }
    }
    if let Err(e) = bounded(t, steps.tailscale_logout(name)).await {
        tracing::warn!(error = %scrub(&e.to_string(), key), "tailscale logout failed, continuing");
    }
    let stop = bounded(t, vm.stop(name)).await;
    if stop.is_ok() {
        slot.vm_stopped.store(true, Ordering::SeqCst);
    }
    if let Some(key) = key
        && let Err(e) = bounded(t, coord.expire_key(key)).await
    {
        residue.push(format!("key: {e}"));
    }
    let node = bounded(t, coord.delete_node(name)).await;
    if let Err(e) = bounded(t, guest.remove_secrets()).await {
        residue.push(format!("secrets: {e}"));
    }
    let mut problems = Vec::new();
    if let Err(e) = &node {
        problems.push(format!("node: {e}"));
    }
    if let Err(e) = &stop {
        problems.push(format!("stop vm: {e}"));
    }
    problems.extend(hook.iter().cloned());
    problems.extend(residue.iter().cloned());
    let reason = scrub(&problems.join("; "), key);
    let name = name.to_owned();
    if stop.is_err() {
        Err(TeardownError::VmStillRunning { name, reason })
    } else if node.is_err() {
        Err(TeardownError::NodeStillPresent { name, reason })
    } else if !residue.is_empty() {
        Err(TeardownError::Residue { name, reason })
    } else if !hook.is_empty() {
        Err(TeardownError::HookFailed { name, reason })
    } else {
        slot.clear();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        io,
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
        mint_hangs: bool,
        files: BTreeMap<String, Vec<u8>>,
        written: Vec<(String, Vec<u8>)>,
        delivered_key: Option<String>,
        online: bool,
        online_on_call: u32,
        online_calls: u32,
        online_error_first: bool,
        online_hangs: bool,
        service_down: bool,
        ready_hangs: bool,
        boot_error: Option<String>,
        boot_hangs: bool,
        vm_running: bool,
        stop_error: Option<String>,
        registered: bool,
        write_fail: Option<String>,
        secrets_fail: Option<String>,
        delete_error: Option<String>,
        expire_error: Option<String>,
        after_ready_fails: bool,
        after_ready_panics: bool,
        after_ready_hangs: bool,
        before_teardown_panics: bool,
        before_teardown_hangs: bool,
        before_teardown_fails: bool,
        hook_needs_vm: bool,
        mint_error: Option<String>,
        ensure_fail: bool,
        logout: Logout,
        logout_error: Option<String>,
        expired: Vec<String>,
        deleted: Vec<String>,
        seen_names: Vec<String>,
    }

    #[derive(Clone, Default)]
    struct World {
        state: Arc<Mutex<State>>,
        slot: Arc<KeySlot>,
    }

    impl World {
        fn online() -> Self {
            let w = Self::default();
            w.st().online = true;
            w
        }

        /// An environment whose VM is up and whose key is in the slot, as after a setup.
        fn running(&self) {
            self.slot.set(JoinKey::new("hskey-auth-abc1"));
            self.slot.booted.store(true, Ordering::SeqCst);
            self.st().vm_running = true;
        }

        fn st(&self) -> MutexGuard<'_, State> {
            self.state.lock().unwrap_or_else(PoisonError::into_inner)
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

        /// A guest that read its key joins late unless its VM is stopped or the key is expired.
        fn settle(&self) {
            let mut s = self.st();
            if let Some(k) = s.delivered_key.clone()
                && s.vm_running
                && !s.expired.contains(&k)
            {
                s.registered = true;
            }
        }
    }

    impl Coordination for World {
        async fn mint_join_key(&self, _tag: &str, _ttl: Duration) -> Result<JoinKey, SeamError> {
            self.push("mint_key");
            if self.st().mint_hangs {
                std::future::pending::<()>().await;
            }
            let mut s = self.st();
            if let Some(e) = s.mint_error.clone() {
                return Err(SeamError::new(e));
            }
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

        async fn node_online(&self, name: &str) -> Result<bool, SeamError> {
            self.push("node_online");
            let (hangs, result) = {
                let mut s = self.st();
                s.seen_names.push(format!("node_online:{name}"));
                s.online_calls += 1;
                let result = if s.online_error_first && s.online_calls == 1 {
                    Err(SeamError::new("transient blip"))
                } else {
                    Ok(s.online && s.online_calls >= s.online_on_call)
                };
                (s.online_hangs, result)
            };
            if hangs {
                std::future::pending::<()>().await;
            }
            result
        }
    }

    impl FileSink for World {
        fn ensure_dir(&self) -> Result<(), SeamError> {
            self.push("ensure_dir");
            if self.st().ensure_fail {
                return Err(SeamError::new("cannot create dir"));
            }
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
            if name == KEY_FILE {
                s.delivered_key = Some(String::from_utf8_lossy(bytes).into_owned());
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
        async fn boot(&self, name: &str) -> Result<(), SeamError> {
            self.push("boot");
            let (err, hangs) = {
                let mut s = self.st();
                s.seen_names.push(format!("boot:{name}"));
                s.vm_running = s.boot_error.is_none();
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

        async fn stop(&self, _name: &str) -> Result<(), SeamError> {
            self.push("stop_vm");
            let mut s = self.st();
            if let Some(e) = s.stop_error.clone() {
                return Err(SeamError::new(e));
            }
            s.vm_running = false;
            Ok(())
        }
    }

    impl ServiceReady for World {
        async fn ready(&self, _name: &str) -> Result<bool, SeamError> {
            self.push("service_ready");
            let (hangs, down) = {
                let s = self.st();
                (s.ready_hangs, s.service_down)
            };
            if hangs {
                std::future::pending::<()>().await;
            }
            Ok(!down)
        }
    }

    impl GuestHooks for World {
        async fn after_ready(&self, _name: &str) -> Result<(), SeamError> {
            self.push("after_ready");
            let (panics, hangs) = {
                let s = self.st();
                (s.after_ready_panics, s.after_ready_hangs)
            };
            assert!(!panics, "after_ready exploded");
            if hangs {
                std::future::pending::<()>().await;
            }
            if self.st().after_ready_fails {
                return Err(SeamError::new("after_ready refused"));
            }
            Ok(())
        }

        async fn before_teardown(&self, _name: &str) -> Result<(), SeamError> {
            self.push("before_teardown");
            let (panics, hangs) = {
                let s = self.st();
                (s.before_teardown_panics, s.before_teardown_hangs)
            };
            assert!(!panics, "before_teardown exploded");
            if hangs {
                std::future::pending::<()>().await;
            }
            if self.st().hook_needs_vm && !self.st().vm_running {
                return Err(SeamError::new("guest unreachable: the VM is down"));
            }
            if self.st().before_teardown_fails {
                return Err(SeamError::new("before_teardown refused"));
            }
            Ok(())
        }
    }

    impl TeardownSteps for World {
        async fn tailscale_logout(&self, name: &str) -> Result<(), SeamError> {
            self.push("tailscale_logout");
            let (mode, text) = {
                let mut s = self.st();
                s.seen_names.push(format!("logout:{name}"));
                (s.logout, s.logout_error.clone())
            };
            match mode {
                Logout::Ok => Ok(()),
                Logout::Fail => Err(SeamError::new(text.unwrap_or_else(|| "logout refused".into()))),
                Logout::Hang => {
                    std::future::pending::<()>().await;
                    Ok(())
                }
            }
        }
    }

    /// A secrets dir whose delivery never returns.
    struct HangDeliver;
    impl GuestDelivery for HangDeliver {
        async fn prepare(&self) -> Result<(), SeamError> {
            Ok(())
        }

        async fn deliver(&self, _files: &[(&str, &[u8])]) -> Result<(), SeamError> {
            std::future::pending::<()>().await;
            Ok(())
        }

        async fn remove_secrets(&self) -> Result<(), SeamError> {
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

    const NAME: &str = "sandbox-test";
    const T: Duration = Duration::from_secs(1);
    const SHORT: Duration = Duration::from_millis(20);
    const CFG: SetupConfig<'static> = SetupConfig {
        tag: "tag:mesh",
        key_ttl: Duration::from_secs(60),
        poll_attempts: 3,
        poll_interval: Duration::ZERO,
        call_timeout: T,
    };

    async fn run_with(w: &World, cfg: &SetupConfig<'_>) -> Result<Provisioned, SetupError> {
        setup(w, &SecretsDir::new(w.clone()), w, w, w, NAME, &w.slot, cfg).await
    }

    async fn run_setup(w: &World) -> Result<Provisioned, SetupError> {
        run_with(w, &CFG).await
    }

    async fn run_teardown(w: &World, limit: Duration) -> Result<(), TeardownError> {
        teardown(w, &SecretsDir::new(w.clone()), w, w, w, NAME, &w.slot, limit).await
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
                "after_ready",
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
        assert_eq!(w.st().expired[0], String::from_utf8(first_key.clone())?);

        run_teardown(&w, T).await.context("teardown between attempts")?;
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
        type Knob = fn(&mut State);
        let cases: [(SetupStep, Knob); 4] = [
            (SetupStep::Boot, |s| s.boot_error = Some("no kvm".into())),
            (SetupStep::Deliver, |s| s.write_fail = Some(HOSTNAME_FILE.into())),
            (SetupStep::ServiceReady, |s| s.service_down = true),
            (SetupStep::AfterReady, |s| s.after_ready_fails = true),
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
    async fn a_failed_delivery_leaves_no_ready_marker() -> Result<()> {
        let w = World::online();
        w.st().write_fail = Some(HOSTNAME_FILE.into());
        let Err(e) = run_setup(&w).await else {
            bail!("must fail");
        };
        assert_eq!(e.step, SetupStep::Deliver);
        assert!(!w.st().files.contains_key(READY_FILE));
        assert!(!w.ran("write .ready"));
        Ok(())
    }

    #[tokio::test]
    async fn a_hung_seam_times_out_into_a_setup_error_with_the_key_expired() -> Result<()> {
        type Knob = fn(&mut State);
        let cases: [(SetupStep, Knob); 4] = [
            (SetupStep::MintKey, |s| s.mint_hangs = true),
            (SetupStep::Boot, |s| s.boot_hangs = true),
            (SetupStep::JoinOnline, |s| s.online_hangs = true),
            (SetupStep::ServiceReady, |s| s.ready_hangs = true),
        ];
        let cfg = SetupConfig {
            call_timeout: SHORT,
            ..CFG
        };
        for (step, knob) in cases {
            let w = World::online();
            knob(&mut w.st());
            // The outer bound only keeps a regression from hanging the suite.
            let r = tokio::time::timeout(Duration::from_secs(10), run_with(&w, &cfg))
                .await
                .with_context(|| format!("{step}: setup did not time its own seam call out"))?;
            let Err(e) = r else { bail!("{step} must fail") };
            assert_eq!(e.step, step);
            let expected: &[&str] = if step == SetupStep::MintKey {
                &[]
            } else {
                &["hskey-auth-abc1"]
            };
            assert_eq!(w.st().expired, expected, "{step}");
        }
        let w = World::online();
        let r = tokio::time::timeout(
            Duration::from_secs(10),
            setup(&w, &HangDeliver, &w, &w, &w, NAME, &w.slot, &cfg),
        )
        .await
        .context("deliver: setup did not time its own seam call out")?;
        let Err(e) = r else { bail!("deliver must fail") };
        assert_eq!(e.step, SetupStep::Deliver);
        assert_eq!(w.st().expired, ["hskey-auth-abc1"]);
        Ok(())
    }

    #[tokio::test]
    async fn a_poll_that_succeeds_on_the_second_probe_is_ready() -> Result<()> {
        let w = World::online();
        w.st().online_on_call = 2;
        run_setup(&w).await.context("setup")?;
        assert_eq!(w.log().iter().filter(|l| *l == "node_online").count(), 2);
        Ok(())
    }

    #[tokio::test]
    async fn a_transient_probe_error_uses_one_attempt_and_does_not_abort_the_poll() -> Result<()> {
        let w = World::online();
        w.st().online_error_first = true;
        run_setup(&w).await.context("setup")?;
        assert_eq!(w.log().iter().filter(|l| *l == "node_online").count(), 2);
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
        assert!(e.key.is_some(), "the error must carry the key");

        let r = run_teardown(&w, T).await;
        assert!(matches!(r, Err(TeardownError::Residue { .. })), "{r:?}");

        w.st().expire_error = None;
        run_teardown(&w, T).await.context("retry")?;
        assert_eq!(w.st().expired.last().map(String::as_str), Some("hskey-auth-abc1"));
        Ok(())
    }

    #[tokio::test]
    async fn a_setup_dropped_during_the_join_poll_is_cleaned_up_with_no_late_join() -> Result<()> {
        let w = World::online();
        w.st().online_hangs = true;
        let r = tokio::time::timeout(Duration::from_millis(50), run_setup(&w)).await;
        assert!(r.is_err(), "setup must still be polling");
        assert!(w.st().delivered_key.is_some(), "the key is already in the guest");

        run_teardown(&w, T).await.context("teardown")?;
        w.settle();
        let s = w.st();
        assert!(!s.registered, "a guest still joining must not register");
        assert_eq!(s.expired, ["hskey-auth-abc1"]);
        assert_eq!(s.deleted, [NAME]);
        assert!(!s.vm_running);
        assert_eq!(
            s.seen_names,
            [
                format!("boot:{NAME}"),
                format!("node_online:{NAME}"),
                format!("logout:{NAME}")
            ]
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_failed_vm_stop_fails_teardown_after_the_rest_ran() -> Result<()> {
        let w = World::online();
        w.st().stop_error = Some("qemu wedged".into());
        let r = run_teardown(&w, T).await;
        assert!(matches!(r, Err(TeardownError::VmStillRunning { .. })), "{r:?}");
        assert!(w.ran("delete_node") && w.ran("remove_secrets"));
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

        let w = World::online();
        w.slot.set(JoinKey::new("plainsecret99"));
        {
            let mut s = w.st();
            s.delete_error = Some("rm node plainsecret99 failed".into());
            s.secrets_fail = Some("rm dir plainsecret99 failed".into());
            s.expire_error = Some("expire plainsecret99 failed".into());
        }
        let Err(err) = run_teardown(&w, T).await else {
            bail!("must fail")
        };
        for text in [err.to_string(), format!("{err:?}")] {
            assert!(!text.contains("plainsecret99"), "{text}");
        }
        w.st().delete_error = None;
        let Err(err) = run_teardown(&w, T).await else {
            bail!("residue must fail")
        };
        assert!(matches!(err, TeardownError::Residue { .. }));
        assert!(!format!("{err}{err:?}").contains("plainsecret99"));
        Ok(())
    }

    #[derive(Clone, Default)]
    struct LogBuf(Arc<Mutex<Vec<u8>>>);

    impl io::Write for LogBuf {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn the_logout_warning_never_carries_the_key() -> Result<()> {
        let buf = LogBuf::default();
        let sink = buf.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(move || sink.clone())
            .with_ansi(false)
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        let w = World::online();
        w.slot.set(JoinKey::new("plainsecret99"));
        {
            let mut s = w.st();
            s.logout = Logout::Fail;
            s.logout_error = Some("logout for plainsecret99 failed".into());
        }
        run_teardown(&w, T).await.context("logout is best effort")?;
        let logged = String::from_utf8(buf.0.lock().unwrap_or_else(PoisonError::into_inner).clone())?;
        assert!(logged.contains("tailscale logout failed"), "{logged}");
        assert!(!logged.contains("plainsecret99"), "{logged}");
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
    async fn teardown_runs_in_order_stopping_the_vm_and_expiring_the_key_before_the_node_delete() -> Result<()> {
        let w = World::online();
        w.running();
        run_teardown(&w, T).await.context("teardown")?;
        assert_eq!(
            w.log(),
            [
                "before_teardown",
                "tailscale_logout",
                "stop_vm",
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
        w.slot.set(JoinKey::new("hskey-auth-abc1"));
        {
            let mut s = w.st();
            s.delete_error = Some("headscale 500".into());
            s.secrets_fail = Some("busy".into());
        }
        let r = run_teardown(&w, T).await;
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
            w.slot.set(JoinKey::new("hskey-auth-abc1"));
            knob(&mut w.st());
            let r = run_teardown(&w, T).await;
            assert!(matches!(r, Err(TeardownError::Residue { .. })), "{r:?}");
            assert!(w.ran("delete_node"));
        }
        Ok(())
    }

    #[tokio::test]
    async fn a_failed_before_teardown_fails_teardown_after_the_rest_ran_but_logout_does_not() -> Result<()> {
        let w = World::online();
        w.running();
        w.st().before_teardown_fails = true;
        let r = run_teardown(&w, T).await;
        assert!(matches!(r, Err(TeardownError::HookFailed { .. })), "{r:?}");
        for step in [
            "tailscale_logout",
            "stop_vm",
            "expire_key",
            "delete_node",
            "remove_secrets",
        ] {
            assert!(w.ran(step), "{step} must still run");
        }

        let w = World::online();
        w.st().logout = Logout::Fail;
        run_teardown(&w, T).await.context("logout is best effort")?;

        let w = World::online();
        w.running();
        {
            let mut s = w.st();
            s.logout = Logout::Fail;
            s.before_teardown_fails = true;
        }
        assert!(
            run_teardown(&w, T).await.is_err(),
            "a failing best-effort step must not mask a real failure"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_panicking_hook_is_contained_in_setup_and_teardown() -> Result<()> {
        let w = World::online();
        w.st().after_ready_panics = true;
        let Err(e) = run_setup(&w).await else {
            bail!("a panicking after_ready must fail setup");
        };
        assert_eq!(e.step, SetupStep::AfterReady);
        assert!(e.key_burned);
        assert_eq!(w.st().expired, ["hskey-auth-abc1"]);

        let w = World::online();
        w.running();
        w.st().before_teardown_panics = true;
        let r = run_teardown(&w, T).await;
        assert!(matches!(r, Err(TeardownError::HookFailed { .. })), "{r:?}");
        for step in [
            "tailscale_logout",
            "stop_vm",
            "expire_key",
            "delete_node",
            "remove_secrets",
        ] {
            assert!(w.ran(step), "{step} must still run");
        }
        Ok(())
    }

    #[tokio::test]
    async fn a_hung_hook_times_out_into_a_typed_error() -> Result<()> {
        let w = World::online();
        w.st().after_ready_hangs = true;
        let cfg = SetupConfig {
            call_timeout: SHORT,
            ..CFG
        };
        let r = tokio::time::timeout(Duration::from_secs(10), run_with(&w, &cfg))
            .await
            .context("after_ready was not bounded")?;
        let Err(e) = r else { bail!("must fail") };
        assert_eq!(e.step, SetupStep::AfterReady);
        assert_eq!(w.st().expired, ["hskey-auth-abc1"]);

        let w = World::online();
        w.running();
        w.st().before_teardown_hangs = true;
        let r = tokio::time::timeout(Duration::from_secs(10), run_teardown(&w, SHORT))
            .await
            .context("before_teardown was not bounded")?;
        assert!(matches!(r, Err(TeardownError::HookFailed { .. })), "{r:?}");
        assert!(w.ran("delete_node"));
        Ok(())
    }

    #[tokio::test]
    async fn after_ready_is_skipped_when_the_service_never_answers() -> Result<()> {
        let w = World::online();
        w.st().service_down = true;
        let Err(e) = run_setup(&w).await else {
            bail!("must fail");
        };
        assert_eq!(e.step, SetupStep::ServiceReady);
        assert!(!w.ran("after_ready"));
        Ok(())
    }

    #[tokio::test]
    async fn teardown_after_an_after_ready_failure_leaves_nothing_behind() -> Result<()> {
        let w = World::online();
        w.st().after_ready_fails = true;
        let Err(e) = run_setup(&w).await else {
            bail!("must fail");
        };
        assert_eq!(e.step, SetupStep::AfterReady);
        run_teardown(&w, T).await.context("teardown")?;
        w.settle();
        let s = w.st();
        assert!(!s.vm_running && !s.registered);
        assert_eq!(s.deleted, [NAME]);
        Ok(())
    }

    /// A sink whose every operation blocks its thread.
    struct WedgedSink(Duration);
    impl FileSink for WedgedSink {
        fn ensure_dir(&self) -> Result<(), SeamError> {
            std::thread::sleep(self.0);
            Ok(())
        }

        fn clear_dir(&self) -> Result<(), SeamError> {
            std::thread::sleep(self.0);
            Ok(())
        }

        fn write_file(&self, _name: &str, _bytes: &[u8]) -> Result<(), SeamError> {
            std::thread::sleep(self.0);
            Ok(())
        }

        fn remove_file(&self, _name: &str) -> Result<(), SeamError> {
            std::thread::sleep(self.0);
            Ok(())
        }

        fn remove_dir_all(&self) -> Result<(), SeamError> {
            std::thread::sleep(self.0);
            Ok(())
        }
    }

    #[tokio::test]
    async fn a_wedged_file_operation_times_out_instead_of_blocking_the_runtime() -> Result<()> {
        // One directory per operation: a second operation on a directory whose
        // first one still runs is refused as busy (#713), not timed out.
        let wedged = || SecretsDir::new(WedgedSink(Duration::from_millis(600)));
        let files: [(&str, &[u8]); 2] = [(KEY_FILE, b"k"), (HOSTNAME_FILE, b"n")];
        let started = std::time::Instant::now();
        let Err(e) = bounded(SHORT, wedged().prepare()).await else {
            bail!("prepare must time out");
        };
        assert!(e.to_string().contains("timed out"), "{e}");
        let Err(e) = bounded(SHORT, wedged().deliver(&files)).await else {
            bail!("deliver must time out");
        };
        assert!(e.to_string().contains("timed out"), "{e}");
        let Err(e) = bounded(SHORT, wedged().remove_secrets()).await else {
            bail!("remove_secrets must time out");
        };
        assert!(e.to_string().contains("timed out"), "{e}");
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "{:?}",
            started.elapsed()
        );
        Ok(())
    }

    /// A sink whose writes park until [`Parked::release`], counting every sink
    /// call and the most threads inside the sink at once (#713).
    #[derive(Clone)]
    struct Parked {
        world: World,
        released: Arc<(Mutex<bool>, std::sync::Condvar)>,
        entered: Arc<std::sync::atomic::AtomicUsize>,
        inside: Arc<std::sync::atomic::AtomicUsize>,
        peak: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl Parked {
        fn new() -> Self {
            Self {
                world: World::default(),
                released: Arc::default(),
                entered: Arc::default(),
                inside: Arc::default(),
                peak: Arc::default(),
            }
        }

        fn release(&self) {
            *self.released.0.lock().unwrap_or_else(PoisonError::into_inner) = true;
            self.released.1.notify_all();
        }

        fn entered(&self) -> usize {
            self.entered.load(std::sync::atomic::Ordering::SeqCst)
        }

        fn peak(&self) -> usize {
            self.peak.load(std::sync::atomic::Ordering::SeqCst)
        }

        /// Run `op` as one sink call.
        fn call<T>(&self, park: bool, op: impl FnOnce(&World) -> T) -> T {
            use std::sync::atomic::Ordering::SeqCst;
            self.entered.fetch_add(1, SeqCst);
            let now = self.inside.fetch_add(1, SeqCst) + 1;
            self.peak.fetch_max(now, SeqCst);
            if park {
                let mut released = self.released.0.lock().unwrap_or_else(PoisonError::into_inner);
                while !*released {
                    released = self.released.1.wait(released).unwrap_or_else(PoisonError::into_inner);
                }
            }
            let out = op(&self.world);
            self.inside.fetch_sub(1, SeqCst);
            out
        }
    }

    impl FileSink for Parked {
        fn ensure_dir(&self) -> Result<(), SeamError> {
            self.call(false, World::ensure_dir)
        }

        fn clear_dir(&self) -> Result<(), SeamError> {
            self.call(false, World::clear_dir)
        }

        fn write_file(&self, name: &str, bytes: &[u8]) -> Result<(), SeamError> {
            self.call(true, |w| w.write_file(name, bytes))
        }

        fn remove_file(&self, name: &str) -> Result<(), SeamError> {
            self.call(false, |w| w.remove_file(name))
        }

        fn remove_dir_all(&self) -> Result<(), SeamError> {
            self.call(false, World::remove_dir_all)
        }
    }

    /// Poll `cond` every 10 ms for up to 5 s.
    async fn wait_until(what: &str, cond: impl Fn() -> bool) -> Result<()> {
        for _ in 0..500 {
            if cond() {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        bail!("timed out waiting for {what}")
    }

    /// #713: a timed-out operation still runs on its blocking thread. A later
    /// operation on the same directory must not queue behind it: it answers
    /// `Busy` at once and never reaches the sink. After the straggler ends, a
    /// retry delivers and nothing from the old operation lands after it.
    #[tokio::test]
    async fn a_second_operation_is_busy_while_a_timed_out_one_still_runs() -> Result<()> {
        let sink = Parked::new();
        let dir = SecretsDir::new(sink.clone());
        let first: [(&str, &[u8]); 2] = [(KEY_FILE, b"old"), (HOSTNAME_FILE, b"n")];
        let Err(e) = bounded(SHORT, dir.deliver(&first)).await else {
            bail!("the parked delivery must time out");
        };
        assert!(e.to_string().contains("timed out"), "{e}");
        // The straggler removed the marker and is now parked in the first write.
        wait_until("the straggler to park in the sink", || sink.entered() == 2).await?;
        let before = sink.entered();

        // Bounded: on the old mutex design these would wait for the sink, not fail.
        let Err(busy) = bounded(T, dir.prepare()).await else {
            bail!("prepare must be refused while an operation is in flight");
        };
        assert!(busy.is_busy(), "{busy}");
        let Err(busy) = bounded(T, dir.remove_secrets()).await else {
            bail!("removal must be refused while an operation is in flight");
        };
        assert!(busy.is_busy(), "{busy}");
        assert_eq!(sink.entered(), before, "a refused operation never reaches the sink");

        sink.release();
        let second: [(&str, &[u8]); 2] = [(KEY_FILE, b"new"), (HOSTNAME_FILE, b"n")];
        let mut delivered = false;
        for _ in 0..200 {
            match bounded(T, dir.deliver(&second)).await {
                Ok(()) => {
                    delivered = true;
                    break;
                }
                Err(e) if e.is_busy() => tokio::time::sleep(Duration::from_millis(10)).await,
                Err(e) => bail!("retry failed: {e}"),
            }
        }
        assert!(delivered, "the retry must run once the straggler is done");
        let files = sink.world.st().files.clone();
        assert_eq!(files.get(KEY_FILE).map(Vec::as_slice), Some(b"new".as_slice()));
        assert!(files.contains_key(READY_FILE), "the retry's marker must stand");
        Ok(())
    }

    /// #713 adversarial: a retry loop against a wedged sink parks no thread per
    /// timeout. Ten timed-out attempts leave one operation in the sink, and once
    /// the sink unblocks only that one operation's calls ever ran.
    #[tokio::test]
    async fn ten_timeouts_in_a_row_run_one_operation() -> Result<()> {
        let sink = Parked::new();
        let dir = SecretsDir::new(sink.clone());
        let files: [(&str, &[u8]); 2] = [(KEY_FILE, b"k"), (HOSTNAME_FILE, b"n")];
        for attempt in 0..10 {
            let Err(_) = bounded(SHORT, dir.deliver(&files)).await else {
                bail!("attempt {attempt} must not succeed while the sink is parked");
            };
        }
        sink.release();
        // One deliver: remove the marker, write two files, write the marker.
        wait_until("the first operation to finish", || sink.entered() == 4).await?;
        // Give a wrongly queued operation time to reach the sink.
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(sink.entered(), 4, "only the first operation may reach the sink");
        assert_eq!(sink.peak(), 1, "at most one thread inside the sink at once");
        Ok(())
    }

    #[tokio::test]
    async fn a_timed_out_delivery_finishes_before_a_later_removal_starts() -> Result<()> {
        let w = World::default();
        let slow = Arc::new(Mutex::new(true));
        struct SlowFirst(World, Arc<Mutex<bool>>);
        impl FileSink for SlowFirst {
            fn ensure_dir(&self) -> Result<(), SeamError> {
                self.0.ensure_dir()
            }

            fn clear_dir(&self) -> Result<(), SeamError> {
                self.0.clear_dir()
            }

            fn write_file(&self, name: &str, bytes: &[u8]) -> Result<(), SeamError> {
                if std::mem::take(&mut *self.1.lock().unwrap_or_else(PoisonError::into_inner)) {
                    std::thread::sleep(Duration::from_millis(200));
                }
                self.0.write_file(name, bytes)
            }

            fn remove_file(&self, name: &str) -> Result<(), SeamError> {
                self.0.remove_file(name)
            }

            fn remove_dir_all(&self) -> Result<(), SeamError> {
                self.0.remove_dir_all()
            }
        }
        let dir = SecretsDir::new(SlowFirst(w.clone(), slow));
        let files: [(&str, &[u8]); 2] = [(KEY_FILE, b"k"), (HOSTNAME_FILE, b"n")];
        let Err(_) = bounded(SHORT, dir.deliver(&files)).await else {
            bail!("the slow delivery must time out");
        };
        // The straggler still runs, so the removal is refused until it ends.
        let mut removed = false;
        for _ in 0..200 {
            match dir.remove_secrets().await {
                Ok(()) => {
                    removed = true;
                    break;
                }
                Err(e) if e.is_busy() => tokio::time::sleep(Duration::from_millis(10)).await,
                Err(e) => bail!("removal failed: {e}"),
            }
        }
        assert!(removed, "the removal must run once the straggler is done");
        assert!(
            w.st().files.is_empty(),
            "a straggling write must not outlive the removal"
        );
        Ok(())
    }

    #[tokio::test]
    async fn setup_refuses_a_slot_that_still_holds_a_key_and_mints_nothing() -> Result<()> {
        let w = World::online();
        run_setup(&w).await.context("first setup")?;
        let before = w.log().len();
        let Err(e) = run_setup(&w).await else {
            bail!("a second setup without teardown must be refused");
        };
        assert_eq!(e.step, SetupStep::SlotInUse);
        assert_eq!(w.st().minted, 1);
        assert_eq!(w.log().len(), before, "a refused setup touches no seam");
        assert!(w.slot.get().is_some(), "the first key stays in the slot");
        Ok(())
    }

    #[tokio::test]
    async fn a_clean_teardown_empties_the_slot_so_the_node_name_can_be_set_up_again() -> Result<()> {
        let w = World::online();
        run_setup(&w).await.context("setup")?;
        run_teardown(&w, T).await.context("teardown")?;
        assert!(w.slot.get().is_none());
        run_setup(&w).await.context("setup again")?;
        Ok(())
    }

    #[tokio::test]
    async fn a_failed_teardown_keeps_the_slot() -> Result<()> {
        let w = World::online();
        run_setup(&w).await.context("setup")?;
        w.st().delete_error = Some("headscale 500".into());
        assert!(run_teardown(&w, T).await.is_err());
        assert!(w.slot.get().is_some());
        Ok(())
    }

    #[tokio::test]
    async fn a_teardown_retry_does_not_rerun_a_hook_that_already_succeeded() -> Result<()> {
        let w = World::online();
        w.st().hook_needs_vm = true;
        run_setup(&w).await.context("setup")?;
        w.st().secrets_fail = Some("busy".into());
        let r = run_teardown(&w, T).await;
        assert!(matches!(r, Err(TeardownError::Residue { .. })), "{r:?}");
        assert!(!w.st().vm_running);
        w.st().secrets_fail = None;
        run_teardown(&w, T).await.context("retry with the VM down")?;
        assert_eq!(w.log().iter().filter(|l| *l == "before_teardown").count(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn a_teardown_retry_after_a_failed_stop_does_not_rerun_a_succeeded_hook() -> Result<()> {
        let w = World::online();
        run_setup(&w).await.context("setup")?;
        w.st().stop_error = Some("qemu wedged".into());
        let r = run_teardown(&w, T).await;
        assert!(matches!(r, Err(TeardownError::VmStillRunning { .. })), "{r:?}");
        w.st().stop_error = None;
        run_teardown(&w, T).await.context("retry")?;
        assert_eq!(w.log().iter().filter(|l| *l == "before_teardown").count(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn a_failed_hook_is_reported_once_and_a_retry_with_the_vm_down_does_not_rerun_it() -> Result<()> {
        let w = World::online();
        run_setup(&w).await.context("setup")?;
        w.st().before_teardown_fails = true;
        let r = run_teardown(&w, T).await;
        assert!(matches!(r, Err(TeardownError::HookFailed { .. })), "{r:?}");
        run_teardown(&w, T)
            .await
            .context("retry: the VM is stopped, nothing is left")?;
        assert_eq!(w.log().iter().filter(|l| *l == "before_teardown").count(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn a_failed_hook_runs_again_on_a_retry_while_the_vm_is_still_up() -> Result<()> {
        let w = World::online();
        run_setup(&w).await.context("setup")?;
        {
            let mut s = w.st();
            s.before_teardown_fails = true;
            s.stop_error = Some("qemu wedged".into());
        }
        let r = run_teardown(&w, T).await;
        assert!(matches!(r, Err(TeardownError::VmStillRunning { .. })), "{r:?}");
        w.st().stop_error = None;
        let r = run_teardown(&w, T).await;
        assert!(matches!(r, Err(TeardownError::HookFailed { .. })), "{r:?}");
        assert_eq!(w.log().iter().filter(|l| *l == "before_teardown").count(), 2);
        Ok(())
    }

    #[tokio::test]
    async fn teardown_after_a_failed_boot_does_not_run_the_hook() -> Result<()> {
        let w = World::online();
        {
            let mut s = w.st();
            s.boot_error = Some("no kvm".into());
            s.hook_needs_vm = true;
        }
        let Err(e) = run_setup(&w).await else {
            bail!("boot must fail");
        };
        assert_eq!(e.step, SetupStep::Boot);
        run_teardown(&w, T)
            .await
            .context("teardown of a VM that never started")?;
        assert!(!w.ran("before_teardown"));
        Ok(())
    }

    #[tokio::test]
    async fn teardown_passes_the_node_name_to_logout() -> Result<()> {
        let w = World::online();
        run_teardown(&w, T).await.context("teardown")?;
        assert!(w.st().seen_names.contains(&format!("logout:{NAME}")));
        Ok(())
    }

    #[tokio::test]
    async fn a_failed_stop_is_reported_even_when_the_node_delete_also_failed() -> Result<()> {
        let w = World::online();
        {
            let mut s = w.st();
            s.stop_error = Some("qemu wedged".into());
            s.delete_error = Some("headscale 500".into());
        }
        let r = run_teardown(&w, T).await;
        let Err(TeardownError::VmStillRunning { reason, .. }) = r else {
            bail!("a possibly running VM must not hide behind NodeStillPresent: {r:?}");
        };
        assert!(
            reason.contains("qemu wedged") && reason.contains("headscale 500"),
            "{reason}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_failed_mint_or_prepare_removes_the_prepared_secrets_dir() -> Result<()> {
        let w = World::online();
        w.st().mint_error = Some("headscale 500 for tskey-leak-1".into());
        let Err(e) = run_setup(&w).await else {
            bail!("a failed mint must fail setup");
        };
        assert_eq!(e.step, SetupStep::MintKey);
        assert!(!e.to_string().contains("tskey-leak-1"), "{e}");
        assert!(w.ran("remove_secrets"), "the prepared directory must go");

        let w = World::online();
        w.st().ensure_fail = true;
        let Err(e) = run_setup(&w).await else {
            bail!("a failed prepare must fail setup");
        };
        assert_eq!(e.step, SetupStep::Prepare);
        assert!(w.ran("remove_secrets"));
        Ok(())
    }

    #[tokio::test]
    async fn a_zero_key_ttl_or_an_empty_node_name_is_a_config_error_and_runs_nothing() -> Result<()> {
        let w = World::online();
        let cfg = SetupConfig {
            key_ttl: Duration::ZERO,
            ..CFG
        };
        let Err(e) = run_with(&w, &cfg).await else {
            bail!("a zero key_ttl must be rejected");
        };
        assert_eq!(e.step, SetupStep::Config);
        let Err(e) = setup(&w, &SecretsDir::new(w.clone()), &w, &w, &w, "", &w.slot, &CFG).await else {
            bail!("an empty name must be rejected");
        };
        assert_eq!(e.step, SetupStep::Config);
        assert!(w.log().is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn the_exact_key_is_scrubbed_whatever_its_case() -> Result<()> {
        let w = World::online();
        w.st().mint_value = Some("PlainSecret99".into());
        w.st().boot_error = Some("dial with plainsecret99 failed".into());
        let Err(e) = run_setup(&w).await else {
            bail!("must fail");
        };
        assert!(!e.to_string().to_lowercase().contains("plainsecret99"), "{e}");
        Ok(())
    }

    #[tokio::test]
    async fn a_failed_after_ready_hook_fails_setup_with_the_key_expired() -> Result<()> {
        let w = World::online();
        w.st().after_ready_fails = true;
        let Err(e) = run_setup(&w).await else {
            bail!("a failing hook must fail setup");
        };
        assert_eq!(e.step, SetupStep::AfterReady);
        assert!(e.key_burned);
        assert_eq!(w.st().expired, ["hskey-auth-abc1"]);
        Ok(())
    }

    #[tokio::test]
    async fn the_default_hooks_do_nothing_and_succeed() -> Result<()> {
        NoHooks.after_ready(NAME).await.context("after_ready")?;
        NoHooks.before_teardown(NAME).await.context("before_teardown")?;
        Ok(())
    }

    #[tokio::test]
    async fn a_hanging_logout_times_out_and_does_not_block_the_node_delete() -> Result<()> {
        let w = World::online();
        w.st().logout = Logout::Hang;
        run_teardown(&w, SHORT).await.context("teardown")?;
        assert_eq!(w.st().deleted, [NAME]);
        Ok(())
    }

    #[tokio::test]
    async fn zero_poll_attempts_or_a_zero_call_timeout_is_a_config_error_and_runs_nothing() -> Result<()> {
        for cfg in [
            SetupConfig {
                poll_attempts: 0,
                ..CFG
            },
            SetupConfig {
                call_timeout: Duration::ZERO,
                ..CFG
            },
        ] {
            let w = World::online();
            let Err(e) = run_with(&w, &cfg).await else {
                bail!("a bad config must be rejected");
            };
            assert_eq!(e.step, SetupStep::Config);
            assert!(w.log().is_empty());
        }
        Ok(())
    }
}
