//! Test-only seam impls that prove the harness: one reference impl per seam that
//! must pass its suite, and deliberately broken impls that must fail it.

use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    hash::{DefaultHasher, Hash, Hasher},
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll, Waker},
};

use futures_core::Stream;
use sandy_api::backend::{BoxState, Outcome, RunSpec};

use crate::{
    capauth::{Cap, CapAuthority, CapError, CapRights, CapScope},
    channel_backend::{ChannelBackend, ChannelBackendError, Envelope, msg_id},
    executor::{Capabilities, Executor, ExecutorError, capabilities_satisfy},
    minter::{MintedSecret, Minter, MinterError, SecretRequest},
    placement::{
        Availability, Capacity, CapacityError, Discovery, DiscoveryError, HostDescriptor, Lease, Lifecycle,
        LifecycleError,
    },
    telemetry::{TelemetryError, TelemetryRecord, TelemetrySink},
    transport::{Frame, Transport, TransportError},
    types::{HostId, PeerId},
};

// ---- CapAuthority ----

/// Proof = a keyed hash of the scope. Not cryptography; enough to detect tampering.
#[derive(Default)]
pub struct FakeAuthority {
    /// When set, the proof does not cover the rights (broken: rights can be edited).
    pub blind_to_rights: bool,
    /// When set, `attenuate` trusts the parent's claimed scope unverified (broken).
    pub trusts_parent: bool,
}

impl FakeAuthority {
    pub fn new() -> Self {
        Self::default()
    }

    fn proof(&self, scope: &CapScope) -> Vec<u8> {
        let mut h = DefaultHasher::new();
        0x5eed_u64.hash(&mut h);
        (&scope.peer, &scope.channel, scope.expires_at).hash(&mut h);
        if !self.blind_to_rights {
            (scope.rights.post, scope.rights.read, scope.rights.invite).hash(&mut h);
        }
        h.finish().to_be_bytes().to_vec()
    }
}

impl CapAuthority for FakeAuthority {
    fn mint(&self, scope: CapScope) -> Result<Cap, CapError> {
        let proof = self.proof(&scope);
        Ok(Cap { scope, proof })
    }

    fn verify(&self, cap: &Cap) -> Result<CapScope, CapError> {
        if cap.proof != self.proof(&cap.scope) {
            return Err(CapError::Forged);
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        match cap.scope.expires_at {
            Some(t) if t <= now => Err(CapError::Expired),
            _ => Ok(cap.scope.clone()),
        }
    }

    fn attenuate(&self, parent: &Cap, rights: CapRights) -> Result<Cap, CapError> {
        let scope = if self.trusts_parent {
            parent.scope.clone()
        } else {
            self.verify(parent)?
        };
        if !rights.is_subset_of(&scope.rights) {
            return Err(CapError::Widened);
        }
        self.mint(CapScope { rights, ..scope })
    }
}

/// Broken: attenuation hands back the parent unchanged.
pub struct NonAttenuatingAuthority(pub FakeAuthority);

impl CapAuthority for NonAttenuatingAuthority {
    fn mint(&self, scope: CapScope) -> Result<Cap, CapError> {
        self.0.mint(scope)
    }

    fn verify(&self, cap: &Cap) -> Result<CapScope, CapError> {
        self.0.verify(cap)
    }

    fn attenuate(&self, parent: &Cap, _rights: CapRights) -> Result<Cap, CapError> {
        Ok(parent.clone())
    }
}

// ---- Minter ----

pub struct FakeMinter {
    counter: AtomicU64,
}

impl FakeMinter {
    pub fn new() -> Self {
        Self {
            counter: AtomicU64::new(1),
        }
    }
}

impl Minter for FakeMinter {
    fn mint(&self, req: &SecretRequest) -> Result<MintedSecret, MinterError> {
        let n = self.counter.fetch_add(1, Ordering::Relaxed);
        Ok(MintedSecret {
            bytes: format!("{}:{n}", req.job).into_bytes(),
        })
    }
}

/// Broken: the same secret every time.
pub struct ConstantMinter;

impl Minter for ConstantMinter {
    fn mint(&self, _req: &SecretRequest) -> Result<MintedSecret, MinterError> {
        Ok(MintedSecret {
            bytes: b"fixed".to_vec(),
        })
    }
}

// ---- ChannelBackend ----

#[derive(Default)]
pub struct LogInner {
    log: Vec<Envelope>,
    wakers: Vec<Waker>,
}

/// An in-memory log, sorted by sequence, deduped on msg_id, waking followers on append.
#[derive(Default, Clone)]
pub struct FakeBackend {
    pub inner: Arc<Mutex<LogInner>>,
    /// When set, dedup keys on `sequence` instead of the msg_id (broken).
    pub dedup_on_sequence: bool,
    /// When set, entries stay in arrival order (broken).
    pub arrival_order: bool,
}

impl FakeBackend {
    fn lock(&self) -> std::sync::MutexGuard<'_, LogInner> {
        self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl ChannelBackend for FakeBackend {
    async fn append(&self, env: Envelope) -> Result<(), ChannelBackendError> {
        let id = msg_id(&env).ok_or(ChannelBackendError::MissingMsgId)?.to_owned();
        let mut inner = self.lock();
        let duplicate = if self.dedup_on_sequence {
            inner.log.iter().any(|e| e.sequence == env.sequence)
        } else {
            inner.log.iter().any(|e| msg_id(e) == Some(id.as_str()))
        };
        if duplicate {
            return Ok(());
        }
        let at = if self.arrival_order {
            inner.log.len()
        } else {
            inner.log.partition_point(|e| e.sequence <= env.sequence)
        };
        inner.log.insert(at, env);
        for waker in inner.wakers.drain(..) {
            waker.wake();
        }
        Ok(())
    }

    async fn fetch(&self, from_seq: u64) -> Result<Vec<Envelope>, ChannelBackendError> {
        Ok(self
            .lock()
            .log
            .iter()
            .filter(|e| e.sequence >= from_seq)
            .cloned()
            .collect())
    }

    fn stream_from(&self, from_seq: u64) -> impl Stream<Item = Result<Envelope, ChannelBackendError>> + Send {
        FollowStream {
            backend: self.clone(),
            next_seq: from_seq,
        }
    }
}

struct FollowStream {
    backend: FakeBackend,
    next_seq: u64,
}

impl Stream for FollowStream {
    type Item = Result<Envelope, ChannelBackendError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        let mut inner = this.backend.lock();
        match inner.log.iter().find(|e| e.sequence >= this.next_seq).cloned() {
            Some(env) => {
                this.next_seq = env.sequence + 1;
                Poll::Ready(Some(Ok(env)))
            }
            None => {
                inner.wakers.push(cx.waker().clone());
                Poll::Pending
            }
        }
    }
}

/// Broken: `stream_from` is a snapshot that ends, so live appends are missed.
#[derive(Default)]
pub struct SnapshotBackend(pub FakeBackend);

impl ChannelBackend for SnapshotBackend {
    async fn append(&self, env: Envelope) -> Result<(), ChannelBackendError> {
        self.0.append(env).await
    }

    async fn fetch(&self, from_seq: u64) -> Result<Vec<Envelope>, ChannelBackendError> {
        self.0.fetch(from_seq).await
    }

    fn stream_from(&self, from_seq: u64) -> impl Stream<Item = Result<Envelope, ChannelBackendError>> + Send {
        let snapshot: Vec<_> = self
            .0
            .lock()
            .log
            .iter()
            .filter(|e| e.sequence >= from_seq)
            .cloned()
            .map(Ok)
            .collect();
        futures_util::stream::iter(snapshot)
    }
}

// ---- Transport ----

#[derive(Default)]
pub struct FakeTransport {
    queues: Mutex<HashMap<PeerId, VecDeque<Frame>>>,
}

impl Transport for FakeTransport {
    async fn send(&self, from: &PeerId, to: &PeerId, frame: &[u8]) -> Result<(), TransportError> {
        let mut queues = self.queues.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        queues.entry(to.clone()).or_default().push_back(Frame {
            from: from.clone(),
            bytes: frame.to_vec(),
        });
        Ok(())
    }

    async fn poll(&self, me: &PeerId) -> Result<Vec<Frame>, TransportError> {
        let mut queues = self.queues.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        Ok(queues.get_mut(me).map(|q| q.drain(..).collect()).unwrap_or_default())
    }
}

/// Broken: frames to a peer that has never polled are dropped (no store-and-forward).
#[derive(Default)]
pub struct LiveOnlyTransport {
    inner: FakeTransport,
    seen: Mutex<Vec<PeerId>>,
}

impl Transport for LiveOnlyTransport {
    async fn send(&self, from: &PeerId, to: &PeerId, frame: &[u8]) -> Result<(), TransportError> {
        let online = self
            .seen
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains(to);
        if online {
            self.inner.send(from, to, frame).await?;
        }
        Ok(())
    }

    async fn poll(&self, me: &PeerId) -> Result<Vec<Frame>, TransportError> {
        self.seen
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(me.clone());
        self.inner.poll(me).await
    }
}

// ---- Executor ----

/// Scripted by command: `true` exits 0, `sh -c "exit N"` exits N.
pub struct FakeExecutor {
    pub caps: Capabilities,
    /// When set, a non-zero exit is misreported as a transport fault (broken).
    pub collapse_failures: bool,
}

impl Executor for FakeExecutor {
    async fn run(&self, spec: &RunSpec<'_>) -> Result<Outcome, ExecutorError> {
        let exit = match spec.command {
            [cmd] if cmd == "true" => 0,
            [sh, c, script] if sh == "sh" && c == "-c" => script
                .strip_prefix("exit ")
                .and_then(|n| n.parse().ok())
                .ok_or_else(|| ExecutorError::Spawn(format!("unscripted: {script}")))?,
            other => return Err(ExecutorError::Spawn(format!("unscripted: {other:?}"))),
        };
        let collapsed = self.collapse_failures && exit != 0;
        Ok(Outcome {
            booted: true,
            guest_exit: (!collapsed).then_some(exit),
            transport_error: collapsed.then(|| "lost".to_owned()),
            timed_out: false,
            console: String::new(),
        })
    }

    async fn kill(&self, _box_id: &str) -> Result<(), ExecutorError> {
        Ok(())
    }

    async fn observe(&self) -> Result<Vec<BoxState>, ExecutorError> {
        Ok(Vec::new())
    }

    fn capabilities(&self) -> Capabilities {
        self.caps
    }
}

// ---- Discovery ----

#[derive(Default)]
pub struct FakeDiscovery {
    pub hosts: Mutex<BTreeMap<HostId, HostDescriptor>>,
    /// When set, `find` ignores the requirements (broken).
    pub ignore_requirements: bool,
}

impl Discovery for FakeDiscovery {
    async fn register(&self, host: HostDescriptor) -> Result<(), DiscoveryError> {
        self.hosts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(host.host.clone(), host);
        Ok(())
    }

    async fn find(&self, req: &crate::executor::Requirements) -> Result<Vec<HostDescriptor>, DiscoveryError> {
        let hosts = self.hosts.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        Ok(hosts
            .values()
            .filter(|h| self.ignore_requirements || capabilities_satisfy(&h.capabilities, req))
            .cloned()
            .collect())
    }
}

// ---- Capacity ----

pub struct FakeCapacity {
    pub slots: Mutex<HashMap<HostId, u32>>,
    /// When set, a probe reserves a slot (broken).
    pub reserving: bool,
    /// When set, an unknown host reports spare capacity (broken).
    pub phantom: bool,
}

impl FakeCapacity {
    pub fn new(host: HostId, slots: u32) -> Self {
        Self {
            slots: Mutex::new(HashMap::from([(host, slots)])),
            reserving: false,
            phantom: false,
        }
    }
}

impl Capacity for FakeCapacity {
    async fn probe(&self, host: &HostId) -> Result<Availability, CapacityError> {
        let mut slots = self.slots.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        match slots.get_mut(host) {
            Some(free) => {
                let available = Availability { free_slots: *free };
                if self.reserving {
                    *free = free.saturating_sub(1);
                }
                Ok(available)
            }
            None if self.phantom => Ok(Availability { free_slots: 1 }),
            None => Err(CapacityError::UnknownHost(host.clone())),
        }
    }
}

// ---- Lifecycle ----

#[derive(Default)]
pub struct FakeLifecycle {
    pub leases: Mutex<BTreeMap<u64, HostId>>,
    pub next: AtomicU64,
    /// When set, heartbeat accepts any lease (broken).
    pub accept_any: bool,
}

impl Lifecycle for FakeLifecycle {
    async fn register(&self, host: HostId) -> Result<Lease, LifecycleError> {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        self.leases
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(id, host.clone());
        Ok(Lease { host, id })
    }

    async fn heartbeat(&self, lease: &Lease) -> Result<(), LifecycleError> {
        let leases = self.leases.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.accept_any || leases.get(&lease.id) == Some(&lease.host) {
            Ok(())
        } else {
            Err(LifecycleError::UnknownLease)
        }
    }

    async fn deregister(&self, lease: &Lease) -> Result<(), LifecycleError> {
        let mut leases = self.leases.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        match leases.get(&lease.id) {
            Some(host) if *host == lease.host => {
                leases.remove(&lease.id);
                Ok(())
            }
            _ => Err(LifecycleError::UnknownLease),
        }
    }

    async fn live(&self) -> Result<Vec<HostId>, LifecycleError> {
        Ok(self
            .leases
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .cloned()
            .collect())
    }
}

// ---- TelemetrySink ----

pub struct FakeSink {
    pub enabled: bool,
    /// When set, records are kept even while disabled (broken).
    pub ignore_disabled: bool,
    /// When set, records are dropped even while enabled (broken).
    pub lossy: bool,
    pub records: Mutex<Vec<TelemetryRecord>>,
}

impl FakeSink {
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            ignore_disabled: false,
            lossy: false,
            records: Mutex::new(Vec::new()),
        }
    }

    pub fn captured(&self) -> usize {
        self.records
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }
}

impl TelemetrySink for FakeSink {
    fn enabled(&self) -> bool {
        self.enabled
    }

    async fn emit(&self, record: &TelemetryRecord) -> Result<(), TelemetryError> {
        if (self.enabled && !self.lossy) || self.ignore_disabled {
            self.records
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(record.clone());
        }
        Ok(())
    }
}
