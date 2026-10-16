//! The all-local placement impls (spec §3.6, §3.7): a static [`Discovery`]
//! registry, a direct-probe [`Capacity`] over an [`Executor`], lease soft-state
//! [`Lifecycle`], and [`place`], which picks a live host with spare capacity.
//!
//! The registry is seeded from explicit [`HostDescriptor`]s. Deriving hosts from
//! the nix machines table is M4 cross-machine work: that table lists build systems
//! (`aarch64-linux`), not hosts with a sandbox kind.

use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex, MutexGuard, PoisonError,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use sandy_fabric::{
    executor::{Arch, Capabilities, Executor, Requirements, SandboxKind, capabilities_satisfy},
    placement::{
        Availability, Capacity, CapacityError, Discovery, DiscoveryError, HostDescriptor, Lease, Lifecycle,
        LifecycleError,
    },
    types::HostId,
};

/// Lock `m`, recovering the data if a holder panicked: every critical section
/// here leaves the map consistent, so a poisoned lock carries no torn state.
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// This host's architecture, or `None` on one the fabric does not model.
pub fn host_arch() -> Option<Arch> {
    match std::env::consts::ARCH {
        "x86_64" => Some(Arch::X86_64),
        "aarch64" => Some(Arch::Aarch64),
        _ => None,
    }
}

/// A [`Discovery`] over a fixed, in-memory host list: the static registry.
///
/// The all-local profile seeds it with [`StaticRegistry::localhost`]; hosts can
/// also be registered at runtime. `find` returns exactly the hosts whose
/// capabilities satisfy the requirements.
#[derive(Debug, Default)]
pub struct StaticRegistry {
    hosts: Mutex<BTreeMap<HostId, HostDescriptor>>,
}

impl StaticRegistry {
    /// The id the all-local profile gives this machine.
    pub const LOCALHOST: &str = "localhost";

    /// A registry holding `hosts`; a later entry for the same id replaces an earlier one.
    pub fn new(hosts: impl IntoIterator<Item = HostDescriptor>) -> Self {
        Self {
            hosts: Mutex::new(hosts.into_iter().map(|h| (h.host.clone(), h)).collect()),
        }
    }

    /// The all-local registry: this machine alone, providing `kind` on `arch`.
    pub fn localhost(kind: SandboxKind, arch: Arch) -> Self {
        Self::new([HostDescriptor {
            host: HostId::from(Self::LOCALHOST),
            capabilities: Capabilities {
                kind,
                arch,
                attestation: None,
            },
        }])
    }
}

impl Discovery for StaticRegistry {
    async fn register(&self, host: HostDescriptor) -> Result<(), DiscoveryError> {
        lock(&self.hosts).insert(host.host.clone(), host);
        Ok(())
    }

    async fn find(&self, req: &Requirements) -> Result<Vec<HostDescriptor>, DiscoveryError> {
        Ok(lock(&self.hosts)
            .values()
            .filter(|h| capabilities_satisfy(&h.capabilities, req))
            .cloned()
            .collect())
    }
}

/// A direct-probe [`Capacity`]: each known host is an [`Executor`] with a slot
/// limit, and its free capacity is the limit minus the boxes it runs right now.
#[derive(Debug)]
pub struct ExecutorCapacity<E> {
    hosts: BTreeMap<HostId, (E, u32)>,
}

impl<E> Default for ExecutorCapacity<E> {
    fn default() -> Self {
        Self { hosts: BTreeMap::new() }
    }
}

impl<E: Executor> ExecutorCapacity<E> {
    /// No known hosts: every probe fails with [`CapacityError::UnknownHost`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Add `host`, served by `executor`, accepting at most `max_slots` concurrent jobs.
    pub fn with_host(mut self, host: HostId, executor: E, max_slots: u32) -> Self {
        self.hosts.insert(host, (executor, max_slots));
        self
    }
}

impl<E: Executor> Capacity for ExecutorCapacity<E> {
    async fn probe(&self, host: &HostId) -> Result<Availability, CapacityError> {
        let (executor, max_slots) = self
            .hosts
            .get(host)
            .ok_or_else(|| CapacityError::UnknownHost(host.clone()))?;
        let running = executor
            .observe()
            .await
            .map_err(|e| CapacityError::Probe(e.to_string()))?
            .len();
        let running = u32::try_from(running).unwrap_or(u32::MAX);
        Ok(Availability {
            free_slots: max_slots.saturating_sub(running),
        })
    }
}

/// A monotonic time source, injectable so lease expiry is testable.
pub trait Clock: Send + Sync {
    /// The current instant.
    fn now(&self) -> Instant;
}

/// The real monotonic clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

impl<C: Clock + ?Sized> Clock for Arc<C> {
    fn now(&self) -> Instant {
        (**self).now()
    }
}

/// Lease soft-state [`Lifecycle`]: a registration lives for `ttl` and each
/// heartbeat renews it for another `ttl`. A lease is live while `now < deadline`;
/// at the deadline it has lapsed, after which it is unknown to every call.
#[derive(Debug)]
pub struct LeaseTable<C = SystemClock> {
    ttl: Duration,
    clock: C,
    leases: Mutex<BTreeMap<u64, (HostId, Instant)>>,
    next_id: AtomicU64,
}

impl LeaseTable<SystemClock> {
    /// A lease table on the real clock.
    pub fn new(ttl: Duration) -> Self {
        Self::with_clock(ttl, SystemClock)
    }
}

impl<C: Clock> LeaseTable<C> {
    /// A lease table on `clock`.
    pub fn with_clock(ttl: Duration, clock: C) -> Self {
        Self {
            ttl,
            clock,
            leases: Mutex::new(BTreeMap::new()),
            next_id: AtomicU64::new(0),
        }
    }

    /// The live leases, with lapsed ones pruned first.
    fn live_leases(&self) -> MutexGuard<'_, BTreeMap<u64, (HostId, Instant)>> {
        let now = self.clock.now();
        let mut leases = lock(&self.leases);
        leases.retain(|_, (_, deadline)| now < *deadline);
        leases
    }
}

impl<C: Clock> Lifecycle for LeaseTable<C> {
    async fn register(&self, host: HostId) -> Result<Lease, LifecycleError> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let deadline = self.clock.now() + self.ttl;
        lock(&self.leases).insert(id, (host.clone(), deadline));
        Ok(Lease { host, id })
    }

    async fn heartbeat(&self, lease: &Lease) -> Result<(), LifecycleError> {
        let renewed = self.clock.now() + self.ttl;
        match self.live_leases().get_mut(&lease.id) {
            Some((host, deadline)) if *host == lease.host => {
                *deadline = renewed;
                Ok(())
            }
            _ => Err(LifecycleError::UnknownLease),
        }
    }

    async fn deregister(&self, lease: &Lease) -> Result<(), LifecycleError> {
        let mut leases = self.live_leases();
        match leases.get(&lease.id) {
            Some((host, _)) if *host == lease.host => {
                leases.remove(&lease.id);
                Ok(())
            }
            _ => Err(LifecycleError::UnknownLease),
        }
    }

    async fn live(&self) -> Result<Vec<HostId>, LifecycleError> {
        let mut hosts: Vec<_> = self.live_leases().values().map(|(h, _)| h.clone()).collect();
        hosts.sort();
        hosts.dedup();
        Ok(hosts)
    }
}

/// A placement failure: the registry or lease store could not be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PlacementError {
    /// Discovery failed.
    #[error(transparent)]
    Discovery(#[from] DiscoveryError),
    /// The lease store failed.
    #[error(transparent)]
    Lifecycle(#[from] LifecycleError),
}

/// Pick a host for a job needing `req`: the first host `discovery` finds that has
/// a live lease and spare capacity, or `None` when no host qualifies.
///
/// A host whose capacity probe fails is skipped, not fatal: one unreachable host
/// must not stall placement on the others.
pub async fn place<D, L, C>(
    discovery: &D,
    lifecycle: &L,
    capacity: &C,
    req: &Requirements,
) -> Result<Option<HostId>, PlacementError>
where
    D: Discovery,
    L: Lifecycle,
    C: Capacity,
{
    let live = lifecycle.live().await?;
    for candidate in discovery.find(req).await? {
        if !live.contains(&candidate.host) {
            continue;
        }
        match capacity.probe(&candidate.host).await {
            Ok(availability) if availability.can_accept() => return Ok(Some(candidate.host)),
            Ok(_) => {}
            Err(e) => tracing::warn!(host = ?candidate.host, error = %e, "capacity probe failed; skipping host"),
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use anyhow::Context;
    use sandy_api::backend::{BoxState, Outcome, RunSpec};
    use sandy_fabric::{
        contract::{capacity_suite, discovery_suite, lifecycle_suite},
        executor::ExecutorError,
    };

    use super::*;

    const TTL: Duration = Duration::from_secs(30);

    /// An executor that reports `running` boxes.
    struct BusyExecutor {
        running: usize,
    }

    impl Executor for BusyExecutor {
        async fn run(&self, _spec: &RunSpec<'_>) -> Result<Outcome, ExecutorError> {
            Err(ExecutorError::Spawn("not used".to_owned()))
        }

        async fn kill(&self, _box_id: &str) -> Result<(), ExecutorError> {
            Ok(())
        }

        async fn observe(&self) -> Result<Vec<BoxState>, ExecutorError> {
            Ok((0..self.running)
                .map(|i| BoxState {
                    box_id: format!("b{i}"),
                    box_name: format!("b{i}"),
                    pid: 0,
                    started: SystemTime::UNIX_EPOCH,
                    rvport: None,
                })
                .collect())
        }

        fn capabilities(&self) -> Capabilities {
            PROCESS_X86
        }
    }

    /// A clock that moves only when told.
    struct ManualClock(Mutex<Instant>);

    impl ManualClock {
        fn new() -> Arc<Self> {
            Arc::new(Self(Mutex::new(Instant::now())))
        }

        fn advance(&self, by: Duration) {
            *lock(&self.0) += by;
        }
    }

    impl Clock for ManualClock {
        fn now(&self) -> Instant {
            *lock(&self.0)
        }
    }

    const PROCESS_X86: Capabilities = Capabilities {
        kind: SandboxKind::Process,
        arch: Arch::X86_64,
        attestation: None,
    };

    fn host(id: &str, kind: SandboxKind, arch: Arch) -> HostDescriptor {
        HostDescriptor {
            host: HostId::from(id),
            capabilities: Capabilities {
                kind,
                arch,
                attestation: None,
            },
        }
    }

    fn need(kind: SandboxKind, arch: Option<Arch>) -> Requirements {
        Requirements { kind, arch }
    }

    // ---- seam contracts (#104) ----

    #[tokio::test]
    async fn static_registry_satisfies_the_discovery_contract() -> anyhow::Result<()> {
        discovery_suite(|| StaticRegistry::new([])).await.context("discovery")
    }

    #[tokio::test]
    async fn executor_capacity_satisfies_the_capacity_contract() -> anyhow::Result<()> {
        let known = HostId::from("h1");
        capacity_suite(known.clone(), || {
            ExecutorCapacity::new().with_host(known.clone(), BusyExecutor { running: 1 }, 4)
        })
        .await
        .context("capacity")
    }

    #[tokio::test]
    async fn lease_table_satisfies_the_lifecycle_contract() -> anyhow::Result<()> {
        lifecycle_suite(|| LeaseTable::new(TTL)).await.context("lifecycle")
    }

    // ---- Discovery ----

    #[tokio::test]
    async fn localhost_registry_finds_this_machine_for_a_matching_job() -> anyhow::Result<()> {
        let registry = StaticRegistry::localhost(SandboxKind::Process, Arch::Aarch64);
        let found = registry.find(&need(SandboxKind::Process, None)).await?;
        anyhow::ensure!(
            found.len() == 1 && found[0].host.0 == StaticRegistry::LOCALHOST,
            "found {found:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn an_arch_or_kind_mismatch_is_never_returned() -> anyhow::Result<()> {
        let registry = StaticRegistry::new([
            host("arm-vm", SandboxKind::Vm, Arch::Aarch64),
            host("x86-proc", SandboxKind::Process, Arch::X86_64),
        ]);
        anyhow::ensure!(
            registry
                .find(&need(SandboxKind::Vm, Some(Arch::X86_64)))
                .await?
                .is_empty(),
            "a VM job on x86 matched a host that is ARM or not a VM"
        );
        let found = registry.find(&need(SandboxKind::Process, Some(Arch::X86_64))).await?;
        anyhow::ensure!(found.len() == 1 && found[0].host.0 == "x86-proc", "found {found:?}");
        Ok(())
    }

    // ---- Capacity ----

    #[tokio::test]
    async fn a_probe_reports_free_slots_and_a_full_host_cannot_accept() -> anyhow::Result<()> {
        let (half, full) = (HostId::from("half"), HostId::from("full"));
        let capacity = ExecutorCapacity::new()
            .with_host(half.clone(), BusyExecutor { running: 1 }, 2)
            .with_host(full.clone(), BusyExecutor { running: 3 }, 2);
        let half = capacity.probe(&half).await?;
        anyhow::ensure!(half.free_slots == 1 && half.can_accept(), "half: {half:?}");
        let full = capacity.probe(&full).await?;
        anyhow::ensure!(full.free_slots == 0 && !full.can_accept(), "full: {full:?}");
        Ok(())
    }

    // ---- Lifecycle ----

    #[tokio::test]
    async fn a_lease_expires_on_a_missed_heartbeat() -> anyhow::Result<()> {
        let clock = ManualClock::new();
        let leases = LeaseTable::with_clock(TTL, clock.clone());
        let lease = leases.register(HostId::from("h1")).await?;

        clock.advance(TTL);
        anyhow::ensure!(leases.live().await?.is_empty(), "a lease is live at its deadline");
        anyhow::ensure!(
            leases.heartbeat(&lease).await == Err(LifecycleError::UnknownLease),
            "a lapsed lease was renewed"
        );
        anyhow::ensure!(leases.live().await?.is_empty(), "a late heartbeat revived the lease");
        Ok(())
    }

    #[tokio::test]
    async fn a_heartbeat_before_the_deadline_renews_the_lease() -> anyhow::Result<()> {
        let clock = ManualClock::new();
        let leases = LeaseTable::with_clock(TTL, clock.clone());
        let lease = leases.register(HostId::from("h1")).await?;

        clock.advance(TTL - Duration::from_secs(1));
        leases.heartbeat(&lease).await?;
        clock.advance(TTL - Duration::from_secs(1));
        anyhow::ensure!(
            leases.live().await? == [HostId::from("h1")],
            "a renewed lease lapsed on the original deadline"
        );
        Ok(())
    }

    // ---- place ----

    /// Three matching hosts, in the order `find` returns them: `a-stale` (lease
    /// lapsed) and `b-full` (no slots) come before `c-free`, so `place` reaches the
    /// right host only by skipping the other two.
    async fn fleet(clock: &Arc<ManualClock>) -> anyhow::Result<(StaticRegistry, LeaseTable<Arc<ManualClock>>)> {
        let registry =
            StaticRegistry::new(["b-full", "c-free", "a-stale"].map(|id| host(id, SandboxKind::Process, Arch::X86_64)));
        let leases = LeaseTable::with_clock(TTL, clock.clone());
        leases.register(HostId::from("a-stale")).await?;
        clock.advance(TTL / 2);
        leases.register(HostId::from("b-full")).await?;
        leases.register(HostId::from("c-free")).await?;
        clock.advance(TTL / 2);
        Ok((registry, leases))
    }

    fn capacity() -> ExecutorCapacity<BusyExecutor> {
        ExecutorCapacity::new()
            .with_host(HostId::from("a-stale"), BusyExecutor { running: 0 }, 4)
            .with_host(HostId::from("b-full"), BusyExecutor { running: 4 }, 4)
            .with_host(HostId::from("c-free"), BusyExecutor { running: 0 }, 4)
    }

    #[tokio::test]
    async fn place_skips_a_stale_host_and_a_full_host() -> anyhow::Result<()> {
        let clock = ManualClock::new();
        let (registry, leases) = fleet(&clock).await?;
        let picked = place(&registry, &leases, &capacity(), &need(SandboxKind::Process, None)).await?;
        anyhow::ensure!(picked == Some(HostId::from("c-free")), "picked {picked:?}");
        Ok(())
    }

    #[tokio::test]
    async fn place_returns_none_when_no_host_qualifies() -> anyhow::Result<()> {
        let clock = ManualClock::new();
        let (registry, leases) = fleet(&clock).await?;
        let picked = place(&registry, &leases, &capacity(), &need(SandboxKind::Vm, None)).await?;
        anyhow::ensure!(picked.is_none(), "a VM job was placed on a process host: {picked:?}");
        Ok(())
    }

    #[tokio::test]
    async fn place_skips_a_live_host_with_no_capacity_source() -> anyhow::Result<()> {
        let registry = StaticRegistry::new([host("ghost", SandboxKind::Process, Arch::X86_64)]);
        let leases = LeaseTable::new(TTL);
        leases.register(HostId::from("ghost")).await?;
        let picked = place(&registry, &leases, &capacity(), &need(SandboxKind::Process, None)).await?;
        anyhow::ensure!(picked.is_none(), "picked a host with no capacity source: {picked:?}");
        Ok(())
    }
}
