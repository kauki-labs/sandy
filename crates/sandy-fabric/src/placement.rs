//! The placement seams (spec §3.6, §3.7): [`Discovery`], [`Capacity`], [`Lifecycle`].
//!
//! Requester-driven: a dispatcher asks [`Discovery`] which hosts can run a job,
//! probes their [`Capacity`], and relies on [`Lifecycle`] leases for which hosts
//! are live. Defaults are a static registry, a direct probe, and lease soft-state;
//! a tracker/DHT, heartbeats, and a full state machine are richer impls over the
//! same contracts.
//!
//! Distinct from [`sandy_api::discovery::Discovery`], which resolves *build*
//! placement (nix systems, remote builder) for one job; this seam finds *hosts*.

use std::future::Future;

use serde::{Deserialize, Serialize};

use crate::{
    executor::{Capabilities, Requirements},
    types::HostId,
};

/// A host and the sandboxes it advertises.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostDescriptor {
    /// The host.
    pub host: HostId,
    /// What it can run (its executor's self-registration).
    pub capabilities: Capabilities,
}

/// A discovery failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DiscoveryError {
    /// The registry or tracker is unreachable.
    #[error("discovery unavailable: {0}")]
    Unavailable(String),
}

/// Finds hosts that can run a job.
pub trait Discovery: Send + Sync {
    /// Register (or replace) a host's advertisement.
    fn register(&self, host: HostDescriptor) -> impl Future<Output = Result<(), DiscoveryError>> + Send;
    /// The registered hosts whose capabilities satisfy `req`, per
    /// [`capabilities_satisfy`](crate::executor::capabilities_satisfy).
    fn find(&self, req: &Requirements) -> impl Future<Output = Result<Vec<HostDescriptor>, DiscoveryError>> + Send;
}

/// A host's spare capacity at probe time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Availability {
    /// Jobs the host can accept now.
    pub free_slots: u32,
}

impl Availability {
    /// Whether the host can accept a job now.
    pub fn can_accept(&self) -> bool {
        self.free_slots > 0
    }
}

/// A capacity failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CapacityError {
    /// The host is not known to this capacity source.
    #[error("unknown host {0:?}")]
    UnknownHost(HostId),
    /// The probe failed.
    #[error("probe failed: {0}")]
    Probe(String),
}

/// Reports a host's spare capacity.
pub trait Capacity: Send + Sync {
    /// Probe `host`. Read-only: probing reserves nothing. An unknown host fails
    /// with [`CapacityError::UnknownHost`] rather than reporting capacity.
    fn probe(&self, host: &HostId) -> impl Future<Output = Result<Availability, CapacityError>> + Send;
}

/// A host's registration, kept alive by heartbeats until its TTL lapses.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Lease {
    /// The leased host.
    pub host: HostId,
    /// The lease id, unique per registration.
    pub id: u64,
}

/// A lifecycle failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LifecycleError {
    /// The lease is unknown, expired, or already deregistered.
    #[error("unknown lease")]
    UnknownLease,
    /// The lease store failed.
    #[error("lease store: {0}")]
    Store(String),
}

/// Tracks which hosts are live, as lease soft-state.
pub trait Lifecycle: Send + Sync {
    /// Register `host`; it is live until deregistered or its lease lapses.
    fn register(&self, host: HostId) -> impl Future<Output = Result<Lease, LifecycleError>> + Send;
    /// Renew `lease`. An unknown lease fails with [`LifecycleError::UnknownLease`].
    fn heartbeat(&self, lease: &Lease) -> impl Future<Output = Result<(), LifecycleError>> + Send;
    /// End `lease`; its host is no longer live. An unknown lease fails with
    /// [`LifecycleError::UnknownLease`].
    fn deregister(&self, lease: &Lease) -> impl Future<Output = Result<(), LifecycleError>> + Send;
    /// The hosts with a live lease.
    fn live(&self) -> impl Future<Output = Result<Vec<HostId>, LifecycleError>> + Send;
}
