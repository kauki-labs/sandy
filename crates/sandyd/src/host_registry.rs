//! The orchestrator side of the host-executor contract (#263, epic #205 M2):
//! authenticating `Register` against an allowlist of known executor hosts,
//! tracking connected host-executors and their declared capabilities, and
//! pushing `Dispatch` messages down a host's persistent connection.
//!
//! Host-client identity (`host_id`) is self-reported and used for bookkeeping
//! and placement only — it is NEVER the authorization boundary. Authorization
//! checks the TRANSPORT's own peer identity (the mesh IP `sandy_conn` reports
//! on accept) against [`ExecutorAllowlist`], the same "never trust a
//! self-reported value for authorization" discipline [`crate::link_auth`]
//! already applies to the agent-link stream. An unknown registrant gets
//! [`RegisterError::NotAllowed`], never [`sandy_executor_proto::Registered`],
//! and is logged by the caller — never silently dropped. A `host_id` already
//! claimed by a different allowlisted peer is refused the same way
//! ([`RegisterError::HostIdClaimedByAnotherPeer`]): an allowed peer is still
//! not allowed to impersonate someone else's self-reported identity.
//!
//! [`HostRegistry::send_dispatch`] enforces the isolation-class gate (#269):
//! a `Dispatch` whose `required_isolation_class` the target host never
//! declared is refused outright, never silently downgraded onto whatever the
//! host happens to run.
//!
//! What this does NOT do: accept network connections or drive the actual
//! connection loop. It makes no I/O calls itself — the caller (the eventual
//! mesh-accept loop) supplies the peer's IP and the parsed `Register` message,
//! and this module answers accept-or-refuse plus holds the registry state.
//! Kept this way so the authorization logic is fully unit-testable without a
//! real socket, matching [`crate::link_auth`]'s own shape.

use std::{
    collections::{HashMap, hash_map::Entry},
    net::IpAddr,
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicU64, Ordering},
    },
};

use sandy_executor_proto::{Capabilities, Dispatch, IsolationClass};
use tokio::sync::mpsc;

/// The mesh identities permitted to register as executor hosts. Self-reported
/// `host_id`s are never checked against this — only the transport's own peer
/// IP is.
#[derive(Debug, Default, Clone)]
pub struct ExecutorAllowlist(std::collections::HashSet<IpAddr>);

impl ExecutorAllowlist {
    /// An allowlist containing exactly `ips`.
    #[must_use]
    pub fn new(ips: impl IntoIterator<Item = IpAddr>) -> Self {
        Self(ips.into_iter().map(|ip| ip.to_canonical()).collect())
    }

    /// Whether `peer_ip` is a permitted executor host. Canonicalizes before
    /// comparing, for the same reason decision 6's peer check does: a
    /// dual-stack accept loop may report an IPv4 peer in its IPv4-mapped IPv6
    /// form, which `IpAddr`'s `PartialEq` would otherwise treat as distinct
    /// from the plain IPv4 form an operator configured.
    #[must_use]
    pub fn permits(&self, peer_ip: IpAddr) -> bool {
        self.0.contains(&peer_ip.to_canonical())
    }

    /// Whether this allowlist contains no entries at all. A caller binding a
    /// mesh listener should treat a configured-but-empty allowlist as a
    /// misconfiguration (#291) — a listener nobody can ever pass is not a
    /// deliberate "allow no one" policy, just an operator who forgot to set
    /// the allowlist alongside the listen address.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Why a `Register` was refused. Carries no capability or job data — a
/// refusal must never leak more than "no" (mirrors [`crate::link_auth`]'s
/// `LinkAuthError` discipline).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RegisterError {
    /// The registrant's mesh identity is not on [`ExecutorAllowlist`].
    #[error("peer is not a permitted executor host")]
    NotAllowed,
    /// `host_id` is already registered from a different peer IP. A reconnect
    /// from the SAME peer replaces its own prior entry; a different
    /// allowlisted peer claiming someone else's `host_id` does not — `host_id`
    /// is self-reported (D5, #263), so without this check one allowed host
    /// could silently steal another's dispatch-eligible identity.
    #[error("host_id is already registered from a different peer")]
    HostIdClaimedByAnotherPeer,
}

/// Identifies one successful [`HostRegistry::register`] call. Its matching
/// [`HostRegistry::remove`] only evicts the entry that call created — never a
/// newer registration that has since replaced it under the same `host_id`,
/// which would otherwise happen when an old connection's teardown races a
/// fresh reconnect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegistrationId(u64);

/// A registered host identified as a placement candidate (#298): its id,
/// peer IP (to bind a decision-6 remote link), and declared capabilities (to
/// decide `Dispatch.backend`), captured together so a placement decision
/// never needs a second registry lookup that could race a disconnect
/// between "picked" and "used."
///
/// `registration` identifies the exact connection picked, not just the
/// `host_id` — pass it to [`HostRegistry::send_dispatch_if_current`] so a
/// dispatch queued after the gap between picking and sending never reaches a
/// DIFFERENT connection that reclaimed the same self-reported `host_id` in
/// between (the original disconnects, a different allowlisted peer registers
/// under the same `host_id` before the send).
#[derive(Debug, Clone, PartialEq)]
pub struct PlacementCandidate {
    /// The host's self-reported id — bookkeeping only, never an auth
    /// boundary (see this module's own doc).
    pub host_id: String,
    /// Identifies the exact connection this candidate was picked from.
    pub registration: RegistrationId,
    /// The host's mesh peer IP, as the transport reported it at `Register`.
    pub peer_ip: IpAddr,
    /// The host's declared capabilities.
    pub capabilities: Capabilities,
}

/// A connected host-executor: its declared capabilities and the channel its
/// connection task reads from to learn about `Dispatch`es placed on it.
struct ConnectedHost {
    peer_ip: IpAddr,
    registration: RegistrationId,
    capabilities: Capabilities,
    dispatch_tx: mpsc::Sender<Dispatch>,
}

/// Every currently-connected, registered host-executor, keyed by its
/// self-reported `host_id`. A host disappears from this registry when its
/// connection task ends (dropping the last `Arc` to its entry) — the
/// connection staying open is the host's liveness signal, so there is no
/// separate expiry or heartbeat to manage here.
#[derive(Default)]
pub struct HostRegistry {
    hosts: Mutex<HashMap<String, Arc<ConnectedHost>>>,
    next_registration: AtomicU64,
}

/// `Dispatch` could not be delivered to the named host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DispatchSendError {
    /// No host is currently registered under that id (never connected, or
    /// its connection already ended).
    #[error("no such connected host")]
    NoSuchHost,
    /// The host's connection task has already ended (a race between losing
    /// the connection and this send); the registry entry just hasn't been
    /// cleaned up yet.
    #[error("the host's connection is closing")]
    ConnectionClosing,
    /// The host never declared `dispatch.required_isolation_class` among its
    /// `supported_isolation_classes` (including an unset/`Unspecified`
    /// class, which is never an implicit match). The fail-closed isolation
    /// gate (#269): the orchestrator must not place a job on a host that
    /// cannot run it, never a silent downgrade onto trusted-process.
    #[error("host does not support the dispatch's required isolation class")]
    UnsupportedIsolationClass,
    /// [`HostRegistry::send_dispatch_if_current`] found `host_id` currently
    /// registered, but under a DIFFERENT connection than the one named —
    /// the original connection ended and a different allowlisted peer
    /// registered under the same self-reported `host_id` in the gap between
    /// a placement decision picking this host and this call. Never deliver
    /// to a connection that wasn't the one actually picked.
    #[error("host_id is registered under a different connection than the one this dispatch was placed on")]
    RegistrationChanged,
}

impl HostRegistry {
    /// Authenticate `peer_ip` against `allowlist` and, if permitted, register
    /// `host_id` with `capabilities`, returning the receiving half of its
    /// dispatch channel for the connection task to read from, plus a
    /// [`RegistrationId`] to pass to the matching [`Self::remove`]. A
    /// reconnect from the SAME `peer_ip` replaces its own previous entry; a
    /// different allowlisted peer registering under an already-claimed
    /// `host_id` is refused with [`RegisterError::HostIdClaimedByAnotherPeer`]
    /// — `host_id` is self-reported, so this is the only thing stopping one
    /// allowed host from claiming another's identity.
    ///
    /// # Errors
    /// [`RegisterError::NotAllowed`] if `peer_ip` is not on `allowlist`;
    /// [`RegisterError::HostIdClaimedByAnotherPeer`] if `host_id` is already
    /// registered under a different peer IP.
    pub fn register(
        &self,
        allowlist: &ExecutorAllowlist,
        peer_ip: IpAddr,
        host_id: String,
        capabilities: Capabilities,
    ) -> Result<(mpsc::Receiver<Dispatch>, RegistrationId), RegisterError> {
        let peer_ip = peer_ip.to_canonical();
        if !allowlist.permits(peer_ip) {
            return Err(RegisterError::NotAllowed);
        }
        let mut hosts = self.hosts.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(existing) = hosts.get(&host_id) {
            if existing.peer_ip != peer_ip {
                return Err(RegisterError::HostIdClaimedByAnotherPeer);
            }
        }
        let registration = RegistrationId(self.next_registration.fetch_add(1, Ordering::Relaxed));
        let (dispatch_tx, dispatch_rx) = mpsc::channel(8);
        hosts.insert(
            host_id,
            Arc::new(ConnectedHost {
                peer_ip,
                registration,
                capabilities,
                dispatch_tx,
            }),
        );
        Ok((dispatch_rx, registration))
    }

    /// Remove `host_id`'s entry, but only if it is still the one `registration`
    /// names — called by the connection task when it ends, so a host that
    /// disconnects stops being dispatch-eligible immediately rather than
    /// lingering as a stale entry other code might still send to. Guarding on
    /// `registration` keeps an old connection's teardown from evicting a
    /// newer reconnect that has already replaced it under the same `host_id`.
    pub fn remove(&self, host_id: &str, registration: RegistrationId) {
        let mut hosts = self.hosts.lock().unwrap_or_else(PoisonError::into_inner);
        if let Entry::Occupied(entry) = hosts.entry(host_id.to_owned()) {
            if entry.get().registration == registration {
                entry.remove();
            }
        }
    }

    /// `host_id`'s declared capabilities, if it is currently connected.
    #[must_use]
    pub fn capabilities_of(&self, host_id: &str) -> Option<Capabilities> {
        self.hosts
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(host_id)
            .map(|host| host.capabilities.clone())
    }

    /// Stage-1 placement (#298): the first currently-registered host
    /// (arbitrary order — D5's single-executor model makes "first match"
    /// equivalent to "the match"; a real scheduling policy is future work
    /// once more than one executor exists to choose between) whose declared
    /// `supported_isolation_classes` includes `required`. `None` if no
    /// registered host qualifies, including when `required` is
    /// `Unspecified` — the same fail-closed-on-missing-data rule
    /// [`Self::send_dispatch`] enforces, applied here too so a caller can't
    /// pick a host `send_dispatch` would then refuse anyway. The caller runs
    /// the job locally when this returns `None`.
    ///
    /// Returns the host's capabilities alongside its id and peer IP so a
    /// caller can build a `Dispatch` (e.g. its `backend`) without a second
    /// lookup that could race a concurrent disconnect between the two calls.
    #[must_use]
    pub fn pick_host_for(&self, required: i32) -> Option<PlacementCandidate> {
        if required == i32::from(IsolationClass::Unspecified) {
            return None;
        }
        self.hosts
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .find(|(_, host)| host.capabilities.supported_isolation_classes.contains(&required))
            .map(|(host_id, host)| PlacementCandidate {
                host_id: host_id.clone(),
                registration: host.registration,
                peer_ip: host.peer_ip,
                capabilities: host.capabilities.clone(),
            })
    }

    /// Queue `dispatch` for delivery to `host_id`'s connection task, after
    /// checking the fail-closed isolation-class gate (#269): `host_id` must
    /// have declared `dispatch.required_isolation_class` among its
    /// `supported_isolation_classes`, or the send is refused outright. An
    /// unset/`Unspecified` required class never matches anything — the gate
    /// fails closed on missing data, not open.
    ///
    /// # Errors
    /// [`DispatchSendError::NoSuchHost`] if no host is registered under that
    /// id; [`DispatchSendError::ConnectionClosing`] if its connection task has
    /// already ended; [`DispatchSendError::UnsupportedIsolationClass`] if the
    /// host never declared the dispatch's required isolation class.
    pub async fn send_dispatch(&self, host_id: &str, dispatch: Dispatch) -> Result<(), DispatchSendError> {
        let host = self
            .hosts
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(host_id)
            .cloned()
            .ok_or(DispatchSendError::NoSuchHost)?;
        Self::send_to(&host, dispatch).await
    }

    /// Like [`Self::send_dispatch`], but additionally refuses if `host_id`'s
    /// CURRENT registration is not `registration` — the exact connection a
    /// [`PlacementCandidate`] was picked from, not just whatever happens to
    /// be registered under that self-reported `host_id` now. Without this, a
    /// dispatch decided against one connection could be delivered to a
    /// DIFFERENT connection that reclaimed the same `host_id` in the gap
    /// between picking and sending (the original disconnects, a different
    /// allowlisted peer registers under the same `host_id` before this
    /// call).
    ///
    /// # Errors
    /// As [`Self::send_dispatch`], plus
    /// [`DispatchSendError::RegistrationChanged`] if `host_id` is currently
    /// registered under a different connection than `registration`.
    pub async fn send_dispatch_if_current(
        &self,
        host_id: &str,
        registration: RegistrationId,
        dispatch: Dispatch,
    ) -> Result<(), DispatchSendError> {
        let host = {
            let hosts = self.hosts.lock().unwrap_or_else(PoisonError::into_inner);
            let host = hosts.get(host_id).ok_or(DispatchSendError::NoSuchHost)?;
            if host.registration != registration {
                return Err(DispatchSendError::RegistrationChanged);
            }
            Arc::clone(host)
        };
        Self::send_to(&host, dispatch).await
    }

    /// The isolation-class gate plus the actual channel send, shared by
    /// [`Self::send_dispatch`] and [`Self::send_dispatch_if_current`] — the
    /// only difference between them is which checks run before this point.
    async fn send_to(host: &ConnectedHost, dispatch: Dispatch) -> Result<(), DispatchSendError> {
        let required = dispatch.required_isolation_class;
        let supported = required != i32::from(IsolationClass::Unspecified)
            && host.capabilities.supported_isolation_classes.contains(&required);
        if !supported {
            return Err(DispatchSendError::UnsupportedIsolationClass);
        }
        host.dispatch_tx
            .send(dispatch)
            .await
            .map_err(|_| DispatchSendError::ConnectionClosing)
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use sandy_executor_proto::SandboxKind;

    use super::*;

    fn executor_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(100, 64, 0, 7))
    }

    fn other_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(100, 64, 0, 9))
    }

    fn capabilities() -> Capabilities {
        Capabilities {
            kind: SandboxKind::Process.into(),
            arch: sandy_executor_proto::Arch::X8664.into(),
            attestation: false,
            supported_isolation_classes: vec![sandy_executor_proto::IsolationClass::Trusted.into()],
        }
    }

    fn dispatch() -> Dispatch {
        Dispatch {
            job_id: "job-1".to_owned(),
            manifest: b"m".to_vec(),
            manifest_encoding: "test/v1".to_owned(),
            backend: SandboxKind::Process.into(),
            link_token: vec![0u8; 32],
            forward_back: "100.64.0.1:9000".to_owned(),
            required_isolation_class: sandy_executor_proto::IsolationClass::Trusted.into(),
        }
    }

    /// Adversarial (#263, D5 mutual auth): a registrant not on the allowlist
    /// is refused — the self-reported host_id must never be the thing that
    /// decides this.
    #[test]
    fn a_fresh_allowlist_is_empty_and_a_populated_one_is_not() {
        assert!(ExecutorAllowlist::new([]).is_empty());
        assert!(!ExecutorAllowlist::new([executor_ip()]).is_empty());
    }

    #[test]
    fn an_unknown_peer_is_refused_regardless_of_the_claimed_host_id() {
        let allowlist = ExecutorAllowlist::new([executor_ip()]);
        let registry = HostRegistry::default();
        let result = registry.register(&allowlist, other_ip(), "ws01".to_owned(), capabilities());
        assert_eq!(result.err(), Some(RegisterError::NotAllowed));
    }

    #[test]
    fn an_allowed_peer_registers_and_its_capabilities_are_visible() -> anyhow::Result<()> {
        let allowlist = ExecutorAllowlist::new([executor_ip()]);
        let registry = HostRegistry::default();
        registry
            .register(&allowlist, executor_ip(), "ws01".to_owned(), capabilities())
            .expect("the allowed peer must register");

        assert_eq!(registry.capabilities_of("ws01"), Some(capabilities()));
        assert_eq!(registry.capabilities_of("ghost"), None);
        Ok(())
    }

    /// A dual-stack accept loop may report the executor's IPv4 peer in its
    /// IPv4-mapped IPv6 form — the allowlist must still recognize it, same
    /// reasoning as decision 6's peer-IP canonicalization.
    #[test]
    fn an_ipv4_mapped_ipv6_peer_matches_a_plain_ipv4_allowlist_entry() -> anyhow::Result<()> {
        use anyhow::Context;
        let allowlist = ExecutorAllowlist::new([executor_ip()]);
        let mapped: IpAddr = "::ffff:100.64.0.7".parse().context("mapped address literal")?;
        assert!(allowlist.permits(mapped));
        Ok(())
    }

    #[tokio::test]
    async fn a_dispatch_is_delivered_to_the_registered_hosts_channel() -> anyhow::Result<()> {
        let allowlist = ExecutorAllowlist::new([executor_ip()]);
        let registry = HostRegistry::default();
        let (mut dispatch_rx, _registration) = registry
            .register(&allowlist, executor_ip(), "ws01".to_owned(), capabilities())
            .expect("the allowed peer must register");

        let dispatch = dispatch();
        registry.send_dispatch("ws01", dispatch.clone()).await?;

        let received = dispatch_rx.recv().await.expect("the dispatch must arrive");
        assert_eq!(received, dispatch);
        Ok(())
    }

    #[tokio::test]
    async fn dispatching_to_an_unregistered_host_is_refused() {
        let registry = HostRegistry::default();
        let result = registry.send_dispatch("ghost", Dispatch::default()).await;
        assert_eq!(result, Err(DispatchSendError::NoSuchHost));
    }

    /// Fail-closed isolation gate (#269): a host that only declared TRUSTED
    /// must never receive a dispatch requiring UNTRUSTED.
    #[tokio::test]
    async fn dispatch_requiring_an_undeclared_isolation_class_is_refused() -> anyhow::Result<()> {
        let allowlist = ExecutorAllowlist::new([executor_ip()]);
        let registry = HostRegistry::default();
        registry
            .register(&allowlist, executor_ip(), "ws01".to_owned(), capabilities())
            .expect("the allowed peer must register");

        let mut dispatch = dispatch();
        dispatch.required_isolation_class = sandy_executor_proto::IsolationClass::Untrusted.into();
        let result = registry.send_dispatch("ws01", dispatch).await;
        assert_eq!(result, Err(DispatchSendError::UnsupportedIsolationClass));
        Ok(())
    }

    /// The gate fails closed on missing data too: an unset required class
    /// never matches anything, even a host that declared classes.
    #[tokio::test]
    async fn dispatch_with_an_unset_isolation_class_is_refused() -> anyhow::Result<()> {
        let allowlist = ExecutorAllowlist::new([executor_ip()]);
        let registry = HostRegistry::default();
        registry
            .register(&allowlist, executor_ip(), "ws01".to_owned(), capabilities())
            .expect("the allowed peer must register");

        let mut dispatch = dispatch();
        dispatch.required_isolation_class = sandy_executor_proto::IsolationClass::Unspecified.into();
        let result = registry.send_dispatch("ws01", dispatch).await;
        assert_eq!(result, Err(DispatchSendError::UnsupportedIsolationClass));
        Ok(())
    }

    /// Once a host's connection task ends and removes its entry, it stops
    /// being dispatch-eligible immediately — never a stale target.
    #[tokio::test]
    async fn a_removed_host_is_no_longer_dispatch_eligible() -> anyhow::Result<()> {
        let allowlist = ExecutorAllowlist::new([executor_ip()]);
        let registry = HostRegistry::default();
        let (_dispatch_rx, registration) = registry
            .register(&allowlist, executor_ip(), "ws01".to_owned(), capabilities())
            .expect("the allowed peer must register");

        registry.remove("ws01", registration);

        let result = registry.send_dispatch("ws01", Dispatch::default()).await;
        assert_eq!(result, Err(DispatchSendError::NoSuchHost));
        Ok(())
    }

    /// Positive (#298): a registered host whose declared capabilities
    /// satisfy the required class is picked, with its peer IP and
    /// capabilities returned alongside its id.
    #[test]
    fn pick_host_for_returns_a_qualifying_registered_host() {
        let allowlist = ExecutorAllowlist::new([executor_ip()]);
        let registry = HostRegistry::default();
        registry
            .register(&allowlist, executor_ip(), "ws01".to_owned(), capabilities())
            .expect("the allowed peer must register");

        let picked = registry
            .pick_host_for(IsolationClass::Trusted.into())
            .expect("a Trusted-capable host is registered");
        assert_eq!(picked.host_id, "ws01");
        assert_eq!(picked.peer_ip, executor_ip());
        assert_eq!(picked.capabilities, capabilities());
    }

    /// Adversarial (#298): no registered host at all means no placement —
    /// the caller must fall back to running the job locally, not panic or
    /// fabricate a target.
    #[test]
    fn pick_host_for_returns_none_with_no_registered_hosts() {
        let registry = HostRegistry::default();
        assert_eq!(registry.pick_host_for(IsolationClass::Trusted.into()), None);
    }

    /// Adversarial (#298): a registered host that does NOT declare the
    /// required class is never picked, even though it's the only host
    /// registered — the fail-closed gate applies at placement time, not
    /// only at `send_dispatch`.
    #[test]
    fn pick_host_for_skips_a_host_that_does_not_support_the_required_class() {
        let allowlist = ExecutorAllowlist::new([executor_ip()]);
        let registry = HostRegistry::default();
        registry
            .register(&allowlist, executor_ip(), "ws01".to_owned(), capabilities()) // Trusted only
            .expect("the allowed peer must register");

        assert_eq!(registry.pick_host_for(IsolationClass::Untrusted.into()), None);
    }

    /// Adversarial (#298, the same fail-closed-on-missing-data rule
    /// `send_dispatch` enforces): an unspecified required class never
    /// matches anything, even a host that declared real classes — picking a
    /// host `send_dispatch` would then refuse anyway is strictly worse than
    /// not placing at all.
    #[test]
    fn pick_host_for_refuses_an_unspecified_required_class() {
        let allowlist = ExecutorAllowlist::new([executor_ip()]);
        let registry = HostRegistry::default();
        registry
            .register(&allowlist, executor_ip(), "ws01".to_owned(), capabilities())
            .expect("the allowed peer must register");

        assert_eq!(registry.pick_host_for(IsolationClass::Unspecified.into()), None);
    }

    /// Regression (#298): a host removed from the registry (disconnected) is
    /// no longer a placement candidate, mirroring
    /// `a_removed_host_is_no_longer_dispatch_eligible` above for the picking
    /// side, not just the sending side.
    #[test]
    fn pick_host_for_skips_a_removed_host() {
        let allowlist = ExecutorAllowlist::new([executor_ip()]);
        let registry = HostRegistry::default();
        let (_rx, registration) = registry
            .register(&allowlist, executor_ip(), "ws01".to_owned(), capabilities())
            .expect("the allowed peer must register");
        registry.remove("ws01", registration);

        assert_eq!(registry.pick_host_for(IsolationClass::Trusted.into()), None);
    }

    /// Regression (CodeRabbit, #301): a dispatch decided against one
    /// connection must never reach a DIFFERENT connection that reclaimed the
    /// same self-reported `host_id` in the gap between picking and sending —
    /// the original disconnects, a different allowlisted peer registers
    /// under the same `host_id` before `send_dispatch_if_current` runs.
    /// Plain `send_dispatch` (host_id alone) would have delivered to the
    /// new, wrong connection; `send_dispatch_if_current` must refuse.
    #[tokio::test]
    async fn send_dispatch_if_current_refuses_a_reclaimed_host_id() -> anyhow::Result<()> {
        let allowlist = ExecutorAllowlist::new([executor_ip(), other_ip()]);
        let registry = HostRegistry::default();

        // The original connection is picked for placement...
        let candidate = registry
            .register(&allowlist, executor_ip(), "ws01".to_owned(), capabilities())
            .map(|(_rx, registration)| PlacementCandidate {
                host_id: "ws01".to_owned(),
                registration,
                peer_ip: executor_ip(),
                capabilities: capabilities(),
            })
            .expect("the allowed peer must register");

        // ...then disconnects, and a DIFFERENT allowlisted peer reclaims the
        // same host_id before the dispatch is actually sent.
        registry.remove("ws01", candidate.registration);
        let (mut new_dispatch_rx, _new_registration) = registry
            .register(&allowlist, other_ip(), "ws01".to_owned(), capabilities())
            .expect("a different allowlisted peer may reclaim the vacated host_id");

        let result = registry
            .send_dispatch_if_current(&candidate.host_id, candidate.registration, dispatch())
            .await;
        assert_eq!(result, Err(DispatchSendError::RegistrationChanged));
        assert!(
            new_dispatch_rx.try_recv().is_err(),
            "the reclaiming connection must never receive a dispatch placed on the connection it replaced"
        );
        Ok(())
    }

    /// Positive counterpart: when `host_id`'s registration has NOT changed
    /// since it was picked, `send_dispatch_if_current` delivers exactly like
    /// plain `send_dispatch` would.
    #[tokio::test]
    async fn send_dispatch_if_current_delivers_when_the_registration_still_matches() -> anyhow::Result<()> {
        let allowlist = ExecutorAllowlist::new([executor_ip()]);
        let registry = HostRegistry::default();
        let (mut dispatch_rx, registration) = registry
            .register(&allowlist, executor_ip(), "ws01".to_owned(), capabilities())
            .expect("the allowed peer must register");

        registry
            .send_dispatch_if_current("ws01", registration, dispatch())
            .await?;
        let received = dispatch_rx.recv().await.expect("the dispatch must arrive");
        assert_eq!(received, dispatch());
        Ok(())
    }

    /// Adversarial (#263, D5): `host_id` is self-reported, so a different
    /// allowlisted peer must never be able to claim one that's already
    /// registered — that would hand it jobs meant for the real host.
    #[test]
    fn a_different_allowed_peer_cannot_claim_an_already_registered_host_id() -> anyhow::Result<()> {
        let allowlist = ExecutorAllowlist::new([executor_ip(), other_ip()]);
        let registry = HostRegistry::default();
        registry
            .register(&allowlist, executor_ip(), "ws01".to_owned(), capabilities())
            .expect("the first peer must register");

        let result = registry.register(&allowlist, other_ip(), "ws01".to_owned(), capabilities());
        assert_eq!(result.err(), Some(RegisterError::HostIdClaimedByAnotherPeer));
        Ok(())
    }

    /// The SAME peer reconnecting under its own `host_id` is a legitimate
    /// reconnect, not an impersonation — it must still succeed, with a fresh
    /// `RegistrationId` distinguishing the new connection from the old one.
    #[test]
    fn the_same_peer_can_reregister_under_its_own_host_id() -> anyhow::Result<()> {
        let allowlist = ExecutorAllowlist::new([executor_ip()]);
        let registry = HostRegistry::default();
        let (_rx1, first) = registry
            .register(&allowlist, executor_ip(), "ws01".to_owned(), capabilities())
            .expect("the first registration must succeed");
        let (_rx2, second) = registry
            .register(&allowlist, executor_ip(), "ws01".to_owned(), capabilities())
            .expect("the reconnect must succeed");

        assert_ne!(first, second);
        Ok(())
    }

    /// Regression: the OLD connection's own teardown racing a fresh reconnect
    /// must not evict the NEW registration that has already replaced it.
    #[tokio::test]
    async fn ending_an_older_registration_leaves_a_newer_one_dispatch_eligible() -> anyhow::Result<()> {
        let allowlist = ExecutorAllowlist::new([executor_ip()]);
        let registry = HostRegistry::default();
        let (_rx1, stale) = registry
            .register(&allowlist, executor_ip(), "ws01".to_owned(), capabilities())
            .expect("the first registration must succeed");
        let (mut rx2, _current) = registry
            .register(&allowlist, executor_ip(), "ws01".to_owned(), capabilities())
            .expect("the reconnect must succeed");

        registry.remove("ws01", stale); // the old connection's own teardown, after the reconnect

        let dispatch = dispatch();
        registry.send_dispatch("ws01", dispatch.clone()).await?;
        assert_eq!(rx2.recv().await, Some(dispatch));
        Ok(())
    }
}
