//! The orchestrator side of the host-client contract (#263, epic #205 M2):
//! authenticating `Register` against an allowlist of known executor hosts,
//! tracking connected host-clients and their declared capabilities, and
//! pushing `Dispatch` messages down a host's persistent connection.
//!
//! Host-client identity (`host_id`) is self-reported and used for bookkeeping
//! and placement only — it is NEVER the authorization boundary. Authorization
//! checks the TRANSPORT's own peer identity (the mesh IP `sandy_conn` reports
//! on accept) against [`ExecutorAllowlist`], the same "never trust a
//! self-reported value for authorization" discipline [`crate::link_auth`]
//! already applies to the agent-link stream. An unknown registrant gets
//! [`RegisterError::NotAllowed`], never [`sandy_executor_proto::Registered`],
//! and is logged by the caller — never silently dropped.
//!
//! What this does NOT do: accept network connections or drive the actual
//! connection loop. It makes no I/O calls itself — the caller (the eventual
//! mesh-accept loop) supplies the peer's IP and the parsed `Register` message,
//! and this module answers accept-or-refuse plus holds the registry state.
//! Kept this way so the authorization logic is fully unit-testable without a
//! real socket, matching [`crate::link_auth`]'s own shape.

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Mutex, PoisonError},
};

use sandy_executor_proto::{Capabilities, Dispatch};
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
}

/// Why a `Register` was refused. Carries no capability or job data — a
/// refusal must never leak more than "no" (mirrors [`crate::link_auth`]'s
/// `LinkAuthError` discipline).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RegisterError {
    /// The registrant's mesh identity is not on [`ExecutorAllowlist`].
    #[error("peer is not a permitted executor host")]
    NotAllowed,
}

/// A connected host-client: its declared capabilities and the channel its
/// connection task reads from to learn about `Dispatch`es placed on it.
struct ConnectedHost {
    capabilities: Capabilities,
    dispatch_tx: mpsc::Sender<Dispatch>,
}

/// Every currently-connected, registered host-client, keyed by its
/// self-reported `host_id`. A host disappears from this registry when its
/// connection task ends (dropping the last `Arc` to its entry) — the
/// connection staying open is the host's liveness signal, so there is no
/// separate expiry or heartbeat to manage here.
#[derive(Default)]
pub struct HostRegistry {
    hosts: Mutex<HashMap<String, Arc<ConnectedHost>>>,
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
}

impl HostRegistry {
    /// Authenticate `peer_ip` against `allowlist` and, if permitted, register
    /// `host_id` with `capabilities`, returning the receiving half of its
    /// dispatch channel for the connection task to read from. Replaces any
    /// previous entry under the same `host_id` (a reconnect, not a reused id
    /// from an impersonator — that distinction is `allowlist`'s job, not
    /// this method's).
    ///
    /// # Errors
    /// [`RegisterError::NotAllowed`] if `peer_ip` is not on `allowlist`.
    pub fn register(
        &self,
        allowlist: &ExecutorAllowlist,
        peer_ip: IpAddr,
        host_id: String,
        capabilities: Capabilities,
    ) -> Result<mpsc::Receiver<Dispatch>, RegisterError> {
        if !allowlist.permits(peer_ip) {
            return Err(RegisterError::NotAllowed);
        }
        let (dispatch_tx, dispatch_rx) = mpsc::channel(8);
        self.hosts.lock().unwrap_or_else(PoisonError::into_inner).insert(
            host_id,
            Arc::new(ConnectedHost {
                capabilities,
                dispatch_tx,
            }),
        );
        Ok(dispatch_rx)
    }

    /// Remove `host_id`'s entry — called by the connection task when it ends,
    /// so a host that disconnects stops being dispatch-eligible immediately
    /// rather than lingering as a stale entry other code might still send to.
    pub fn remove(&self, host_id: &str) {
        self.hosts
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(host_id);
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

    /// Queue `dispatch` for delivery to `host_id`'s connection task.
    ///
    /// # Errors
    /// [`DispatchSendError::NoSuchHost`] if no host is registered under that
    /// id; [`DispatchSendError::ConnectionClosing`] if its connection task has
    /// already ended.
    pub async fn send_dispatch(&self, host_id: &str, dispatch: Dispatch) -> Result<(), DispatchSendError> {
        let host = self
            .hosts
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(host_id)
            .cloned()
            .ok_or(DispatchSendError::NoSuchHost)?;
        host.dispatch_tx
            .send(dispatch)
            .await
            .map_err(|_| DispatchSendError::ConnectionClosing)
    }
}

#[cfg(test)]
mod tests {
    use sandy_executor_proto::SandboxKind;

    use super::*;

    fn executor_ip() -> IpAddr {
        "100.64.0.7".parse().unwrap()
    }

    fn other_ip() -> IpAddr {
        "100.64.0.9".parse().unwrap()
    }

    fn capabilities() -> Capabilities {
        Capabilities {
            kind: SandboxKind::Process.into(),
            arch: sandy_executor_proto::Arch::X8664.into(),
            attestation: false,
            supported_isolation_classes: vec![sandy_executor_proto::IsolationClass::Trusted.into()],
        }
    }

    /// Adversarial (#263, D5 mutual auth): a registrant not on the allowlist
    /// is refused — the self-reported host_id must never be the thing that
    /// decides this.
    #[test]
    fn an_unknown_peer_is_refused_regardless_of_the_claimed_host_id() {
        let allowlist = ExecutorAllowlist::new([executor_ip()]);
        let registry = HostRegistry::default();
        let result = registry.register(&allowlist, other_ip(), "ws01".to_owned(), capabilities());
        assert_eq!(result.err(), Some(RegisterError::NotAllowed));
    }

    #[test]
    fn an_allowed_peer_registers_and_its_capabilities_are_visible() {
        let allowlist = ExecutorAllowlist::new([executor_ip()]);
        let registry = HostRegistry::default();
        registry
            .register(&allowlist, executor_ip(), "ws01".to_owned(), capabilities())
            .expect("the allowed peer must register");

        assert_eq!(registry.capabilities_of("ws01"), Some(capabilities()));
        assert_eq!(registry.capabilities_of("ghost"), None);
    }

    /// A dual-stack accept loop may report the executor's IPv4 peer in its
    /// IPv4-mapped IPv6 form — the allowlist must still recognize it, same
    /// reasoning as decision 6's peer-IP canonicalization.
    #[test]
    fn an_ipv4_mapped_ipv6_peer_matches_a_plain_ipv4_allowlist_entry() {
        let allowlist = ExecutorAllowlist::new([executor_ip()]);
        let mapped: IpAddr = "::ffff:100.64.0.7".parse().unwrap();
        assert!(allowlist.permits(mapped));
    }

    #[tokio::test]
    async fn a_dispatch_is_delivered_to_the_registered_hosts_channel() -> anyhow::Result<()> {
        let allowlist = ExecutorAllowlist::new([executor_ip()]);
        let registry = HostRegistry::default();
        let mut dispatch_rx = registry
            .register(&allowlist, executor_ip(), "ws01".to_owned(), capabilities())
            .expect("the allowed peer must register");

        let dispatch = Dispatch {
            job_id: "job-1".to_owned(),
            manifest: b"m".to_vec(),
            manifest_encoding: "test/v1".to_owned(),
            backend: SandboxKind::Process.into(),
            link_token: vec![0u8; 32],
            forward_back: "100.64.0.1:9000".to_owned(),
            required_isolation_class: sandy_executor_proto::IsolationClass::Trusted.into(),
        };
        registry.send_dispatch("ws01", dispatch.clone()).await?;

        let received = dispatch_rx.recv().await.expect("the dispatch must arrive");
        assert_eq!(received, dispatch);
        Ok(())
    }

    #[tokio::test]
    async fn dispatching_to_an_unregistered_host_is_refused() {
        let registry = HostRegistry::default();
        let dispatch = Dispatch::default();
        let result = registry.send_dispatch("ghost", dispatch).await;
        assert_eq!(result, Err(DispatchSendError::NoSuchHost));
    }

    /// Once a host's connection task ends and removes its entry, it stops
    /// being dispatch-eligible immediately — never a stale target.
    #[tokio::test]
    async fn a_removed_host_is_no_longer_dispatch_eligible() -> anyhow::Result<()> {
        let allowlist = ExecutorAllowlist::new([executor_ip()]);
        let registry = HostRegistry::default();
        let _dispatch_rx = registry
            .register(&allowlist, executor_ip(), "ws01".to_owned(), capabilities())
            .expect("the allowed peer must register");

        registry.remove("ws01");

        let result = registry.send_dispatch("ws01", Dispatch::default()).await;
        assert_eq!(result, Err(DispatchSendError::NoSuchHost));
        Ok(())
    }
}
