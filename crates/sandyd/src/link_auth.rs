//! The remote agent-link authentication gate (#212 decision 6; M2 pillar 2 —
//! architect ruling, issue #212).
//!
//! A run id is an addressing label only, never an authorization token:
//! `serve_agent_link` writes the run's agent cap as its first frame with no
//! check before it, which holds locally only because the link there is a
//! private socketpair. Once a remote executor's stream reaches the
//! orchestrator over the mesh (#159/#234), demuxing by run id alone hands the
//! real cap to whichever peer names that run id first — a mesh-authenticated
//! but wrong peer can then read the job's stdin, post forged output, or send
//! a forged `Exit` that breaks INV-11. This module is the fix: a run bound to
//! a remote executor records that executor's mesh IP and a 32-byte per-run
//! bearer token; [`JobRegistry::authenticate_remote_link`] requires both,
//! plus an unclaimed link slot, before the caller may proceed to
//! `serve_agent_link` at all.
//!
//! What this does NOT do: accept network connections. It makes no I/O calls
//! and has no `sandy-conn` dependency — the caller (the eventual mesh-accept
//! loop, #263) supplies the peer's IP and presented token from whatever
//! transport it used, and this module answers accept-or-refuse. Kept this
//! way so the authorization logic is fully unit-testable without a real
//! socket, and so it does not depend on `sandy-conn`'s `Conn`/`Listener`
//! shape, which does not yet expose a peer address to its caller.

use std::{
    net::IpAddr,
    sync::atomic::{AtomicBool, Ordering},
};

/// The length of a per-run link token, in bytes.
pub const LINK_TOKEN_LEN: usize = 32;

/// A per-run link token: a bearer secret (INV-1 discipline, same handling as
/// an agent cap). Never logged, never on argv or in an env var; travels only
/// over the encrypted control RPC to the executor and is held in forwarder
/// memory there.
#[derive(Clone)]
pub struct LinkToken([u8; LINK_TOKEN_LEN]);

impl LinkToken {
    /// A fresh, random token.
    ///
    /// # Errors
    /// [`std::io::Error`] if the OS RNG is unavailable.
    pub fn generate() -> std::io::Result<Self> {
        let mut bytes = [0u8; LINK_TOKEN_LEN];
        getrandom::fill(&mut bytes).map_err(|e| std::io::Error::other(e.to_string()))?;
        Ok(Self(bytes))
    }

    /// The raw token bytes, to send the executor over the encrypted control
    /// RPC at dispatch time. Callers must never log this value or place it
    /// anywhere other than that one RPC call (INV-1 discipline).
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; LINK_TOKEN_LEN] {
        &self.0
    }

    /// Whether `presented` matches this token, compared in constant time so a
    /// wrong guess cannot be narrowed down byte-by-byte via response timing.
    #[must_use]
    pub fn matches(&self, presented: &[u8; LINK_TOKEN_LEN]) -> bool {
        let mut diff = 0u8;
        for (a, b) in self.0.iter().zip(presented.iter()) {
            diff |= a ^ b;
        }
        diff == 0
    }
}

impl std::fmt::Debug for LinkToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("LinkToken").field(&"<redacted>").finish()
    }
}

/// A run's binding to a remote executor: the executor's mesh IP, the per-run
/// token it must present, and whether the link has already been claimed.
/// Lives on the run's [`crate::dispatch::JobChannel`] entry; `None` there for
/// a job dispatched locally, which has no mesh stream to authenticate.
pub struct RemoteLink {
    executor_ip: IpAddr,
    token: LinkToken,
    claimed: AtomicBool,
}

impl RemoteLink {
    /// Bind a run to `executor_ip` with a fresh token. Stores the address in
    /// canonical form (an IPv4-mapped IPv6 address becomes plain IPv4) so a
    /// dual-stack accept loop's `peer_addr()` — which may report an IPv4 peer
    /// in either form depending on the socket — compares equal either way;
    /// otherwise every legitimate executor on such a deployment would be
    /// refused as `WrongPeer`, a fail-closed but hard-to-diagnose outage.
    ///
    /// # Errors
    /// [`std::io::Error`] if the OS RNG is unavailable.
    pub fn new(executor_ip: IpAddr) -> std::io::Result<Self> {
        Ok(Self {
            executor_ip: executor_ip.to_canonical(),
            token: LinkToken::generate()?,
            claimed: AtomicBool::new(false),
        })
    }

    /// The token to send the executor over the control RPC (never logged by
    /// the caller).
    #[must_use]
    pub fn token(&self) -> &LinkToken {
        &self.token
    }

    /// Invalidate this link so no future stream can claim it — called on
    /// cancel, dispatch timeout, or executor teardown (#269's token-lifecycle
    /// requirement). Reuses the same `claimed` flag `authenticate` claims on
    /// success: an invalidated link and an already-claimed link both need
    /// "reject any future attempt, write zero bytes," so one flag serves
    /// both. Idempotent — invalidating an already-claimed or already-invalid
    /// link is a no-op, never a panic or error.
    pub fn invalidate(&self) {
        self.claimed.store(true, Ordering::Release);
    }

    /// Test-only: bind a run to `executor_ip` with a caller-chosen token
    /// rather than a random one, so a cross-module leak-regression test
    /// (`mesh_accept`'s tracing-capture test) can assert on predictable
    /// marker bytes it can reconstruct, instead of a value only
    /// [`LinkToken::generate`] ever sees.
    #[cfg(test)]
    pub(crate) fn with_token(executor_ip: IpAddr, token: [u8; LINK_TOKEN_LEN]) -> Self {
        Self {
            executor_ip: executor_ip.to_canonical(),
            token: LinkToken(token),
            claimed: AtomicBool::new(false),
        }
    }
}

impl std::fmt::Debug for RemoteLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteLink")
            .field("executor_ip", &self.executor_ip)
            .field("token", &self.token)
            .field("claimed", &self.claimed.load(Ordering::Relaxed))
            .finish()
    }
}

/// Why an incoming remote agent-link stream was refused. Every variant is a
/// named refusal, never a fabricated success — the caller closes the stream
/// having written zero bytes on any of these (no cap leaks on refusal).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LinkAuthError {
    /// No run is registered under this id.
    #[error("no such run")]
    UnknownRun,
    /// The run exists but was dispatched locally — it has no remote link to
    /// authenticate against.
    #[error("this run has no remote link")]
    NotRemote,
    /// The connecting peer's IP does not match the run's bound executor.
    #[error("peer does not match the run's bound executor")]
    WrongPeer,
    /// The presented token does not match.
    #[error("token does not match")]
    WrongToken,
    /// The run's link slot was already claimed by an earlier, successful
    /// stream — at most one link per run, ever.
    #[error("this run's link was already claimed")]
    AlreadyClaimed,
}

/// Authenticate an incoming remote agent-link stream against `link`'s
/// recorded executor binding, claiming the link slot atomically on success.
/// Checks peer IP and token before ever touching the claim, and claims only
/// once both match — a failed attempt never spends the slot.
///
/// # Errors
/// See [`LinkAuthError`].
pub fn authenticate(
    link: &RemoteLink,
    peer_ip: IpAddr,
    presented_token: &[u8; LINK_TOKEN_LEN],
) -> Result<(), LinkAuthError> {
    if link.executor_ip != peer_ip.to_canonical() {
        return Err(LinkAuthError::WrongPeer);
    }
    if !link.token.matches(presented_token) {
        return Err(LinkAuthError::WrongToken);
    }
    link.claimed
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .map(|_| ())
        .map_err(|_| LinkAuthError::AlreadyClaimed)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;

    fn executor_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(100, 64, 0, 7))
    }

    fn other_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(100, 64, 0, 9))
    }

    #[test]
    fn a_matching_peer_and_token_authenticates_and_claims_once() -> std::io::Result<()> {
        let link = RemoteLink::new(executor_ip())?;
        let token = *token_bytes(&link);

        assert_eq!(authenticate(&link, executor_ip(), &token), Ok(()));
        assert_eq!(
            authenticate(&link, executor_ip(), &token),
            Err(LinkAuthError::AlreadyClaimed)
        );
        Ok(())
    }

    #[test]
    fn a_mismatched_peer_is_refused_without_spending_the_slot() -> std::io::Result<()> {
        let link = RemoteLink::new(executor_ip())?;
        let token = *token_bytes(&link);

        assert_eq!(authenticate(&link, other_ip(), &token), Err(LinkAuthError::WrongPeer));
        // The wrong-peer attempt must not have claimed the slot: the real
        // executor can still connect afterward.
        assert_eq!(authenticate(&link, executor_ip(), &token), Ok(()));
        Ok(())
    }

    #[test]
    fn a_wrong_token_is_refused_without_spending_the_slot() -> std::io::Result<()> {
        let link = RemoteLink::new(executor_ip())?;
        let wrong = [0xAA; LINK_TOKEN_LEN];

        assert_eq!(
            authenticate(&link, executor_ip(), &wrong),
            Err(LinkAuthError::WrongToken)
        );
        let real = *token_bytes(&link);
        assert_eq!(authenticate(&link, executor_ip(), &real), Ok(()));
        Ok(())
    }

    /// The one-link-per-run invariant must hold under concurrent callers, not
    /// just sequential reuse: the atomic claim is the whole reason this isn't
    /// a lock-then-check race. 16 threads racing to authenticate the same run
    /// at once must admit exactly one.
    #[test]
    fn concurrent_claims_admit_exactly_one_stream() -> std::io::Result<()> {
        use std::sync::{Arc, Barrier};

        let link = Arc::new(RemoteLink::new(executor_ip())?);
        let token = *token_bytes(&link);
        let n = 16;
        let barrier = Arc::new(Barrier::new(n));
        let handles: Vec<_> = (0..n)
            .map(|_| {
                let (link, barrier) = (Arc::clone(&link), Arc::clone(&barrier));
                std::thread::spawn(move || {
                    barrier.wait();
                    authenticate(&link, executor_ip(), &token)
                })
            })
            .collect();
        let results: Vec<_> = handles.into_iter().filter_map(|handle| handle.join().ok()).collect();

        assert_eq!(results.len(), n);
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert!(
            results
                .iter()
                .filter(|result| result.is_err())
                .all(|result| *result == Err(LinkAuthError::AlreadyClaimed))
        );
        Ok(())
    }

    /// A dual-stack accept loop may report an IPv4 peer as an IPv4-mapped
    /// IPv6 address (`::ffff:100.64.0.7`); `IpAddr`'s `PartialEq` treats that
    /// as distinct from plain `100.64.0.7`, so without canonicalizing both
    /// sides, every legitimate executor on such a deployment would be
    /// refused — fail-closed, but a hard-to-diagnose outage, not a bypass.
    #[test]
    fn an_ipv4_mapped_ipv6_peer_matches_a_plain_ipv4_binding() -> anyhow::Result<()> {
        use anyhow::Context;
        let link = RemoteLink::new(executor_ip())?;
        let token = *token_bytes(&link);
        let mapped: IpAddr = "::ffff:100.64.0.7".parse().context("mapped address literal")?;

        assert_eq!(authenticate(&link, mapped, &token), Ok(()));
        Ok(())
    }

    /// Adversarial: nothing about the token ever appears in a `Debug` format
    /// of a [`RemoteLink`] — this is the proof backing the "the token is
    /// never logged" requirement, since `tracing`'s structured fields and ad
    /// hoc `{:?}` logging both go through `Debug`. A direct substring check
    /// on the token's hex encoding is unambiguous: no byte value can
    /// coincidentally collide with it the way a single decimal byte might
    /// collide with an IP octet.
    #[test]
    fn debug_output_excludes_the_tokens_hex_encoding() -> std::io::Result<()> {
        let link = RemoteLink::new(executor_ip())?;
        let token = token_bytes(&link);
        let hex: String = token.iter().map(|b| format!("{b:02x}")).collect();

        let rendered = format!("{link:?}");
        assert!(
            rendered.contains("redacted"),
            "expected a redaction marker in Debug output, got {rendered:?}"
        );
        assert!(
            !rendered.contains(&hex),
            "the token's hex encoding leaked into Debug output"
        );
        Ok(())
    }

    fn token_bytes(link: &RemoteLink) -> &[u8; LINK_TOKEN_LEN] {
        link.token().as_bytes()
    }
}
