//! The channel abstraction (spec §3.3, issue #106): membership, cap verification,
//! envelope construction and delivery, layered once over any [`ChannelBackend`] so
//! every backend (in-memory, vsock, P2P, …) inherits boundedness, dedup and
//! ordering without reimplementing them.
//!
//! Membership is per-join, not per-peer: `join(cap)` returns a [`MembershipId`]
//! keyed on the cap's own proof, so a principal holding two distinct caps (its own,
//! and an attenuated representative cap handed to a sub-agent) is two distinct
//! members. That is the fabric's representative-delegation model (spec §3.8: a
//! sub-agent "joins as the parent's representative" — same principal, narrower
//! rights, not a new one).

use std::{
    collections::HashMap,
    pin::Pin,
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll, Waker},
};

use futures_core::Stream;
use sandy_fabric::{
    capauth::{Cap, CapAuthority, CapError, CapRights},
    channel_backend::{ChannelBackend, ChannelBackendError, Envelope, MSG_ID_KEY},
    types::ChannelId,
};
use sandy_proto::MessageType;
use sha2::{Digest, Sha256};
use tokio::sync::Mutex as AsyncMutex;

/// A [`Channel`] failure: membership, capability, or the backing [`ChannelBackend`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ChannelError {
    /// The membership id names no current member (post/subscribe/leave/invite by
    /// one, or a membership `leave` already removed).
    #[error("not a member of this channel")]
    NotAMember,
    /// A presented capability failed verification.
    #[error("capability rejected: {0}")]
    Cap(#[from] CapError),
    /// A capability verified but scopes to a different channel (boundedness).
    #[error("capability scoped to a different channel")]
    WrongChannel,
    /// The member's rights don't cover the attempted action.
    #[error("missing `{0}` right")]
    InsufficientRights(&'static str),
    /// The backing store failed.
    #[error("backend error: {0}")]
    Backend(#[from] ChannelBackendError),
}

/// An opaque handle to one accepted [`Channel::join`]: identifies a specific cap's
/// membership, not a peer. Holds a digest of the cap's proof, not the proof
/// itself, so the key a caller holds and compares can't be used to forge
/// presentation elsewhere. The channel's own `members` map still retains the
/// full [`Cap`] (proof included) as the stored value — `invite()` needs it to
/// re-verify and attenuate — guarded instead by `Cap`'s own redacting `Debug`
/// (sandy-fabric). A digest key means re-presenting the same cap resolves to
/// the same membership, and two distinct caps (even for the same peer) are two
/// distinct memberships.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct MembershipId(String);

impl std::fmt::Debug for MembershipId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("MembershipId")
            .field(&format_args!("{}…", self.0.get(..8).unwrap_or(&self.0)))
            .finish()
    }
}

/// Hex-encoded SHA-256 over the concatenation of `parts`, as distinct byte
/// strings (the caller is responsible for framing each part unambiguously if
/// the boundary between them matters — see `content_id`).
fn hash_hex(parts: &[&[u8]]) -> String {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hex::encode(hasher.finalize())
}

/// The membership id for `cap`: a digest of its proof, not the proof itself.
fn membership_id(cap: &Cap) -> MembershipId {
    MembershipId(hash_hex(&[&cap.proof]))
}

/// Per-membership delivery state for a resumable `subscribe()`: which
/// generation is live, the delivery cursor, and a waker to notify when the
/// generation changes. `generation` comes from `Channel::next_generation`
/// (channel-wide monotonic, never reset per membership), so a rejoin after
/// `leave()` always gets a generation no stale stream from a prior life can
/// ever match, even when the rejoin reuses the same `MembershipId` (the same
/// cap re-presented).
struct MembershipState {
    generation: u64,
    cursor: u64,
    waker: Option<Waker>,
}

/// Bounded membership + delivery over a [`ChannelBackend`] (spec §3.3). Every
/// boundedness/dedup/ordering guarantee is enforced here, once, so every backend
/// inherits it. `B`'s `stream_from` is `'static` by its trait contract, so
/// `subscribe()`'s returned stream outlives the call that created it without
/// `Channel` itself needing to be `Clone`.
pub struct Channel<B, A> {
    id: ChannelId,
    backend: B,
    authority: A,
    members: Mutex<HashMap<MembershipId, Cap>>,
    sessions: Arc<Mutex<HashMap<MembershipId, MembershipState>>>,
    next_generation: AtomicU64,
    // An async mutex, not an AtomicU64: sequence assignment and the backend
    // append it labels must land as one atomic unit (held across the .await),
    // or two concurrent posts can make their appends visible out of sequence
    // order. A live follower's cursor only ever advances to "next available
    // sequence >= cursor" (see ChannelBackend::stream_from); if post N+1's
    // append completes before post N's, a follower parked at or before N jumps
    // straight to N+1 and N is never delivered live again, even though it's
    // correctly stored (a later fetch/resubscribe-from-0 would still see it).
    // Holding this across the append makes that ordering impossible: N+1
    // cannot even be assigned until N's append has returned.
    next_seq: AsyncMutex<u64>,
}

impl<B: ChannelBackend, A: CapAuthority> Channel<B, A> {
    /// A channel `id` backed by `backend`, with no members. Resumes sequence
    /// assignment after `backend`'s highest stored entry rather than assuming
    /// `backend` is empty: a fresh `InMem::default()` has nothing to find and
    /// starts at 0 as before, but a reattached or otherwise pre-populated
    /// backend (e.g. two `Channel`s constructed around one cloned handle) would
    /// otherwise restart at 0 and collide with what's already stored — `InMem`
    /// rejects that outright (#107's `sequence_collision_between_distinct_ids_is_rejected`),
    /// so the very first post would fail. This does not make concurrent
    /// multi-`Channel` writers against one backend safe in general — that's the
    /// multi-writer ordering already deferred by the single-writer MVP decision
    /// — it only fixes the construction-time starting point.
    ///
    /// # Errors
    /// Whatever `backend.fetch` returns, propagated: the initial read this
    /// needs to find the current high-water mark can fail like any other call.
    pub async fn new(id: ChannelId, backend: B, authority: A) -> Result<Self, ChannelBackendError> {
        let next = backend
            .fetch(0)
            .await?
            .iter()
            .map(|env| env.sequence + 1)
            .max()
            .unwrap_or(0);
        Ok(Self {
            id,
            backend,
            authority,
            members: Mutex::new(HashMap::new()),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            next_generation: AtomicU64::new(0),
            next_seq: AsyncMutex::new(next),
        })
    }

    /// The stored cap for `membership`, cloned out from under the lock (so the
    /// caller never holds `members`' mutex across anything slower than a clone
    /// — see `invite`'s use of this), then re-verified against the authority:
    /// a cap that expired or was revoked (#129) since `join` is rejected here,
    /// not trusted from the cache. Closes that gap for every fresh
    /// `post`/`subscribe`/`invite` call. What this does NOT close: a `leave()`
    /// racing a just-started call still lands it (checked once, not held
    /// across the call). An already-open `subscribe()` stream DOES have its
    /// own checkpoint now (`CursorStream`'s generation check, #184) — but only
    /// against an explicit `leave()`; it does not re-verify against the
    /// authority, so a cap that organically expires (TTL) while its stream is
    /// open is not caught by either path. That's #188, not this.
    fn member(&self, membership: &MembershipId) -> Result<Cap, ChannelError> {
        let cap = self
            .members
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(membership)
            .cloned()
            .ok_or(ChannelError::NotAMember)?;
        self.authority.verify(&cap)?;
        Ok(cap)
    }

    fn rights_of(&self, membership: &MembershipId) -> Result<CapRights, ChannelError> {
        Ok(self.member(membership)?.scope.rights)
    }

    /// Verify `cap` against this channel and admit it as a new membership.
    /// Boundedness: a cap scoped to a different channel is rejected.
    pub fn join(&self, cap: &Cap) -> Result<MembershipId, ChannelError> {
        let scope = self.authority.verify(cap)?;
        if scope.channel != self.id {
            return Err(ChannelError::WrongChannel);
        }
        let id = membership_id(cap);
        self.members
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(id.clone(), cap.clone());
        Ok(id)
    }

    /// Remove `membership` and end its session. If a `subscribe()` stream is
    /// currently open for it, this wakes it: the stream re-polls, observes its
    /// generation no longer matches (the entry is gone), and ends itself
    /// (`CursorStream`) rather than waiting indefinitely for the backend's next
    /// append, which may never come (#184). Covers only this explicit call: an
    /// organically-expiring TTL on an open stream is NOT proactively caught —
    /// no periodic re-check runs here — tracked separately as #188.
    pub fn leave(&self, membership: &MembershipId) {
        self.members
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(membership);
        if let Some(state) = self
            .sessions
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(membership)
        {
            if let Some(waker) = state.waker {
                waker.wake();
            }
        }
    }

    /// Request an attenuated cap narrowed to `rights`, for a sub-agent that will
    /// join as `inviter`'s representative (spec §3.8): same principal, same
    /// channel, only narrower. `inviter` must hold `invite` rights. This does not
    /// itself admit anyone — the Channel is not a minting authority (INV-1); the
    /// returned cap travels out of band and its holder still calls `join`.
    pub fn invite(&self, inviter: &MembershipId, rights: CapRights) -> Result<Cap, ChannelError> {
        // `member()` already releases the lock before returning: `attenuate` is
        // a signing operation, and a real backend's latency shouldn't serialize
        // every other join/leave/post/subscribe behind this one mutex.
        let parent = self.member(inviter)?;
        if !parent.scope.rights.invite {
            return Err(ChannelError::InsufficientRights("invite"));
        }
        Ok(self.authority.attenuate(&parent, rights)?)
    }

    /// Post `payload` as `membership`, which must hold `post` rights. Returns the
    /// envelope's content id. A re-post of identical content (`payload` +
    /// `content_type` + `message_type`, never `sequence`) is deduplicated by the
    /// backend to the same id.
    pub async fn post(
        &self,
        membership: &MembershipId,
        message_type: Option<MessageType>,
        content_type: impl Into<String>,
        payload: Vec<u8>,
    ) -> Result<String, ChannelError> {
        let rights = self.rights_of(membership)?;
        if !rights.post {
            return Err(ChannelError::InsufficientRights("post"));
        }
        let content_type = content_type.into();
        let id = content_id(&message_type, &content_type, &payload);
        // Held across the append: see the field comment on `next_seq` for why
        // assign-then-append must be one atomic unit, not two separate steps.
        let mut next_seq = self.next_seq.lock().await;
        let sequence = *next_seq;
        let env = Envelope {
            sequence,
            message_type,
            content_type,
            payload,
            metadata: HashMap::from([(MSG_ID_KEY.to_owned(), id.clone())]),
        };
        self.backend.append(env).await?;
        *next_seq += 1;
        Ok(id)
    }

    /// Subscribe as `membership`, which must hold `read` rights. Resumes from this
    /// membership's last-delivered cursor (0 on first subscribe), so dropping the
    /// stream and subscribing again later — the "member goes offline, comes back"
    /// case — delivers what was missed, not just the live tail. The cursor
    /// advances as the stream is read.
    ///
    /// Two concurrent `subscribe()` calls on the same membership each read the
    /// cursor independently and race on writing it back as they're polled; the
    /// result is unspecified interleaving, not corruption. Not a step-1 concern:
    /// one membership subscribing twice at once isn't the expected shape (a
    /// membership is one agent's one session).
    pub fn subscribe(
        &self,
        membership: &MembershipId,
    ) -> Result<impl Stream<Item = Result<Envelope, ChannelBackendError>> + Send + 'static, ChannelError> {
        let rights = self.rights_of(membership)?;
        if !rights.read {
            return Err(ChannelError::InsufficientRights("read"));
        }
        // Reuse the existing session (same generation, resume at its cursor)
        // if this membership already has one open or recently closed; a fresh
        // generation is assigned only when there's none — i.e. the first
        // subscribe ever, or after a `leave()` removed the prior one.
        let mut sessions = self.sessions.lock().unwrap_or_else(PoisonError::into_inner);
        let state = sessions.entry(membership.clone()).or_insert_with(|| MembershipState {
            generation: self.next_generation.fetch_add(1, Ordering::SeqCst),
            cursor: 0,
            waker: None,
        });
        let generation = state.generation;
        let from = state.cursor;
        drop(sessions);
        Ok(CursorStream {
            inner: Box::pin(self.backend.stream_from(from)),
            sessions: Arc::clone(&self.sessions),
            membership: membership.clone(),
            generation,
        })
    }
}

/// Wraps a backend stream to advance the membership's stored cursor as it's
/// read, so a later `subscribe()` on the same membership resumes where this
/// one left off rather than from the start, and to end itself when `leave()`
/// invalidates its generation (#184) — explicit `leave()` only: an
/// organically-expiring TTL on an already-open stream is NOT proactively
/// caught, no periodic re-check runs here; that's #188, and `member()`'s doc
/// comment carries the same caveat for the per-call path.
///
/// Accepted step-1 simplification: the cursor advances on yield (`poll_next`
/// returning `Ready`), before the consumer has actually acted on the envelope.
/// A consumer cancelled between the yield and acting on it (e.g. the stream
/// dropped mid-`select!`) loses that envelope — at-most-once, not the
/// at-least-once the spec wants for the offline/reconnect case. True
/// at-least-once needs a consumer-ack'd or consumer-managed cursor instead of
/// one the backend advances on delivery; tracked as #186, not fixed here.
struct CursorStream {
    inner: Pin<Box<dyn Stream<Item = Result<Envelope, ChannelBackendError>> + Send>>,
    sessions: Arc<Mutex<HashMap<MembershipId, MembershipState>>>,
    membership: MembershipId,
    /// The generation this stream was created (or last confirmed current)
    /// under. Compared against `sessions`' live value on every poll; a
    /// mismatch (including the entry being gone entirely) means `leave()`
    /// happened, and this stream ends rather than continuing to deliver.
    generation: u64,
}

impl Stream for CursorStream {
    type Item = Result<Envelope, ChannelBackendError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        // Still current? Checked before polling the backend at all: no point
        // fetching an envelope for a membership that's already gone.
        {
            let sessions = this.sessions.lock().unwrap_or_else(PoisonError::into_inner);
            match sessions.get(&this.membership) {
                Some(state) if state.generation == this.generation => {}
                _ => return Poll::Ready(None),
            }
        }

        match this.inner.as_mut().poll_next(cx) {
            Poll::Ready(Some(Ok(env))) => {
                let mut sessions = this.sessions.lock().unwrap_or_else(PoisonError::into_inner);
                match sessions.get_mut(&this.membership) {
                    Some(state) if state.generation == this.generation => {
                        state.cursor = env.sequence + 1;
                        Poll::Ready(Some(Ok(env)))
                    }
                    // Revoked between the check above and the backend's
                    // yield: discard rather than deliver past the end.
                    _ => Poll::Ready(None),
                }
            }
            Poll::Pending => {
                // Stash our own waker: the backend's own stream only wakes on
                // its next append (see ChannelBackend::stream_from), which may
                // never come. leave() wakes THIS one directly, so the stream
                // re-polls and hits the generation check above even when
                // nothing is ever posted again.
                if let Some(state) = this
                    .sessions
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .get_mut(&this.membership)
                {
                    state.waker = Some(cx.waker().clone());
                }
                Poll::Pending
            }
            other => other,
        }
    }
}

/// The content id: a hash of `payload` + `content_type` + `message_type`'s variant
/// — never `sequence` or `metadata` — so a re-post under a new sequence still
/// dedups to the same id. Step-1 `message_type` variants carry no fields, so the
/// variant tag is their whole identity; this match being exhaustive means adding a
/// field to a variant later forces a compile-time update here rather than a silent
/// hash that ignores the new content.
fn content_id(message_type: &Option<MessageType>, content_type: &str, payload: &[u8]) -> String {
    let tag: u8 = match message_type {
        None => 0,
        Some(MessageType::Control(_)) => 1,
        Some(MessageType::Tty(_)) => 2,
        Some(MessageType::Output(_)) => 3,
        Some(MessageType::Telemetry(_)) => 4,
        Some(MessageType::Escalate(_)) => 5,
        Some(MessageType::PeerMsg(_)) => 6,
    };
    // Length-prefix content_type: without it, ("ab","c") and ("a","bc") hash
    // identically, so a genuinely different message would silently dedup away
    // as a "duplicate" of an unrelated one. The length makes the boundary
    // between content_type and payload unambiguous; nothing after payload
    // needs its own prefix since it's always the last field.
    let len_prefix = (content_type.len() as u64).to_be_bytes();
    hash_hex(&[&[tag], &len_prefix, content_type.as_bytes(), payload])
}

#[cfg(test)]
mod tests {
    use std::{
        hash::{DefaultHasher, Hash, Hasher},
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    use anyhow::Context;
    use futures_util::StreamExt;
    use sandy_fabric::{capauth::CapScope, types::PeerId};

    use super::*;
    use crate::inmem::InMem;

    /// A minimal [`CapAuthority`] test double: proof = a keyed hash of the scope,
    /// enough to catch tampering, not real cryptography. sandy-fabric's own
    /// equivalent (`contract::fakes::FakeAuthority`) is `#[cfg(test)]`-private to
    /// that crate, so Channel's tests carry this small mirror rather than wait on
    /// it being exported. `Clone` + an `Arc`-backed revoked set: a test needs a
    /// handle to the SAME authority instance `Channel` holds internally, to call
    /// `revoke()` on it from outside.
    #[derive(Default, Clone)]
    struct TestAuthority {
        revoked: Arc<Mutex<std::collections::HashSet<Vec<u8>>>>,
    }

    impl TestAuthority {
        fn proof(&self, scope: &CapScope) -> Vec<u8> {
            let mut h = DefaultHasher::new();
            0x5eed_u64.hash(&mut h);
            (&scope.peer, &scope.channel, scope.expires_at).hash(&mut h);
            (scope.rights.post, scope.rights.read, scope.rights.invite).hash(&mut h);
            h.finish().to_be_bytes().to_vec()
        }

        fn revoke(&self, cap: &Cap) {
            self.revoked
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(cap.proof.clone());
        }
    }

    impl CapAuthority for TestAuthority {
        fn mint(&self, scope: CapScope) -> Result<Cap, CapError> {
            let proof = self.proof(&scope);
            Ok(Cap { scope, proof })
        }

        fn verify(&self, cap: &Cap) -> Result<CapScope, CapError> {
            if cap.proof != self.proof(&cap.scope) {
                return Err(CapError::Forged);
            }
            let now = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
            if cap.scope.expires_at.is_some_and(|t| t <= now) {
                return Err(CapError::Expired);
            }
            if self
                .revoked
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .contains(&cap.proof)
            {
                return Err(CapError::Revoked);
            }
            Ok(cap.scope.clone())
        }

        fn attenuate(&self, parent: &Cap, rights: CapRights) -> Result<Cap, CapError> {
            let scope = self.verify(parent)?;
            if !rights.is_subset_of(&scope.rights) {
                return Err(CapError::Widened);
            }
            self.mint(CapScope { rights, ..scope })
        }
    }

    fn full() -> CapRights {
        CapRights {
            post: true,
            read: true,
            invite: true,
        }
    }

    fn read_only() -> CapRights {
        CapRights {
            read: true,
            ..CapRights::default()
        }
    }

    fn later() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs()) + 3600
    }

    fn mint(
        authority: &TestAuthority,
        peer: &str,
        channel: &ChannelId,
        rights: CapRights,
        expires_at: Option<u64>,
    ) -> Cap {
        authority
            .mint(CapScope {
                peer: PeerId::from(peer),
                channel: channel.clone(),
                rights,
                expires_at,
            })
            .expect("mint")
    }

    async fn new_channel() -> anyhow::Result<(Channel<InMem, TestAuthority>, InMem, ChannelId, TestAuthority)> {
        let id = ChannelId::from("c1");
        let backend = InMem::default();
        let authority = TestAuthority::default();
        // Clone, not a second `default()`: the returned `authority` must be the
        // SAME instance Channel holds (shared `revoked` set), so a test can call
        // `authority.revoke(&cap)` and have Channel's own `member()` see it.
        let channel = Channel::new(id.clone(), backend.clone(), authority.clone())
            .await
            .context("Channel::new")?;
        Ok((channel, backend, id, authority))
    }

    async fn next(stream: &mut (impl Stream<Item = Result<Envelope, ChannelBackendError>> + Unpin)) -> Envelope {
        tokio::time::timeout(Duration::from_secs(2), stream.next())
            .await
            .expect("stream yielded before the deadline")
            .expect("stream did not end")
            .expect("stream did not error")
    }

    #[tokio::test]
    async fn posting_then_subscribing_delivers_in_order() -> anyhow::Result<()> {
        let (channel, _backend, id, authority) = new_channel().await?;
        let member = channel.join(&mint(&authority, "p1", &id, full(), Some(later())))?;

        channel
            .post(&member, None, "text/plain", b"a".to_vec())
            .await
            .context("post a")?;
        channel
            .post(&member, None, "text/plain", b"b".to_vec())
            .await
            .context("post b")?;

        let mut stream = Box::pin(channel.subscribe(&member)?);
        assert_eq!(next(&mut stream).await.payload, b"a");
        assert_eq!(next(&mut stream).await.payload, b"b");
        Ok(())
    }

    #[tokio::test]
    async fn a_non_member_cannot_post_or_subscribe() -> anyhow::Result<()> {
        let (channel, _backend, _id, _authority) = new_channel().await?;
        let ghost = MembershipId("never-joined".to_owned());

        assert_eq!(
            channel.post(&ghost, None, "text/plain", b"x".to_vec()).await,
            Err(ChannelError::NotAMember)
        );
        assert_eq!(channel.subscribe(&ghost).err(), Some(ChannelError::NotAMember));
        Ok(())
    }

    #[tokio::test]
    async fn joining_with_a_cap_scoped_to_another_channel_is_rejected() -> anyhow::Result<()> {
        let (channel, _backend, _id, authority) = new_channel().await?;
        let other = ChannelId::from("c2");

        assert_eq!(
            channel.join(&mint(&authority, "p1", &other, full(), Some(later()))),
            Err(ChannelError::WrongChannel)
        );
        Ok(())
    }

    #[tokio::test]
    async fn joining_with_an_expired_cap_is_rejected() -> anyhow::Result<()> {
        let (channel, _backend, id, authority) = new_channel().await?;

        assert_eq!(
            channel.join(&mint(&authority, "p1", &id, full(), Some(1))),
            Err(ChannelError::Cap(CapError::Expired))
        );
        Ok(())
    }

    #[tokio::test]
    async fn new_resumes_sequence_assignment_after_a_pre_populated_backend() -> anyhow::Result<()> {
        let id = ChannelId::from("c1");
        let authority = TestAuthority::default();
        let backend = InMem::default();

        // First Channel posts one entry, then is dropped — its handle on
        // `backend` is the only thing that outlives it (InMem is a cheap clone
        // over shared state).
        let first = Channel::new(id.clone(), backend.clone(), authority.clone()).await?;
        let m1 = first.join(&mint(&authority, "p1", &id, full(), Some(later())))?;
        first
            .post(&m1, None, "text/plain", b"a".to_vec())
            .await
            .context("post from first")?;

        // A second Channel constructed around the SAME, now non-empty backend
        // must not restart sequence assignment at 0 and collide with "a".
        let second = Channel::new(id.clone(), backend.clone(), authority.clone()).await?;
        let m2 = second.join(&mint(&authority, "p1", &id, full(), Some(later())))?;
        second
            .post(&m2, None, "text/plain", b"b".to_vec())
            .await
            .context("post from second, into a pre-populated backend")?;

        let stored = backend.fetch(0).await.context("fetch")?;
        assert_eq!(stored.len(), 2, "both entries survive, no sequence collision");
        Ok(())
    }

    #[tokio::test]
    async fn a_post_after_revocation_is_rejected() -> anyhow::Result<()> {
        let (channel, _backend, id, authority) = new_channel().await?;
        let cap = mint(&authority, "p1", &id, full(), Some(later()));
        let member = channel.join(&cap)?;
        // Still admitted at this point — revocation hasn't happened yet.
        channel
            .post(&member, None, "text/plain", b"before".to_vec())
            .await
            .context("post before revocation")?;

        authority.revoke(&cap);

        // The membership entry is untouched (no leave() was called); only a
        // fresh re-verify against the authority catches the revocation.
        assert_eq!(
            channel.post(&member, None, "text/plain", b"after".to_vec()).await,
            Err(ChannelError::Cap(CapError::Revoked))
        );
        assert_eq!(
            channel.subscribe(&member).err(),
            Some(ChannelError::Cap(CapError::Revoked))
        );
        Ok(())
    }

    #[tokio::test]
    async fn leaving_removes_membership_and_blocks_further_action() -> anyhow::Result<()> {
        let (channel, _backend, id, authority) = new_channel().await?;
        let member = channel.join(&mint(&authority, "p1", &id, full(), Some(later())))?;

        channel.leave(&member);

        assert_eq!(
            channel.post(&member, None, "text/plain", b"x".to_vec()).await,
            Err(ChannelError::NotAMember)
        );
        assert_eq!(channel.subscribe(&member).err(), Some(ChannelError::NotAMember));
        Ok(())
    }

    #[tokio::test]
    async fn a_duplicate_post_is_deduplicated_to_one_stored_entry() -> anyhow::Result<()> {
        let (channel, backend, id, authority) = new_channel().await?;
        let member = channel.join(&mint(&authority, "p1", &id, full(), Some(later())))?;

        let first = channel
            .post(&member, None, "text/plain", b"same".to_vec())
            .await
            .context("post first")?;
        let second = channel
            .post(&member, None, "text/plain", b"same".to_vec())
            .await
            .context("post second")?;

        assert_eq!(first, second, "identical content addresses to the same id");
        let stored = backend.fetch(0).await.context("fetch")?;
        assert_eq!(stored.len(), 1, "a re-post of the same content is a no-op in the store");
        Ok(())
    }

    #[tokio::test]
    async fn a_member_offline_then_resubscribing_gets_what_it_missed() -> anyhow::Result<()> {
        let (channel, _backend, id, authority) = new_channel().await?;
        let member = channel.join(&mint(&authority, "p1", &id, full(), Some(later())))?;

        channel
            .post(&member, None, "text/plain", b"a".to_vec())
            .await
            .context("post a")?;
        {
            let mut stream = Box::pin(channel.subscribe(&member)?);
            assert_eq!(next(&mut stream).await.payload, b"a");
            // Dropped here: the member goes offline mid-stream, cursor already
            // advanced past "a".
        }

        channel
            .post(&member, None, "text/plain", b"b".to_vec())
            .await
            .context("post b")?;
        channel
            .post(&member, None, "text/plain", b"c".to_vec())
            .await
            .context("post c")?;

        let mut resumed = Box::pin(channel.subscribe(&member)?);
        assert_eq!(
            next(&mut resumed).await.payload,
            b"b",
            "resumes at the cursor, not from the start"
        );
        assert_eq!(
            next(&mut resumed).await.payload,
            b"c",
            "and delivers everything missed while offline"
        );
        Ok(())
    }

    #[tokio::test]
    async fn invite_grows_membership_as_a_distinct_representative_of_the_same_peer() -> anyhow::Result<()> {
        let (channel, _backend, id, authority) = new_channel().await?;
        let parent = channel.join(&mint(&authority, "p1", &id, full(), Some(later())))?;

        let child_cap = channel.invite(&parent, read_only())?;
        assert_eq!(
            child_cap.scope.peer,
            PeerId::from("p1"),
            "the representative shares the inviter's principal, per spec §3.8"
        );

        let child = channel.join(&child_cap)?;
        assert_ne!(
            child, parent,
            "a distinct cap is a distinct membership even for the same peer"
        );

        // The representative can read but, per its narrowed cap, not post.
        assert!(channel.subscribe(&child).is_ok());
        assert_eq!(
            channel.post(&child, None, "text/plain", b"x".to_vec()).await,
            Err(ChannelError::InsufficientRights("post"))
        );

        // Revoking the parent's membership leaves the representative's intact:
        // they are distinct entries, not aliases of one peer-keyed slot.
        channel.leave(&parent);
        assert!(channel.subscribe(&child).is_ok());
        Ok(())
    }

    #[tokio::test]
    async fn subscribing_without_the_read_right_is_rejected() -> anyhow::Result<()> {
        let post_only = CapRights {
            post: true,
            ..CapRights::default()
        };
        let (channel, _backend, id, authority) = new_channel().await?;
        let member = channel.join(&mint(&authority, "p1", &id, post_only, Some(later())))?;

        assert_eq!(
            channel.subscribe(&member).err(),
            Some(ChannelError::InsufficientRights("read"))
        );
        Ok(())
    }

    /// A correctness-property test, not a reliable mutation-catching regression
    /// test: it did NOT reproduce the pre-fix bug when checked against a
    /// deliberately non-atomic `post()` (assign and append as two separate lock
    /// acquisitions) — `tokio::join!` on the default test runtime doesn't force
    /// genuine interleaving when `InMem::append` never actually yields. The fix
    /// (holding one lock across assign-then-append) is justified by construction
    /// — see the `next_seq` field comment — not by this test failing red first.
    /// Kept as a positive assertion of the invariant for whoever changes this
    /// later.
    #[tokio::test]
    async fn concurrent_posts_are_never_lost_to_a_live_subscriber() -> anyhow::Result<()> {
        let (channel, _backend, id, authority) = new_channel().await?;
        let member = channel.join(&mint(&authority, "p1", &id, full(), Some(later())))?;
        // Subscribed before either post, so this stream is exactly the "live
        // follower" case the sequence-then-append race could starve: if one
        // post's append became visible out of order, this stream would skip
        // straight past the lower sequence and never deliver it.
        let mut stream = Box::pin(channel.subscribe(&member)?);

        let (a, b) = tokio::join!(
            channel.post(&member, None, "text/plain", b"a".to_vec()),
            channel.post(&member, None, "text/plain", b"b".to_vec()),
        );
        a.context("post a")?;
        b.context("post b")?;

        let mut got = vec![next(&mut stream).await.payload, next(&mut stream).await.payload];
        got.sort();
        assert_eq!(
            got,
            [b"a".to_vec(), b"b".to_vec()],
            "both concurrent posts arrive, none lost"
        );
        Ok(())
    }

    #[tokio::test]
    async fn leaving_ends_an_already_open_subscribe_stream() -> anyhow::Result<()> {
        let (channel, _backend, id, authority) = new_channel().await?;
        let channel = Arc::new(channel);
        let member = channel.join(&mint(&authority, "p1", &id, full(), Some(later())))?;

        // A genuinely separate spawned task, not a sibling branch of one
        // `join!` — tokio only re-polls a parked task when ITS OWN waker
        // fires, so this is the shape that actually proves `leave()`'s
        // `waker.wake()` call matters: nothing else in this test ever touches
        // this task, so if the wake call were silently dropped, it would stay
        // parked forever and the `.await` below would hang until the outer
        // timeout, rather than being incidentally re-polled by unrelated
        // activity (which a same-task `join!` would do regardless).
        let watch_channel = Arc::clone(&channel);
        let watch_member = member.clone();
        let watcher = tokio::spawn(async move {
            let mut stream = Box::pin(watch_channel.subscribe(&watch_member)?);
            Ok::<_, ChannelError>(stream.next().await)
        });

        // Nothing is posted, so the spawned task's first poll parks Pending
        // and stashes its waker; this sleep just gives the executor a chance
        // to actually run that poll before leave() fires.
        tokio::time::sleep(Duration::from_millis(20)).await;
        channel.leave(&member);

        let ended = tokio::time::timeout(Duration::from_secs(2), watcher)
            .await
            .context("leave() did not wake the open stream within the deadline")?
            .context("watcher task panicked")?
            .context("watcher stream errored")?;

        assert!(
            ended.is_none(),
            "the stream must end, not keep delivering, after leave()"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_rejoin_after_leave_gets_a_fresh_generation_unaffected_by_the_old_stream() -> anyhow::Result<()> {
        let (channel, _backend, id, authority) = new_channel().await?;
        let cap = mint(&authority, "p1", &id, full(), Some(later()));
        let member = channel.join(&cap)?;
        let mut old_stream = Box::pin(channel.subscribe(&member)?);

        channel.leave(&member);
        // TestAuthority is deterministic (no nonce), so re-minting the
        // identical scope reproduces the identical proof — this rejoin
        // reuses the SAME MembershipId, the exact case a generation counter
        // (vs. just removing the map entry) is for.
        let rejoined = channel.join(&cap)?;
        assert_eq!(
            rejoined, member,
            "same cap, same membership id, deterministic authority"
        );

        let ended = tokio::time::timeout(Duration::from_secs(2), old_stream.next())
            .await
            .context("the pre-leave stream did not end")?;
        assert!(
            ended.is_none(),
            "a stream from before the leave must not pick up the rejoined session"
        );

        channel
            .post(&rejoined, None, "text/plain", b"after-rejoin".to_vec())
            .await
            .context("post after rejoin")?;
        let mut new_stream = Box::pin(channel.subscribe(&rejoined)?);
        assert_eq!(next(&mut new_stream).await.payload, b"after-rejoin");
        Ok(())
    }

    #[tokio::test]
    async fn invite_requires_the_invite_right() -> anyhow::Result<()> {
        let (channel, _backend, id, authority) = new_channel().await?;
        let member = channel.join(&mint(&authority, "p1", &id, read_only(), Some(later())))?;

        assert_eq!(
            channel.invite(&member, read_only()),
            Err(ChannelError::InsufficientRights("invite"))
        );
        Ok(())
    }

    #[test]
    fn content_id_is_stable_for_identical_content_and_differs_otherwise() {
        let a = content_id(&None, "text/plain", b"hello");
        let b = content_id(&None, "text/plain", b"hello");
        let different_payload = content_id(&None, "text/plain", b"goodbye");
        let different_content_type = content_id(&None, "application/json", b"hello");
        let different_message_type = content_id(
            &Some(MessageType::Control(sandy_proto::Control {})),
            "text/plain",
            b"hello",
        );

        assert_eq!(a, b, "identical content hashes identically");
        assert_ne!(a, different_payload);
        assert_ne!(a, different_content_type);
        assert_ne!(a, different_message_type);
    }

    /// Regression for a real collision: before length-prefixing content_type,
    /// `("ab","c")` and `("a","bc")` hashed identically, so the second post
    /// would have silently deduped away as a "duplicate" of the first.
    #[test]
    fn content_id_does_not_collide_across_the_content_type_payload_boundary() {
        let a = content_id(&None, "ab", b"c");
        let b = content_id(&None, "a", b"bc");
        assert_ne!(a, b, "distinct (content_type, payload) splits must not collide");
    }
}
