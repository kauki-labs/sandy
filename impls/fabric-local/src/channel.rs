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
    task::{Context, Poll},
};

use futures_core::Stream;
use sandy_fabric::{
    capauth::{Cap, CapAuthority, CapError, CapRights},
    channel_backend::{ChannelBackend, ChannelBackendError, Envelope, MSG_ID_KEY},
    types::ChannelId,
};
use sandy_proto::MessageType;
use sha2::{Digest, Sha256};

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

/// The membership id for `cap`: a digest of its proof, not the proof itself.
fn membership_id(cap: &Cap) -> MembershipId {
    let mut hasher = Sha256::new();
    hasher.update(&cap.proof);
    MembershipId(hex::encode(hasher.finalize()))
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
    cursors: Arc<Mutex<HashMap<MembershipId, u64>>>,
    next_seq: AtomicU64,
}

impl<B: ChannelBackend, A: CapAuthority> Channel<B, A> {
    /// A fresh channel `id`, backed by `backend`, with no members.
    pub fn new(id: ChannelId, backend: B, authority: A) -> Self {
        Self {
            id,
            backend,
            authority,
            members: Mutex::new(HashMap::new()),
            cursors: Arc::new(Mutex::new(HashMap::new())),
            next_seq: AtomicU64::new(0),
        }
    }

    /// Checked once at the start of `post`/`subscribe`, not held across the call:
    /// a `leave()` racing a just-started `post()` can still land it. Enforcing
    /// revocation against an in-flight action is the open question spec §8 defers
    /// ("capability revocation before TTL, and where that governance lives"), not
    /// step-1 scope.
    fn rights_of(&self, membership: &MembershipId) -> Result<CapRights, ChannelError> {
        self.members
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(membership)
            .map(|cap| cap.scope.rights)
            .ok_or(ChannelError::NotAMember)
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

    /// Remove `membership` and drop its delivery cursor.
    pub fn leave(&self, membership: &MembershipId) {
        self.members
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(membership);
        self.cursors
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(membership);
    }

    /// Request an attenuated cap narrowed to `rights`, for a sub-agent that will
    /// join as `inviter`'s representative (spec §3.8): same principal, same
    /// channel, only narrower. `inviter` must hold `invite` rights. This does not
    /// itself admit anyone — the Channel is not a minting authority (INV-1); the
    /// returned cap travels out of band and its holder still calls `join`.
    pub fn invite(&self, inviter: &MembershipId, rights: CapRights) -> Result<Cap, ChannelError> {
        let members = self.members.lock().unwrap_or_else(PoisonError::into_inner);
        let parent = members.get(inviter).ok_or(ChannelError::NotAMember)?;
        if !parent.scope.rights.invite {
            return Err(ChannelError::InsufficientRights("invite"));
        }
        Ok(self.authority.attenuate(parent, rights)?)
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
        let sequence = self.next_seq.fetch_add(1, Ordering::SeqCst);
        let env = Envelope {
            sequence,
            message_type,
            content_type,
            payload,
            metadata: HashMap::from([(MSG_ID_KEY.to_owned(), id.clone())]),
        };
        self.backend.append(env).await?;
        Ok(id)
    }

    /// Subscribe as `membership`, which must hold `read` rights. Resumes from this
    /// membership's last-delivered cursor (0 on first subscribe), so dropping the
    /// stream and subscribing again later — the "member goes offline, comes back"
    /// case — delivers what was missed, not just the live tail. The cursor
    /// advances as the stream is read.
    pub fn subscribe(
        &self,
        membership: &MembershipId,
    ) -> Result<impl Stream<Item = Result<Envelope, ChannelBackendError>> + Send + 'static, ChannelError> {
        let rights = self.rights_of(membership)?;
        if !rights.read {
            return Err(ChannelError::InsufficientRights("read"));
        }
        let from = *self
            .cursors
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(membership)
            .unwrap_or(&0);
        Ok(CursorStream {
            inner: Box::pin(self.backend.stream_from(from)),
            cursors: Arc::clone(&self.cursors),
            membership: membership.clone(),
        })
    }
}

/// Wraps a backend stream to advance the membership's stored cursor as it's read,
/// so a later `subscribe()` on the same membership resumes where this one left
/// off rather than from the start.
///
/// Accepted step-1 simplification: the cursor advances on yield (`poll_next`
/// returning `Ready`), before the consumer has actually acted on the envelope.
/// A consumer cancelled between the yield and acting on it (e.g. the stream
/// dropped mid-`select!`) loses that envelope — at-most-once, not the
/// at-least-once the spec wants for the offline/reconnect case. True
/// at-least-once needs a consumer-ack'd or consumer-managed cursor instead of
/// one the backend advances on delivery; tracked as a follow-up, not fixed
/// here.
struct CursorStream {
    inner: Pin<Box<dyn Stream<Item = Result<Envelope, ChannelBackendError>> + Send>>,
    cursors: Arc<Mutex<HashMap<MembershipId, u64>>>,
    membership: MembershipId,
}

impl Stream for CursorStream {
    type Item = Result<Envelope, ChannelBackendError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        let next = this.inner.as_mut().poll_next(cx);
        if let Poll::Ready(Some(Ok(ref env))) = next {
            this.cursors
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(this.membership.clone(), env.sequence + 1);
        }
        next
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
    let mut hasher = Sha256::new();
    hasher.update([tag]);
    hasher.update(content_type.as_bytes());
    hasher.update(payload);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use std::{
        hash::{DefaultHasher, Hash, Hasher},
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    use futures_util::StreamExt;
    use sandy_fabric::{capauth::CapScope, types::PeerId};

    use super::*;
    use crate::inmem::InMem;

    /// A minimal [`CapAuthority`] test double: proof = a keyed hash of the scope,
    /// enough to catch tampering, not real cryptography. sandy-fabric's own
    /// equivalent (`contract::fakes::FakeAuthority`) is `#[cfg(test)]`-private to
    /// that crate, so Channel's tests carry this small mirror rather than wait on
    /// it being exported.
    #[derive(Default)]
    struct TestAuthority;

    impl TestAuthority {
        fn proof(&self, scope: &CapScope) -> Vec<u8> {
            let mut h = DefaultHasher::new();
            0x5eed_u64.hash(&mut h);
            (&scope.peer, &scope.channel, scope.expires_at).hash(&mut h);
            (scope.rights.post, scope.rights.read, scope.rights.invite).hash(&mut h);
            h.finish().to_be_bytes().to_vec()
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
            match cap.scope.expires_at {
                Some(t) if t <= now => Err(CapError::Expired),
                _ => Ok(cap.scope.clone()),
            }
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

    fn new_channel() -> (Channel<InMem, TestAuthority>, InMem, ChannelId, TestAuthority) {
        let id = ChannelId::from("c1");
        let backend = InMem::default();
        let authority = TestAuthority;
        let channel = Channel::new(id.clone(), backend.clone(), TestAuthority);
        (channel, backend, id, authority)
    }

    async fn next(stream: &mut (impl Stream<Item = Result<Envelope, ChannelBackendError>> + Unpin)) -> Envelope {
        tokio::time::timeout(Duration::from_secs(2), stream.next())
            .await
            .expect("stream yielded before the deadline")
            .expect("stream did not end")
            .expect("stream did not error")
    }

    #[tokio::test]
    async fn posting_then_subscribing_delivers_in_order() {
        let (channel, _backend, id, authority) = new_channel();
        let member = channel
            .join(&mint(&authority, "p1", &id, full(), Some(later())))
            .unwrap();

        channel.post(&member, None, "text/plain", b"a".to_vec()).await.unwrap();
        channel.post(&member, None, "text/plain", b"b".to_vec()).await.unwrap();

        let mut stream = Box::pin(channel.subscribe(&member).unwrap());
        assert_eq!(next(&mut stream).await.payload, b"a");
        assert_eq!(next(&mut stream).await.payload, b"b");
    }

    #[tokio::test]
    async fn a_non_member_cannot_post_or_subscribe() {
        let (channel, _backend, _id, _authority) = new_channel();
        let ghost = MembershipId("never-joined".to_owned());

        assert_eq!(
            channel.post(&ghost, None, "text/plain", b"x".to_vec()).await,
            Err(ChannelError::NotAMember)
        );
        assert_eq!(channel.subscribe(&ghost).err(), Some(ChannelError::NotAMember));
    }

    #[tokio::test]
    async fn joining_with_a_cap_scoped_to_another_channel_is_rejected() {
        let (channel, _backend, _id, authority) = new_channel();
        let other = ChannelId::from("c2");

        assert_eq!(
            channel.join(&mint(&authority, "p1", &other, full(), Some(later()))),
            Err(ChannelError::WrongChannel)
        );
    }

    #[tokio::test]
    async fn joining_with_an_expired_cap_is_rejected() {
        let (channel, _backend, id, authority) = new_channel();

        assert_eq!(
            channel.join(&mint(&authority, "p1", &id, full(), Some(1))),
            Err(ChannelError::Cap(CapError::Expired))
        );
    }

    #[tokio::test]
    async fn leaving_removes_membership_and_blocks_further_action() {
        let (channel, _backend, id, authority) = new_channel();
        let member = channel
            .join(&mint(&authority, "p1", &id, full(), Some(later())))
            .unwrap();

        channel.leave(&member);

        assert_eq!(
            channel.post(&member, None, "text/plain", b"x".to_vec()).await,
            Err(ChannelError::NotAMember)
        );
        assert_eq!(channel.subscribe(&member).err(), Some(ChannelError::NotAMember));
    }

    #[tokio::test]
    async fn a_duplicate_post_is_deduplicated_to_one_stored_entry() {
        let (channel, backend, id, authority) = new_channel();
        let member = channel
            .join(&mint(&authority, "p1", &id, full(), Some(later())))
            .unwrap();

        let first = channel
            .post(&member, None, "text/plain", b"same".to_vec())
            .await
            .unwrap();
        let second = channel
            .post(&member, None, "text/plain", b"same".to_vec())
            .await
            .unwrap();

        assert_eq!(first, second, "identical content addresses to the same id");
        let stored = backend.fetch(0).await.unwrap();
        assert_eq!(stored.len(), 1, "a re-post of the same content is a no-op in the store");
    }

    #[tokio::test]
    async fn a_member_offline_then_resubscribing_gets_what_it_missed() {
        let (channel, _backend, id, authority) = new_channel();
        let member = channel
            .join(&mint(&authority, "p1", &id, full(), Some(later())))
            .unwrap();

        channel.post(&member, None, "text/plain", b"a".to_vec()).await.unwrap();
        {
            let mut stream = Box::pin(channel.subscribe(&member).unwrap());
            assert_eq!(next(&mut stream).await.payload, b"a");
            // Dropped here: the member goes offline mid-stream, cursor already
            // advanced past "a".
        }

        channel.post(&member, None, "text/plain", b"b".to_vec()).await.unwrap();
        channel.post(&member, None, "text/plain", b"c".to_vec()).await.unwrap();

        let mut resumed = Box::pin(channel.subscribe(&member).unwrap());
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
    }

    #[tokio::test]
    async fn invite_grows_membership_as_a_distinct_representative_of_the_same_peer() {
        let (channel, _backend, id, authority) = new_channel();
        let parent = channel
            .join(&mint(&authority, "p1", &id, full(), Some(later())))
            .unwrap();

        let child_cap = channel.invite(&parent, read_only()).unwrap();
        assert_eq!(
            child_cap.scope.peer,
            PeerId::from("p1"),
            "the representative shares the inviter's principal, per spec §3.8"
        );

        let child = channel.join(&child_cap).unwrap();
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
    }

    #[tokio::test]
    async fn subscribing_without_the_read_right_is_rejected() {
        let post_only = CapRights {
            post: true,
            ..CapRights::default()
        };
        let (channel, _backend, id, authority) = new_channel();
        let member = channel
            .join(&mint(&authority, "p1", &id, post_only, Some(later())))
            .unwrap();

        assert_eq!(
            channel.subscribe(&member).err(),
            Some(ChannelError::InsufficientRights("read"))
        );
    }

    #[tokio::test]
    async fn invite_requires_the_invite_right() {
        let (channel, _backend, id, authority) = new_channel();
        let member = channel
            .join(&mint(&authority, "p1", &id, read_only(), Some(later())))
            .unwrap();

        assert_eq!(
            channel.invite(&member, read_only()),
            Err(ChannelError::InsufficientRights("invite"))
        );
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
}
