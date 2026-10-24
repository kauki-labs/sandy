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
    MembershipId(hash_hex(&[cap.proof()]))
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
    // Keyed by each CursorStream's own stream_id (#225), not just a bare
    // `Vec<Waker>`: `subscribe()` is never restricted to one stream per
    // membership (its own doc comment already notes two concurrent
    // subscriptions aren't the expected shape, but nothing stops it), so a
    // second stream's waker would otherwise silently overwrite the first's —
    // leaving the first parked forever on `leave()`, exactly the hang this
    // mechanism exists to close, just for that stream. The id also lets
    // `CursorStream::drop` remove exactly its own entry: `Waker::will_wake`
    // is a best-effort identity check (two distinct streams on the same task
    // can produce wakers that compare equal under it, as seen in this fix's
    // own regression test), so it can't be used to tell "my waker" from
    // "some other stream's waker that happens to look the same" on drop.
    wakers: Vec<(u64, Waker)>,
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
    // Channel-wide, never reused: identifies one `CursorStream` for the life
    // of its own `wakers` entry, so its `Drop` can remove exactly that entry
    // (#225) regardless of what other streams on the same membership exist.
    next_stream_id: AtomicU64,
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
            next_stream_id: AtomicU64::new(0),
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
        Ok(self.member(membership)?.scope().rights)
    }

    /// This channel's id.
    #[must_use]
    pub fn id(&self) -> &ChannelId {
        &self.id
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
    /// (every `CursorStream` open for it — `subscribe()` doesn't restrict a
    /// membership to one) rather than waiting indefinitely for the backend's
    /// next append, which may never come (#184). Covers only this explicit
    /// call: an organically-expiring TTL on an open stream is NOT proactively
    /// caught — no periodic re-check runs here — tracked separately as #188.
    pub fn leave(&self, membership: &MembershipId) {
        self.members
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(membership);
        // Bound to a plain `let`, not used as an `if let` scrutinee directly:
        // under edition 2024's temporary-scope rules, a guard produced in an
        // `if let` scrutinee stays alive for the WHOLE body, not just the
        // match. Waking tasks below while `sessions` is still locked risks a
        // synchronous re-entrant poll_next trying to lock it again — a real
        // deadlock, not just a style nit, for any executor that can poll a
        // woken task inline rather than only ever scheduling it for later.
        // This `let` is an ordinary statement: its temporary guard drops at
        // the semicolon, well before the loop below runs.
        let removed = self
            .sessions
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(membership);
        if let Some(state) = removed {
            for (_, waker) in state.wakers {
                waker.wake();
            }
        }
    }

    /// How many memberships are currently joined. A caller driving an
    /// "is anyone attached" policy (e.g. sandyd's attach-relay, #340) reads
    /// this around its own `join`/`leave` calls to detect a 0→1 or 1→0
    /// transition; this method itself does not track transitions, only the
    /// current count.
    #[must_use]
    pub fn member_count(&self) -> usize {
        self.members.lock().unwrap_or_else(PoisonError::into_inner).len()
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
        if !parent.scope().rights.invite {
            return Err(ChannelError::InsufficientRights("invite"));
        }
        Ok(self.authority.attenuate(&parent, rights)?)
    }

    /// Post `payload` as `membership`, which must hold `post` rights. Returns the
    /// envelope's content id. A re-post of identical content (`payload` +
    /// `content_type` + `message_type`, never `sequence`) is deduplicated by the
    /// backend to the same id — except for `MessageType::Tty`: a live TTY byte
    /// stream legitimately repeats identical chunks (the same keystroke, the
    /// same echoed line), and deduplicating those would silently drop the
    /// second one (#327). Its content id folds in `sequence` instead, so no two
    /// TTY posts ever collide.
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
        // Held across the append: see the field comment on `next_seq` for why
        // assign-then-append must be one atomic unit, not two separate steps.
        // The content id is computed in here too (not before the lock), since a
        // TTY post's id now depends on `sequence`.
        let mut next_seq = self.next_seq.lock().await;
        let sequence = *next_seq;
        let id = content_id(&message_type, &content_type, &payload, sequence);
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
            wakers: Vec::new(),
        });
        let generation = state.generation;
        let from = state.cursor;
        drop(sessions);
        Ok(CursorStream {
            inner: Box::pin(self.backend.stream_from(from)),
            sessions: Arc::clone(&self.sessions),
            membership: membership.clone(),
            generation,
            stream_id: self.next_stream_id.fetch_add(1, Ordering::SeqCst),
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
/// one the backend advances on delivery; tracked as #173, not fixed here.
struct CursorStream {
    inner: Pin<Box<dyn Stream<Item = Result<Envelope, ChannelBackendError>> + Send>>,
    sessions: Arc<Mutex<HashMap<MembershipId, MembershipState>>>,
    membership: MembershipId,
    /// The generation this stream was created (or last confirmed current)
    /// under. Compared against `sessions`' live value on every poll; a
    /// mismatch (including the entry being gone entirely) means `leave()`
    /// happened, and this stream ends rather than continuing to deliver.
    generation: u64,
    /// This stream's own identity in `MembershipState::wakers` (#225):
    /// assigned once at `subscribe()` time, used to update its own entry on
    /// each `Pending` poll and to remove exactly that entry on `Drop`.
    stream_id: u64,
}

impl Drop for CursorStream {
    /// Deregisters exactly this stream's own waker entry, if it's still
    /// registered (#225): the reconnect pattern of subscribing, parking, and
    /// dropping without ever reading must not leak one entry per reconnect.
    fn drop(&mut self) {
        // Pulled out under the lock, dropped only after releasing it — same
        // discipline as `leave()` above, and for the same reason: a `Waker`'s
        // drop glue is caller-defined and may run arbitrary code, including
        // dropping another `CursorStream` whose own `Drop` wants this same
        // `sessions` lock. Dropping it (via `retain`, in place) while still
        // holding the lock would make that a reentrant self-deadlock.
        //
        // A membership this stream's generation has already left behind (or
        // that was removed by `leave()` entirely) has nothing to clean up
        // here: `leave()` already drained and woke the whole `Vec`, including
        // this stream's own entry if it was still in it.
        let displaced = {
            let mut sessions = self.sessions.lock().unwrap_or_else(PoisonError::into_inner);
            sessions.get_mut(&self.membership).and_then(|state| {
                let pos = state.wakers.iter().position(|(id, _)| *id == self.stream_id)?;
                Some(state.wakers.swap_remove(pos))
            })
        };
        drop(displaced);
    }
}

impl Stream for CursorStream {
    type Item = Result<Envelope, ChannelBackendError>;

    /// Ends the stream (`Ready(None)`) once its membership's generation has
    /// moved on (a `leave()`, possibly followed by a rejoin); otherwise polls
    /// the backing stream, updating or registering this stream's own waker
    /// entry by `stream_id` on `Pending` (#225).
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
                // Check-and-store under ONE lock acquisition, not two: the
                // generation check above already released its lock before
                // polling the backend, so leave() (or a leave()+rejoin) can
                // land in that gap. If we blindly stored a waker here without
                // re-checking, two races follow: (a) leave() already ran,
                // found no waker to wake yet, and will never run again — we'd
                // park forever, unwoken until the backend's next append, which
                // may never come (the exact hang this mechanism exists to
                // remove); (b) a rejoin landed a NEWER generation at the same
                // MembershipId, and we'd clobber the REJOINED stream's waker
                // with our own stale one. Re-checking the generation in the
                // same critical section as the store closes both: either
                // we're still current and the store is safe, or we're not and
                // we end immediately instead of parking a waker nothing will
                // ever fire.
                // Cloned before locking `sessions`, not after: a `Waker`
                // clone callback is caller-defined too, and allowed to run
                // the same arbitrary, lock-wanting code a drop callback can
                // (see `Drop for CursorStream` above). Any waker THIS poll
                // displaces from the slot is likewise dropped only after the
                // guard below is released.
                let waker = cx.waker().clone();
                let mut sessions = this.sessions.lock().unwrap_or_else(PoisonError::into_inner);
                match sessions.get_mut(&this.membership) {
                    Some(state) if state.generation == this.generation => {
                        // Update-in-place by this stream's own id, not a
                        // `will_wake` dedup: this same stream's own task can
                        // poll multiple times before ever yielding (normal
                        // executor behavior, and the waker can legitimately
                        // change between polls), so each Pending poll
                        // replaces this stream's one entry rather than
                        // pushing another — `will_wake` can't tell two
                        // distinct streams' wakers apart when both happen to
                        // run on the same task (#225's regression test hits
                        // this), so identity has to come from `stream_id`.
                        let displaced = match state.wakers.iter_mut().find(|(id, _)| *id == this.stream_id) {
                            Some((_, slot)) => Some(std::mem::replace(slot, waker)),
                            None => {
                                state.wakers.push((this.stream_id, waker));
                                None
                            }
                        };
                        drop(sessions);
                        drop(displaced);
                        Poll::Pending
                    }
                    _ => Poll::Ready(None),
                }
            }
            other => other,
        }
    }
}

/// The content id: a hash of `payload` + `content_type` + `message_type`'s variant
/// — never `metadata` — so a re-post under a new sequence still dedups to the
/// same id. Step-1 `message_type` variants carry no fields, so the variant tag
/// is their whole identity; this match being exhaustive means adding a field to
/// a variant later forces a compile-time update here rather than a silent hash
/// that ignores the new content.
///
/// `MessageType::Tty` is the one exception: `sequence` folds into its hash, so
/// it never dedups at all (#327). A TTY post is one chunk of a live byte
/// stream, not an idempotent message — two identical chunks (a repeated
/// keystroke, an echoed line) are two distinct, both-real events, and treating
/// the second as "the same id, already stored" would silently drop it.
fn content_id(message_type: &Option<MessageType>, content_type: &str, payload: &[u8], sequence: u64) -> String {
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
    // needs its own prefix since it's always the last field (except the TTY
    // sequence suffix below, which is fixed-width and so needs no length
    // prefix of its own).
    let len_prefix = (content_type.len() as u64).to_be_bytes();
    if matches!(message_type, Some(MessageType::Tty(_))) {
        let seq_bytes = sequence.to_be_bytes();
        hash_hex(&[&[tag], &len_prefix, content_type.as_bytes(), payload, &seq_bytes])
    } else {
        hash_hex(&[&[tag], &len_prefix, content_type.as_bytes(), payload])
    }
}

#[cfg(test)]
mod tests {
    use std::{
        hash::{DefaultHasher, Hash, Hasher},
        sync::{atomic::AtomicBool, mpsc},
        task::Wake,
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    use anyhow::Context;
    use futures_util::StreamExt;
    use sandy_fabric::{capauth::CapScope, types::PeerId};
    use tokio::sync::Notify;

    use super::*;
    use crate::{agent::TTY_STDOUT, inmem::InMem};

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
                .insert(cap.proof().to_vec());
        }
    }

    impl CapAuthority for TestAuthority {
        fn mint(&self, scope: CapScope) -> Result<Cap, CapError> {
            let proof = self.proof(&scope);
            Ok(Cap::new(scope, proof))
        }

        fn verify(&self, cap: &Cap) -> Result<CapScope, CapError> {
            if cap.proof() != self.proof(cap.scope()) {
                return Err(CapError::Forged);
            }
            let now = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
            if cap.scope().expires_at.is_some_and(|t| t <= now) {
                return Err(CapError::Expired);
            }
            if self
                .revoked
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .contains(cap.proof())
            {
                return Err(CapError::Revoked);
            }
            Ok(cap.scope().clone())
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

    /// A `Waker` whose drop glue runs an arbitrary closure instead of nothing:
    /// `std::task::Wake` lets any `Arc<W>` back a real `Waker` without
    /// `unsafe` (forbidden in this crate), and standard library permits a
    /// `Waker`'s clone/drop callbacks to do anything (`RawWakerVTable`'s own
    /// contract). Used to reproduce the exact adversarial case CodeRabbit's
    /// #254 review raised: a displaced waker's drop glue that drops ANOTHER
    /// `CursorStream`, reentering `sessions` from inside whichever caller is
    /// in the middle of removing or replacing this one.
    struct DropBomb {
        on_drop: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    }

    // Waking is a no-op by design: only the `Drop` impl below matters for
    // this test double. `Waker::noop()` can't stand in for it (clippy's
    // suggestion) since it doesn't run user code on drop at all.
    #[allow(
        clippy::manual_noop_waker,
        reason = "the point of this type is its Drop impl, not its wake behavior"
    )]
    impl Wake for DropBomb {
        fn wake(self: Arc<Self>) {}

        fn wake_by_ref(self: &Arc<Self>) {}
    }

    impl Drop for DropBomb {
        fn drop(&mut self) {
            if let Some(f) = self.on_drop.lock().unwrap_or_else(PoisonError::into_inner).take() {
                f();
            }
        }
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

    /// `member_count` reflects joins and leaves as they happen — the fact a
    /// 0→1/1→0 attach-state policy (#340) is built on.
    #[tokio::test]
    async fn member_count_tracks_joins_and_leaves() -> anyhow::Result<()> {
        let (channel, _backend, id, authority) = new_channel().await?;
        assert_eq!(channel.member_count(), 0);

        let first = channel.join(&mint(&authority, "p1", &id, full(), Some(later())))?;
        assert_eq!(channel.member_count(), 1);

        let second = channel.join(&mint(&authority, "p2", &id, full(), Some(later())))?;
        assert_eq!(channel.member_count(), 2);

        channel.leave(&first);
        assert_eq!(channel.member_count(), 1);

        channel.leave(&second);
        assert_eq!(channel.member_count(), 0);
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
            child_cap.scope().peer,
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

    /// Pauses the one `append()` call whose envelope sequence equals
    /// `pause_sequence`, so a test can land a concurrent `post()` inside the
    /// window #106's `next_seq` lock exists to close: the window between
    /// assigning a sequence and the backend append that stores it (#213).
    /// `fetch`/`stream_from` delegate straight to `inner`.
    struct PausedAppend<B> {
        inner: B,
        pause_sequence: u64,
        armed: Arc<Notify>,
        release: Arc<Notify>,
    }

    impl<B: ChannelBackend> ChannelBackend for PausedAppend<B> {
        async fn append(&self, env: Envelope) -> Result<(), ChannelBackendError> {
            if env.sequence == self.pause_sequence {
                // `Notify::notify_one` stores a permit if nothing is waiting
                // yet, so this handshake is race-free regardless of which
                // side reaches its half first.
                self.armed.notify_one();
                self.release.notified().await;
            }
            self.inner.append(env).await
        }

        async fn fetch(&self, from_seq: u64) -> Result<Vec<Envelope>, ChannelBackendError> {
            self.inner.fetch(from_seq).await
        }

        fn stream_from(
            &self,
            from_seq: u64,
        ) -> impl Stream<Item = Result<Envelope, ChannelBackendError>> + Send + 'static {
            self.inner.stream_from(from_seq)
        }
    }

    /// The controlling half of a [`PausedAppend`]'s gate.
    struct AppendGateHandle {
        armed: Arc<Notify>,
        release: Arc<Notify>,
    }

    impl AppendGateHandle {
        /// Waits for the paused `append()` call to actually reach its pause
        /// point. Bounded, so a regression that never reaches it fails the
        /// test instead of hanging the run.
        async fn wait_until_armed(&self) -> anyhow::Result<()> {
            tokio::time::timeout(Duration::from_secs(5), self.armed.notified())
                .await
                .context("the paused append never reached its pause point before the deadline")
        }

        fn release(&self) {
            self.release.notify_one();
        }
    }

    fn paused_append<B>(inner: B, pause_sequence: u64) -> (PausedAppend<B>, AppendGateHandle) {
        let armed = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        (
            PausedAppend {
                inner,
                pause_sequence,
                armed: Arc::clone(&armed),
                release: Arc::clone(&release),
            },
            AppendGateHandle { armed, release },
        )
    }

    /// Deterministic regression for #106 (#213): forces the exact interleaving
    /// the `next_seq` field comment only justified by trace, rather than
    /// relying on `tokio::join!` to race two posts through a backend that
    /// never actually yields (which the test below this one could not do,
    /// and said so). Sequence 0's append is paused mid-flight while sequence
    /// 1's post runs concurrently; the live subscriber, parked before either
    /// post, must see nothing until sequence 0 actually lands — proving
    /// `next_seq` is held across the whole assign-then-append, not released
    /// in between.
    #[tokio::test]
    async fn concurrent_posts_do_not_let_a_live_subscriber_skip_a_paused_entry() -> anyhow::Result<()> {
        let id = ChannelId::from("c1");
        let authority = TestAuthority::default();
        let (backend, gate) = paused_append(InMem::default(), 0);
        let channel = Arc::new(Channel::new(id.clone(), backend, authority.clone()).await?);
        let member = channel.join(&mint(&authority, "p1", &id, full(), Some(later())))?;

        // Parked before either post: nothing stored yet, so the first poll
        // registers this follower's waker and returns Pending.
        let mut stream = Box::pin(channel.subscribe(&member)?);
        std::future::poll_fn(|cx| {
            let _ = stream.as_mut().poll_next(cx);
            Poll::Ready(())
        })
        .await;

        let post_a = {
            let channel = Arc::clone(&channel);
            let member = member.clone();
            tokio::spawn(async move { channel.post(&member, None, "text/plain", b"a".to_vec()).await })
        };
        gate.wait_until_armed().await.context("post_a's append")?;

        let post_b = {
            let channel = Arc::clone(&channel);
            let member = member.clone();
            tokio::spawn(async move { channel.post(&member, None, "text/plain", b"b".to_vec()).await })
        };
        // Give the scheduler a chance to drive post_b as far as the lock
        // currently allows, before releasing post_a's paused append.
        tokio::time::sleep(Duration::from_millis(20)).await;

        let mid_race = std::future::poll_fn(|cx| Poll::Ready(stream.as_mut().poll_next(cx))).await;
        assert!(
            matches!(mid_race, Poll::Pending),
            "nothing must be visible to the live subscriber while sequence 0's append is still paused; got \
             {mid_race:?} (a two-step assign-then-append would let post_b land sequence 1 here, which this subscriber \
             would then skip straight to, losing sequence 0 forever)"
        );

        gate.release();
        post_a.await.context("join post_a")?.context("post a")?;
        post_b.await.context("join post_b")?.context("post b")?;

        assert_eq!(next(&mut stream).await.payload, b"a", "sequence 0 is delivered first");
        assert_eq!(
            next(&mut stream).await.payload,
            b"b",
            "and sequence 1 follows, nothing skipped"
        );
        Ok(())
    }

    /// A correctness-property test for the same invariant as the harness-based
    /// regression above, kept as a cheap smoke check: `tokio::join!` on the
    /// default test runtime doesn't force genuine interleaving when
    /// `InMem::append` never actually yields, so this one alone would not
    /// have caught a reverted fix — see
    /// `concurrent_posts_do_not_let_a_live_subscriber_skip_a_paused_entry`
    /// (#213) for the version that forces the race deterministically.
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
    async fn leaving_wakes_every_open_stream_on_the_same_membership() -> anyhow::Result<()> {
        // subscribe() has never restricted a membership to one stream (its
        // own doc comment already calls two concurrent subscriptions an
        // accepted, unspecified-interleaving edge case) — but a membership
        // with a SECOND stream open must still have BOTH end on leave(), not
        // just whichever one most recently registered a waker.
        let (channel, _backend, id, authority) = new_channel().await?;
        let channel = Arc::new(channel);
        let member = channel.join(&mint(&authority, "p1", &id, full(), Some(later())))?;

        let spawn_watcher = |channel: &Arc<Channel<InMem, TestAuthority>>, member: &MembershipId| {
            let channel = Arc::clone(channel);
            let member = member.clone();
            tokio::spawn(async move {
                let mut stream = Box::pin(channel.subscribe(&member)?);
                Ok::<_, ChannelError>(stream.next().await)
            })
        };
        let first = spawn_watcher(&channel, &member);
        let second = spawn_watcher(&channel, &member);

        // Let both spawned tasks actually run their first poll (parking
        // Pending, each registering its own waker) before leaving.
        tokio::time::sleep(Duration::from_millis(20)).await;
        channel.leave(&member);

        for watcher in [first, second] {
            let ended = tokio::time::timeout(Duration::from_secs(2), watcher)
                .await
                .context("leave() did not wake every open stream on this membership within the deadline")?
                .context("watcher task panicked")?
                .context("watcher stream errored")?;
            assert!(
                ended.is_none(),
                "every stream on a left membership must end, not just one"
            );
        }
        Ok(())
    }

    /// Pauses the first `poll_next` call on the stream a [`PausedPollBackend`]
    /// returns that is about to yield `Pending`, synchronously blocking the
    /// calling thread until released. Used to land a concurrent `leave()`
    /// inside the exact window between `CursorStream` seeing `Pending` from
    /// the backend and storing its own waker (#184, #213).
    ///
    /// Blocks the thread, not the task: the pause point sits inside a
    /// backend's synchronous `poll_next`, which cannot yield to an executor
    /// mid-call the way an `async fn` can. The caller drives the paused poll
    /// from a dedicated OS thread (see the test below) so the thread calling
    /// `leave()` stays free to run concurrently; `leave()` itself never locks
    /// the backend, so this cannot deadlock.
    struct PollGate {
        arrived: mpsc::Sender<()>,
        release: mpsc::Receiver<()>,
    }

    impl PollGate {
        fn pause(self) {
            let _ = self.arrived.send(());
            let _ = self.release.recv();
        }
    }

    /// The controlling half of a [`PollGate`].
    struct PollGateHandle {
        arrived: mpsc::Receiver<()>,
        release: mpsc::Sender<()>,
    }

    impl PollGateHandle {
        /// Blocks until the paused poll has reached its pause point. Bounded,
        /// so a regression that never reaches it fails the test instead of
        /// hanging the run.
        fn wait_until_armed(&self) -> anyhow::Result<()> {
            self.arrived
                .recv_timeout(Duration::from_secs(5))
                .context("poll_next never reached its pause point before the deadline")
        }

        fn release(&self) {
            let _ = self.release.send(());
        }
    }

    fn poll_gate() -> (PollGate, PollGateHandle) {
        let (arrived_tx, arrived_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        (
            PollGate {
                arrived: arrived_tx,
                release: release_rx,
            },
            PollGateHandle {
                arrived: arrived_rx,
                release: release_tx,
            },
        )
    }

    /// Wraps a backend stream to pause (see [`PollGate`]) the first time it is
    /// about to return `Pending`, then forwards that `Pending` on unchanged.
    /// Boxed as a trait object rather than generic over the inner stream type,
    /// so it doesn't need to assume the inner stream is `Unpin`.
    struct PausedFollow {
        inner: Pin<Box<dyn Stream<Item = Result<Envelope, ChannelBackendError>> + Send>>,
        gate: Option<PollGate>,
    }

    impl Stream for PausedFollow {
        type Item = Result<Envelope, ChannelBackendError>;

        fn poll_next(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Option<Self::Item>> {
            let this = self.get_mut();
            match this.inner.as_mut().poll_next(cx) {
                Poll::Pending => {
                    if let Some(gate) = this.gate.take() {
                        gate.pause();
                    }
                    Poll::Pending
                }
                other => other,
            }
        }
    }

    /// Wraps `inner` so its very first `stream_from()` call returns a
    /// [`PausedFollow`] armed with `gate`. `append`/`fetch` delegate straight
    /// to `inner`.
    struct PausedPollBackend<B> {
        inner: B,
        gate: Mutex<Option<PollGate>>,
    }

    impl<B: ChannelBackend> ChannelBackend for PausedPollBackend<B> {
        async fn append(&self, env: Envelope) -> Result<(), ChannelBackendError> {
            self.inner.append(env).await
        }

        async fn fetch(&self, from_seq: u64) -> Result<Vec<Envelope>, ChannelBackendError> {
            self.inner.fetch(from_seq).await
        }

        fn stream_from(
            &self,
            from_seq: u64,
        ) -> impl Stream<Item = Result<Envelope, ChannelBackendError>> + Send + 'static {
            let gate = self.gate.lock().unwrap_or_else(PoisonError::into_inner).take();
            PausedFollow {
                inner: Box::pin(self.inner.stream_from(from_seq)),
                gate,
            }
        }
    }

    /// Deterministic regression for #184's Pending-branch fix (#213): pins the
    /// backend-boundary half of it. Once `CursorStream` sees `Pending` from
    /// the backend, it must re-check the membership's generation in the same
    /// lock acquisition it uses to store its own waker, not store it
    /// unconditionally — otherwise a `leave()` landing in the window between
    /// "backend said Pending" and "waker stored" leaves the stream parked on
    /// a waker nothing will ever fire, instead of ending it.
    ///
    /// Limit: this harness pauses at the backend's `poll_next` boundary, so it
    /// proves the re-check exists. It cannot prove the check and the store
    /// share one lock acquisition internally rather than two adjacent ones —
    /// that would need a hook inside `CursorStream` itself, out of scope here
    /// (this issue is a test-harness addition, not a `CursorStream` change).
    #[tokio::test]
    async fn a_leave_landing_between_pending_and_the_waker_store_ends_the_stream() -> anyhow::Result<()> {
        let id = ChannelId::from("c1");
        let authority = TestAuthority::default();
        let (gate, handle) = poll_gate();
        let backend = PausedPollBackend {
            inner: InMem::default(),
            gate: Mutex::new(Some(gate)),
        };
        let channel = Channel::new(id.clone(), backend, authority.clone()).await?;
        let member = channel.join(&mint(&authority, "p1", &id, full(), Some(later())))?;
        let mut stream = Box::pin(channel.subscribe(&member)?);

        // `poll_next` is plain and synchronous (it only ever touches
        // `std::sync::Mutex`es, no tokio primitive), so it runs on its own
        // thread with no runtime needed — same discipline as the drop-bomb
        // tests above, and for the same reason: a regression here would hang
        // this one thread, not the whole test run.
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let waker = Waker::noop().clone();
            let mut cx = std::task::Context::from_waker(&waker);
            let poll = stream.as_mut().poll_next(&mut cx);
            let _ = tx.send(poll);
        });

        handle.wait_until_armed().context("the paused poll_next")?;
        channel.leave(&member);
        handle.release();

        let poll = rx
            .recv_timeout(Duration::from_secs(5))
            .context("poll_next did not return after leave() + release")?;
        assert!(
            matches!(poll, Poll::Ready(None)),
            "a leave() landing in this exact window must end the stream, not leave it parked forever on a waker \
             nothing will ever fire; got {poll:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn dropping_a_pending_stream_removes_its_own_waker_not_just_on_leave() -> anyhow::Result<()> {
        // #225: the documented reconnect pattern (subscribe, read nothing,
        // drop, subscribe again later) must not accumulate one dead Waker per
        // reconnect for the membership's whole lifetime — only leave() used to
        // clear the Vec, so a long-lived membership that reconnects many times
        // without ever leaving grew it unboundedly.
        let (channel, _backend, id, authority) = new_channel().await?;
        let member = channel.join(&mint(&authority, "p1", &id, full(), Some(later())))?;

        for _ in 0..5 {
            let mut stream = Box::pin(channel.subscribe(&member)?);
            // Poll once to Pending (nothing posted yet), registering a waker,
            // then drop the stream still parked — the exact reconnect pattern
            // the issue describes.
            let polled_once = std::future::poll_fn(|cx| {
                let _ = stream.as_mut().poll_next(cx);
                std::task::Poll::Ready(())
            });
            polled_once.await;
            drop(stream);
        }

        let wakers_len = channel
            .sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&member)
            .map(|state| state.wakers.len())
            .unwrap_or(0);
        assert_eq!(
            wakers_len, 0,
            "every dropped stream must deregister its own waker; none are left open here"
        );
        Ok(())
    }

    #[tokio::test]
    async fn two_streams_polled_from_the_same_task_keep_independent_waker_entries() -> anyhow::Result<()> {
        // #225's identity claim: a `will_wake`-based dedup can't distinguish
        // two DISTINCT streams whose wakers both come from the SAME task,
        // because `will_wake` only answers "would waking this wake the same
        // task" — both wakers here are will_wake-equal despite belonging to
        // different streams. Drives two real streams through interleaved
        // polls on one task (not two spawned tasks, which would already have
        // distinct task identity and so wouldn't exercise this collision),
        // then drops one mid-interleaving and asserts the surviving stream's
        // own entry is untouched — not "whichever one happened to dedup."
        let (channel, _backend, id, authority) = new_channel().await?;
        let member = channel.join(&mint(&authority, "p1", &id, full(), Some(later())))?;

        let mut first = Box::pin(channel.subscribe(&member)?);
        let mut second = Box::pin(channel.subscribe(&member)?);

        // Interleaved: both polled to Pending from the exact same `cx`, so
        // both register a waker that would be `will_wake`-equal to the
        // other's under the old dedup scheme.
        std::future::poll_fn(|cx| {
            let _ = first.as_mut().poll_next(cx);
            let _ = second.as_mut().poll_next(cx);
            std::task::Poll::Ready(())
        })
        .await;

        // `subscribe` returns an opaque `impl Stream`, so identity is read
        // from the registered entries themselves rather than a private field:
        // under the old `will_wake` dedup this first assertion already fails
        // (both polls share one `cx`, so `second`'s waker would have been
        // treated as a duplicate of `first`'s and collapsed into one entry).
        let ids_before = {
            let sessions = channel
                .sessions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let state = sessions.get(&member).context("membership present before any drop")?;
            assert_eq!(
                state.wakers.len(),
                2,
                "both concurrently open streams must each hold their own entry, not collapse into one"
            );
            state
                .wakers
                .iter()
                .map(|(id, _)| *id)
                .collect::<std::collections::BTreeSet<_>>()
        };

        drop(first);

        let ids_after_first = {
            let sessions = channel
                .sessions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let state = sessions
                .get(&member)
                .context("membership present after dropping one stream")?;
            state
                .wakers
                .iter()
                .map(|(id, _)| *id)
                .collect::<std::collections::BTreeSet<_>>()
        };
        assert_eq!(
            ids_after_first.len(),
            1,
            "dropping one of two concurrently open streams must remove exactly one entry"
        );
        assert!(
            ids_after_first.is_subset(&ids_before),
            "the surviving entry must be one of the original two, not a new or corrupted id"
        );

        drop(second);

        let wakers_len = channel
            .sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&member)
            .map(|state| state.wakers.len())
            .unwrap_or(0);
        assert_eq!(
            wakers_len, 0,
            "dropping the second stream must remove its own entry too, proving the first drop didn't remove the wrong \
             one (which would have left this one stuck, or been a double-removal)"
        );
        Ok(())
    }

    #[tokio::test]
    async fn dropping_a_pending_stream_during_a_panic_unwind_still_deregisters_its_waker() -> anyhow::Result<()> {
        // #225 calls out panic-unwind explicitly as an adversarial case: Drop
        // has to run its cleanup when invoked by unwinding, not only when the
        // caller reaches a normal scope exit or an explicit `drop()`.
        let (channel, _backend, id, authority) = new_channel().await?;
        let member = channel.join(&mint(&authority, "p1", &id, full(), Some(later())))?;

        let mut stream = Box::pin(channel.subscribe(&member)?);
        std::future::poll_fn(|cx| {
            let _ = stream.as_mut().poll_next(cx);
            std::task::Poll::Ready(())
        })
        .await;

        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _stream = stream; // moved in; its Drop runs during the unwind below.
            panic!("deliberate panic to unwind through a parked CursorStream");
        }));
        assert!(
            panicked.is_err(),
            "the panic must actually have fired for this test to mean anything"
        );

        let wakers_len = channel
            .sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&member)
            .map(|state| state.wakers.len())
            .unwrap_or(0);
        assert_eq!(
            wakers_len, 0,
            "Drop must deregister the waker even when it runs via a panicking unwind"
        );
        Ok(())
    }

    #[tokio::test]
    async fn dropping_a_stream_does_not_deadlock_when_its_displaced_waker_drops_another_stream() -> anyhow::Result<()> {
        // CodeRabbit #254 (major): `Drop for CursorStream` must pull its own
        // displaced waker out from under the `sessions` lock and drop it only
        // after releasing the guard — not drop it in place (e.g. via
        // `Vec::retain`) while still holding the lock, which would make a
        // waker whose drop glue reenters `sessions` (by dropping another
        // `CursorStream`) deadlock on itself.
        let (channel, _backend, id, authority) = new_channel().await?;
        let member = channel.join(&mint(&authority, "p1", &id, full(), Some(later())))?;

        let mut first = Box::pin(channel.subscribe(&member)?);
        let second = Box::pin(channel.subscribe(&member)?);

        // A real poll with an inert waker learns this stream's own slot:
        // `stream_id` is opaque to callers (see
        // `two_streams_polled_from_the_same_task_keep_independent_waker_entries`
        // above), so it's read back from the one registered entry, not
        // guessed.
        std::future::poll_fn(|cx| {
            let _ = first.as_mut().poll_next(cx);
            Poll::Ready(())
        })
        .await;

        let fired = Arc::new(AtomicBool::new(false));
        let fired_in_bomb = Arc::clone(&fired);
        let bomb_waker: Waker = Arc::new(DropBomb {
            on_drop: Mutex::new(Some(Box::new(move || {
                drop(second);
                fired_in_bomb.store(true, Ordering::SeqCst);
            }))),
        })
        .into();

        // Swapped directly into the registered slot rather than via another
        // `poll_next` call: that would also hand a clone to `Follow`'s own
        // dedup'd waker list (`inmem.rs`), which only drains on the next
        // `append` — never in this test — and would keep the Arc's count
        // above zero no matter what `CursorStream` does with its own copy,
        // masking the result.
        {
            let mut sessions = channel.sessions.lock().unwrap_or_else(PoisonError::into_inner);
            let state = sessions.get_mut(&member).context("membership present")?;
            let slot = state
                .wakers
                .first_mut()
                .context("the poll above must have registered exactly one waker")?;
            slot.1 = bomb_waker;
        }

        // Drop `first` on its own thread: a regression (reentrant
        // self-deadlock on `sessions`) parks that thread forever, and a
        // bounded `recv_timeout` turns that into a clean test failure instead
        // of hanging the whole run.
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            drop(first);
            let _ = tx.send(());
        });
        rx.recv_timeout(Duration::from_secs(5))
            .context("dropping a stream whose displaced waker drops another stream deadlocked on `sessions`")?;

        assert!(
            fired.load(Ordering::SeqCst),
            "the bomb waker's drop glue must actually have run for this test to mean anything"
        );
        Ok(())
    }

    #[tokio::test]
    async fn replacing_a_pending_waker_does_not_deadlock_when_the_displaced_waker_drops_another_stream()
    -> anyhow::Result<()> {
        // CodeRabbit #254 (major, "Also applies to: 461-461"): the `Pending`
        // arm's replace-in-place path (`*slot = waker`, now `mem::replace`)
        // carries the identical risk as the Drop path above — the OLD waker
        // in that slot is dropped as part of the replace, and must not drop
        // while `sessions` is still locked either.
        let (channel, _backend, id, authority) = new_channel().await?;
        let member = channel.join(&mint(&authority, "p1", &id, full(), Some(later())))?;

        let mut first = Box::pin(channel.subscribe(&member)?);
        let second = Box::pin(channel.subscribe(&member)?);

        // A real poll with an inert waker learns this stream's own slot (see
        // the Drop-path test above for why).
        std::future::poll_fn(|cx| {
            let _ = first.as_mut().poll_next(cx);
            Poll::Ready(())
        })
        .await;

        let fired = Arc::new(AtomicBool::new(false));
        let fired_in_bomb = Arc::clone(&fired);
        let bomb_waker: Waker = Arc::new(DropBomb {
            on_drop: Mutex::new(Some(Box::new(move || {
                drop(second);
                fired_in_bomb.store(true, Ordering::SeqCst);
            }))),
        })
        .into();

        // Swapped directly into the registered slot, not via another
        // `poll_next` call — same reasoning as the Drop-path test above.
        {
            let mut sessions = channel.sessions.lock().unwrap_or_else(PoisonError::into_inner);
            let state = sessions.get_mut(&member).context("membership present")?;
            let slot = state
                .wakers
                .first_mut()
                .context("the poll above must have registered exactly one waker")?;
            slot.1 = bomb_waker;
        }

        // Second poll, with a plain waker, replaces the bomb in place —
        // exercising the `Some((_, slot))` arm, not `Drop`. `poll_next` is a
        // plain synchronous fn (the backing `Follow` stream parks on a
        // `std::sync::Mutex`, not any tokio primitive), so it can be called
        // directly here with no runtime needed, on its own thread so a
        // regression (reentrant self-deadlock) parks only that thread.
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let plain_waker = Waker::noop().clone();
            let mut cx = std::task::Context::from_waker(&plain_waker);
            let _ = first.as_mut().poll_next(&mut cx);
            let _ = tx.send(());
        });
        rx.recv_timeout(Duration::from_secs(5))
            .context("replacing a stream's waker with a displaced bomb waker deadlocked on `sessions`")?;

        assert!(
            fired.load(Ordering::SeqCst),
            "the bomb waker's drop glue must actually have run for this test to mean anything"
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
        let a = content_id(&None, "text/plain", b"hello", 0);
        let b = content_id(&None, "text/plain", b"hello", 0);
        let different_payload = content_id(&None, "text/plain", b"goodbye", 0);
        let different_content_type = content_id(&None, "application/json", b"hello", 0);
        let different_message_type = content_id(
            &Some(MessageType::Control(sandy_proto::Control {})),
            "text/plain",
            b"hello",
            0,
        );
        // A non-Tty id must not depend on `sequence` — it's still the same
        // idempotent-message dedup contract this test's own name promises.
        let different_sequence = content_id(&None, "text/plain", b"hello", 1);

        assert_eq!(a, b, "identical content hashes identically");
        assert_ne!(a, different_payload);
        assert_ne!(a, different_content_type);
        assert_ne!(a, different_message_type);
        assert_eq!(a, different_sequence, "a non-Tty id ignores sequence, same as before");
    }

    /// Regression for a real collision: before length-prefixing content_type,
    /// `("ab","c")` and `("a","bc")` hashed identically, so the second post
    /// would have silently deduped away as a "duplicate" of the first.
    #[test]
    fn content_id_does_not_collide_across_the_content_type_payload_boundary() {
        let a = content_id(&None, "ab", b"c", 0);
        let b = content_id(&None, "a", b"bc", 0);
        assert_ne!(a, b, "distinct (content_type, payload) splits must not collide");
    }

    /// Regression (#327): a Tty id DOES depend on `sequence` — the whole point
    /// is that identical TTY chunks never dedup.
    #[test]
    fn tty_content_id_differs_by_sequence_even_for_identical_bytes() {
        let tty = Some(MessageType::Tty(sandy_proto::Tty {}));
        let first = content_id(&tty, TTY_STDOUT, b"same bytes", 0);
        let second = content_id(&tty, TTY_STDOUT, b"same bytes", 1);
        assert_ne!(first, second, "two TTY posts of identical bytes must get distinct ids");
    }

    /// Regression (#327): two identical TTY posts on a real channel are BOTH
    /// delivered, not silently deduplicated to one stored entry — the exact
    /// shape `a_duplicate_post_is_deduplicated_to_one_stored_entry` proves for
    /// an ordinary (non-Tty) post, with the opposite expectation.
    #[tokio::test]
    async fn identical_tty_posts_are_both_delivered_not_deduplicated() -> anyhow::Result<()> {
        let (channel, backend, id, authority) = new_channel().await?;
        let member = channel.join(&mint(&authority, "p1", &id, full(), Some(later())))?;
        let tty = Some(MessageType::Tty(sandy_proto::Tty {}));

        channel
            .post(&member, tty, TTY_STDOUT, b"\n".to_vec())
            .await
            .context("post first newline")?;
        channel
            .post(&member, tty, TTY_STDOUT, b"\n".to_vec())
            .await
            .context("post second, identical newline")?;

        let stored = backend.fetch(0).await.context("fetch")?;
        assert_eq!(
            stored.len(),
            2,
            "both identical TTY posts must be stored, not deduplicated to one"
        );
        Ok(())
    }
}
