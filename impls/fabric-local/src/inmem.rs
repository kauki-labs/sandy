//! `InMem`: the trivial local [`ChannelBackend`] (spec §3.3, issue #107).
//!
//! A content-addressed, replay-durable in-memory log: envelopes keyed by
//! `sequence` for ordered replay, deduplicated on their content id (never on
//! `sequence`, so a re-post under a new sequence is still a no-op). `stream_from`
//! replays the backlog from a cursor, then follows live appends with no gap.

use std::{
    collections::{BTreeMap, HashSet, btree_map::Entry},
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    task::{Context, Poll, Waker},
};

use futures_core::Stream;
use sandy_fabric::channel_backend::{ChannelBackend, ChannelBackendError, Envelope, msg_id};

/// The shared state behind one [`InMem`] handle: the log, its dedup index, and
/// the followers parked on an empty tail.
#[derive(Default)]
struct Log {
    /// Stored envelopes keyed by `sequence`, giving ordered iteration for free
    /// regardless of append order (store-and-forward delivers out of order).
    entries: BTreeMap<u64, Envelope>,
    /// Content ids already stored, for an O(1) dedup check per append.
    ids: HashSet<String>,
    /// Wakers parked by a `stream_from` follower with nothing new to yield.
    wakers: Vec<Waker>,
}

/// The trivial local [`ChannelBackend`]: one channel's log held in memory.
///
/// Cheap to clone: an `InMem` is a handle to shared state (an `Arc`), so
/// `stream_from`'s `'static` follower and every clone of the backend see the
/// same log. A fresh `InMem::default()` is an empty log.
#[derive(Default, Clone)]
pub struct InMem {
    log: Arc<Mutex<Log>>,
}

impl InMem {
    fn lock(&self) -> MutexGuard<'_, Log> {
        // A panic elsewhere while the lock is held should not permanently
        // poison this channel's log; recover and keep serving.
        self.log.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl ChannelBackend for InMem {
    async fn append(&self, env: Envelope) -> Result<(), ChannelBackendError> {
        let id = msg_id(&env).ok_or(ChannelBackendError::MissingMsgId)?.to_owned();
        let mut log = self.lock();
        if !log.ids.insert(id.clone()) {
            // A re-post of a stored content id is a no-op; the first entry stands.
            return Ok(());
        }
        if let Entry::Vacant(slot) = log.entries.entry(env.sequence) {
            slot.insert(env);
            for waker in log.wakers.drain(..) {
                waker.wake();
            }
        } else {
            // Two distinct content ids collided on `sequence`; the channel layer
            // assigns it and should never produce this. The id is already marked
            // seen above, so a silent drop here would absorb the second envelope
            // forever, even on a re-post. Surface it loudly instead: a
            // debug_assert catches it in dev/test, a tracing::error keeps it
            // observable in release.
            debug_assert!(
                false,
                "sequence {} already holds a different content id than {id:?}",
                env.sequence
            );
            tracing::error!(
                sequence = env.sequence,
                msg_id = %id,
                "channel backend: sequence collision between distinct content ids, dropping the second envelope"
            );
        }
        Ok(())
    }

    async fn fetch(&self, from_seq: u64) -> Result<Vec<Envelope>, ChannelBackendError> {
        Ok(self
            .lock()
            .entries
            .range(from_seq..)
            .map(|(_, env)| env.clone())
            .collect())
    }

    fn stream_from(&self, from_seq: u64) -> impl Stream<Item = Result<Envelope, ChannelBackendError>> + Send + 'static {
        Follow {
            log: Arc::clone(&self.log),
            next_seq: from_seq,
        }
    }
}

/// The `stream_from` follower: replays from `next_seq`, then parks a waker on
/// the shared log until the next append.
struct Follow {
    log: Arc<Mutex<Log>>,
    next_seq: u64,
}

impl Stream for Follow {
    type Item = Result<Envelope, ChannelBackendError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        let mut log = this.log.lock().unwrap_or_else(PoisonError::into_inner);
        match log.entries.range(this.next_seq..).next() {
            Some((&seq, env)) => {
                let env = env.clone();
                this.next_seq = seq + 1;
                Poll::Ready(Some(Ok(env)))
            }
            None => {
                log.wakers.push(cx.waker().clone());
                Poll::Pending
            }
        }
    }
}
