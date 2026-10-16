//! The channel-backend seam (spec §3.3): the store behind one channel.
//!
//! A deliberately dumb, content-addressed log plus live follow. The channel layers
//! membership, cap checks, sequencing and the content id on top, once; every
//! backend (in-memory, vsock, P2P overlay, chat, MQ, …) only stores and replays.
//! One backend instance holds one channel's log. The message is `sandy-proto`'s
//! [`Envelope`]; its `sequence` is the order key.

use std::future::Future;

use futures_core::Stream;
pub use sandy_proto::Envelope;

/// The metadata key under which the channel stores an envelope's content id.
///
/// The channel derives the id from the envelope's content (never `sequence` or
/// metadata, so a re-post dedups to the same id) and sets it before
/// [`ChannelBackend::append`]; a backend dedups on it.
pub const MSG_ID_KEY: &str = "msg_id";

/// The content id the channel set under [`MSG_ID_KEY`], if any.
pub fn msg_id(env: &Envelope) -> Option<&str> {
    env.metadata.get(MSG_ID_KEY).map(String::as_str)
}

/// A channel-backend failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ChannelBackendError {
    /// The envelope carries no content id under [`MSG_ID_KEY`], so it cannot be
    /// deduplicated.
    #[error("envelope has no msg_id")]
    MissingMsgId,
    /// The backing store is unreachable or failed.
    #[error("backend unavailable: {0}")]
    Unavailable(String),
}

/// The store behind one channel.
pub trait ChannelBackend: Send + Sync {
    /// Append a fully formed envelope. Idempotent on its content id: a repeat is a
    /// no-op and the store holds exactly one entry per id. An envelope without an
    /// id fails with [`ChannelBackendError::MissingMsgId`].
    fn append(&self, env: Envelope) -> impl Future<Output = Result<(), ChannelBackendError>> + Send;

    /// A bounded snapshot: the stored envelopes with `sequence >= from_seq`, in
    /// `sequence` order regardless of arrival order (store-and-forward delivers out of order).
    fn fetch(&self, from_seq: u64) -> impl Future<Output = Result<Vec<Envelope>, ChannelBackendError>> + Send;

    /// Replay the stored envelopes with `sequence >= from_seq` in order, then follow
    /// live appends, as one primitive with no gap between the two. The stream
    /// does not end while the backend lives: a reconnecting subscriber resumes
    /// with `stream_from(cursor)` and misses nothing at or above the cursor. An
    /// envelope that arrives below what a stream already yielded is in `fetch`;
    /// whether it is emitted live is open (#162).
    fn stream_from(&self, from_seq: u64) -> impl Stream<Item = Result<Envelope, ChannelBackendError>> + Send;
}
