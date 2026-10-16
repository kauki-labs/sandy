//! The channel message envelope: the *logical* contract (spec §3.3).
//!
//! Protobuf is its default codec (`sandy-proto`, which depends on this crate), and a
//! text/chat backend re-encodes the same envelope as structured text. The concrete
//! per-role message types are an open question (spec §8), so [`Envelope::msg_type`]
//! is an opaque discriminator here, not a closed enum.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// The metadata key under which the channel stores an envelope's content id.
///
/// The channel computes the id from `payload`, `content_type` and `msg_type`
/// (never `seq` or metadata, so a re-post dedups to the same id) and sets it before
/// [`append`](crate::channel_backend::ChannelBackend::append); a backend dedups on it.
pub const MSG_ID_KEY: &str = "msg_id";

/// One channel message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    /// Per-channel monotonic sequence, assigned by the channel.
    pub seq: u64,
    /// The message-type discriminator (the protobuf `oneof` tag).
    pub msg_type: String,
    /// The payload's media type; `text/plain` by default, a protobuf type when structured.
    pub content_type: String,
    /// The opaque payload bytes.
    pub payload: Vec<u8>,
    /// Free-form metadata, including the content id under [`MSG_ID_KEY`].
    pub metadata: BTreeMap<String, String>,
}

impl Envelope {
    /// The content id the channel set under [`MSG_ID_KEY`], if any.
    pub fn msg_id(&self) -> Option<&str> {
        self.metadata.get(MSG_ID_KEY).map(String::as_str)
    }
}
