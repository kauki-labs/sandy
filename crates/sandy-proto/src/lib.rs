//! The sandy agent-fabric channel envelope and its protobuf codec.
//!
//! The envelope is the logical contract every channel backend carries
//! (spec `sandy-agent-fabric.md` §3.3): a [`oneof`](Envelope::message_type)
//! message-type discriminator, a [`sequence`](Envelope::sequence) number,
//! free-form [`metadata`](Envelope::metadata), an opaque
//! [`payload`](Envelope::payload), and a [`content_type`](Envelope::content_type).
//! protobuf is the default codec; a text/chat backend re-encodes the same
//! envelope as structured text.
//!
//! ```
//! use sandy_proto::{CONTENT_TYPE_TEXT, Envelope, decode, encode};
//!
//! let envelope = Envelope {
//!     sequence: 1,
//!     content_type: CONTENT_TYPE_TEXT.to_owned(),
//!     payload: b"hello, channel".to_vec(),
//!     ..Default::default()
//! };
//!
//! let bytes = encode(&envelope);
//! let decoded = decode(&bytes).expect("round-trip");
//! assert_eq!(decoded, envelope);
//! ```

use prost::Message as _;

/// Generated protobuf types for `package sandy.proto.v1`.
pub mod v1 {
    // prost-generated code is not hand-maintained: it carries no doc comments and
    // is not written to the workspace clippy standard. Scope the allows here so
    // the rest of the crate keeps `missing_docs`/clippy denials.
    #![allow(missing_docs, clippy::all, clippy::pedantic)]
    include!(concat!(env!("OUT_DIR"), "/sandy.proto.v1.rs"));
}

pub use v1::{Control, Envelope, Escalate, Output, PeerMsg, Telemetry, Tty, envelope::MessageType};

/// Default `content_type`: the payload is UTF-8 text. An empty `content_type`
/// field means the same thing; this is the explicit spelling.
pub const CONTENT_TYPE_TEXT: &str = "text/plain; charset=utf-8";

/// `content_type` for a payload that is itself an encoded protobuf message.
pub const CONTENT_TYPE_PROTOBUF: &str = "application/protobuf";

/// Errors from decoding a channel envelope off the wire.
#[derive(Debug, thiserror::Error)]
pub enum ProtoError {
    /// The bytes are not a valid envelope: a malformed or truncated frame. The
    /// caller gets this error rather than a silently default-empty envelope.
    #[error("malformed envelope frame: {0}")]
    Decode(#[from] prost::DecodeError),
}

/// Encode an envelope to its protobuf wire bytes.
#[must_use]
pub fn encode(envelope: &Envelope) -> Vec<u8> {
    envelope.encode_to_vec()
}

/// Decode a channel envelope from protobuf wire bytes.
///
/// A truncated or malformed frame returns [`ProtoError::Decode`], never a
/// default-empty [`Envelope`]. An unknown (future) field or `message_type`
/// variant is skipped, leaving the known fields intact (forward compatibility).
///
/// This crate places no upper bound on `bytes`: the `metadata` map and
/// `payload` allocations scale with the input size. `bytes` crosses a trust
/// boundary (a channel backend carrying sandbox traffic), so the caller is
/// responsible for capping frame size before calling `decode` on untrusted input.
///
/// # Errors
///
/// Returns [`ProtoError::Decode`] when `bytes` is not a valid envelope frame.
pub fn decode(bytes: &[u8]) -> Result<Envelope, ProtoError> {
    Ok(Envelope::decode(bytes)?)
}
