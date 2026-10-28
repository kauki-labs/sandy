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

/// The largest encoded envelope [`decode`] accepts: 1 MiB, the agent link's own
/// `MAX_FRAME`. An envelope the link can carry always fits; anything bigger is
/// refused before it is parsed (#390).
pub const MAX_ENVELOPE_BYTES: usize = 1 << 20;

/// Errors from decoding a channel envelope off the wire.
#[derive(Debug, thiserror::Error)]
pub enum ProtoError {
    /// The input is over [`MAX_ENVELOPE_BYTES`]. It was not parsed, so no payload
    /// or metadata allocation scaled with it.
    #[error("envelope frame is {len} bytes, over the {max}-byte limit")]
    TooLarge {
        /// The input's length.
        len: usize,
        /// The limit it exceeded, [`MAX_ENVELOPE_BYTES`].
        max: usize,
    },
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
/// `bytes` crosses a trust boundary (a channel backend carrying sandbox traffic),
/// and the `metadata` map and `payload` allocations scale with its size, so an
/// input over [`MAX_ENVELOPE_BYTES`] is refused before it is parsed. A caller
/// that frames the stream should still cap the frame before it buffers it: this
/// check bounds the decoder's allocation, not the caller's own read buffer.
///
/// # Errors
///
/// Returns [`ProtoError::TooLarge`] when `bytes` is over [`MAX_ENVELOPE_BYTES`],
/// and [`ProtoError::Decode`] when it is not a valid envelope frame.
pub fn decode(bytes: &[u8]) -> Result<Envelope, ProtoError> {
    if bytes.len() > MAX_ENVELOPE_BYTES {
        return Err(ProtoError::TooLarge {
            len: bytes.len(),
            max: MAX_ENVELOPE_BYTES,
        });
    }
    Ok(Envelope::decode(bytes)?)
}

/// `Envelope.payload` is opaque to the channel layer and can carry a bearer
/// credential (an attenuated channel-join cap, a staged secret, …): `build.rs`
/// skips prost's derived `Debug` for this message, and this redacts `payload`
/// the same way `sandy_control_proto::AttachResponse` redacts its `cap`
/// (#211). The other fields carry no secret material and print normally.
impl std::fmt::Debug for Envelope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Envelope")
            .field("sequence", &self.sequence)
            .field("metadata", &self.metadata)
            .field("content_type", &self.content_type)
            .field("payload", &format_args!("<redacted {} bytes>", self.payload.len()))
            .field("message_type", &self.message_type)
            .finish()
    }
}

/// `skip_debug` on `Envelope` also drops the derived `Debug` for its nested
/// `oneof` enum (prost generates it as part of the same message's codegen).
/// Each variant wraps an empty marker type with no secret material, so this
/// just delegates to that type's own (still-derived) `Debug`.
impl std::fmt::Debug for MessageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MessageType::Control(inner) => f.debug_tuple("Control").field(inner).finish(),
            MessageType::Tty(inner) => f.debug_tuple("Tty").field(inner).finish(),
            MessageType::Output(inner) => f.debug_tuple("Output").field(inner).finish(),
            MessageType::Telemetry(inner) => f.debug_tuple("Telemetry").field(inner).finish(),
            MessageType::Escalate(inner) => f.debug_tuple("Escalate").field(inner).finish(),
            MessageType::PeerMsg(inner) => f.debug_tuple("PeerMsg").field(inner).finish(),
        }
    }
}
