//! Behavioural contract for the channel envelope codec (issue #105).
//!
//! Positive: each message type round-trips; a text payload rides unchanged.
//! Adversarial: an unknown message-type tag is tolerated (forward-compat), and a
//! truncated frame is a protocol error, never a defaulted-empty envelope.

use std::collections::HashMap;

use anyhow::{Context as _, Result};
use rstest::rstest;
use sandy_proto::{
    CONTENT_TYPE_PROTOBUF, CONTENT_TYPE_TEXT, Control, Envelope, Escalate, MessageType, Output, PeerMsg, ProtoError,
    Telemetry, Tty, decode, encode,
};

/// Every step-1 message-type variant survives an encode/decode round-trip with
/// its envelope fields intact.
#[rstest]
#[case(MessageType::Control(Control {}))]
#[case(MessageType::Tty(Tty {}))]
#[case(MessageType::Output(Output {}))]
#[case(MessageType::Telemetry(Telemetry {}))]
#[case(MessageType::Escalate(Escalate {}))]
#[case(MessageType::PeerMsg(PeerMsg {}))]
fn each_message_type_round_trips(#[case] message_type: MessageType) -> Result<()> {
    let envelope = Envelope {
        sequence: 9,
        metadata: HashMap::from([("channel".to_owned(), "orchestrator".to_owned())]),
        content_type: CONTENT_TYPE_PROTOBUF.to_owned(),
        payload: b"structured-body".to_vec(),
        message_type: Some(message_type),
    };

    let decoded = decode(&encode(&envelope)).context("round-trip")?;

    assert_eq!(decoded, envelope);
    Ok(())
}

/// A text payload (the default body) rides through unchanged, and an envelope
/// with no message-type set decodes with `message_type` absent.
#[test]
fn text_payload_rides_unchanged() -> Result<()> {
    let envelope = Envelope {
        sequence: 1,
        content_type: CONTENT_TYPE_TEXT.to_owned(),
        payload: "hello, channel — ünïcödé".as_bytes().to_vec(),
        ..Default::default()
    };

    let decoded = decode(&encode(&envelope)).context("round-trip")?;

    assert_eq!(decoded.payload, envelope.payload);
    assert_eq!(decoded.content_type, CONTENT_TYPE_TEXT);
    assert!(decoded.message_type.is_none());
    Ok(())
}

/// Sequence and metadata survive the round-trip.
#[test]
fn sequence_and_metadata_survive() -> Result<()> {
    let envelope = Envelope {
        sequence: u64::MAX,
        metadata: HashMap::from([
            ("sender".to_owned(), "agent-7".to_owned()),
            ("cap".to_owned(), "sha256:abc".to_owned()),
        ]),
        ..Default::default()
    };

    let decoded = decode(&encode(&envelope)).context("round-trip")?;

    assert_eq!(decoded.sequence, u64::MAX);
    assert_eq!(decoded.metadata, envelope.metadata);
    Ok(())
}

/// Forward compatibility: an unknown message-type tag (a future `oneof` variant,
/// here field 16 as a length-delimited message) is skipped, not rejected. The
/// known fields decode intact and `message_type` stays absent.
///
/// prost drops unknown fields rather than byte-preserving them, so the contract
/// is graceful tolerance: a newer sender's message still decodes on older code.
#[test]
fn unknown_message_type_tag_is_tolerated() -> Result<()> {
    let base = Envelope {
        sequence: 7,
        content_type: CONTENT_TYPE_TEXT.to_owned(),
        payload: b"body".to_vec(),
        ..Default::default()
    };

    let mut wire = encode(&base);
    // Append field #16, wire type 2 (length-delimited), empty: tag varint 0x82
    // 0x01 (= (16 << 3) | 2 = 130), length 0x00. This is how an unknown future
    // message-type variant would appear on the wire.
    wire.extend_from_slice(&[0x82, 0x01, 0x00]);

    let decoded = decode(&wire).context("decode with unknown tag")?;

    assert_eq!(decoded.sequence, 7);
    assert_eq!(decoded.content_type, CONTENT_TYPE_TEXT);
    assert_eq!(decoded.payload, b"body");
    assert!(decoded.message_type.is_none());
    Ok(())
}

/// A truncated frame is a decode error, never a silently default-empty envelope.
#[test]
fn truncated_frame_is_a_protocol_error() {
    // Only `payload` (field 4) is set, so it is the last field on the wire;
    // dropping its trailing bytes leaves a length-delimited field whose declared
    // length overruns the buffer.
    let envelope = Envelope {
        payload: b"0123456789".to_vec(),
        ..Default::default()
    };

    let wire = encode(&envelope);
    let truncated = &wire[..wire.len() - 3];

    let result = decode(truncated);

    assert!(
        matches!(result, Err(ProtoError::Decode(_))),
        "expected a decode error, got {result:?}"
    );
}
