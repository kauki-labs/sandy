//! Behavioural contract for the channel envelope codec (issue #105).
//!
//! Positive: each message type round-trips; a text payload rides unchanged.
//! Adversarial: an unknown message-type tag is tolerated (forward-compat), and a
//! truncated frame is a protocol error, never a defaulted-empty envelope.

use std::collections::HashMap;

use anyhow::{Context as _, Result};
use rstest::rstest;
use sandy_proto::{
    CONTENT_TYPE_PROTOBUF, CONTENT_TYPE_TEXT, Control, Envelope, Escalate, MAX_ENVELOPE_BYTES, MessageType, Output,
    PeerMsg, ProtoError, Telemetry, Tty, decode, encode,
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

/// `Envelope`'s other fields still render in `Debug` output; only `payload` is
/// redacted.
#[test]
fn debug_output_still_shows_the_non_secret_fields() {
    let envelope = Envelope {
        sequence: 42,
        metadata: HashMap::from([("channel".to_owned(), "orchestrator".to_owned())]),
        content_type: CONTENT_TYPE_TEXT.to_owned(),
        payload: b"body".to_vec(),
        message_type: Some(MessageType::Control(Control {})),
    };

    let rendered = format!("{envelope:?}");

    assert!(
        rendered.contains("42"),
        "sequence missing from Debug output: {rendered}"
    );
    assert!(
        rendered.contains("orchestrator"),
        "metadata missing from Debug output: {rendered}"
    );
    assert!(
        rendered.contains(CONTENT_TYPE_TEXT),
        "content_type missing from Debug output: {rendered}"
    );
    assert!(
        rendered.contains("Control"),
        "message_type missing from Debug output: {rendered}"
    );
}

/// `Envelope.payload` can carry a bearer credential (#215): prost's default
/// derived `Debug` would print it in the clear. Check both leak shapes, the
/// same way #211's `AttachResponse` regression test does — a marker-text-only
/// check would miss the raw-byte-array leak shape.
#[test]
fn debug_output_redacts_the_payload() {
    let marker = "sandy-envelope-leak-marker-7e2b91";
    let payload = marker.as_bytes().to_vec();
    let envelope = Envelope {
        payload: payload.clone(),
        ..Default::default()
    };

    let rendered = format!("{envelope:?}");

    assert!(
        !rendered.contains(marker),
        "the payload's decoded text leaked into Debug output: {rendered}"
    );
    let numeric_repr = format!("{payload:?}");
    assert!(
        !rendered.contains(&numeric_repr),
        "the payload's raw bytes leaked into Debug output: {rendered}"
    );
    assert!(
        rendered.contains("redacted"),
        "expected an explicit redaction marker, got: {rendered}"
    );
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

/// #390: `decode` refuses an input over the cap before it parses anything, so a
/// hostile peer cannot make the decoder allocate a multi-gigabyte payload. The
/// refusal names the size and the cap and is not a `Decode` error.
#[test]
fn an_envelope_over_the_size_cap_is_refused_before_parsing() -> Result<()> {
    let oversized = Envelope {
        payload: vec![7; MAX_ENVELOPE_BYTES],
        ..Default::default()
    };
    let bytes = encode(&oversized);
    assert!(bytes.len() > MAX_ENVELOPE_BYTES, "the fixture must exceed the cap");

    let err = decode(&bytes).err().context("an oversized envelope must be refused")?;

    assert!(
        matches!(err, ProtoError::TooLarge { len, max } if len == bytes.len() && max == MAX_ENVELOPE_BYTES),
        "got {err:?}"
    );
    Ok(())
}

/// #390: the size check runs first, so over-cap bytes that are not even a valid
/// frame are `TooLarge`, never a parse attempt.
#[test]
fn over_cap_garbage_is_too_large_not_a_decode_error() -> Result<()> {
    let err = decode(&vec![0xff; MAX_ENVELOPE_BYTES + 1])
        .err()
        .context("over-cap garbage must be refused")?;
    assert!(matches!(err, ProtoError::TooLarge { .. }), "got {err:?}");
    Ok(())
}

/// #390: the cap is inclusive. An input of exactly `MAX_ENVELOPE_BYTES` reaches
/// the parser (here: not a valid frame, so `Decode`, not `TooLarge`).
#[test]
fn an_input_of_exactly_the_cap_reaches_the_parser() -> Result<()> {
    let err = decode(&vec![0xff; MAX_ENVELOPE_BYTES])
        .err()
        .context("junk at the cap is still malformed")?;
    assert!(matches!(err, ProtoError::Decode(_)), "got {err:?}");
    Ok(())
}

/// #390: a legitimate envelope near the cap still round-trips: the cap must not
/// reject what the agent link (`MAX_FRAME`, 1 MiB) can carry.
#[test]
fn a_large_envelope_under_the_cap_still_round_trips() -> Result<()> {
    let envelope = Envelope {
        sequence: 3,
        payload: vec![9; MAX_ENVELOPE_BYTES - 64],
        ..Default::default()
    };
    let bytes = encode(&envelope);
    assert!(bytes.len() <= MAX_ENVELOPE_BYTES, "the fixture must fit the cap");

    assert_eq!(decode(&bytes).context("round-trip")?, envelope);
    Ok(())
}
