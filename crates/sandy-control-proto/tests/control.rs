//! Behavioural contract for the control RPC message surface (issue #211).
//!
//! Positive: every `ControlRequest`/`ControlResponse` oneof variant round-trips
//! through the plain protobuf codec with its fields intact. Adversarial: an
//! unknown future oneof tag decodes as an absent variant, never an error or a
//! panic — mirrors `sandy_proto::Envelope`'s own forward-compatibility test.

use anyhow::{Context as _, Result};
use prost::Message as _;
use rstest::rstest;
use sandy_control_proto::{
    AttachRequest, AttachResponse, CancelRequest, CancelResponse, ControlError, ControlRequest, ControlResponse,
    JobStatus, JobSummary, ListRequest, ListResponse, StatusRequest, StatusResponse, SubmitRequest, SubmitResponse,
    control_request, control_response,
};

/// Every `ControlRequest.op` variant survives an encode/decode round-trip with
/// the envelope's own fields (`request_id`) intact.
#[rstest]
#[case(control_request::Op::Submit(SubmitRequest { client_id: None,
    digests: false,
    manifest: b"manifest-bytes".to_vec(),
    manifest_encoding: "sandy.orchestrator.v1.JobManifest".to_owned(),
    submitter_caps: vec![b"cap-a".to_vec(), b"cap-b".to_vec()],
    required_isolation_class: sandy_control_proto::IsolationClass::Trusted.into(),
    inputs: vec![],
    outputs: vec![],
    secrets: vec![],
    credential: None,
    cred_capabilities: Vec::new(),
    egress: None,
}))]
#[case(control_request::Op::Cancel(CancelRequest { job_id: "job-1".to_owned(), attach_token: Some(vec![1, 2, 3]) }))]
#[case(control_request::Op::Attach(AttachRequest {
    job_id: "job-1".to_owned(),
    attach_token: Some(b"attach-token".to_vec()),
 collector: false,

}))]
#[case(control_request::Op::Status(StatusRequest { job_id: "job-1".to_owned() }))]
#[case(control_request::Op::List(ListRequest {}))]
fn each_control_request_op_round_trips(#[case] op: control_request::Op) -> Result<()> {
    let request = ControlRequest {
        request_id: 7,
        op: Some(op),
    };

    let decoded = ControlRequest::decode(request.encode_to_vec().as_slice()).context("round-trip")?;

    assert_eq!(decoded, request);
    Ok(())
}

/// Every `ControlResponse.result` variant, including the `ControlError`
/// failure case, survives the same round-trip.
#[rstest]
#[case(control_response::Result::Submit(SubmitResponse {
    job_id: "job-1".to_owned(),
    attach_token: b"attach-token".to_vec(),
}))]
#[case(control_response::Result::Cancel(CancelResponse {}))]
#[case(control_response::Result::Attach(AttachResponse {
    channel_id: "orchestrator".to_owned(),
    cap: b"cap-bytes".to_vec(),
}))]
#[case(control_response::Result::Status(StatusResponse {
    job_id: "job-1".to_owned(),
    status: i32::from(JobStatus::Running),
    exit_code: Some(0),
    console_tail: "hi\n".to_owned(),
    result_envelope: None,
}))]
#[case(control_response::Result::List(ListResponse {
    jobs: vec![JobSummary {
        job_id: "job-1".to_owned(),
        status: i32::from(JobStatus::Succeeded),
    }],
}))]
#[case(control_response::Result::Error(ControlError { message: "unknown job id".to_owned() }))]
fn each_control_response_result_round_trips(#[case] result: control_response::Result) -> Result<()> {
    let response = ControlResponse {
        request_id: 7,
        result: Some(result),
    };

    let decoded = ControlResponse::decode(response.encode_to_vec().as_slice()).context("round-trip")?;

    assert_eq!(decoded, response);
    Ok(())
}

/// Forward compatibility: an unknown `ControlRequest.op` tag (a future oneof
/// variant this build doesn't know about, here field 50 as an empty
/// length-delimited message) is skipped, not rejected. The known
/// `request_id` field decodes intact and `op` stays absent — the same
/// contract `sandy_proto::Envelope` holds for its own `message_type` oneof.
#[test]
fn unknown_control_request_op_tag_decodes_as_absent() -> Result<()> {
    let base = ControlRequest {
        request_id: 9,
        op: None,
    };

    let mut wire = base.encode_to_vec();
    // Field 50, wire type 2 (length-delimited), empty: tag varint 0x92 0x03
    // (= (50 << 3) | 2 = 402), length 0x00.
    wire.extend_from_slice(&[0x92, 0x03, 0x00]);

    let decoded = ControlRequest::decode(wire.as_slice()).context("decode with unknown op tag")?;

    assert_eq!(decoded.request_id, 9);
    assert!(decoded.op.is_none(), "expected an absent op, got {:?}", decoded.op);
    Ok(())
}

/// The same forward-compatibility contract on the response side: an unknown
/// `ControlResponse.result` tag decodes with `result` absent, not as an error.
#[test]
fn unknown_control_response_result_tag_decodes_as_absent() -> Result<()> {
    let base = ControlResponse {
        request_id: 9,
        result: None,
    };

    let mut wire = base.encode_to_vec();
    // Same unknown field 50 as above; the two oneofs don't share field
    // numbers with each other, but an unknown tag is unknown regardless.
    wire.extend_from_slice(&[0x92, 0x03, 0x00]);

    let decoded = ControlResponse::decode(wire.as_slice()).context("decode with unknown result tag")?;

    assert_eq!(decoded.request_id, 9);
    assert!(
        decoded.result.is_none(),
        "expected an absent result, got {:?}",
        decoded.result
    );
    Ok(())
}

/// #888: `client_id` is optional on the wire. A Submit from a caller that never set it decodes with none (the same
/// bytes a client from before the field sends), and one that set it keeps it, so existing callers are unchanged.
#[test]
fn a_submit_client_id_is_optional_on_the_wire() -> Result<()> {
    let without = SubmitRequest::default();
    let with = SubmitRequest {
        client_id: Some("alice".to_owned()),
        ..SubmitRequest::default()
    };

    let decoded_without = SubmitRequest::decode(without.encode_to_vec().as_slice()).context("decode without")?;
    let decoded_with = SubmitRequest::decode(with.encode_to_vec().as_slice()).context("decode with")?;

    assert_eq!(decoded_without.client_id, None);
    assert_eq!(decoded_with.client_id.as_deref(), Some("alice"));
    assert!(
        without.encode_to_vec().len() < with.encode_to_vec().len(),
        "an absent client id adds no bytes"
    );
    Ok(())
}

/// #888: the one validity check sandyd and the broker share. 1 to 128 bytes (bytes, not characters), no control
/// character: NUL, newline, tab and DEL are all refused.
#[rstest]
#[case("a", None)]
#[case("client-a", None)]
#[case("ünïcode-ok", None)]
#[case("", Some("is empty"))]
#[case("a\nb", Some("has a control character"))]
#[case("a\0b", Some("has a control character"))]
#[case("a\tb", Some("has a control character"))]
#[case("a\u{7f}b", Some("has a control character"))]
fn the_client_id_check_names_the_broken_rule(#[case] id: &str, #[case] problem: Option<&str>) {
    assert_eq!(sandy_control_proto::client_id_problem(id), problem, "{id:?}");
}

#[test]
fn the_client_id_bound_counts_bytes_and_is_inclusive() {
    assert_eq!(sandy_control_proto::MAX_CLIENT_ID_BYTES, 128);
    assert_eq!(sandy_control_proto::client_id_problem(&"x".repeat(128)), None);
    assert_eq!(
        sandy_control_proto::client_id_problem(&"x".repeat(129)),
        Some("is longer than 128 bytes")
    );
    // 64 two-byte characters are 128 bytes (valid); 65 are 130 bytes (too long).
    assert_eq!(sandy_control_proto::client_id_problem(&"é".repeat(64)), None);
    assert_eq!(
        sandy_control_proto::client_id_problem(&"é".repeat(65)),
        Some("is longer than 128 bytes")
    );
}
