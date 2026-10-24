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
#[case(control_request::Op::Submit(SubmitRequest {
    manifest: b"manifest-bytes".to_vec(),
    manifest_encoding: "sandy.orchestrator.v1.JobManifest".to_owned(),
    submitter_caps: vec![b"cap-a".to_vec(), b"cap-b".to_vec()],
}))]
#[case(control_request::Op::Cancel(CancelRequest { job_id: "job-1".to_owned() }))]
#[case(control_request::Op::Attach(AttachRequest {
    job_id: "job-1".to_owned(),
    attach_token: Some(b"attach-token".to_vec()),
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
