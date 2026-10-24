//! A minimal client-side helper over the control RPC (#205, B4): one
//! [`call`] per request, matching the server's own one-request-one-response
//! loop (`sandyd::serve_connection`). Shared here, not duplicated per
//! frontend, so the CLI (B4) and the future MCP (B5) both speak the protocol
//! the same way.
//!
//! Transport-agnostic like the rest of this crate: `call` takes any
//! `AsyncRead + AsyncWrite` stream, so it rides UDS today and vsock / TCP
//! over mesh later (B6) without changing shape.

use crate::{ControlRequest, ControlResponse, FrameError, control_request, read_frame, write_frame};

/// A control-RPC call failed.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// Writing the request or reading the response faulted.
    #[error(transparent)]
    Frame(#[from] FrameError),
    /// The daemon closed the connection before answering — the request was
    /// sent, but no response ever arrived.
    #[error("the daemon closed the connection before responding")]
    ConnectionClosed,
    /// The daemon answered a different request than the one just sent. The
    /// protocol is strictly one-at-a-time with no pipelining (#211's decision
    /// record §1), so this means a protocol violation, not a case to resync
    /// from — never silently accepted as if it were the right answer.
    #[error("sent request {sent}, but the daemon answered request {answered}")]
    MismatchedRequestId {
        /// The request id this call sent.
        sent: u64,
        /// The request id the daemon's response actually carried.
        answered: u64,
    },
    /// `request_id` was 0. proto3 gives `request_id` no separate presence
    /// bit, so 0 and "unset" are the same wire value (#211's decision record
    /// §1): rejected here, before anything is written, rather than letting a
    /// request with no real id ride to the wire and risk matching a
    /// different in-flight call that also defaulted to 0.
    #[error("request_id must be non-zero (0 means absent)")]
    MissingRequestId,
}

/// Send one `op` as request `request_id` over `stream` and return the
/// daemon's matching response. One request, one response, per call — the
/// protocol's own contract (#211 §1); `stream` is expected to carry exactly
/// one conversation at a time, same as the server's `serve_connection` loop.
///
/// # Errors
///
/// [`ClientError::MissingRequestId`] if `request_id` is 0, before anything is
/// written; [`ClientError::Frame`] if the write or read itself fails;
/// [`ClientError::ConnectionClosed`] if the daemon closes before answering;
/// [`ClientError::MismatchedRequestId`] if the response's `request_id`
/// doesn't match what was sent (a protocol violation, never silently
/// accepted).
pub async fn call(
    stream: &mut (impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin),
    request_id: u64,
    op: control_request::Op,
) -> Result<ControlResponse, ClientError> {
    if request_id == 0 {
        return Err(ClientError::MissingRequestId);
    }
    write_frame(
        stream,
        &ControlRequest {
            request_id,
            op: Some(op),
        },
    )
    .await?;
    let response: ControlResponse = read_frame(stream).await?.ok_or(ClientError::ConnectionClosed)?;
    if response.request_id != request_id {
        return Err(ClientError::MismatchedRequestId {
            sent: request_id,
            answered: response.request_id,
        });
    }
    Ok(response)
}

#[cfg(test)]
mod tests {
    use anyhow::Context;

    use super::*;
    use crate::{ListRequest, ListResponse, control_response};

    #[tokio::test]
    async fn a_call_matches_its_response_by_request_id() -> anyhow::Result<()> {
        let (mut client_side, mut server_side) = tokio::io::duplex(4096);
        let serving = tokio::spawn(async move {
            let request: ControlRequest = read_frame(&mut server_side).await?.context("expected a request")?;
            write_frame(
                &mut server_side,
                &ControlResponse {
                    request_id: request.request_id,
                    result: Some(control_response::Result::List(ListResponse { jobs: vec![] })),
                },
            )
            .await?;
            Ok::<_, anyhow::Error>(())
        });

        let response = call(&mut client_side, 42, control_request::Op::List(ListRequest {})).await?;
        assert_eq!(response.request_id, 42);
        serving.await??;
        Ok(())
    }

    /// Adversarial: a response carrying the wrong `request_id` is a protocol
    /// violation, never silently accepted as the answer to the call that was
    /// actually made.
    #[tokio::test]
    async fn a_mismatched_request_id_is_rejected_not_accepted() -> anyhow::Result<()> {
        let (mut client_side, mut server_side) = tokio::io::duplex(4096);
        let serving = tokio::spawn(async move {
            let _request: ControlRequest = read_frame(&mut server_side).await?.context("expected a request")?;
            write_frame(
                &mut server_side,
                &ControlResponse {
                    request_id: 999, // wrong on purpose
                    result: Some(control_response::Result::List(ListResponse { jobs: vec![] })),
                },
            )
            .await?;
            Ok::<_, anyhow::Error>(())
        });

        let result = call(&mut client_side, 1, control_request::Op::List(ListRequest {})).await;
        assert!(
            matches!(result, Err(ClientError::MismatchedRequestId { sent: 1, answered: 999 })),
            "got {result:?}"
        );
        serving.await??;
        Ok(())
    }

    /// Adversarial (#211's adversarial test, decision record §1):
    /// `request_id: 0` means absent — `call` refuses to send such a request
    /// at all, rather than letting it ride to the wire and risk a confusing
    /// match later. The server side is a live, responding peer (not an
    /// idle one): if the guard were missing, `call` would write the request,
    /// the server would answer it, and `call` would return `Ok` instead of
    /// hanging — so a dropped guard fails this test fast, not by stalling.
    #[tokio::test]
    async fn a_request_id_of_zero_is_rejected_before_anything_is_written() -> anyhow::Result<()> {
        let (mut client_side, mut server_side) = tokio::io::duplex(4096);
        let serving = tokio::spawn(async move {
            let request: Option<ControlRequest> = read_frame(&mut server_side).await?;
            let saw_no_frame = request.is_none();
            if let Some(request) = request {
                write_frame(
                    &mut server_side,
                    &ControlResponse {
                        request_id: request.request_id,
                        result: Some(control_response::Result::List(ListResponse { jobs: vec![] })),
                    },
                )
                .await?;
            }
            Ok::<_, anyhow::Error>(saw_no_frame)
        });

        let result = call(&mut client_side, 0, control_request::Op::List(ListRequest {})).await;
        assert!(matches!(result, Err(ClientError::MissingRequestId)), "got {result:?}");

        // Nothing was written: dropping the client side now lets the server
        // observe a clean close rather than wait on a frame that never comes.
        drop(client_side);
        assert!(serving.await??, "expected the server to see a clean close, not a frame");
        Ok(())
    }

    /// Adversarial (#211, decision: 0 is not a wildcard): a response carrying
    /// `request_id: 0` must still be rejected as mismatched when the request
    /// actually sent a different id — `request_id: 0` must never be read as
    /// "no correlation check required" and let a wrong response through.
    #[tokio::test]
    async fn a_response_of_zero_does_not_bypass_the_mismatch_check() -> anyhow::Result<()> {
        let (mut client_side, mut server_side) = tokio::io::duplex(4096);
        let serving = tokio::spawn(async move {
            let _request: ControlRequest = read_frame(&mut server_side).await?.context("expected a request")?;
            write_frame(
                &mut server_side,
                &ControlResponse {
                    request_id: 0, // wrong on purpose: the client sent a non-zero id
                    result: Some(control_response::Result::List(ListResponse { jobs: vec![] })),
                },
            )
            .await?;
            Ok::<_, anyhow::Error>(())
        });

        let result = call(&mut client_side, 5, control_request::Op::List(ListRequest {})).await;
        assert!(
            matches!(result, Err(ClientError::MismatchedRequestId { sent: 5, answered: 0 })),
            "got {result:?}"
        );
        serving.await??;
        Ok(())
    }

    /// Adversarial: the daemon closing before answering is a named error, not
    /// a silent default response.
    #[tokio::test]
    async fn a_connection_closed_before_a_response_is_a_named_error() -> anyhow::Result<()> {
        let (mut client_side, mut server_side) = tokio::io::duplex(4096);
        // The request must actually be sent (and read) before the daemon
        // closes, or the write itself fails with a broken pipe instead of
        // exercising the "sent but never answered" path this test names.
        let serving = tokio::spawn(async move {
            let _request: ControlRequest = read_frame(&mut server_side).await?.context("expected a request")?;
            drop(server_side); // close without ever answering
            Ok::<_, anyhow::Error>(())
        });

        let result = call(&mut client_side, 1, control_request::Op::List(ListRequest {})).await;
        assert!(matches!(result, Err(ClientError::ConnectionClosed)), "got {result:?}");
        serving.await??;
        Ok(())
    }
}
