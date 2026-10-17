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
}

/// Send one `op` as request `request_id` over `stream` and return the
/// daemon's matching response. One request, one response, per call — the
/// protocol's own contract (#211 §1); `stream` is expected to carry exactly
/// one conversation at a time, same as the server's `serve_connection` loop.
///
/// # Errors
///
/// [`ClientError::Frame`] if the write or read itself fails;
/// [`ClientError::ConnectionClosed`] if the daemon closes before answering;
/// [`ClientError::MismatchedRequestId`] if the response's `request_id`
/// doesn't match what was sent (a protocol violation, never silently
/// accepted).
pub async fn call(
    stream: &mut (impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin),
    request_id: u64,
    op: control_request::Op,
) -> Result<ControlResponse, ClientError> {
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
