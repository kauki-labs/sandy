//! sandyd's control-plane RPC surface (epic #205, B0 #211): the
//! `ControlRequest`/`ControlResponse` protobuf messages for Submit, Cancel,
//! Attach, Status, and List, plus the length-prefixed framing they ride over a
//! stream (UDS today; vsock, then TCP/QUIC-over-mesh, land over the same
//! framing per the epic's one-stream-abstraction decision, B6).
//!
//! Pure request/response, never streaming: job output, telemetry, and
//! escalation ride the fabric's `Channel`/`ChannelBackend` (the data/event
//! plane), not this RPC. `Attach` hands back a channel identity and cap; the
//! caller subscribes on the data plane itself.
//!
//! ```
//! use sandy_control_proto::{ControlRequest, control_request};
//!
//! let request = ControlRequest {
//!     request_id: 1,
//!     op: Some(control_request::Op::List(Default::default())),
//! };
//! assert_eq!(request.request_id, 1);
//! ```

/// Generated protobuf types for `package sandy.control.v1`.
pub mod v1 {
    // prost-generated code is not hand-maintained: it carries no doc comments and
    // is not written to the workspace clippy standard. Scope the allows here so
    // the rest of the crate keeps `missing_docs`/clippy denials.
    #![allow(missing_docs, clippy::all, clippy::pedantic)]
    include!(concat!(env!("OUT_DIR"), "/sandy.control.v1.rs"));
}

pub use v1::{
    AttachRequest, AttachResponse, CancelRequest, CancelResponse, ControlError, ControlRequest, ControlResponse,
    JobStatus, JobSummary, ListRequest, ListResponse, StatusRequest, StatusResponse, SubmitRequest, SubmitResponse,
    control_request, control_response,
};

/// `AttachResponse.cap` is a bearer credential (an encoded, attenuated
/// channel-join `Cap`): a holder can present it as that scope, so it must
/// never print in the clear. `build.rs` skips prost's derived `Debug` for this
/// message; this redacts the cap the same way `sandy_fabric::capauth::Cap`
/// redacts its own proof.
impl std::fmt::Debug for AttachResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttachResponse")
            .field("channel_id", &self.channel_id)
            .field("cap", &format_args!("<redacted {} bytes>", self.cap.len()))
            .finish()
    }
}

/// The largest frame this codec accepts, guarding against a hostile or broken
/// peer claiming an unbounded length prefix. Generous for a control message
/// (job manifests are small compared to job output, which never rides this
/// RPC at all).
pub const MAX_FRAME_LEN: u32 = 1 << 20;

/// A framing failure reading or writing a length-prefixed message.
#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    /// The encoded message is larger than [`MAX_FRAME_LEN`] (or does not fit a
    /// `u32` length prefix at all).
    #[error("message of {0} bytes exceeds the {MAX_FRAME_LEN}-byte frame limit")]
    TooLarge(usize),
    /// The frame's bytes are not a valid message of the expected type.
    #[error("malformed frame: {0}")]
    Decode(#[from] prost::DecodeError),
    /// The underlying stream faulted.
    #[error("frame I/O: {0}")]
    Io(#[source] std::io::Error),
}

/// Write `message` as one length-prefixed frame: a big-endian `u32` byte
/// length, then the encoded message.
///
/// # Errors
/// [`FrameError::TooLarge`] if the encoded message exceeds [`MAX_FRAME_LEN`];
/// [`FrameError::Io`] if the write cannot be completed.
pub async fn write_frame<M: prost::Message>(
    writer: &mut (impl tokio::io::AsyncWrite + Unpin),
    message: &M,
) -> Result<(), FrameError> {
    use tokio::io::AsyncWriteExt;

    let bytes = message.encode_to_vec();
    let len = u32::try_from(bytes.len()).map_err(|_| FrameError::TooLarge(bytes.len()))?;
    if len > MAX_FRAME_LEN {
        return Err(FrameError::TooLarge(bytes.len()));
    }
    writer.write_u32(len).await.map_err(FrameError::Io)?;
    writer.write_all(&bytes).await.map_err(FrameError::Io)?;
    writer.flush().await.map_err(FrameError::Io)
}

/// Read one length-prefixed frame and decode it as `M`.
///
/// Returns `Ok(None)` when the stream closes before (or while) reading the
/// length prefix — the ordinary "no more frames, the peer hung up" case, not
/// an error. A length prefix over [`MAX_FRAME_LEN`], or bytes that decode as
/// something other than `M`, are errors: a frame that announces itself and
/// then fails to parse as the expected type is never silently skipped.
///
/// # Errors
/// [`FrameError::TooLarge`] if the announced length exceeds [`MAX_FRAME_LEN`];
/// [`FrameError::Decode`] if the frame's bytes are not a valid `M`;
/// [`FrameError::Io`] if the stream faults after the length prefix starts.
pub async fn read_frame<M: prost::Message + Default>(
    reader: &mut (impl tokio::io::AsyncRead + Unpin),
) -> Result<Option<M>, FrameError> {
    use tokio::io::AsyncReadExt;

    let len = match reader.read_u32().await {
        Ok(len) => len,
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(FrameError::Io(e)),
    };
    if len > MAX_FRAME_LEN {
        return Err(FrameError::TooLarge(len as usize));
    }
    let mut buf = vec![0_u8; len as usize];
    reader.read_exact(&mut buf).await.map_err(FrameError::Io)?;
    Ok(Some(M::decode(buf.as_slice())?))
}

#[cfg(test)]
mod tests {
    use anyhow::Context;

    use super::*;

    fn sample_request(id: u64) -> ControlRequest {
        ControlRequest {
            request_id: id,
            op: Some(control_request::Op::Status(StatusRequest {
                job_id: "job-1".to_owned(),
            })),
        }
    }

    /// Adversarial (credential leak): `AttachResponse`'s `Debug` must never
    /// print the raw cap bytes — it's a bearer credential a holder can present
    /// as that scope. Mirrors `sandy_fabric::capauth::Cap`'s own redaction
    /// test.
    #[test]
    fn attach_response_debug_redacts_the_cap() {
        let marker = "sandy-cap-leak-marker-9f3c1a";
        let cap = marker.as_bytes().to_vec();
        let response = AttachResponse {
            channel_id: "orchestrator".to_owned(),
            cap: cap.clone(),
        };
        let rendered = format!("{response:?}");

        // Check both leak shapes: prost's default-derived Debug on a bearer
        // credential would print the bytes either as the decoded UTF-8 text
        // (unlikely to render by chance, but cheap to also guard) or as its
        // numeric byte array (`[115, 97, 110, ...]`, the actual shape a plain
        // `#[derive(Debug)]` on `Vec<u8>` prints) — a marker-text-only check
        // would miss the real leak shape entirely.
        assert!(
            !rendered.contains(marker),
            "the cap's decoded text leaked into Debug output: {rendered}"
        );
        let numeric_repr = format!("{cap:?}");
        assert!(
            !rendered.contains(&numeric_repr),
            "the cap's raw bytes leaked into Debug output: {rendered}"
        );
        assert!(
            rendered.contains("redacted"),
            "expected an explicit redaction marker, got: {rendered}"
        );
    }

    #[tokio::test]
    async fn a_request_round_trips_through_the_frame_codec() -> anyhow::Result<()> {
        let (mut write_side, mut read_side) = tokio::io::duplex(4096);
        write_frame(&mut write_side, &sample_request(7)).await?;

        let decoded: ControlRequest = read_frame(&mut read_side)
            .await?
            .context("expected a frame, got a clean close")?;
        assert_eq!(decoded, sample_request(7));
        Ok(())
    }

    #[tokio::test]
    async fn multiple_frames_are_read_in_order() -> anyhow::Result<()> {
        let (mut write_side, mut read_side) = tokio::io::duplex(4096);
        write_frame(&mut write_side, &sample_request(1)).await?;
        write_frame(&mut write_side, &sample_request(2)).await?;

        let first: ControlRequest = read_frame(&mut read_side).await?.context("frame 1")?;
        let second: ControlRequest = read_frame(&mut read_side).await?.context("frame 2")?;
        assert_eq!(first.request_id, 1);
        assert_eq!(second.request_id, 2);
        Ok(())
    }

    /// Adversarial: a clean close before any frame is a `None`, not an error —
    /// the ordinary "peer hung up between requests" case a server loop ends on.
    #[tokio::test]
    async fn a_clean_close_before_any_frame_is_none_not_an_error() -> anyhow::Result<()> {
        let (write_side, mut read_side) = tokio::io::duplex(4096);
        drop(write_side);

        let frame = read_frame::<ControlRequest>(&mut read_side).await?;
        assert!(frame.is_none(), "expected a clean close, got {frame:?}");
        Ok(())
    }

    /// Adversarial: a length prefix with no payload behind it (truncated
    /// mid-frame) is an error, never silently decoded as a default message.
    #[tokio::test]
    async fn a_truncated_frame_is_rejected_not_defaulted() -> anyhow::Result<()> {
        let (mut write_side, mut read_side) = tokio::io::duplex(4096);
        use tokio::io::AsyncWriteExt;
        write_side.write_u32(100).await?; // announces 100 bytes
        write_side.write_all(b"short").await?; // far fewer than announced
        drop(write_side); // close so read_exact fails instead of hanging

        let result = read_frame::<ControlRequest>(&mut read_side).await;
        assert!(matches!(result, Err(FrameError::Io(_))), "got {result:?}");
        Ok(())
    }

    /// Adversarial: an announced length over the frame cap is refused before
    /// ever allocating or reading that many bytes.
    #[tokio::test]
    async fn an_oversized_frame_is_refused() -> anyhow::Result<()> {
        let (mut write_side, mut read_side) = tokio::io::duplex(4096);
        use tokio::io::AsyncWriteExt;
        write_side.write_u32(MAX_FRAME_LEN + 1).await?;

        let result = read_frame::<ControlRequest>(&mut read_side).await;
        assert!(matches!(result, Err(FrameError::TooLarge(_))), "got {result:?}");
        Ok(())
    }

    /// Adversarial: bytes that are a valid frame but not a valid `ControlRequest`
    /// (the wrong message type) fail to decode rather than silently producing a
    /// default-valued request.
    #[tokio::test]
    async fn bytes_of_the_wrong_message_type_fail_to_decode() -> anyhow::Result<()> {
        // A valid SubmitResponse, read back as a ControlRequest: field 1 (string)
        // vs ControlRequest's field 1 (uint64) is a wire-type mismatch.
        let (mut write_side, mut read_side) = tokio::io::duplex(4096);
        write_frame(
            &mut write_side,
            &SubmitResponse {
                job_id: "not-a-control-request".to_owned(),
            },
        )
        .await?;

        let result = read_frame::<ControlRequest>(&mut read_side).await;
        assert!(matches!(result, Err(FrameError::Decode(_))), "got {result:?}");
        Ok(())
    }
}
