//! The orchestrator<->host-client contract (#263, epic #205 M2): capability-
//! declaring registration (kubelet-style) plus the dispatch RPC, as
//! `HostClientMessage`/`OrchestratorMessage` protobuf messages over one
//! persistent, bidirectional connection per host-client.
//!
//! Rides [`sandy_control_proto::write_frame`]/[`sandy_control_proto::read_frame`]
//! directly — the same length-prefixed framing as the control RPC, just a
//! different message shape, since this is a management channel (the
//! orchestrator pushes `Dispatch` down the connection a host-client opened
//! with `Register`) rather than the control RPC's pure request/response.
//!
//! ```
//! use sandy_executor_proto::{HostClientMessage, host_client_message};
//!
//! let message = HostClientMessage {
//!     op: Some(host_client_message::Op::Register(Default::default())),
//! };
//! assert!(message.op.is_some());
//! ```

/// Generated protobuf types for `package sandy.executor.v1`.
pub mod v1 {
    // prost-generated code is not hand-maintained: it carries no doc comments
    // and is not written to the workspace clippy standard. Scope the allows
    // here so the rest of the crate keeps `missing_docs`/clippy denials.
    #![allow(missing_docs, clippy::all, clippy::pedantic)]
    include!(concat!(env!("OUT_DIR"), "/sandy.executor.v1.rs"));
}

/// Re-exported so a caller bounding generic code against these message types
/// (e.g. a connection handler generic over `M: prost::Message`, mirroring
/// `sandy_control_proto::write_frame`/`read_frame`) doesn't need its own
/// direct `prost` dependency just for that bound.
pub use prost::Message;
pub use v1::{
    Arch, Capabilities, Dispatch, HostClientMessage, IsolationClass, OrchestratorMessage, Register, RegisterRefused,
    Registered, SandboxKind, host_client_message, orchestrator_message,
};

/// `Dispatch.link_token` is a bearer secret (INV-1): a holder can authenticate
/// the remote agent-link stream as that run's forwarder. `build.rs` skips
/// prost's derived `Debug` for this message; this redacts the token the same
/// way `sandy_control_proto::AttachResponse` redacts its cap.
impl std::fmt::Debug for Dispatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Dispatch")
            .field("job_id", &self.job_id)
            .field("manifest", &format_args!("<{} bytes>", self.manifest.len()))
            .field("manifest_encoding", &self.manifest_encoding)
            .field("backend", &self.backend)
            .field(
                "link_token",
                &format_args!("<redacted {} bytes>", self.link_token.len()),
            )
            .field("forward_back", &self.forward_back)
            .field("required_isolation_class", &self.required_isolation_class)
            .finish()
    }
}

/// A [`decode_remote_link_prefix`] failure: the bytes read so far do not (or
/// cannot yet) form a complete, valid prefix.
#[derive(Debug, thiserror::Error)]
pub enum RemoteLinkPrefixError {
    /// The stream ended before a complete prefix arrived.
    #[error("the stream closed before a full run-id+token prefix arrived")]
    Truncated,
    /// The run id's declared length exceeds what this decoder will attempt
    /// to read — a defensive bound against a hostile or corrupted peer
    /// claiming an enormous length and forcing an unbounded allocation,
    /// mirroring `sandy-control-proto`'s own `MAX_FRAME`-style guard.
    #[error("run id length {0} exceeds the maximum of {MAX_JOB_ID_LEN}")]
    JobIdTooLong(u32),
    /// The run id's bytes were not valid UTF-8.
    #[error("run id is not valid UTF-8: {0}")]
    InvalidUtf8(#[from] std::str::Utf8Error),
}

/// The largest run id [`decode_remote_link_prefix`] will read, in bytes. Job
/// ids are short, human-assigned identifiers; this bound exists only to stop
/// a corrupt or hostile length prefix from forcing a large allocation before
/// any authentication has happened.
pub const MAX_JOB_ID_LEN: u32 = 4096;

/// The length, in bytes, of the per-run link token
/// [`encode_remote_link_prefix`]/[`decode_remote_link_prefix`] carry raw,
/// with no length prefix of their own — mirrors `sandyd::link_auth::LINK_TOKEN_LEN`,
/// duplicated here (not imported) so this crate has no dependency on
/// `sandyd`; the two constants name the same fixed-size secret and must stay
/// in sync if either changes.
pub const REMOTE_LINK_TOKEN_LEN: usize = 32;

/// Encode the run-id + link-token prefix [`forward_agent_link`] (sandy-fabric-local)
/// writes before any agent-link frame, and [`decode_remote_link_prefix`]
/// reads on the orchestrator's mesh-accept loop (decision 6, #279) — the one
/// shared definition of this wire seam, so the two ends can never drift
/// independently of each other.
///
/// On the wire: a big-endian `u32` byte-length of `job_id`, then `job_id`'s
/// UTF-8 bytes, then `link_token`'s raw bytes with no length prefix of their
/// own (both sides already agree on [`REMOTE_LINK_TOKEN_LEN`]). Matches
/// `sandy_control_proto`'s own length-prefix framing style.
///
/// # Errors
/// A plain [`String`] if `job_id` is implausibly large (over 4 GiB) to fit
/// the `u32` length prefix.
///
/// [`forward_agent_link`]: https://docs.rs/sandy-fabric-local
pub fn encode_remote_link_prefix(job_id: &str, link_token: &[u8]) -> Result<Vec<u8>, String> {
    let job_id_bytes = job_id.as_bytes();
    let len = u32::try_from(job_id_bytes.len())
        .map_err(|_| format!("job_id is {} bytes, too large to prefix", job_id_bytes.len()))?;
    let mut prefix = Vec::with_capacity(4 + job_id_bytes.len() + link_token.len());
    prefix.extend_from_slice(&len.to_be_bytes());
    prefix.extend_from_slice(job_id_bytes);
    prefix.extend_from_slice(link_token);
    Ok(prefix)
}

/// Read one run-id + link-token prefix from `r`, the exact inverse of
/// [`encode_remote_link_prefix`]. Reads exactly the run id's declared length
/// plus [`REMOTE_LINK_TOKEN_LEN`] more bytes for the token — nothing past
/// the prefix itself; the caller's next read picks up the agent-link frames
/// that follow.
///
/// # Errors
/// [`RemoteLinkPrefixError::Truncated`] if the stream ends before a full
/// prefix arrives; [`RemoteLinkPrefixError::JobIdTooLong`] if the declared
/// run-id length exceeds [`MAX_JOB_ID_LEN`]; [`RemoteLinkPrefixError::InvalidUtf8`]
/// if the run-id bytes are not valid UTF-8. An I/O failure reading `r` is
/// wrapped as [`RemoteLinkPrefixError::Truncated`] (the actual error reason
/// is not disclosed before authentication has happened — same
/// zero-bytes-on-refusal discipline as decision 6's other refusals).
pub async fn decode_remote_link_prefix(
    r: &mut (impl tokio::io::AsyncRead + Unpin),
) -> Result<(String, [u8; REMOTE_LINK_TOKEN_LEN]), RemoteLinkPrefixError> {
    use tokio::io::AsyncReadExt;

    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)
        .await
        .map_err(|_| RemoteLinkPrefixError::Truncated)?;
    let len = u32::from_be_bytes(len_buf);
    if len > MAX_JOB_ID_LEN {
        return Err(RemoteLinkPrefixError::JobIdTooLong(len));
    }

    let mut job_id_buf = vec![0u8; len as usize];
    r.read_exact(&mut job_id_buf)
        .await
        .map_err(|_| RemoteLinkPrefixError::Truncated)?;
    let job_id = std::str::from_utf8(&job_id_buf)?.to_owned();

    let mut token = [0u8; REMOTE_LINK_TOKEN_LEN];
    r.read_exact(&mut token)
        .await
        .map_err(|_| RemoteLinkPrefixError::Truncated)?;

    Ok((job_id, token))
}

#[cfg(test)]
mod tests {
    use anyhow::Context;
    use sandy_control_proto::{read_frame, write_frame};
    use tokio::io::AsyncWriteExt;

    use super::*;

    /// Adversarial (credential leak, INV-1): `Dispatch`'s `Debug` must never
    /// print the raw link-token bytes. Mirrors
    /// `sandy_control_proto::AttachResponse`'s own redaction test.
    #[test]
    fn dispatch_debug_redacts_the_link_token() {
        let marker = b"sandy-link-token-leak-marker-7e2b";
        let dispatch = Dispatch {
            job_id: "job-1".to_owned(),
            manifest: b"m".to_vec(),
            manifest_encoding: "test/v1".to_owned(),
            backend: SandboxKind::Process.into(),
            link_token: marker.to_vec(),
            forward_back: "100.64.0.1:9000".to_owned(),
            required_isolation_class: IsolationClass::Trusted.into(),
        };
        let rendered = format!("{dispatch:?}");

        // Check both leak shapes: prost's default-derived Debug on a bearer
        // credential would print the bytes either as decoded text (unlikely
        // to render by chance here, but cheap to also guard) or as its
        // numeric byte array (the actual shape a plain `Vec<u8>` Debug
        // prints) — a marker-text-only check would miss the real leak shape.
        assert!(
            !rendered.contains(std::str::from_utf8(marker).unwrap()),
            "the token's decoded text leaked into Debug output: {rendered}"
        );
        let numeric_repr = format!("{:?}", marker.to_vec());
        assert!(
            !rendered.contains(&numeric_repr),
            "the token's raw bytes leaked into Debug output: {rendered}"
        );
        assert!(
            rendered.contains("redacted"),
            "expected an explicit redaction marker, got: {rendered}"
        );
    }

    #[tokio::test]
    async fn a_register_round_trips_through_the_frame_codec() -> anyhow::Result<()> {
        let (mut write_side, mut read_side) = tokio::io::duplex(4096);
        let message = HostClientMessage {
            op: Some(host_client_message::Op::Register(Register {
                host_id: "ws01".to_owned(),
                capabilities: Some(Capabilities {
                    kind: SandboxKind::Process.into(),
                    arch: Arch::X8664.into(),
                    attestation: false,
                    supported_isolation_classes: vec![IsolationClass::Trusted.into()],
                }),
            })),
        };
        write_frame(&mut write_side, &message).await?;

        let decoded: HostClientMessage = read_frame(&mut read_side)
            .await?
            .context("expected a frame, got a clean close")?;
        assert_eq!(decoded, message);
        Ok(())
    }

    #[tokio::test]
    async fn an_orchestrator_can_push_dispatch_after_registered() -> anyhow::Result<()> {
        let (mut write_side, mut read_side) = tokio::io::duplex(4096);
        write_frame(
            &mut write_side,
            &OrchestratorMessage {
                op: Some(orchestrator_message::Op::Registered(Registered {
                    host_id: "ws01".to_owned(),
                })),
            },
        )
        .await?;
        write_frame(
            &mut write_side,
            &OrchestratorMessage {
                op: Some(orchestrator_message::Op::Dispatch(Dispatch {
                    job_id: "job-1".to_owned(),
                    manifest: b"m".to_vec(),
                    manifest_encoding: "test/v1".to_owned(),
                    backend: SandboxKind::Process.into(),
                    link_token: vec![0u8; 32],
                    forward_back: "100.64.0.1:9000".to_owned(),
                    required_isolation_class: IsolationClass::Trusted.into(),
                })),
            },
        )
        .await?;

        let first: OrchestratorMessage = read_frame(&mut read_side).await?.context("frame 1")?;
        let second: OrchestratorMessage = read_frame(&mut read_side).await?.context("frame 2")?;
        assert!(matches!(first.op, Some(orchestrator_message::Op::Registered(_))));
        assert!(matches!(second.op, Some(orchestrator_message::Op::Dispatch(_))));
        Ok(())
    }

    /// The load-bearing property: encode on one side, decode on the other,
    /// over a real async stream — not just checking the encoded bytes'
    /// shape. This is the one test that would catch the two ends drifting if
    /// either is ever edited without the other.
    #[tokio::test]
    async fn the_prefix_round_trips_through_a_real_stream() -> anyhow::Result<()> {
        let (mut write_side, mut read_side) = tokio::io::duplex(256);
        let token = [0x5A_u8; REMOTE_LINK_TOKEN_LEN];

        let prefix = encode_remote_link_prefix("job-42", &token)
            .map_err(anyhow::Error::msg)
            .context("encode")?;
        write_side.write_all(&prefix).await?;

        let (job_id, decoded_token) = decode_remote_link_prefix(&mut read_side).await.context("decode")?;
        assert_eq!(job_id, "job-42");
        assert_eq!(decoded_token, token);
        Ok(())
    }

    #[tokio::test]
    async fn an_empty_job_id_round_trips_too() -> anyhow::Result<()> {
        let (mut write_side, mut read_side) = tokio::io::duplex(256);
        let token = [0u8; REMOTE_LINK_TOKEN_LEN];

        let prefix = encode_remote_link_prefix("", &token)
            .map_err(anyhow::Error::msg)
            .context("encode")?;
        write_side.write_all(&prefix).await?;

        let (job_id, decoded_token) = decode_remote_link_prefix(&mut read_side).await.context("decode")?;
        assert_eq!(job_id, "");
        assert_eq!(decoded_token, token);
        Ok(())
    }

    /// Adversarial: a declared run-id length far larger than any real run id
    /// must be refused before the decoder ever allocates or reads that many
    /// bytes — a hostile or corrupted peer naming a multi-gigabyte length
    /// must not be able to force a large allocation pre-authentication.
    #[tokio::test]
    async fn an_oversized_declared_length_is_refused_before_reading_it() -> anyhow::Result<()> {
        let (mut write_side, mut read_side) = tokio::io::duplex(256);
        write_side.write_all(&(MAX_JOB_ID_LEN + 1).to_be_bytes()).await?;

        let err = decode_remote_link_prefix(&mut read_side)
            .await
            .expect_err("an oversized length must be refused");
        assert!(matches!(err, RemoteLinkPrefixError::JobIdTooLong(len) if len == MAX_JOB_ID_LEN + 1));
        Ok(())
    }

    /// Adversarial: a stream that closes mid-prefix (before the job id, or
    /// before the token) must be a named, honest error — never a hang, and
    /// never a partially-decoded value treated as valid.
    #[tokio::test]
    async fn a_stream_closed_mid_prefix_is_truncated_not_a_hang() -> anyhow::Result<()> {
        let (write_side, mut read_side) = tokio::io::duplex(256);
        drop(write_side); // closed before even the length prefix arrives

        let err = decode_remote_link_prefix(&mut read_side)
            .await
            .expect_err("a stream closed before any bytes must be Truncated");
        assert!(matches!(err, RemoteLinkPrefixError::Truncated));
        Ok(())
    }

    #[tokio::test]
    async fn invalid_utf8_in_the_job_id_is_refused() -> anyhow::Result<()> {
        let (mut write_side, mut read_side) = tokio::io::duplex(256);
        let invalid_utf8 = [0xFF_u8, 0xFE];
        write_side.write_all(&(invalid_utf8.len() as u32).to_be_bytes()).await?;
        write_side.write_all(&invalid_utf8).await?;
        write_side.write_all(&[0u8; REMOTE_LINK_TOKEN_LEN]).await?;

        let err = decode_remote_link_prefix(&mut read_side)
            .await
            .expect_err("invalid UTF-8 in the job id must be refused");
        assert!(matches!(err, RemoteLinkPrefixError::InvalidUtf8(_)));
        Ok(())
    }
}
