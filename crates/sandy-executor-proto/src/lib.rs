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

#[cfg(test)]
mod tests {
    use anyhow::Context;
    use sandy_control_proto::{read_frame, write_frame};

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
}
