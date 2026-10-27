//! The escalation-sink seam (spec §3.4): where an escalation reaches a human.
//!
//! A redundant path alongside posting to the escalation [`Channel`](crate) itself:
//! the sink is a *separate* backend instance from the orchestrator channel, so a
//! message still reaches the sink when the orchestrator path is degraded (the
//! property the adversarial contract case proves). Kept to the in-fabric
//! contract only — which transport the sink rides (a mobile push, IPC, …) is an
//! operator decision for later; this seam names only what an escalation says and
//! that it was accepted, nothing about how it gets to a device.

use std::future::Future;

use serde::{Deserialize, Serialize};

use crate::types::PeerId;

/// How urgently an escalation needs a human, shown to the operator alongside
/// the summary so a busy operator can triage without reading every message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Worth knowing, nothing is blocked.
    Info,
    /// Something needs attention soon, but the sandbox is still making progress.
    Warning,
    /// The sandbox is blocked; a human is needed to proceed.
    Critical,
}

/// One escalation: a sandbox asking for a human, independent of the
/// orchestrator's own health (#130's resolved `EscalationRequest` shape).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EscalationRequest {
    /// The sandbox (or its representative) raising the escalation.
    pub from: PeerId,
    /// How urgently this needs a human.
    pub severity: Severity,
    /// Human-readable summary, shown to the operator.
    pub summary: String,
    /// An opaque reference the operator can use to find more detail (e.g. a
    /// job id, channel id, or URL) — never interpreted by the fabric itself,
    /// same as `PeerMessage`'s payload is opaque to the channel layer. May be
    /// empty: not every escalation has a natural external reference.
    pub context_ref: String,
}

/// An [`EscalationRequest`] codec failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("escalation request codec: {0}")]
pub struct EscalationCodecError(String);

/// Encode `request` for an `Escalate` envelope's payload.
///
/// # Errors
/// Returns [`EscalationCodecError`] if JSON serialization fails (an invariant
/// violation of `PeerId`/`Severity`'s own `Serialize` impls, not an expected
/// runtime condition).
pub fn encode_escalation(request: &EscalationRequest) -> Result<Vec<u8>, EscalationCodecError> {
    serde_json::to_vec(request).map_err(|e| EscalationCodecError(e.to_string()))
}

/// Decode bytes written by [`encode_escalation`].
///
/// # Errors
/// Returns [`EscalationCodecError`] if `bytes` is not a valid encoded
/// [`EscalationRequest`] — a malformed or foreign payload, never a panic.
pub fn decode_escalation(bytes: &[u8]) -> Result<EscalationRequest, EscalationCodecError> {
    serde_json::from_slice(bytes).map_err(|e| EscalationCodecError(e.to_string()))
}

/// An escalation-sink failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EscalationSinkError {
    /// The sink could not accept or forward the message.
    #[error("escalation sink: {0}")]
    Sink(String),
}

/// Notifies a human that a sandbox has escalated.
pub trait EscalationSink: Send + Sync {
    /// Whether the sink is wired to anything. Stable for the sink's lifetime.
    fn enabled(&self) -> bool;
    /// Notify of `request`; a no-op when the sink is disabled.
    fn notify(&self, request: &EscalationRequest) -> impl Future<Output = Result<(), EscalationSinkError>> + Send;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> EscalationRequest {
        EscalationRequest {
            from: PeerId::from("sandbox-1"),
            severity: Severity::Critical,
            summary: "needs human input".to_owned(),
            context_ref: "job-42".to_owned(),
        }
    }

    #[test]
    fn a_request_round_trips_through_its_encoding() -> Result<(), EscalationCodecError> {
        let encoded = encode_escalation(&request())?;
        assert_eq!(
            decode_escalation(&encoded)?,
            request(),
            "the request changed in the round trip"
        );
        Ok(())
    }

    #[test]
    fn a_foreign_payload_is_a_codec_error_not_a_panic() {
        assert!(decode_escalation(b"not json").is_err());
    }

    /// `context_ref` is allowed to be empty: not every escalation has a
    /// natural external reference to point at.
    #[test]
    fn an_empty_context_ref_round_trips_too() -> Result<(), EscalationCodecError> {
        let request = EscalationRequest {
            context_ref: String::new(),
            ..request()
        };
        let encoded = encode_escalation(&request)?;
        assert_eq!(
            decode_escalation(&encoded)?,
            request,
            "an empty context_ref must survive the round trip"
        );
        Ok(())
    }
}
