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

/// One escalation: a sandbox asking for a human, independent of the
/// orchestrator's own health.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EscalationMessage {
    /// The sandbox (or its representative) raising the escalation.
    pub from: PeerId,
    /// Human-readable reason, shown to the operator.
    pub reason: String,
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
    /// Notify of `message`; a no-op when the sink is disabled.
    fn notify(&self, message: &EscalationMessage) -> impl Future<Output = Result<(), EscalationSinkError>> + Send;
}
