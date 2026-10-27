//! The first concrete [`EscalationSink`] (#205 B8): logs every escalation at
//! `error` level. This genuinely reaches the operator today — the
//! master-controller session running the relay ([`crate::roles::EscalationRelay`])
//! sees it directly in its own terminal/log stream — without needing external
//! credentials this crate cannot itself verify live (a Telegram bot, tracked
//! separately: #161). A richer backend plugs in behind the same
//! [`EscalationSink`] seam later without touching [`EscalationRelay`] at all.
//!
//! [`EscalationRelay`]: crate::roles::EscalationRelay

use sandy_fabric::escalation::{EscalationRequest, EscalationSink, EscalationSinkError};

/// Logs every escalation via `tracing::error!`. Always enabled: there is no
/// external dependency that could be down.
#[derive(Debug, Default, Clone, Copy)]
pub struct LogEscalationSink;

impl EscalationSink for LogEscalationSink {
    fn enabled(&self) -> bool {
        true
    }

    async fn notify(&self, request: &EscalationRequest) -> Result<(), EscalationSinkError> {
        tracing::error!(
            from = %request.from.0,
            severity = ?request.severity,
            summary = %request.summary,
            context_ref = %request.context_ref,
            "sandbox escalation: needs a human"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use sandy_fabric::{escalation::Severity, types::PeerId};

    use super::*;

    #[tokio::test]
    async fn the_sink_is_always_enabled_and_notify_always_succeeds() -> anyhow::Result<()> {
        let sink = LogEscalationSink;
        assert!(sink.enabled());
        sink.notify(&EscalationRequest {
            from: PeerId::from("sandbox-1"),
            severity: Severity::Critical,
            summary: "needs human input".to_owned(),
            context_ref: "job-42".to_owned(),
        })
        .await?;
        Ok(())
    }
}
