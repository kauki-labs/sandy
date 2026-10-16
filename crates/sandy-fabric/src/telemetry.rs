//! The telemetry-sink seam (spec §3.5): where an agent's telemetry goes.
//!
//! Local-first: the default sink appends to a local log, which needs no network and
//! survives an unreachable orchestrator. A channel, content-addressed pull, or OTLP
//! are richer sinks. Telemetry is off by default; a disabled sink drops every
//! record.

use std::{collections::BTreeMap, future::Future};

use serde::{Deserialize, Serialize};

/// One telemetry record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TelemetryRecord {
    /// The record kind (event name).
    pub kind: String,
    /// The record's fields.
    pub fields: BTreeMap<String, String>,
}

/// A telemetry-sink failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TelemetryError {
    /// The sink could not store or forward the record.
    #[error("telemetry sink: {0}")]
    Sink(String),
}

/// Receives telemetry records.
pub trait TelemetrySink: Send + Sync {
    /// Whether the sink records anything. Stable for the sink's lifetime.
    fn enabled(&self) -> bool;
    /// Record `record`; a no-op when the sink is disabled.
    fn emit(&self, record: &TelemetryRecord) -> impl Future<Output = Result<(), TelemetryError>> + Send;
}
