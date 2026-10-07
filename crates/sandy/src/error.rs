//! The error type for the core journal / reconcile layer.

/// Errors raised by the core journal / reconcile layer.
#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    /// A filesystem operation failed.
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    /// A journal record could not be (de)serialized.
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    /// No journal record exists for the given job id.
    #[error("job record not found: {0}")]
    NotFound(String),
    /// The per-job flock could not be acquired (another writer holds it).
    #[error("could not acquire job lock for {0}")]
    Lock(String),
    /// `$SANDY_HOME` is not a local POSIX filesystem (INV-5).
    #[error("$SANDY_HOME is not a local POSIX filesystem: {0}")]
    NonLocalFs(String),
    /// A journal record is in an unexpected state for the requested transition.
    #[error("invalid journal state: {0}")]
    State(String),
    /// Applying or reverting an egress ruleset on the host failed.
    #[error("egress enforcement failed: {0}")]
    Egress(String),
}
