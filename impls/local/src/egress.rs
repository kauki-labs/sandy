//! The no-op egress applier for platforms with no per-VM boundary.

use sandy::{CoreError, EgressApplier};

/// A no-op egress applier for platforms with no per-VM boundary. On macOS
/// `plan_egress` yields `NoBoundary`, so `enforce` never calls these — it exists
/// only to satisfy the `EgressApplier` bound off the Linux path.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoEgress;

impl EgressApplier for NoEgress {
    fn apply(&self, _ruleset: &str) -> Result<(), CoreError> {
        Ok(())
    }

    fn revert(&self) -> Result<(), CoreError> {
        Ok(())
    }
}
