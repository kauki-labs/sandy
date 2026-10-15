//! The no-op egress applier for platforms with no per-VM boundary.

use sandy::{EgressApplier, EgressError};

/// A no-op egress applier for platforms with no per-VM boundary. On macOS
/// `plan_egress` yields `NoBoundary`, so `enforce` never calls these — it exists
/// only to satisfy the `EgressApplier` bound off the Linux path.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoEgress;

impl EgressApplier for NoEgress {
    fn apply(&self, _ruleset: &str) -> Result<(), EgressError> {
        Ok(())
    }

    fn revert(&self) -> Result<(), EgressError> {
        Ok(())
    }
}
