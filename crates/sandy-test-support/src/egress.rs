//! [`FakeApplier`]: an [`EgressApplier`] test double that records instead of
//! touching the host.

use std::cell::{Cell, RefCell};

use sandy_api::egress::{EgressApplier, EgressError};

/// A test double that records what it was asked to apply and whether it was
/// reverted, instead of touching the host.
#[derive(Debug, Default)]
pub struct FakeApplier {
    applied: RefCell<Vec<String>>,
    reverted: Cell<bool>,
}

impl FakeApplier {
    /// A fresh double that has applied nothing and not been reverted.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The rulesets passed to [`EgressApplier::apply`], in call order.
    #[must_use]
    pub fn applied_rulesets(&self) -> Vec<String> {
        self.applied.borrow().clone()
    }

    /// Whether [`EgressApplier::revert`] has been called.
    #[must_use]
    pub fn was_reverted(&self) -> bool {
        self.reverted.get()
    }
}

impl EgressApplier for FakeApplier {
    fn apply(&self, ruleset: &str) -> Result<(), EgressError> {
        self.applied.borrow_mut().push(ruleset.to_string());
        Ok(())
    }

    fn revert(&self) -> Result<(), EgressError> {
        self.reverted.set(true);
        Ok(())
    }
}
