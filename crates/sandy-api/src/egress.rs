//! The egress seam: the applier contract, its OS-resolved plan/outcome types, the
//! allow-list it is computed from, and the narrow error it returns.
//!
//! The translation (`to_nftables`), the planners (`plan_egress`), the appliers
//! (`NftablesApplier`, the fake), and the `enforce` driver live in the core; this
//! crate carries only the contract.

use serde::{Deserialize, Serialize};

/// One permitted egress destination.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressRule {
    /// The destination host (DNS name or address) to permit.
    pub host: String,
    /// The destination TCP port to permit.
    pub port: u16,
}

/// A bundle's egress allow-list: the only destinations a guest may reach.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllowList {
    /// The permitted destinations; everything else is denied.
    pub rules: Vec<EgressRule>,
}

/// The target OS an egress plan is computed for — injected so the core's
/// `plan_egress` is a pure function unit-testable without a real host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressOs {
    /// Linux: nftables enforces a default-deny per-VM egress boundary.
    Linux,
    /// macOS (vmnet): no per-VM egress boundary can be enforced.
    MacOs,
}

/// A typed, OS-resolved egress enforcement plan.
///
/// Keeping the plan a value (not an action) makes the Linux/macOS decision
/// testable without touching the host, and makes macOS honesty explicit: a
/// platform with no boundary yields [`EgressPlan::NoBoundary`], never an empty
/// [`EgressPlan::Enforce`] that would read as "filtered" while permitting all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EgressPlan {
    /// Apply this nftables ruleset as the per-VM boundary (Linux).
    Enforce {
        /// The default-deny ruleset to load; see the core's `to_nftables`.
        ruleset: String,
    },
    /// No boundary is enforced; `reason` states why, honestly (macOS).
    NoBoundary {
        /// Why no boundary exists — surfaced to the operator, never swallowed.
        reason: String,
    },
}

/// The result of driving an [`EgressPlan`] through the core's `enforce`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EgressOutcome {
    /// The ruleset was applied as the per-VM boundary (Linux).
    Enforced,
    /// No boundary was applied; `reason` carries the honest explanation (macOS).
    Unenforced {
        /// Why egress is unenforced — mirrors [`EgressPlan::NoBoundary`]'s reason.
        reason: String,
    },
}

/// The narrow error an [`EgressApplier`] returns.
///
/// Kept in the contract crate so the egress seam does not drag the core's broad
/// journal/reconcile `CoreError`; the core maps it back with a
/// `From<EgressError> for CoreError`.
#[derive(Debug, thiserror::Error)]
pub enum EgressError {
    /// Applying or reverting the ruleset on the host failed (e.g. `nft` exited
    /// non-zero). The string is the diagnostic; egress rules are destinations, not
    /// secrets, so it is in the clear (INV-1).
    #[error("egress enforcement failed: {0}")]
    Apply(String),
    /// A host IO error while applying or reverting the boundary.
    #[error("egress i/o error: {0}")]
    Io(#[from] std::io::Error),
}

/// A seam that applies and reverts a compiled egress ruleset on the host.
///
/// Abstracting the host away lets the core's `enforce` be wired and tested with a
/// fake (no root, no `nft`); the real host-tier impl shells `nft`. Egress rules
/// are destinations, not secrets (INV-1), so the ruleset is passed and logged in
/// the clear.
pub trait EgressApplier {
    /// Load `ruleset` as the active egress boundary.
    ///
    /// # Errors
    /// Returns [`EgressError`] if the ruleset cannot be applied on the host.
    fn apply(&self, ruleset: &str) -> Result<(), EgressError>;

    /// Tear the applied boundary back down.
    ///
    /// # Errors
    /// Returns [`EgressError`] if the teardown fails.
    fn revert(&self) -> Result<(), EgressError>;
}
