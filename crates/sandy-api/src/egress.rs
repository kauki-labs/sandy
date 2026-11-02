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

/// The guest network profile (#602): whether the guest boots with a NIC.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkMode {
    /// No NIC: the guest reaches the host only over virtio-fs and vsock (#360). The default.
    #[default]
    None,
    /// A NIC, for sandboxes that need a routable guest. On Linux it needs a bound tap, and the caller applies the
    /// nftables boundary on it; it never shares a run with the egress proxy. On macOS it is the trusted-only NAT
    /// NIC with no boundary (#603).
    Nic,
}

/// The environment variable that selects the guest network profile (#602), read by each VM backend
/// like `$SANDY_TAP`. Unset or empty means [`NetworkMode::None`].
pub const NETWORK_ENV: &str = "SANDY_NETWORK";

impl NetworkMode {
    /// Parse a [`NETWORK_ENV`] value. An unknown value is an error, so a typo can never fall back
    /// silently to a different profile.
    ///
    /// # Errors
    ///
    /// Returns the rejected value when it is neither `none` nor `nic`.
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "" | "none" => Ok(Self::None),
            "nic" => Ok(Self::Nic),
            other => Err(format!("{NETWORK_ENV}={other:?} is not a network profile (none|nic)")),
        }
    }

    /// Read [`NETWORK_ENV`]: unset is [`NetworkMode::None`]; a value that is not UTF-8 or not a
    /// profile is an error, never a silent default.
    ///
    /// # Errors
    ///
    /// Returns the reason when the variable holds a non-UTF-8 or unknown value.
    pub fn from_env() -> Result<Self, String> {
        Self::from_var(std::env::var(NETWORK_ENV))
    }

    /// [`Self::from_env`] over an already-read variable, so the non-UTF-8 case is unit-testable.
    ///
    /// # Errors
    ///
    /// Returns the reason when the variable holds a non-UTF-8 or unknown value.
    pub fn from_var(var: Result<String, std::env::VarError>) -> Result<Self, String> {
        match var {
            Ok(value) => Self::parse(&value),
            Err(std::env::VarError::NotPresent) => Ok(Self::None),
            Err(std::env::VarError::NotUnicode(_)) => Err(format!("{NETWORK_ENV} is not valid UTF-8")),
        }
    }
}

/// Whether `tap` is a safe guest tap interface name (#602): 1 to 15 bytes (the Linux `IFNAMSIZ` limit) of ASCII
/// letters, digits, `_`, `-` and `.`. It is interpolated into the qemu `-netdev` argument and the nftables ruleset, so
/// a `,` or a space would let a value like `sandytap0,vhost=on` split the argument or open the ruleset.
#[must_use]
pub fn is_valid_tap_name(tap: &str) -> bool {
    !tap.is_empty()
        && tap.len() <= 15
        && tap != "."
        && tap != ".."
        && tap
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
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
    /// The guest has no NIC and the backend runs a per-run egress proxy that
    /// applies the allow-list (#360). Nothing is applied on the host here; the
    /// allow-list travels to the backend in [`crate::backend::RunSpec::egress`].
    Proxy,
}

/// The result of driving an [`EgressPlan`] through the core's `enforce`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EgressOutcome {
    /// The ruleset was applied as the per-VM boundary (Linux).
    Enforced,
    /// The boundary is the backend's egress proxy: the host applied nothing, so
    /// there is nothing to revert. A backend that cannot run the proxy refuses
    /// the run before boot, so this outcome never covers an unbounded run.
    Proxied,
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

#[cfg(test)]
mod tests {
    use super::*;

    /// #602: the profile defaults to no NIC and a typo is refused, not defaulted.
    #[test]
    fn network_mode_parses_none_nic_and_refuses_a_typo() {
        assert_eq!(NetworkMode::parse(""), Ok(NetworkMode::None));
        assert_eq!(NetworkMode::parse("none"), Ok(NetworkMode::None));
        assert_eq!(NetworkMode::parse("nic"), Ok(NetworkMode::Nic));
        assert!(NetworkMode::parse("NIC").is_err());
        assert_eq!(NetworkMode::default(), NetworkMode::None);
    }

    /// #602: an unset variable is `none`, a non-UTF-8 one is refused rather than defaulted.
    #[test]
    fn network_mode_from_var_refuses_non_utf8() {
        use std::{env::VarError, ffi::OsString};
        assert_eq!(NetworkMode::from_var(Err(VarError::NotPresent)), Ok(NetworkMode::None));
        assert!(NetworkMode::from_var(Err(VarError::NotUnicode(OsString::new()))).is_err());
        assert_eq!(NetworkMode::from_var(Ok("nic".to_string())), Ok(NetworkMode::Nic));
    }
}
