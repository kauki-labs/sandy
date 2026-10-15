//! The placement/discovery seam: where a job can be built/run.
//!
//! Requester-driven placement behind a pluggable [`Discovery`] seam. The resolved
//! [`Placement`] is the single-struct surface the core's `classify` consumes and
//! the forward-compatible slot for richer discovery (tracker/DHT, host
//! self-registration). The trivial static-registry impl lives in the core crate.

use std::collections::BTreeSet;

/// The resolved placement for a job: which systems can be built, and the optional
/// remote builder / builder-VM seed to use. It mirrors what the core's `HostFacts`
/// consumes, and is the forward-compatible slot for richer discovery (a
/// tracker/DHT grows fields; the trait stays).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Placement {
    /// The builder systems available from the host matrix (the nix machines table).
    pub systems: BTreeSet<String>,
    /// A remote builder host, if one is available (stage D). `None` = local only.
    pub remote_builder: Option<String>,
    /// A builder-VM seed, if one is available (stage C). `None` = local only.
    pub seed: Option<String>,
}

/// Resolve where a job targeting `target` (a nixpkgs system string) can be placed.
///
/// The trivial impl is a static registry over the current host matrix; the result
/// is a [`Placement`] the caller turns into the core's `HostFacts`.
pub trait Discovery {
    /// Resolve the placement for a job whose guest targets `target`.
    fn resolve(&self, target: &str) -> Placement;
}
