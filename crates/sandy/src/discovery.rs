//! The placement/discovery seam: where a job can be built/run.
//!
//! Requester-driven placement behind a pluggable [`Discovery`] seam. The trivial
//! default is a **static registry** over today's host matrix — the builder systems
//! in the nix machines table; richer impls (tracker / DHT, and host
//! self-registration) are future.
//!
//! `classify` stays a pure function of [`HostFacts`](crate::HostFacts): the caller
//! resolves a [`Placement`] via [`Discovery`], builds the `HostFacts` from it, then
//! classifies — so the seam feeds placement in without changing the strategy logic.

use std::collections::BTreeSet;

/// The resolved placement for a job: which systems can be built, and the optional
/// remote builder / builder-VM seed to use. It mirrors what
/// [`HostFacts`](crate::HostFacts) consumes, and is the forward-compatible slot for
/// richer discovery (a tracker/DHT grows fields; the trait stays).
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
/// is a [`Placement`] the caller turns into [`HostFacts`](crate::HostFacts).
pub trait Discovery {
    /// Resolve the placement for a job whose guest targets `target`.
    fn resolve(&self, target: &str) -> Placement;
}

/// The trivial [`Discovery`]: a static registry over today's host matrix — the
/// builder systems from the nix machines table, with no remote builder or seed
/// resolved (stage C/D are future). This is a literal extraction of today's
/// placement read; it adds no system the matrix did not list.
pub struct StaticRegistry {
    builder_systems: BTreeSet<String>,
}

impl StaticRegistry {
    /// Build the registry from the builder systems parsed from the nix machines
    /// table. An empty set is the degenerate case (no matrix entries).
    pub fn new(builder_systems: BTreeSet<String>) -> Self {
        Self { builder_systems }
    }
}

impl Discovery for StaticRegistry {
    fn resolve(&self, _target: &str) -> Placement {
        // A literal extraction of today's placement: the matrix builder systems as-is,
        // with no remote builder or seed resolved (stage C/D), and no host system
        // added — doctor never unioned one. `target` does not steer the result for a
        // single static registry; richer discovery will use it.
        Placement {
            systems: self.builder_systems.clone(),
            remote_builder: None,
            seed: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The pure-extraction contract (#131 T2): the static registry resolves to
    /// today's production placement — exactly the matrix builder systems, with no
    /// remote builder or seed (stage C/D resolve to `None` in prod) and no added
    /// host system. The result must equal the registry's own matrix set.
    #[test]
    fn static_registry_resolves_to_the_matrix_systems_only() {
        let matrix = BTreeSet::from(["x86_64-linux".to_string(), "aarch64-linux".to_string()]);
        let registry = StaticRegistry::new(matrix.clone());
        let placement = registry.resolve("aarch64-linux");
        assert_eq!(
            placement,
            Placement {
                systems: matrix,
                remote_builder: None,
                seed: None,
            },
            "the static registry must resolve to the matrix systems only — no local union, no remote/seed"
        );
    }

    /// The degenerate case: an empty matrix resolves to an empty placement, not a
    /// fabricated host entry.
    #[test]
    fn empty_matrix_resolves_to_empty_placement() {
        let registry = StaticRegistry::new(BTreeSet::new());
        assert_eq!(registry.resolve("aarch64-linux"), Placement::default());
    }
}
