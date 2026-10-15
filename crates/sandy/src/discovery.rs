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

pub use sandy_api::discovery::{Discovery, Placement};

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

/// Parse the systems a remote builder is configured for from the `/etc/nix/machines`
/// table. Each non-comment line's second whitespace field is a comma-separated
/// systems list (`aarch64-linux`, `x86_64-linux,i686-linux`). This is the matrix
/// read a [`StaticRegistry`] is built from.
#[must_use]
pub fn parse_builder_systems(machines: &str) -> BTreeSet<String> {
    let mut systems = BTreeSet::new();
    for line in machines.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(field) = line.split_whitespace().nth(1) {
            for system in field.split(',').filter(|system| !system.is_empty()) {
                systems.insert(system.to_string());
            }
        }
    }
    systems
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The real two-builder `/etc/nix/machines` shape (a remote x86_64 node plus
    /// the darwin linux-builder) parses to both systems.
    #[test]
    fn parse_builder_systems_reads_the_machines_table() {
        let machines = "ssh://user@host x86_64-linux /key 8 2 big-parallel - -\nssh://builder@linux-builder \
                        aarch64-linux /key 4 1 benchmark - -\n";
        let systems = parse_builder_systems(machines);
        assert!(systems.contains("aarch64-linux"));
        assert!(systems.contains("x86_64-linux"));
    }

    /// Comments, blank lines, and comma-separated system lists are handled.
    #[test]
    fn parse_builder_systems_ignores_comments_and_splits_lists() {
        let machines = "# a comment\n\n  ssh://b x86_64-linux,i686-linux /k 2 1 - - -\n";
        let systems = parse_builder_systems(machines);
        assert!(systems.contains("x86_64-linux"));
        assert!(systems.contains("i686-linux"));
    }

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
