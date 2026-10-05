//! Locked-down-Linux fallback decision (Phase D, D.2 / D-REQ-2, D14).
//!
//! A Nix-free Linux host where a local install is impossible (no root, no user
//! namespaces) cannot build locally. This module decides the fallback over
//! injected host facts: route to C's seed/builder machinery, to a remote builder,
//! or refuse naming the blocker. The decision is pure and sandbox-provable; the
//! actual boots are host-tier.

use sandy::{HostFacts, ProvisioningStrategy};

/// Decide the provisioning fallback for a locked-down, Nix-free Linux host where a
/// local Nix install is impossible (D-REQ-2 / D14).
///
/// Contract the implementer satisfies (pinned by the tests):
/// - a builder-VM seed available → [`ProvisioningStrategy::BuilderVM`] (reuses C's seed/builder machinery);
/// - else a remote builder available → [`ProvisioningStrategy::RemoteBuild`] at [`HostFacts::target_arch`];
/// - else [`ProvisioningStrategy::Refuse`] whose reason names the blocker (the `seed` and `remote` axes) — never a
///   silent hang.
///
/// `seed_available` / `remote_available` are the reachability signals; the seed id
/// and remote host are read from [`HostFacts::seed`] / [`HostFacts::remote_builder`].
#[must_use]
pub fn decide_fallback(facts: &HostFacts, seed_available: bool, remote_available: bool) -> ProvisioningStrategy {
    // A reachable seed reuses C's seed/builder machinery; prefer it over a remote.
    if let (true, Some(seed_id)) = (seed_available, &facts.seed) {
        return ProvisioningStrategy::BuilderVM {
            seed_id: seed_id.clone(),
        };
    }
    // Else a reachable remote builder evaluates locally and builds remotely.
    if let (true, Some(host)) = (remote_available, &facts.remote_builder) {
        return ProvisioningStrategy::RemoteBuild {
            host: host.clone(),
            arch: facts.target_arch.clone(),
        };
    }
    ProvisioningStrategy::Refuse {
        reason: "locked-down Linux has no fallback: no seed (no reachable builder-VM seed) and no remote (no \
                 reachable remote builder)"
            .to_string(),
    }
}

#[cfg(test)]
mod tests {
    use sandy::{BootAxis, BuildAxis, HostFacts, ProvisioningStrategy};

    use super::decide_fallback;

    const TARGET: &str = "x86_64-linux";

    /// A locked-down Nix-free Linux host: boot ok, no build, install impossible.
    fn locked_down_facts() -> HostFacts {
        HostFacts {
            boot: BootAxis::Ok,
            build: BuildAxis::None,
            target_arch: TARGET.to_string(),
            build_can_produce_target: false,
            seed: None,
            remote_builder: None,
        }
    }

    /// D-REQ-2 (positive): install-impossible Linux routes to `BuilderVM` when a
    /// seed is available, and to `RemoteBuild` when only a remote builder is.
    #[test]
    fn locked_down_linux_fallback() {
        let seeded = HostFacts {
            seed: Some("seed-7".to_string()),
            ..locked_down_facts()
        };
        let got = decide_fallback(&seeded, true, false);
        assert!(
            matches!(got, ProvisioningStrategy::BuilderVM { .. }),
            "a seed-backed fallback must route BuilderVM, got {got:?}"
        );

        let remote = HostFacts {
            remote_builder: Some("builder.example".to_string()),
            ..locked_down_facts()
        };
        let got = decide_fallback(&remote, false, true);
        assert!(
            matches!(got, ProvisioningStrategy::RemoteBuild { .. }),
            "a remote-only fallback must route RemoteBuild, got {got:?}"
        );
    }

    /// D-REQ-2 (adversarial / MUST NOT): neither a seed nor a remote → `Refuse`
    /// naming the blocker, never a silent hang.
    #[test]
    fn no_fallback_refuses_named() {
        let facts = locked_down_facts();
        let got = decide_fallback(&facts, false, false);
        let ProvisioningStrategy::Refuse { reason } = got else {
            panic!("no fallback available must refuse, got {got:?}");
        };
        assert!(
            reason.contains("seed"),
            "the refusal must name the seed blocker: {reason}"
        );
        assert!(
            reason.contains("remote"),
            "the refusal must name the remote blocker: {reason}"
        );
    }
}
