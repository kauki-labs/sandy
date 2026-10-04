//! Capability detection and strategy selection (Phase B, B-REQ-1..4, 7).
//!
//! [`classify`] is the pure core of `sandy doctor`: it maps a set of injected,
//! OS-aware [`HostFacts`] onto a [`ProvisioningStrategy`]. The live boot/build
//! observations that *produce* those facts are the integration-layer part
//! (tier-3); this module is provable in a sandbox over injected facts (tier-1).
//!
//! The function body is `todo!()`: this is the API skeleton plus its red test
//! suite. A separate implementer fills in the matrix the doc and tests pin.

/// The provisioning strategy `sandy doctor` selects for a host.
///
/// Phase B implements `HostNix` + `Refuse`. `BuilderVM` and `RemoteBuild` are
/// typed stubs: when [`classify`] yields them, the router refuses with a stage
/// pointer (B-REQ-7) rather than attempting an unbuilt path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProvisioningStrategy {
    /// Build + boot locally on this host (on the Mac, via the linux-builder).
    /// `arch` is the target architecture the host will produce and run.
    HostNix {
        /// The target architecture (e.g. `"x86_64-linux"`, `"aarch64-linux"`).
        arch: String,
    },
    /// Build inside a seeded builder VM (Nix-free Mac, seed + erofs). Deferred
    /// to **stage C**; the router refuses it at stage B (B-REQ-7).
    BuilderVM {
        /// The seed image identifier the builder VM would boot from.
        seed_id: String,
    },
    /// Evaluate locally, build on a remote host. Deferred to **stage D**; the
    /// router refuses it at stage B (B-REQ-7).
    RemoteBuild {
        /// The remote builder host.
        host: String,
        /// The target architecture to build for.
        arch: String,
    },
    /// No strategy fits. `reason` NAMES the missing/failed axis (or axes); the
    /// caller never falls through to a run (B-REQ-2).
    Refuse {
        /// Why no strategy fits. MUST name each missing axis — the substrings
        /// `boot`, `build`, `arch`, `seed`, `remote` identify them (see
        /// [`classify`]).
        reason: String,
    },
}

/// The boot axis: the result of a *real* trivial boot observation (B-REQ-3).
///
/// On macOS this is `vfkit` plus a trivial boot; on Linux it is `/dev/kvm` plus
/// a hypervisor plus a trivial boot. The value is an observation, never the
/// absence of an error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootAxis {
    /// A trivial guest booted and exited cleanly (observed).
    Ok,
    /// The trivial boot was attempted and observably failed (no `/dev/kvm`, a
    /// vfkit entitlement failure, ...).
    Failed,
}

/// The build axis: how (if at all) this host can produce the target artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuildAxis {
    /// Nix is present on this host and can build at the target arch (NixOS or
    /// any distro with Nix) — route `HostNix`.
    HostNix,
    /// No Nix, but installing it is possible (root once, or `nix-user-chroot`
    /// under user namespaces). After install the host is a host-nix host, so
    /// this also routes `HostNix`; the install step itself is the router /
    /// tier-3 concern (B-REQ-6).
    NixFreeInstallable,
    /// No Nix and no viable install path.
    None,
}

/// The injected, OS-aware facts [`classify`] decides over (B-REQ-1).
///
/// Two independent axes ([`boot`](HostFacts::boot), [`build`](HostFacts::build))
/// plus the target arch and whether the build axis can actually produce it. The
/// optional `seed` / `remote_builder` express the facts that imply the deferred
/// `BuilderVM` / `RemoteBuild` strategies. Every field is a plain enum / bool /
/// `String` so the full classify matrix
/// (boot∈{ok,fail} × build∈{host-nix,install,none} × arch∈{match,mismatch}) is
/// expressible in a table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostFacts {
    /// The boot axis observation.
    pub boot: BootAxis,
    /// The build axis observation.
    pub build: BuildAxis,
    /// The architecture the job targets.
    pub target_arch: String,
    /// Whether the build axis can produce [`target_arch`](HostFacts::target_arch).
    /// `false` with a producing `build` axis is an arch mismatch (B-REQ-4).
    pub build_can_produce_target: bool,
    /// A builder-VM seed, if one is available (stage C territory). When present
    /// and no host-nix build fits, [`classify`] yields [`ProvisioningStrategy::BuilderVM`].
    pub seed: Option<String>,
    /// A remote builder host, if one is available (stage D territory). When
    /// present and no host-nix build fits, [`classify`] yields
    /// [`ProvisioningStrategy::RemoteBuild`].
    pub remote_builder: Option<String>,
}

/// Classify injected [`HostFacts`] into a [`ProvisioningStrategy`] (pure;
/// B-REQ-1..4, 7).
///
/// The contract the implementer satisfies (and the tests below pin):
///
/// - **Boot is a prerequisite.** [`BootAxis::Failed`] → [`ProvisioningStrategy::Refuse`] whose `reason` names the
///   `boot` axis; no run (B-REQ-2, B-REQ-3).
/// - **Arch before build.** A producing build axis ([`BuildAxis::HostNix`] / [`BuildAxis::NixFreeInstallable`]) that
///   cannot produce the target (`build_can_produce_target == false`) → `Refuse` whose `reason` names `arch`, with **no
///   build attempted** (B-REQ-4).
/// - **Host-nix, boot ok, arch match** → [`ProvisioningStrategy::HostNix`] with `arch == target_arch`.
///   [`BuildAxis::NixFreeInstallable`] routes the same way (install → host-nix, B-REQ-6; the install is the
///   router/tier-3 step).
/// - **No host-nix build.** When `build == None` and boot is ok, a `seed` → [`ProvisioningStrategy::BuilderVM`]; else a
///   `remote_builder` → [`ProvisioningStrategy::RemoteBuild`] (so the router can refuse stage C/D, B-REQ-7).
/// - **Nothing fits** → `Refuse` whose `reason` names **each** missing axis (`boot`, `build`, `seed`, `remote`); never
///   a fall-through (B-REQ-2).
///
/// Refuse reasons MUST contain the lowercase axis token(s) above so a caller (or
/// an operator) can tell which axis blocked the run.
#[must_use]
pub fn classify(facts: &HostFacts) -> ProvisioningStrategy {
    // Boot is a prerequisite and takes precedence over every build/arch decision
    // (B-REQ-2, B-REQ-3): a failed boot refuses, naming `boot` alongside any other
    // missing axis.
    if !matches!(facts.boot, BootAxis::Ok) {
        return ProvisioningStrategy::Refuse {
            reason: missing_axes_reason(facts),
        };
    }

    // Boot is ok. A producing build axis that cannot target the requested arch
    // refuses naming `arch`, with no build attempted (B-REQ-4).
    if matches!(facts.build, BuildAxis::HostNix | BuildAxis::NixFreeInstallable) {
        if facts.build_can_produce_target {
            return ProvisioningStrategy::HostNix {
                arch: facts.target_arch.clone(),
            };
        }
        return ProvisioningStrategy::Refuse {
            reason: format!(
                "build axis cannot produce the target arch `{}` (no build attempted)",
                facts.target_arch
            ),
        };
    }

    // No host-nix build. A seed implies stage C, a remote builder stage D; the
    // router refuses both with a stage pointer (B-REQ-7).
    if let Some(seed_id) = &facts.seed {
        return ProvisioningStrategy::BuilderVM {
            seed_id: seed_id.clone(),
        };
    }
    if let Some(host) = &facts.remote_builder {
        return ProvisioningStrategy::RemoteBuild {
            host: host.clone(),
            arch: facts.target_arch.clone(),
        };
    }

    // Nothing fits: refuse naming each missing axis (B-REQ-2).
    ProvisioningStrategy::Refuse {
        reason: missing_axes_reason(facts),
    }
}

/// Build a refuse reason naming every unsatisfied axis (`boot`, `build`, `seed`,
/// `remote`) so a caller can tell which axes blocked the run (B-REQ-2).
fn missing_axes_reason(facts: &HostFacts) -> String {
    let mut missing = Vec::new();
    if !matches!(facts.boot, BootAxis::Ok) {
        missing.push("boot (no bootable hypervisor observed)");
    }
    if matches!(facts.build, BuildAxis::None) {
        missing.push("build (no Nix and no viable install path)");
    }
    if facts.seed.is_none() {
        missing.push("seed (no builder-VM seed available)");
    }
    if facts.remote_builder.is_none() {
        missing.push("remote (no remote builder available)");
    }
    format!("no viable provisioning strategy; missing axes: {}", missing.join(", "))
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::{BootAxis, BuildAxis, HostFacts, ProvisioningStrategy, classify};

    const TARGET: &str = "x86_64-linux";

    /// A host-facts fixture; override fields per case.
    fn facts(boot: BootAxis, build: BuildAxis, arch_ok: bool) -> HostFacts {
        HostFacts {
            boot,
            build,
            target_arch: TARGET.to_string(),
            build_can_produce_target: arch_ok,
            seed: None,
            remote_builder: None,
        }
    }

    /// B-REQ-1, B-REQ-3: the full axis matrix (boot × build × arch) selects the
    /// pinned strategy. `boot == Failed` always refuses (boot is a
    /// prerequisite); an arch mismatch on a producing build axis refuses naming
    /// `arch`; host-nix / installable with boot-ok + arch-match route `HostNix`;
    /// `build == None` with boot-ok refuses naming `build`.
    #[rstest]
    // boot ok, host-nix, arch match -> HostNix
    #[case::hostnix_match(BootAxis::Ok, BuildAxis::HostNix, true, Expect::HostNix)]
    // boot ok, host-nix, arch mismatch -> Refuse(arch), no build
    #[case::hostnix_arch_mismatch(BootAxis::Ok, BuildAxis::HostNix, false, Expect::RefuseArch)]
    // boot ok, installable, arch match -> HostNix (install -> host-nix)
    #[case::installable_match(BootAxis::Ok, BuildAxis::NixFreeInstallable, true, Expect::HostNix)]
    // boot ok, installable, arch mismatch -> Refuse(arch)
    #[case::installable_arch_mismatch(BootAxis::Ok, BuildAxis::NixFreeInstallable, false, Expect::RefuseArch)]
    // boot ok, no build -> Refuse(build) regardless of the arch flag
    #[case::no_build_arch_ok(BootAxis::Ok, BuildAxis::None, true, Expect::RefuseBuild)]
    #[case::no_build_arch_bad(BootAxis::Ok, BuildAxis::None, false, Expect::RefuseBuild)]
    // boot failed -> Refuse(boot) for every build / arch combination
    #[case::bootfail_hostnix(BootAxis::Failed, BuildAxis::HostNix, true, Expect::RefuseBoot)]
    #[case::bootfail_hostnix_badarch(BootAxis::Failed, BuildAxis::HostNix, false, Expect::RefuseBoot)]
    #[case::bootfail_installable(BootAxis::Failed, BuildAxis::NixFreeInstallable, true, Expect::RefuseBoot)]
    #[case::bootfail_none(BootAxis::Failed, BuildAxis::None, true, Expect::RefuseBoot)]
    fn classify_selects_strategy_matrix(
        #[case] boot: BootAxis,
        #[case] build: BuildAxis,
        #[case] arch_ok: bool,
        #[case] expect: Expect,
    ) {
        let got = classify(&facts(boot, build, arch_ok));
        match expect {
            Expect::HostNix => {
                assert_eq!(
                    got,
                    ProvisioningStrategy::HostNix {
                        arch: TARGET.to_string()
                    },
                    "expected HostNix at the target arch, got {got:?}"
                );
            }
            Expect::RefuseArch => assert_refuse_names(&got, "arch"),
            Expect::RefuseBuild => assert_refuse_names(&got, "build"),
            Expect::RefuseBoot => assert_refuse_names(&got, "boot"),
        }
    }

    /// B-REQ-2: nothing available (no boot, no build, no seed, no remote) →
    /// `Refuse` whose reason names **each** missing axis, with no fall-through to
    /// any run variant.
    #[test]
    fn no_viable_strategy_refuses_each_axis() {
        let got = classify(&facts(BootAxis::Failed, BuildAxis::None, false));
        let ProvisioningStrategy::Refuse { reason } = &got else {
            panic!("expected Refuse, got {got:?}");
        };
        for axis in ["boot", "build", "seed", "remote"] {
            assert!(
                reason.contains(axis),
                "refuse reason must name the `{axis}` axis, got: {reason}"
            );
        }
    }

    /// B-REQ-4: when the build axis can only produce the wrong arch, refuse
    /// naming `arch` with **no build** — never route `HostNix`.
    #[test]
    fn wrong_arch_refuses_no_build() {
        let got = classify(&facts(BootAxis::Ok, BuildAxis::HostNix, false));
        assert!(
            !matches!(got, ProvisioningStrategy::HostNix { .. }),
            "an arch mismatch must not route HostNix (no build), got {got:?}"
        );
        assert_refuse_names(&got, "arch");
    }

    /// B-REQ-7 (classify half): facts carrying a seed imply `BuilderVM`; facts
    /// carrying a remote builder imply `RemoteBuild`. The router then refuses
    /// these with a stage pointer (see the router test suite).
    #[test]
    fn deferred_facts_yield_builder_and_remote_variants() {
        let seeded = HostFacts {
            seed: Some("seed-42".to_string()),
            ..facts(BootAxis::Ok, BuildAxis::None, true)
        };
        assert_eq!(
            classify(&seeded),
            ProvisioningStrategy::BuilderVM {
                seed_id: "seed-42".to_string()
            }
        );

        let remote = HostFacts {
            remote_builder: Some("builder.example".to_string()),
            ..facts(BootAxis::Ok, BuildAxis::None, true)
        };
        assert_eq!(
            classify(&remote),
            ProvisioningStrategy::RemoteBuild {
                host: "builder.example".to_string(),
                arch: TARGET.to_string(),
            }
        );
    }

    /// The expected shape of a matrix case.
    #[derive(Debug, Clone, Copy)]
    enum Expect {
        HostNix,
        RefuseArch,
        RefuseBuild,
        RefuseBoot,
    }

    /// Assert `got` is a `Refuse` whose reason names `axis`.
    fn assert_refuse_names(got: &ProvisioningStrategy, axis: &str) {
        let ProvisioningStrategy::Refuse { reason } = got else {
            panic!("expected Refuse naming `{axis}`, got {got:?}");
        };
        assert!(
            reason.contains(axis),
            "refuse reason must name the `{axis}` axis, got: {reason}"
        );
    }
}
