//! Provisioning strategy types: the facts and the strategy the core's `classify`
//! decides between (Phase B). The classification logic itself lives in the core.

/// The provisioning strategy `sandy doctor` selects for a host.
///
/// Phase B implements `HostNix` + `Refuse`. `BuilderVM` and `RemoteBuild` are
/// typed stubs: when `classify` yields them, the router refuses with a stage
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
        /// `boot`, `build`, `arch`, `seed`, `remote` identify them (see the
        /// core's `classify`).
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

/// The injected, OS-aware facts the core's `classify` decides over (B-REQ-1).
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
    /// and no host-nix build fits, `classify` yields [`ProvisioningStrategy::BuilderVM`].
    pub seed: Option<String>,
    /// A remote builder host, if one is available (stage D territory). When
    /// present and no host-nix build fits, `classify` yields
    /// [`ProvisioningStrategy::RemoteBuild`].
    pub remote_builder: Option<String>,
}
