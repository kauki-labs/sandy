//! The typed VM [`Topology`] and the Nix seam that produces it.
//!
//! sandy reads the guest's topology by evaluating the guest config itself
//! (`nix … --json`); it never re-derives the hypervisor argv. The JSON that a
//! microvm.nix guest emits deserializes 1:1 into [`Topology`] via serde
//! (`snake_case`, no rename layer). Per INV-TOPOLOGY a [`Topology`] is either
//! fully populated from a real eval or a typed [`BackendError`] — a missing
//! required field is a hard error, never a silent default.

use std::path::PathBuf;

use serde::Deserialize;

use crate::backend::BackendError;

/// Where the guest's read-only Nix store comes from.
///
/// microvm.nix backs the store either as a prebuilt erofs image attached as a
/// block device, or as a virtiofs share of the host store identified by a mount
/// tag. The enum is externally tagged `snake_case`, so the JSON is
/// `{ "erofs_image": "/nix/store/…" }` or `{ "virtiofs": "ro-store" }`.
#[derive(Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StoreBacking {
    /// A prebuilt erofs store image at this host path, attached as a block device.
    ErofsImage(PathBuf),
    /// A virtiofs share of the host store, identified by this mount tag.
    Virtiofs(String),
}

/// The hypervisor the topology targets.
///
/// Serialized `snake_case` as a bare string: `"qemu"` or `"vfkit"`. qemu is the
/// Linux/CI path; vfkit is the macOS path.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Hypervisor {
    /// `qemu-system-*` — the Linux/CI backend.
    Qemu,
    /// `vfkit` — the macOS (Virtualization.framework) backend.
    Vfkit,
}

/// One host→guest virtiofs share declared by the guest config.
///
/// Mirrors a microvm.nix share: `host` is the exported host directory
/// (microvm's `source`), `guest` is the in-guest mount point (`mountPoint`),
/// and `tag` is the virtiofs mount tag (`tag`) that binds the two.
#[derive(Debug, PartialEq, Eq, Deserialize)]
pub struct Share {
    /// Host directory exposed to the guest.
    pub host: PathBuf,
    /// Guest mount point where it appears.
    pub guest: PathBuf,
    /// The virtiofs mount tag binding host to guest.
    pub tag: String,
}

/// The complete VM topology sandy evaluates out of a guest flake attr.
///
/// Every field but [`Topology::vsock_cid`] is required: deserialization of a
/// JSON object missing one fails, surfacing as [`BackendError::Protocol`] rather
/// than a defaulted value (INV-TOPOLOGY). The native backends (#33/#34) consume
/// this to assemble the hypervisor argv.
#[derive(Debug, PartialEq, Eq, Deserialize)]
pub struct Topology {
    /// Host path to the guest kernel image (bzImage/Image).
    pub kernel: PathBuf,
    /// Host path to the guest initrd.
    pub initrd: PathBuf,
    /// How the read-only Nix store is backed.
    pub store: StoreBacking,
    /// The full kernel command line (console, root, init, …).
    pub kernel_cmdline: String,
    /// vCPU count.
    pub cpu: u32,
    /// Memory budget in MiB.
    pub mem: u32,
    /// The guest's vsock context id, when the topology assigns one. Absent in
    /// the JSON deserializes to `None`; it is the only optional field.
    #[serde(default)]
    pub vsock_cid: Option<u32>,
    /// Extra host→guest virtiofs shares beyond the store.
    pub shares: Vec<Share>,
    /// The hypervisor this topology targets.
    pub hypervisor: Hypervisor,
}

/// Parse a topology JSON document (as emitted by `nix … --json`) into a
/// [`Topology`].
///
/// This is the pure seam: no process is spawned, so it is the tier-1 unit
/// target. Malformed JSON or a missing required field both yield
/// [`BackendError::Protocol`]; the function never fabricates or defaults a
/// field (INV-TOPOLOGY).
///
/// # Errors
///
/// Returns [`BackendError::Protocol`] if `json` is not valid JSON or does not
/// carry every required [`Topology`] field.
pub fn parse_topology(json: &[u8]) -> Result<Topology, BackendError> {
    todo!("deserialize {} bytes of topology JSON into Topology", json.len())
}

/// Evaluate `flake_attr` with the Nix CLI and parse the resulting topology.
///
/// Shells `nix eval`/`nix build … --json` (ambient ssh builders from #37 carry
/// x86_64), then hands the JSON to [`parse_topology`]. The Nix invocation is the
/// tier-2/host concern and is not unit-tested in the sandbox; a transient eval
/// failure maps to [`BackendError::Transport`] (retryable), a malformed result
/// to [`BackendError::Protocol`].
///
/// # Errors
///
/// Returns [`BackendError::Transport`] if the `nix` invocation fails
/// transiently, or [`BackendError::Protocol`] if its output is not a complete
/// topology.
pub fn topology(flake_attr: &str) -> Result<Topology, BackendError> {
    todo!("shell `nix … --json` for {flake_attr}, then parse_topology its output")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A complete microvm.nix topology JSON (x86_64, qemu, erofs store).
    const X86_64_FIXTURE: &[u8] = include_bytes!("../../tests/fixtures/topology-x86_64.json");
    /// A complete topology JSON (aarch64, vfkit, virtiofs store, no vsock_cid).
    const AARCH64_FIXTURE: &[u8] = include_bytes!("../../tests/fixtures/topology-aarch64.json");
    /// The x86_64 fixture with its required `kernel` field removed.
    const MISSING_KERNEL_FIXTURE: &[u8] = include_bytes!("../../tests/fixtures/topology-missing-kernel.json");

    /// Tier-1: a complete fixture parses into a fully populated `Topology` with
    /// the real store path, hypervisor, and cpu/mem carried through verbatim.
    /// RED until `parse_topology` is implemented (todo!() panics).
    #[test]
    fn parses_a_complete_topology() -> anyhow::Result<()> {
        use anyhow::Context;
        let topology = parse_topology(X86_64_FIXTURE).context("parse x86_64 fixture")?;
        assert_eq!(topology.hypervisor, Hypervisor::Qemu);
        assert_eq!(topology.cpu, 2);
        assert_eq!(topology.mem, 2048);
        assert_eq!(topology.vsock_cid, Some(3));
        assert_eq!(
            topology.store,
            StoreBacking::ErofsImage(PathBuf::from(
                "/nix/store/1q2w3r4y5a6s7d8f9g0hjklzxcvbnm12-sandy-store.erofs"
            ))
        );
        assert_eq!(topology.shares.len(), 1);
        Ok(())
    }

    /// INV-TOPOLOGY round-trip on the other arch: the aarch64 fixture (vfkit +
    /// virtiofs store, `vsock_cid` absent) parses, exercising the other enum
    /// arms and the one optional field. RED until implemented.
    #[test]
    fn parses_the_aarch64_variant() -> anyhow::Result<()> {
        use anyhow::Context;
        let topology = parse_topology(AARCH64_FIXTURE).context("parse aarch64 fixture")?;
        assert_eq!(topology.hypervisor, Hypervisor::Vfkit);
        assert_eq!(topology.store, StoreBacking::Virtiofs("ro-store".to_string()));
        assert_eq!(topology.vsock_cid, None);
        Ok(())
    }

    /// Adversarial (INV-TOPOLOGY): a fixture missing the required `kernel` field
    /// is a hard `Protocol` error, never a defaulted/partial `Topology`. RED
    /// until implemented.
    #[test]
    fn missing_required_field_is_a_hard_error() {
        assert!(matches!(
            parse_topology(MISSING_KERNEL_FIXTURE),
            Err(BackendError::Protocol(_))
        ));
    }

    /// Adversarial: garbage bytes are a `Protocol` error, not a panic or a
    /// defaulted value. RED until implemented.
    #[test]
    fn malformed_json_is_a_protocol_error() {
        assert!(matches!(
            parse_topology(b"not json at all {"),
            Err(BackendError::Protocol(_))
        ));
    }

    /// Tier-2/host: a real `nix eval --json` of a dev-VM attr yields a complete
    /// `Topology`. Ignored in the sandbox (no Nix/eval); run on the host tier
    /// with `cargo test -p sandy -- --ignored real_nix_eval`.
    #[test]
    #[ignore = "tier-2/host: requires a real `nix … --json` eval (S9)"]
    fn real_nix_eval_yields_a_complete_topology() -> anyhow::Result<()> {
        use anyhow::Context;
        let topology = topology("./dev#nixosConfigurations.sandy-dev.config.microvm").context("real nix eval")?;
        assert!(topology.cpu >= 1);
        Ok(())
    }
}
