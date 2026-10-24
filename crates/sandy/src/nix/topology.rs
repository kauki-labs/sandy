//! The typed VM [`Topology`] and the Nix seam that produces it.
//!
//! sandy reads the guest's topology by evaluating the guest config itself
//! (`nix … --json`); it never re-derives the hypervisor argv. The JSON that a
//! microvm.nix guest emits deserializes 1:1 into [`Topology`] via serde
//! (`snake_case`, no rename layer). Per INV-TOPOLOGY a [`Topology`] is either
//! fully populated from a real eval or a typed [`BackendError`] — a missing
//! required field is a hard error, never a silent default.

use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

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
/// Every field but [`Topology::vsock_cid`] and [`Topology::agent_program`] is
/// required: deserialization of a
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
    /// the JSON deserializes to `None`.
    #[serde(default)]
    pub vsock_cid: Option<u32>,
    /// The guest's path to the `sandy-agent` baked into this image (#238): the
    /// binary an agent-mode backend launches inside the guest, so it is always
    /// the one this image carries. Absent for an image without the agent.
    #[serde(default)]
    pub agent_program: Option<PathBuf>,
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
    serde_json::from_slice::<Topology>(json).map_err(|e| BackendError::Protocol(e.to_string()))
}

/// Resolve `source` into a typed [`Topology`], Nix-free when it is a prebuilt
/// JSON file.
///
/// Two paths, chosen by whether `source` names an existing file:
///
/// - **Nix-free (#28)**: when `source` is an existing file, its bytes are read and handed straight to
///   [`parse_topology`] — no `nix` process is spawned. This is the "erofs hinge": `sandy run /path/to/topology.json --
///   …` boots with Nix entirely off `PATH`, provided the kernel/initrd/erofs-store paths the JSON names already exist
///   in the store (prebuilt at build time).
/// - **Nix eval**: otherwise `source` is treated as a flake attr and evaluated with `nix eval --json` (ambient ssh
///   builders from #37 carry x86_64), then its JSON is parsed. This is the tier-2/host concern, not unit-tested in the
///   sandbox.
///
/// A transient eval failure maps to [`BackendError::Transport`] (retryable), a
/// malformed result (either path) to [`BackendError::Protocol`].
///
/// # Errors
///
/// Returns [`BackendError::Transport`] if a prebuilt file cannot be read or the
/// `nix` invocation fails transiently, or [`BackendError::Protocol`] if the
/// resulting JSON is not a complete topology.
pub fn topology(source: &str) -> Result<Topology, BackendError> {
    if Path::new(source).is_file() {
        tracing::debug!(source, "reading prebuilt guest topology (Nix-free, #28)");
        let json = fs::read(source)
            .map_err(|e| BackendError::Transport(format!("failed to read topology file {source}: {e}")))?;
        return parse_topology(&json);
    }

    tracing::debug!(source, "evaluating guest topology via `nix eval --json`");
    let mut command = Command::new(nix_bin());
    command.args(["eval", "--json", source]);
    // nix's OWN internal `git+https://…` fetcher does its own PATH lookup
    // for `git`, a second one this call doesn't otherwise control — see
    // `sandy-guest-template`'s identical `nix_subprocess_path` (duplicated
    // here for the same reason `nix_bin` is) for the full rationale (#337
    // follow-up).
    if let Some(path) = nix_subprocess_path() {
        command.env("PATH", path);
    }
    let output = command
        .output()
        .map_err(|e| BackendError::Transport(format!("failed to spawn `nix eval {source}`: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(BackendError::Transport(format!(
            "`nix eval {source}` failed ({}): {}",
            output.status,
            stderr.trim()
        )));
    }

    parse_topology(&output.stdout)
}

/// `SANDY_NIX_BIN`, falling back to a bare `nix` (`PATH` lookup) — the same
/// escape hatch `sandy-guest-template`'s own `nix_bin()` gives `run_nix`
/// (duplicated here, not shared: `sandy-lib` deliberately does not depend on
/// `sandy-guest-template`, a CLI/operator-shaped crate, see that crate's own
/// doc comment). Needed on a host whose environment setup (PAM, systemd
/// session handling, etc.) does not reliably carry a unit's own
/// `Environment=PATH=` through to the spawned child — confirmed on the remote host
/// (#335/#336): `SANDY_NIX_BIN` alone did not help if THIS call site still
/// did a bare `PATH` lookup (CodeRabbit finding on #336).
fn nix_bin() -> String {
    std::env::var("SANDY_NIX_BIN").unwrap_or_else(|_| "nix".to_string())
}

/// The `PATH` to hand `nix`'s own child process, built from `SANDY_GIT_BIN`
/// so its internal `git+https://…` fetcher can find `git` (duplicated from
/// `sandy-guest-template`'s identical `nix_subprocess_path`, same reason
/// `nix_bin` is) — `None` (inherit this process's own ambient `PATH`,
/// today's behavior) when `SANDY_GIT_BIN` isn't set.
fn nix_subprocess_path() -> Option<String> {
    nix_subprocess_path_with(
        std::env::var("SANDY_GIT_BIN").ok().as_deref(),
        std::env::var("PATH").ok().as_deref(),
    )
}

/// [`nix_subprocess_path`]'s pure core — see `sandy-guest-template`'s
/// identical split for why (this workspace forbids `unsafe_code`, so a test
/// cannot call `std::env::set_var`, unsafe as of edition 2024).
fn nix_subprocess_path_with(git_bin: Option<&str>, ambient_path: Option<&str>) -> Option<String> {
    let git_bin = git_bin?;
    let git_dir = Path::new(git_bin).parent()?.to_str()?;
    Some(match ambient_path {
        Some(ambient) if !ambient.is_empty() => format!("{git_dir}:{ambient}"),
        _ => git_dir.to_string(),
    })
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

    /// No override: nix's child inherits this process's ambient PATH
    /// unchanged — today's local-dev behavior, no `SANDY_GIT_BIN` involved.
    #[test]
    fn nix_subprocess_path_is_none_without_a_git_override() {
        assert_eq!(nix_subprocess_path_with(None, Some("/usr/bin:/bin")), None);
    }

    /// An override prepends git's own directory ahead of the ambient PATH.
    #[test]
    fn nix_subprocess_path_prepends_gits_directory() {
        assert_eq!(
            nix_subprocess_path_with(Some("/nix/store/abc-git-2.54.0/bin/git"), Some("/usr/bin:/bin")),
            Some("/nix/store/abc-git-2.54.0/bin:/usr/bin:/bin".to_string())
        );
    }

    /// An override with no ambient PATH at all (unset or empty) still
    /// resolves cleanly — git's directory alone.
    #[test]
    fn nix_subprocess_path_handles_no_ambient_path() {
        assert_eq!(
            nix_subprocess_path_with(Some("/nix/store/abc-git-2.54.0/bin/git"), None),
            Some("/nix/store/abc-git-2.54.0/bin".to_string())
        );
        assert_eq!(
            nix_subprocess_path_with(Some("/nix/store/abc-git-2.54.0/bin/git"), Some("")),
            Some("/nix/store/abc-git-2.54.0/bin".to_string())
        );
    }

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

    /// #238: the agent's in-guest path is carried when the image has one, and is
    /// `None` (never a guessed path) when it does not.
    #[test]
    fn the_agent_program_is_carried_when_present_and_none_otherwise() -> anyhow::Result<()> {
        use anyhow::Context;
        let mut doc: serde_json::Value = serde_json::from_slice(X86_64_FIXTURE).context("fixture json")?;
        assert_eq!(parse_topology(X86_64_FIXTURE)?.agent_program, None);
        doc["agent_program"] = serde_json::json!("/nix/store/abc-sandy-agent/bin/sandy-agent");
        let topology = parse_topology(&serde_json::to_vec(&doc)?)?;
        assert_eq!(
            topology.agent_program,
            Some(PathBuf::from("/nix/store/abc-sandy-agent/bin/sandy-agent"))
        );
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

    /// Tier-1 (#28): a prebuilt topology JSON file is read and parsed by
    /// `topology` with no `nix` process — the Nix-free hinge. Writing the x86_64
    /// fixture to a temp file and passing its path yields the same `Topology` the
    /// pure parse seam produces, proving the file branch bypasses `nix eval`.
    #[test]
    fn prebuilt_file_boots_nix_free() -> anyhow::Result<()> {
        use std::io::Write;

        use anyhow::Context;

        let mut file = tempfile::Builder::new()
            .suffix(".json")
            .tempfile()
            .context("create temp topology file")?;
        file.write_all(X86_64_FIXTURE).context("write fixture")?;
        let path = file.path().to_str().context("temp path is utf-8")?;

        let topology = topology(path).context("read prebuilt topology Nix-free")?;
        assert_eq!(topology.hypervisor, Hypervisor::Qemu);
        assert_eq!(
            topology.store,
            StoreBacking::ErofsImage(PathBuf::from(
                "/nix/store/1q2w3r4y5a6s7d8f9g0hjklzxcvbnm12-sandy-store.erofs"
            ))
        );
        Ok(())
    }

    /// Tier-1 adversarial (#28): a prebuilt file that exists but holds malformed
    /// JSON is a `Protocol` error from the file branch — the Nix-free path still
    /// never fabricates a `Topology` (INV-TOPOLOGY).
    #[test]
    fn prebuilt_file_with_garbage_is_a_protocol_error() -> anyhow::Result<()> {
        use std::io::Write;

        use anyhow::Context;

        let mut file = tempfile::Builder::new()
            .suffix(".json")
            .tempfile()
            .context("create temp topology file")?;
        file.write_all(b"not json at all {").context("write garbage")?;
        let path = file.path().to_str().context("temp path is utf-8")?;

        assert!(matches!(topology(path), Err(BackendError::Protocol(_))));
        Ok(())
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
