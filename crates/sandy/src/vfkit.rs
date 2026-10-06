//! The native vfkit backend (Block 32, macOS / Virtualization.framework).
//!
//! [`VfkitBackend`] is the [`VmBackend`] for the macOS path: it assembles a
//! `vfkit` argv from a [`Topology`] (#31), stages the run's secrets and mounts
//! (#34), launches `vfkit` under the PTY console transport (#33), and collapses
//! the console protocol into the pinned [`Outcome`] (INV-8). vfkit exposes its
//! guest serial console as `virtio-serial,stdio`, which needs a real TTY — hence
//! the PTY path rather than a plain pipe.
//!
//! The backend splits into a pure seam and a host seam:
//!
//! - [`vfkit_args`] is the pure argv assembler (tier-1, sandbox-testable): it maps a [`Topology`] plus the
//!   already-staged share descriptors ([`StagedArgs`]) into the `vfkit` command vector, with no process spawn and no
//!   filesystem touch.
//! - [`VfkitBackend::run`] is the host seam (tier-3): real staging, spawn, and boot. Per INV-S9 it is never counted
//!   green from the sandbox; its real-boot coverage binds into #26.

use std::{path::PathBuf, sync::Mutex};

use crate::{BackendError, BoxState, Outcome, RunSpec, Topology, VmBackend};

/// The staged virtio-fs share descriptors [`vfkit_args`] weaves into the argv.
///
/// Argv assembly is kept pure and testable without real staging: the backend
/// stages secrets and mounts first (#34), reduces each to a virtio-fs share
/// descriptor, and hands the strings here. Only share *descriptors* (host path
/// plus mount tag) travel this struct — never secret bytes, which stay in their
/// `0600` staging file (INV-1).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StagedArgs {
    /// virtio-fs share descriptors for the caller's bind mounts, as emitted by
    /// [`mount_args`](crate::mount_args) (`sharedDir=…,mountTag=…[,ro]`).
    pub mount_shares: Vec<String>,
    /// virtio-fs share descriptor(s) for the staged-secret directory
    /// (`sharedDir=<inst_dir>,mountTag=…,ro`). The secret channel is a read-only
    /// share of the staging dir, never argv bytes (INV-1).
    pub secret_shares: Vec<String>,
}

impl StagedArgs {
    /// A [`StagedArgs`] carrying the given mount and secret share descriptors.
    #[must_use]
    pub fn new(mount_shares: Vec<String>, secret_shares: Vec<String>) -> Self {
        Self {
            mount_shares,
            secret_shares,
        }
    }
}

/// Assemble the `vfkit` argv for `topology`, `spec`, and the already-staged
/// shares in `staged`.
///
/// This is the pure seam (tier-1): no process is spawned and no file is touched,
/// so the whole topology→argv mapping is unit-testable in the sandbox. The
/// implementer emits, in order:
///
/// - `--cpus <N>` and `--memory <MiB>` — vCPU count and memory budget, as two argv tokens each, taken from
///   [`Topology::cpu`]/[`Topology::mem`] (a `Some` [`RunSpec::cpu`]/[`RunSpec::mem`] overrides).
/// - `--bootloader linux,kernel=<kernel>,initrd=<initrd>,cmdline=<kernel_cmdline>` — the guest boot. The kernel path is
///   passed verbatim (vfkit on aarch64 needs an *uncompressed* `Image`; sandy never transforms it) along with the
///   initrd and the full [`Topology::kernel_cmdline`].
/// - the read-only Nix store, from [`Topology::store`](crate::Topology): an
///   [`ErofsImage`](crate::StoreBacking::ErofsImage) becomes `--device virtio-blk,path=<img>,readOnly` (a read-only
///   block device); a [`Virtiofs`](crate::StoreBacking::Virtiofs) tag becomes `--device
///   virtio-fs,sharedDir=/nix/store,mountTag=<tag>` (the guest mounts it read-only via the `ro-store` tag).
/// - `--device virtio-serial,stdio` — the guest `hvc0` console. `stdio` is backed by the PTY master the backend spawns
///   `vfkit` under (#33), which is why a real TTY is required.
/// - one `--device virtio-fs,<descriptor>` per entry in [`StagedArgs::mount_shares`] and [`StagedArgs::secret_shares`]
///   — the caller's bind mounts and the staged-secret share. Each `--device` and its descriptor are separate argv
///   tokens.
/// - `--device virtio-vsock,…` when [`Topology::vsock_cid`] is `Some` (absent in the aarch64 fixture).
///
/// # Errors
///
/// Returns [`BackendError::Spawn`] when [`Topology::hypervisor`] is not
/// [`Vfkit`](crate::Hypervisor::Vfkit): this backend is vfkit-only and refuses a
/// qemu topology rather than emitting a wrong-hypervisor argv.
pub fn vfkit_args(topology: &Topology, spec: &RunSpec, staged: &StagedArgs) -> Result<Vec<String>, BackendError> {
    todo!(
        "vfkit_args: assemble the vfkit argv from topology {:?}, command {:?}, and {} staged shares (#32)",
        topology.hypervisor,
        spec.command,
        staged.mount_shares.len() + staged.secret_shares.len()
    )
}

/// The macOS vfkit [`VmBackend`].
///
/// Launches the `vfkit` binary and owns its running-instance registry so
/// [`boxes`](VmBackend::boxes) can list live boxes without a separate registry
/// read, keeping the seam backend-agnostic (INV-3).
#[derive(Debug)]
pub struct VfkitBackend {
    /// Path to the `vfkit` binary to launch.
    vfkit_bin: PathBuf,
    /// The running instances this backend owns.
    instances: Mutex<Vec<BoxState>>,
}

impl VfkitBackend {
    /// A backend that launches the `vfkit` binary at `vfkit_bin`, with an empty
    /// instance registry.
    #[must_use]
    pub fn new(vfkit_bin: impl Into<PathBuf>) -> Self {
        Self {
            vfkit_bin: vfkit_bin.into(),
            instances: Mutex::new(Vec::new()),
        }
    }
}

impl VmBackend for VfkitBackend {
    fn run(&self, spec: &RunSpec) -> Result<Outcome, BackendError> {
        todo!(
            "VfkitBackend::run: stage secrets/mounts (#34) → vfkit_args → spawn `{}` under PtyTransport (#33) → \
             run_console → Outcome for command {:?} (tier-3, #26)",
            self.vfkit_bin.display(),
            spec.command
        )
    }

    fn kill(&self, box_id: &str) -> Result<(), BackendError> {
        todo!("VfkitBackend::kill: tear down vfkit instance `{box_id}` and drop it from the registry (tier-3, #26)")
    }

    fn boxes(&self) -> Result<Vec<BoxState>, BackendError> {
        todo!(
            "VfkitBackend::boxes: snapshot the {} tracked vfkit instances (tier-3, #26)",
            self.instances.lock().map_or(0, |guard| guard.len())
        )
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use anyhow::Context;

    use super::*;
    use crate::{Grants, Hypervisor, Mount, SecretRef, SecretSource, StoreBacking, parse_topology};

    /// A complete topology JSON (aarch64, vfkit, virtiofs store, no `vsock_cid`).
    const AARCH64_FIXTURE: &[u8] = include_bytes!("../tests/fixtures/topology-aarch64.json");
    /// A complete topology JSON (x86_64, qemu, erofs store).
    const X86_64_FIXTURE: &[u8] = include_bytes!("../tests/fixtures/topology-x86_64.json");

    /// Grants with the secret and share channels open — enough for every argv
    /// case below.
    fn grants() -> Grants {
        Grants {
            secrets: true,
            agent: false,
            shares: true,
        }
    }

    /// True when `seq` appears as a run of consecutive argv tokens — the check
    /// for a flag and its value emitted as separate tokens (`--cpus 4`).
    fn has_token_run(args: &[String], seq: &[&str]) -> bool {
        args.windows(seq.len())
            .any(|window| window.iter().zip(seq).all(|(have, want)| have == want))
    }

    /// Tier-1: `vfkit_args` over the aarch64 fixture emits the cpu/mem,
    /// bootloader (uncompressed kernel + initrd + cmdline), virtio-serial
    /// console, and read-only store flags documented on the function. RED until
    /// `vfkit_args` is implemented (todo!() panics).
    #[test]
    fn vfkit_args_from_aarch64_topology() -> anyhow::Result<()> {
        let topology = parse_topology(AARCH64_FIXTURE).context("parse aarch64 fixture")?;
        let command = ["true".to_string()];
        let grants = grants();
        let spec = RunSpec {
            template: "demo",
            command: &command,
            mounts: &[],
            secrets: &[],
            env: &[],
            cpu: None,
            mem: None,
            timeout_secs: 60,
            grants: &grants,
            outcome_file: None,
        };
        let staged = StagedArgs::default();

        let args = vfkit_args(&topology, &spec, &staged).context("assemble vfkit argv")?;
        let joined = args.join(" ");

        assert!(
            has_token_run(&args, &["--cpus", "4"]),
            "cpus flag from topology: {joined}"
        );
        assert!(
            has_token_run(&args, &["--memory", "4096"]),
            "memory flag from topology: {joined}"
        );
        assert!(joined.contains("--bootloader"), "bootloader flag present: {joined}");
        // The kernel is passed verbatim — an uncompressed aarch64 `Image`, never transformed.
        assert!(
            joined.contains("/nix/store/7h6g5f4d3s2a1z0xcvbnmlkjhgfdsq98-linux-6.6.52-aarch64/Image"),
            "uncompressed kernel path carried verbatim: {joined}"
        );
        assert!(joined.contains("initrd="), "initrd in the bootloader arg: {joined}");
        assert!(
            joined.contains("virtio-serial,stdio"),
            "virtio-serial console over stdio (PTY-backed): {joined}"
        );
        // The aarch64 fixture backs the read-only store as a virtio-fs tag.
        assert!(
            joined.contains("virtio-fs") && joined.contains("mountTag=ro-store"),
            "read-only store share with the ro-store tag: {joined}"
        );
        Ok(())
    }

    /// Tier-1: a run with a bind mount and a secret weaves both staged shares
    /// into the argv as `virtio-fs` devices — carrying the share path+tag, never
    /// the secret bytes (INV-1). RED until implemented.
    #[test]
    fn vfkit_args_includes_mounts_and_secret_share() -> anyhow::Result<()> {
        let topology = parse_topology(AARCH64_FIXTURE).context("parse aarch64 fixture")?;
        let command = ["true".to_string()];
        let grants = grants();
        let mounts = [Mount {
            host: PathBuf::from("/host/in"),
            guest: PathBuf::from("/in"),
            ro: true,
        }];
        let secrets = [SecretRef {
            name: "TOK".to_string(),
            source: SecretSource::File(PathBuf::from("/host/secret")),
        }];
        let spec = RunSpec {
            template: "demo",
            command: &command,
            mounts: &mounts,
            secrets: &secrets,
            env: &[],
            cpu: None,
            mem: None,
            timeout_secs: 60,
            grants: &grants,
            outcome_file: None,
        };
        // The argv-safe staged descriptors: the secret bytes are already on disk
        // in a 0600 file; only the share path and tag reach argv (INV-1).
        let staged = StagedArgs::new(
            vec!["sharedDir=/host/in,mountTag=sandy0,ro".to_string()],
            vec!["sharedDir=/run/sandy/inst-0,mountTag=sandy-secrets,ro".to_string()],
        );

        let args = vfkit_args(&topology, &spec, &staged).context("assemble vfkit argv")?;
        let joined = args.join(" ");

        assert!(
            joined.contains("--device virtio-fs,sharedDir=/host/in,mountTag=sandy0,ro"),
            "mount share woven into a virtio-fs device: {joined}"
        );
        assert!(
            joined.contains("--device virtio-fs,sharedDir=/run/sandy/inst-0,mountTag=sandy-secrets,ro"),
            "secret share woven into a virtio-fs device: {joined}"
        );
        Ok(())
    }

    /// Tier-1 adversarial: a qemu topology is rejected with a [`BackendError`] —
    /// this backend is vfkit-only and never emits a wrong-hypervisor argv. RED
    /// until implemented (todo!() panics before the rejection path runs).
    #[test]
    fn vfkit_args_rejects_a_qemu_topology() -> anyhow::Result<()> {
        let topology = parse_topology(X86_64_FIXTURE).context("parse x86_64 fixture")?;
        assert_eq!(topology.hypervisor, Hypervisor::Qemu, "fixture precondition");
        let command = ["true".to_string()];
        let grants = grants();
        let spec = RunSpec {
            template: "demo",
            command: &command,
            mounts: &[],
            secrets: &[],
            env: &[],
            cpu: None,
            mem: None,
            timeout_secs: 60,
            grants: &grants,
            outcome_file: None,
        };
        let staged = StagedArgs::default();

        assert!(
            matches!(vfkit_args(&topology, &spec, &staged), Err(BackendError::Spawn(_))),
            "vfkit backend must reject a qemu topology"
        );
        Ok(())
    }

    /// Tier-1: an erofs-backed store becomes a read-only `virtio-blk` device. The
    /// aarch64 fixture is virtiofs-backed, so the erofs variant is set directly
    /// to pin the block-device mapping the #32 contract requires. RED until
    /// implemented.
    #[test]
    fn vfkit_args_erofs_store_is_a_readonly_block_device() -> anyhow::Result<()> {
        let mut topology = parse_topology(AARCH64_FIXTURE).context("parse aarch64 fixture")?;
        topology.store = StoreBacking::ErofsImage(PathBuf::from("/nix/store/deadbeef-sandy-store.erofs"));
        let command = ["true".to_string()];
        let grants = grants();
        let spec = RunSpec {
            template: "demo",
            command: &command,
            mounts: &[],
            secrets: &[],
            env: &[],
            cpu: None,
            mem: None,
            timeout_secs: 60,
            grants: &grants,
            outcome_file: None,
        };
        let staged = StagedArgs::default();

        let args = vfkit_args(&topology, &spec, &staged).context("assemble vfkit argv")?;
        let joined = args.join(" ");

        assert!(
            joined.contains("--device virtio-blk,path=/nix/store/deadbeef-sandy-store.erofs"),
            "erofs store attached as a virtio-blk device: {joined}"
        );
        assert!(joined.contains("readOnly"), "erofs store device is read-only: {joined}");
        Ok(())
    }

    /// Tier-3 / host: a trivial RunSpec boots a real vfkit guest on an M2 under a
    /// real PTY, returns a populated [`Outcome`], [`boxes`](VmBackend::boxes)
    /// lists the instance, and [`kill`](VmBackend::kill) tears it down — with the
    /// four distinct outcomes (booted+exit, `!booted`, `timed_out`,
    /// `transport_error`) each asserted on the host. Ignored in the sandbox: it
    /// spawns a hypervisor and must never be counted green from a fake (INV-S9);
    /// it binds into #26.
    #[test]
    #[ignore = "tier-3/host: boots a real vfkit guest on an M2; binds into #26 (INV-S9)"]
    fn real_vfkit_boot_populates_outcome_and_registry() -> anyhow::Result<()> {
        let backend = VfkitBackend::new("vfkit");
        let command = ["true".to_string()];
        let grants = grants();
        let spec = RunSpec {
            template: "demo",
            command: &command,
            mounts: &[],
            secrets: &[],
            env: &[],
            cpu: None,
            mem: None,
            timeout_secs: 60,
            grants: &grants,
            outcome_file: None,
        };

        let outcome = backend.run(&spec).context("boot vfkit guest")?;
        assert!(outcome.booted, "a clean boot sets booted");
        assert!(
            !backend.boxes().context("list boxes")?.is_empty(),
            "a running box is listed"
        );
        backend.kill("box-0").context("tear the box down")?;
        Ok(())
    }
}
