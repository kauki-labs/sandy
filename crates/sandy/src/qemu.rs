//! The native qemu/KVM backend (Block 35): assemble the hypervisor argv from a
//! [`Topology`] and run it with its serial console on pipes (#33).
//!
//! This is the Linux/CI counterpart to the vfkit backend (#32). It is split so
//! the argv assembly stays pure and tier-1 testable:
//!
//! - [`qemu_args`] — the pure assembler. Given a [`Topology`], a [`RunSpec`], and the already-[`StagedArgs`] (secret
//!   share + [`mount_args`](crate::stage::mount_args) output), it builds the `qemu-system-<arch>` command vector with
//!   no IO. Proven on ws01 (x86_64, `/dev/kvm` world-rw): the microvm.nix runner booted → result → poweroff in ~8s with
//!   `-nographic -serial chardev:stdio console=ttyS0` and sentinels on stdout.
//! - [`QemuBackend`] — the [`VmBackend`] seam. `run` stages secrets/mounts (#34), calls [`qemu_args`], spawns qemu with
//!   serial on the #33 [`PipeTransport`](crate::console::PipeTransport), drives
//!   [`run_console`](crate::console::run_console), and populates the pinned [`Outcome`]. The spawn/boot is host-tier
//!   (tier-3, ws01), not unit-tested in the sandbox.
//!
//! The module is private (INV-FACADE); `lib.rs` re-exports only
//! [`QemuBackend`], [`qemu_args`], and [`StagedArgs`].

use std::sync::Mutex;

use crate::{
    backend::{BackendError, BoxState, Outcome, RunSpec, VmBackend},
    nix::Topology,
};

/// The already-staged inputs [`qemu_args`] needs, kept out of the pure assembler
/// so argv assembly does no IO and stays tier-1 testable.
///
/// `run` produces this from [`stage_secrets`](crate::stage::stage_secrets) and
/// [`mount_args`](crate::stage::mount_args) before calling [`qemu_args`]:
/// `mounts` is the `mount_args` output (one `sharedDir=…,mountTag=…[,ro]` string
/// per [`RunSpec`] mount), `secret_share` is the read-only share for the staged
/// secrets directory, and `kvm` records whether `/dev/kvm` was usable (probed by
/// `run`, so the assembler itself touches no host state).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct StagedArgs {
    /// The virtiofs/9p share spec for each [`RunSpec`] mount, as produced by
    /// [`mount_args`](crate::stage::mount_args).
    pub mounts: Vec<String>,
    /// The read-only share spec for the staged-secrets directory, when the run
    /// carries secrets.
    pub secret_share: Option<String>,
    /// Whether `/dev/kvm` is usable → emit `-enable-kvm -cpu host`.
    pub kvm: bool,
}

/// Assemble the `qemu-system-<arch>` command vector for `topology` + `spec`.
///
/// This is the pure seam: no process is spawned and no host state is read (that
/// is why `kvm` and the shares arrive pre-resolved in `staged`), so it is the
/// tier-1 unit target. The emitted argv, with `argv[0]` the `qemu-system-<arch>`
/// binary derived from the guest/host architecture:
///
/// - `-kernel <topology.kernel>` / `-initrd <topology.initrd>` — the direct boot pair.
/// - `-append <topology.kernel_cmdline>` — the full guest command line (`console=ttyS0 …`).
/// - the store ([`StoreBacking::ErofsImage`](crate::nix::StoreBacking::ErofsImage)) as a read-only virtio-blk drive,
///   e.g. `-drive file=<image>,if=virtio,format=raw,readonly=on`.
/// - `-smp <topology.cpu>` / `-m <topology.mem>` — vCPUs and memory in MiB (a [`RunSpec`] `cpu`/`mem` may narrow them).
/// - `-nographic` and `-serial chardev:<id>` — the guest serial console; `run` adds the matching `-chardev pipe,…` that
///   binds `<id>` to the #33 pipe (the fifo path is a host-tier detail, so it is not emitted here).
/// - `-enable-kvm -cpu host` when `staged.kvm`.
/// - the virtiofs/virtio-9p shares from `staged.mounts` and `staged.secret_share`.
/// - `-device vhost-vsock-pci,guest-cid=<cid>` when `topology.vsock_cid` is set.
///
/// # Errors
///
/// Returns a [`BackendError`] when `topology.hypervisor` is not
/// [`Hypervisor::Qemu`](crate::nix::Hypervisor::Qemu) — this backend is
/// qemu-only and refuses to emit argv for a vfkit topology rather than producing
/// a wrong-hypervisor command — or when the store backing cannot be expressed as
/// a qemu drive.
pub fn qemu_args(topology: &Topology, spec: &RunSpec, staged: &StagedArgs) -> Result<Vec<String>, BackendError> {
    let _ = (topology, spec, staged);
    todo!("assemble the qemu-system-<arch> argv from the topology, spec, and staged shares (#35)")
}

/// The native qemu/KVM [`VmBackend`] (Linux).
///
/// Owns its running-instance registry so [`boxes`](VmBackend::boxes) reports live
/// state without a direct supervisor read (INV-3), mirroring the seam contract in
/// [`crate::backend`]. Construct with [`QemuBackend::new`].
#[derive(Debug, Default)]
pub struct QemuBackend {
    /// The boxes this backend has launched and not yet reaped. Read by
    /// `boxes`/`kill` once the host-tier spawn (#26) lands; unused in the
    /// skeleton.
    #[allow(
        dead_code,
        reason = "running-instance registry is read by boxes()/kill() once #26 wires the spawn"
    )]
    instances: Mutex<Vec<BoxState>>,
}

impl QemuBackend {
    /// A backend with an empty instance registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl VmBackend for QemuBackend {
    fn run(&self, spec: &RunSpec) -> Result<Outcome, BackendError> {
        let _ = spec;
        todo!("stage secrets/mounts (#34) → qemu_args → spawn qemu with serial on the #33 pipe → run_console → Outcome")
    }

    fn kill(&self, box_id: &str) -> Result<(), BackendError> {
        let _ = box_id;
        todo!("terminate the qemu process for box_id and drop it from the registry (#35)")
    }

    fn boxes(&self) -> Result<Vec<BoxState>, BackendError> {
        todo!("report the live qemu instances from the registry (#35)")
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use anyhow::Context;

    use super::*;
    use crate::{
        backend::{Grants, Mount},
        nix::{Hypervisor, parse_topology},
        stage::{TagPool, mount_args},
    };

    /// A complete microvm.nix topology JSON (x86_64, qemu, erofs store).
    const X86_64_FIXTURE: &[u8] = include_bytes!("../tests/fixtures/topology-x86_64.json");
    /// A complete topology JSON (aarch64, vfkit) — the wrong hypervisor for this backend.
    const AARCH64_FIXTURE: &[u8] = include_bytes!("../tests/fixtures/topology-aarch64.json");

    /// No trust tokens — the trivial grant for an argv-shape test.
    const NO_GRANTS: Grants = Grants {
        secrets: false,
        agent: false,
        shares: false,
    };

    /// Tier-1: `qemu_args` over the x86_64 fixture and a trivial spec emits the
    /// key boot flags (`-kernel`/`-initrd`/`-append`/`-nographic`/`-serial`/
    /// `-smp`/`-m`), the topology's cpu/mem, and the erofs store as a read-only
    /// virtio-blk drive. RED until `qemu_args` is implemented (todo!() panics).
    #[test]
    fn qemu_args_from_x86_64_topology() -> anyhow::Result<()> {
        let topology = parse_topology(X86_64_FIXTURE).context("parse x86_64 fixture")?;
        let command = ["true".to_string()];
        let spec = RunSpec {
            template: "demo",
            command: &command,
            mounts: &[],
            secrets: &[],
            env: &[],
            cpu: None,
            mem: None,
            timeout_secs: 60,
            grants: &NO_GRANTS,
            outcome_file: None,
        };
        let staged = StagedArgs::default();

        let args = qemu_args(&topology, &spec, &staged).context("assemble qemu argv")?;

        assert!(
            args.first().is_some_and(|binary| binary.starts_with("qemu-system")),
            "argv[0] is the qemu-system-<arch> binary: {:?}",
            args.first()
        );
        for flag in ["-kernel", "-initrd", "-append", "-nographic", "-serial", "-smp", "-m"] {
            assert!(args.iter().any(|arg| arg == flag), "missing {flag} in {args:?}");
        }
        let joined = args.join(" ");
        assert!(joined.contains("bzImage"), "kernel path present: {joined}");
        assert!(joined.contains("initrd"), "initrd path present: {joined}");
        assert!(joined.contains("console=ttyS0"), "kernel cmdline appended: {joined}");
        assert!(
            args.iter().any(|arg| arg == "2"),
            "smp vCPU count (topology.cpu=2): {args:?}"
        );
        assert!(
            args.iter().any(|arg| arg == "2048"),
            "memory in MiB (topology.mem=2048): {args:?}"
        );
        assert!(
            joined.contains("sandy-store.erofs"),
            "erofs store path present: {joined}"
        );
        assert!(joined.contains("readonly"), "erofs store drive is read-only: {joined}");
        Ok(())
    }

    /// Tier-1: with `/dev/kvm` usable and a mount, `qemu_args` emits
    /// `-enable-kvm -cpu host` and threads the mount share and the secret share
    /// into the argv. RED until implemented.
    #[test]
    fn qemu_args_enables_kvm_and_mounts() -> anyhow::Result<()> {
        let topology = parse_topology(X86_64_FIXTURE).context("parse x86_64 fixture")?;
        let tmp = tempfile::TempDir::new()?;
        let rw_host = tmp.path().join("rw");
        std::fs::create_dir_all(&rw_host).context("create mount host dir")?;
        let mounts = [Mount {
            host: rw_host.clone(),
            guest: PathBuf::from("/out"),
            ro: false,
        }];
        let mut tags = TagPool::new();
        let mount_shares = mount_args(&mounts, &mut tags).context("assemble mount shares")?;
        let secret_tag = tags.next_tag();
        let staged = StagedArgs {
            mounts: mount_shares,
            secret_share: Some(format!(
                "sharedDir={}/inst,mountTag={secret_tag},ro",
                tmp.path().display()
            )),
            kvm: true,
        };
        let command = ["true".to_string()];
        let grants = Grants {
            secrets: true,
            agent: false,
            shares: true,
        };
        let spec = RunSpec {
            template: "demo",
            command: &command,
            mounts: &mounts,
            secrets: &[],
            env: &[],
            cpu: None,
            mem: None,
            timeout_secs: 60,
            grants: &grants,
            outcome_file: None,
        };

        let args = qemu_args(&topology, &spec, &staged).context("assemble qemu argv")?;

        let joined = args.join(" ");
        assert!(
            args.iter().any(|arg| arg == "-enable-kvm"),
            "KVM acceleration flag: {args:?}"
        );
        assert!(args.iter().any(|arg| arg == "-cpu"), "-cpu flag present: {args:?}");
        assert!(joined.contains("host"), "-cpu host passthrough: {joined}");
        assert!(
            joined.contains(&rw_host.display().to_string()),
            "mount host path shared into the guest: {joined}"
        );
        assert!(
            joined.contains(&secret_tag),
            "secret share threaded into argv: {joined}"
        );
        Ok(())
    }

    /// Tier-1 adversarial: a vfkit topology is rejected (this backend is
    /// qemu-only) rather than assembling a wrong-hypervisor argv. RED until
    /// implemented.
    #[test]
    fn qemu_args_rejects_a_vfkit_topology() -> anyhow::Result<()> {
        let topology = parse_topology(AARCH64_FIXTURE).context("parse aarch64 (vfkit) fixture")?;
        assert_eq!(topology.hypervisor, Hypervisor::Vfkit, "fixture is the vfkit topology");
        let command = ["true".to_string()];
        let spec = RunSpec {
            template: "demo",
            command: &command,
            mounts: &[],
            secrets: &[],
            env: &[],
            cpu: None,
            mem: None,
            timeout_secs: 60,
            grants: &NO_GRANTS,
            outcome_file: None,
        };
        let staged = StagedArgs::default();

        let result = qemu_args(&topology, &spec, &staged);

        assert!(
            result.is_err(),
            "a vfkit topology must be rejected by the qemu-only backend, got {result:?}"
        );
        Ok(())
    }

    /// Tier-3 (host-gated, ws01): a trivial job boots on a real Linux/KVM node
    /// over the #33 pipe transport, returns a populated [`Outcome`], and
    /// `boxes`/`kill` work across the four distinct outcomes. Never run in the
    /// sandbox (INV-S9: no green from a fake); binds into #26/#27.
    #[test]
    #[ignore = "tier-3: real qemu/KVM boot on a Linux node (ws01) over the pipe transport; host-gated, binds into \
                #26/#27"]
    fn boots_a_trivial_job_on_kvm() -> anyhow::Result<()> {
        let backend = QemuBackend::new();
        let command = ["true".to_string()];
        let spec = RunSpec {
            template: "demo",
            command: &command,
            mounts: &[],
            secrets: &[],
            env: &[],
            cpu: None,
            mem: None,
            timeout_secs: 60,
            grants: &NO_GRANTS,
            outcome_file: None,
        };

        let outcome = backend.run(&spec).context("boot the trivial job on KVM")?;
        assert!(outcome.booted, "guest must boot");
        assert_eq!(outcome.guest_exit, Some(0), "`true` exits 0");
        assert!(!outcome.timed_out, "a trivial job must not time out");

        let boxes = backend.boxes().context("list running boxes")?;
        if let Some(state) = boxes.first() {
            backend.kill(&state.box_id).context("tear the box down")?;
        }
        Ok(())
    }
}
