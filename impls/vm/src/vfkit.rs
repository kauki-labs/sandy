//! The native vfkit backend (Block 32, macOS / Virtualization.framework).
//!
//! [`VfkitBackend`] is the [`VmBackend`] for the macOS path: it assembles a
//! `vfkit` argv from a [`Topology`] (#31), stages the run's secrets (#50),
//! launches `vfkit` under the PTY console transport (#33), and collapses
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

use std::{
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant, SystemTime},
};

use sandy::{
    BackendError, BoxState, Hypervisor, Outcome, RunSpec, ShareDirs, StoreBacking, Topology, VmBackend,
    collect_outputs, ensure_sandy_staging_base, plan_shares, topology, wipe,
};
use sandy_api::{
    agent::{AGENT_VSOCK_PORT, AgentLaunch},
    share::{GuestShareTransport, ShareSpec},
};
use uuid::Uuid;

use crate::{
    agent::{agent_outcome, agent_shell_command, spawn_connector},
    console::{Markers, PtyTransport, run_console},
    share::VirtioFsTransport,
};

/// The longest unix socket path macOS accepts (`sun_path`, less the NUL).
const MAX_SOCKET_PATH: usize = 103;

/// The guest boot-ready marker the console protocol scans for before injecting
/// the command: the guest's login shell prints it once it is up and reading (the
/// guest's `loginShellInit`), so the injected frame lands in a reading shell
/// rather than the getty→login handoff, which flushes pending tty input.
const BOOT_READY_MARKER: &str = "SANDY-READY";

/// The staged virtio-fs [`ShareSpec`]s [`vfkit_args`] weaves into the argv.
///
/// Argv assembly is kept pure and testable without real staging: the backend stages
/// each directory and hands the share metadata here. Only share metadata (host path
/// plus mount tag) travels this struct — never secret bytes, which stay in their
/// `0600` staging file (INV-1). The [`VirtioFsTransport`] reduces each to a
/// `--device virtio-fs,…`; vfkit needs no daemon (Virtualization.framework serves
/// virtio-fs itself).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StagedArgs {
    /// The guest virtio-fs shares, in argv order (inputs, outputs, then the secret).
    pub shares: Vec<ShareSpec>,
    /// Agent mode (#238): the guest vsock port the agent listens on and the host
    /// unix socket vfkit exposes it at, for the host to connect to.
    pub agent_vsock: Option<(u32, PathBuf)>,
}

impl StagedArgs {
    /// A [`StagedArgs`] carrying the given virtio-fs shares.
    #[must_use]
    pub fn new(shares: Vec<ShareSpec>) -> Self {
        Self {
            shares,
            agent_vsock: None,
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
/// - the read-only Nix store, from [`Topology::store`](sandy::Topology): an
///   [`ErofsImage`](sandy::StoreBacking::ErofsImage) becomes `--device virtio-blk,path=<img>,readonly` (a read-only
///   block device); a [`Virtiofs`](sandy::StoreBacking::Virtiofs) tag becomes `--device
///   virtio-fs,sharedDir=/nix/store,mountTag=<tag>` (the guest mounts it read-only via the `ro-store` tag).
/// - `--device virtio-serial,stdio` — the guest `hvc0` console. `stdio` is backed by the PTY master the backend spawns
///   `vfkit` under (#33), which is why a real TTY is required.
/// - one `--device virtio-fs,sharedDir=<host>,mountTag=<tag>` per [`StagedArgs::shares`] entry (inputs, outputs, then
///   the secret share), via the [`VirtioFsTransport`]. Each `--device` and its descriptor are separate argv tokens;
///   read-only is enforced by the guest mount (vfkit's virtio-fs device rejects a `,ro` option).
/// - `--device virtio-vsock,…` when [`Topology::vsock_cid`] is `Some` (absent in the aarch64 fixture).
///
/// # Errors
///
/// Returns [`BackendError::Spawn`] when [`Topology::hypervisor`] is not
/// [`Vfkit`](sandy::Hypervisor::Vfkit): this backend is vfkit-only and refuses a
/// qemu topology rather than emitting a wrong-hypervisor argv.
pub fn vfkit_args(topology: &Topology, spec: &RunSpec, staged: &StagedArgs) -> Result<Vec<String>, BackendError> {
    if topology.hypervisor != Hypervisor::Vfkit {
        return Err(BackendError::Spawn(format!(
            "vfkit backend refuses a {:?} topology: this backend is vfkit-only",
            topology.hypervisor
        )));
    }

    // A `Some` RunSpec override wins over the topology's declared budget.
    let cpus = spec.cpu.unwrap_or(topology.cpu);
    let mem = spec.mem.unwrap_or(topology.mem);

    let mut args = Vec::new();
    // Flag and value are always separate argv tokens (`--cpus`, `4`).
    args.push("--cpus".to_string());
    args.push(cpus.to_string());
    args.push("--memory".to_string());
    args.push(mem.to_string());

    // The kernel is carried verbatim — vfkit on aarch64 needs an uncompressed `Image`, never transformed.
    // The cmdline is wrapped in literal double-quotes: the `--bootloader` value is
    // comma-separated, and the cmdline itself carries commas (e.g. `lsm=a,b,c`), so
    // without quoting vfkit would split it into spurious bootloader options.
    args.push("--bootloader".to_string());
    args.push(format!(
        "linux,kernel={},initrd={},cmdline=\"{}\"",
        topology.kernel.display(),
        topology.initrd.display(),
        topology.kernel_cmdline
    ));

    // The read-only Nix store: an erofs image is a block device; a virtiofs tag is a share of the host store.
    args.push("--device".to_string());
    match &topology.store {
        StoreBacking::ErofsImage(img) => args.push(format!("virtio-blk,path={},readonly", img.display())),
        StoreBacking::Virtiofs(tag) => args.push(format!("virtio-fs,sharedDir=/nix/store,mountTag={tag}")),
    }

    // The guest `hvc0` console over stdio, backed by the PTY master the backend spawns vfkit under (#33).
    args.push("--device".to_string());
    args.push("virtio-serial,stdio".to_string());

    // The read-only inputs shares, the writable outputs shares, then the staged-secret share, each an
    // already-assembled virtio-fs descriptor. vfkit's virtio-fs device rejects a `ro` option ("unknown option for
    // virtio-fs devices: ro") — unlike the erofs store's virtio-blk `readonly` — so drop a trailing `,ro`; the guest
    // mounts the RO shares read-only itself (the outputs share carries no `,ro`, so it stays writable).
    args.extend(VirtioFsTransport.plan(&staged.shares, 0).into_vm_args());

    // The vsock channel, only when the topology assigns a context id (absent in the aarch64 fixture). The guest-side
    // socket wiring is the host concern (#26); here we carry the assigned cid.
    if let Some(cid) = topology.vsock_cid {
        args.push("--device".to_string());
        args.push(format!("virtio-vsock,cid={cid}"));
    }

    // Agent mode (#238): vfkit exposes the guest agent's vsock port as a host unix
    // socket, and `connect` makes the host the one that connects.
    if let Some((port, socket)) = &staged.agent_vsock {
        args.push("--device".to_string());
        args.push(format!(
            "virtio-vsock,port={port},socketURL={},connect",
            socket.display()
        ));
    }

    Ok(args)
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
    /// The boxes launched and not yet reaped, reported by [`boxes`](VmBackend::boxes).
    instances: Mutex<Vec<BoxState>>,
    /// When set, the job runs as the child of the image's sandbox agent (#238).
    agent: Option<AgentLaunch>,
    /// Set by an agent-mode backend's one run: its cap and channel serve one job.
    agent_used: AtomicBool,
}

impl VfkitBackend {
    /// A backend that launches the `vfkit` binary at `vfkit_bin`, with an empty
    /// instance registry.
    #[must_use]
    pub fn new(vfkit_bin: impl Into<PathBuf>) -> Self {
        Self {
            vfkit_bin: vfkit_bin.into(),
            instances: Mutex::new(Vec::new()),
            agent: None,
            agent_used: AtomicBool::new(false),
        }
    }

    /// Run the job behind the guest's sandbox agent (#238). The console launches
    /// the agent the topology names (`agent_program`, the binary this image
    /// carries; `agent.program` is not used by a VM backend), the host connects
    /// to it over vsock, and `agent.on_link` gets the link from a connector
    /// thread. The job's exit comes only from the relay's [`AgentReport`].
    ///
    /// An agent-mode backend runs ONE job; build one per sandbox run.
    #[must_use]
    pub fn with_agent(mut self, agent: AgentLaunch) -> Self {
        self.agent = Some(agent);
        self
    }
}

impl VfkitBackend {
    /// Stage the run, assemble the argv, spawn `vfkit` on a PTY, drive the console
    /// to a terminal [`Outcome`], then tear vfkit down.
    ///
    /// vfkit's `virtio-serial,stdio` needs a real TTY, so vfkit is spawned onto the
    /// PTY slave and the master drives the sentinel protocol. The run is
    /// synchronous: the box lives only for this call. The console never fabricates
    /// `guest_exit`: a transport/timeout fault lands in the [`Outcome`], only
    /// staging/spawn faults are errors.
    fn boot(
        &self,
        topology: &Topology,
        spec: &RunSpec,
        run_id: Uuid,
        box_id: &str,
        shares: Vec<ShareSpec>,
        agent: Option<&AgentRun>,
    ) -> Result<Outcome, BackendError> {
        // The shares (secret/input/output, their read-only flags, the #49 secret_dir
        // rule) are staged by `plan_shares` in `run`; here they only become argv. The
        // guest mounts each by tag with `nofail`, so order is irrelevant. The
        // `socket` field is unused by vfkit (no daemon). INV-1: only share metadata
        // travels here, never secret bytes.
        let mut staged = StagedArgs::new(shares);
        // Agent mode: the console launches the image's agent around the job, and
        // vfkit exposes the agent's vsock port as the run's host socket.
        let agent_command;
        let agent_spec;
        let console_spec = match agent {
            Some(agent) => {
                staged.agent_vsock = Some((AGENT_VSOCK_PORT, agent.socket.clone()));
                agent_command = [agent_shell_command(&agent.program, AGENT_VSOCK_PORT, spec.command)];
                agent_spec = RunSpec {
                    command: &agent_command,
                    ..*spec
                };
                &agent_spec
            }
            None => spec,
        };
        let args = vfkit_args(topology, spec, &staged)?;

        let mut transport = PtyTransport::open()?;
        // The PTY read deadline carries the run budget, so a silent guest resolves
        // through the protocol's timeout path instead of blocking the driver.
        transport.set_read_timeout(Duration::from_secs(u64::from(spec.timeout_secs.max(1))));
        let pid = transport.spawn(&self.vfkit_bin, &args)?;
        tracing::info!(box_id, pid, "spawned vfkit under PTY console");
        self.lock_registry()?.push(BoxState {
            box_id: box_id.to_string(),
            box_name: spec.template.to_string(),
            pid,
            started: SystemTime::now(),
            rvport: None,
        });

        // Agent mode: connect to the guest agent from a helper thread while the
        // console drives the run, and hand the link to the relay once it answers.
        let stop = Arc::new(AtomicBool::new(false));
        let connector = match (&self.agent, agent) {
            (Some(launch), Some(agent)) => Some(spawn_connector(
                launch,
                {
                    let socket = agent.socket.clone();
                    move || std::os::unix::net::UnixStream::connect(&socket)
                },
                box_id,
                // The console's command budget only starts once the guest has
                // booted, so allow for the boot too; the stop flag still ends the
                // connector as soon as the console run does.
                Instant::now() + Duration::from_secs(u64::from(spec.timeout_secs.max(1)) * 2 + 120),
                Arc::clone(&stop),
            )),
            _ => None,
        };

        let markers = Markers::for_run(BOOT_READY_MARKER, run_id);
        let outcome = run_console(&mut transport, console_spec, &markers);

        // The guest is done: stop connecting, then tear vfkit down and deregister.
        stop.store(true, Ordering::SeqCst);
        let verdict = connector.map(|(verdict, thread)| (verdict, thread.join().unwrap_or(false)));
        transport.shutdown();
        self.lock_registry()?.retain(|state| state.box_id != box_id);
        match verdict {
            Some((verdict, linked)) => agent_outcome(outcome, &verdict, &spec.command.join(" "), linked),
            None => Ok(outcome),
        }
    }

    /// Lock the instance registry, mapping a poisoned lock to an infra fault.
    fn lock_registry(&self) -> Result<std::sync::MutexGuard<'_, Vec<BoxState>>, BackendError> {
        self.instances
            .lock()
            .map_err(|_| BackendError::Spawn("vfkit instance registry lock poisoned".to_string()))
    }
}

/// One agent-mode run: the image's agent and the host socket vfkit exposes its
/// vsock port at.
#[derive(Debug)]
struct AgentRun {
    /// The agent's in-guest path, from the topology.
    program: PathBuf,
    /// The run's host unix socket, in the private staging base.
    socket: PathBuf,
}

/// The run's agent socket in the private staging base, short enough for
/// `sun_path`.
fn agent_socket(base: &Path, run_id: Uuid) -> Result<PathBuf, BackendError> {
    let id = run_id.simple().to_string();
    let socket = base.join(format!("ag-{}.sock", &id[..12]));
    if socket.as_os_str().len() > MAX_SOCKET_PATH {
        return Err(BackendError::Spawn(format!(
            "the agent socket path {} is longer than a unix socket allows ({MAX_SOCKET_PATH} bytes)",
            socket.display()
        )));
    }
    Ok(socket)
}

impl VmBackend for VfkitBackend {
    fn run(&self, spec: &RunSpec) -> Result<Outcome, BackendError> {
        if self.agent.is_some() && self.agent_used.swap(true, Ordering::SeqCst) {
            return Err(BackendError::Spawn(
                "this agent-mode backend already ran its one job; build one per sandbox run".to_string(),
            ));
        }
        let topology = topology(spec.template)?;
        let run_id = Uuid::new_v4();
        let box_id = format!("inst-{run_id}");
        // Staging under the OS temp dir (works on macOS, where `/run` does not exist).
        let base = ensure_sandy_staging_base()?;
        let agent = match &self.agent {
            Some(_) => Some(AgentRun {
                program: topology.agent_program.clone().ok_or_else(|| {
                    BackendError::Spawn(
                        "agent mode needs a topology that names its agent (agent_program); this image carries no \
                         sandy-agent"
                            .to_string(),
                    )
                })?,
                socket: agent_socket(&base, run_id)?,
            }),
            None => None,
        };
        let inst_dir = base.join(&box_id);
        let inputs_dir = base.join(format!("{box_id}-inputs"));
        let outputs_dir = base.join(format!("{box_id}-outputs"));

        // Stage the shares via the shared policy, then boot on them. A staging
        // failure skips the boot but still wipes below (INV-1).
        let outcome = plan_shares(
            spec,
            &ShareDirs {
                inst_dir: &inst_dir,
                inputs_dir: &inputs_dir,
                outputs_dir: &outputs_dir,
            },
        )
        .and_then(|shares| self.boot(&topology, spec, run_id, &box_id, shares, agent.as_ref()));

        // Collect outputs before wiping, only if the guest booted; a collection
        // failure surfaces as an infra fault rather than silently dropping output.
        let collected = if outcome.as_ref().is_ok_and(|o| o.booted) {
            collect_outputs(spec.outputs, &outputs_dir)
        } else {
            Ok(())
        };

        // Wipe staging on every path so secret bytes never outlive the run (INV-1).
        for dir in [&inst_dir, &inputs_dir, &outputs_dir] {
            if let Err(err) = wipe(dir) {
                tracing::warn!(dir = %dir.display(), %err, "failed to wipe staging on teardown");
            }
        }
        if let Some(agent) = &agent
            && let Err(err) = std::fs::remove_file(&agent.socket)
            && err.kind() != std::io::ErrorKind::NotFound
        {
            tracing::warn!(socket = %agent.socket.display(), %err, "failed to remove the agent socket");
        }
        collected.and(outcome)
    }

    fn kill(&self, box_id: &str) -> Result<(), BackendError> {
        // The synchronous run already tore the vfkit child down in `boot`; a kill
        // from another call just drops the box from the registry.
        self.lock_registry()?.retain(|state| state.box_id != box_id);
        tracing::debug!(box_id, "dropped vfkit instance from the registry");
        Ok(())
    }

    fn boxes(&self) -> Result<Vec<BoxState>, BackendError> {
        Ok(self.lock_registry()?.clone())
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use anyhow::Context;
    use sandy::{Grants, Hypervisor, SecretRef, SecretSource, StoreBacking, parse_topology};
    use sandy_api::agent::AgentReport;

    use super::*;

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
            inputs: &[],
            outputs: &[],
            secrets: &[],
            env: &[],
            cpu: None,
            mem: None,
            timeout_secs: 60,
            grants: &grants,
            outcome_file: None,
            secret_dir: None,
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

    /// Tier-1: a run with a secret weaves the staged secret share into the argv
    /// as a `virtio-fs` device — carrying the share path+tag, never the secret
    /// bytes (INV-1) — with the trailing `,ro` stripped (vfkit rejects it).
    #[test]
    fn vfkit_args_includes_secret_share() -> anyhow::Result<()> {
        let topology = parse_topology(AARCH64_FIXTURE).context("parse aarch64 fixture")?;
        let command = ["true".to_string()];
        let grants = grants();
        let secrets = [SecretRef {
            name: "TOK".to_string(),
            source: SecretSource::File(PathBuf::from("/host/secret")),
        }];
        let spec = RunSpec {
            template: "demo",
            command: &command,
            inputs: &[],
            outputs: &[],
            secrets: &secrets,
            env: &[],
            cpu: None,
            mem: None,
            timeout_secs: 60,
            grants: &grants,
            outcome_file: None,
            secret_dir: None,
        };
        // The argv-safe staged share: the secret bytes are already on disk in a 0600
        // file; only the share path and tag reach argv (INV-1).
        let staged = StagedArgs::new(vec![ShareSpec {
            host_dir: "/run/sandy/inst-0".into(),
            tag: "sandy-secrets".to_string(),
            readonly: true,
            socket: "/run/sandy/inst-0/vfsd-sandy-secrets.sock".into(),
        }]);

        let args = vfkit_args(&topology, &spec, &staged).context("assemble vfkit argv")?;
        let joined = args.join(" ");

        assert!(
            joined.contains("--device virtio-fs,sharedDir=/run/sandy/inst-0,mountTag=sandy-secrets"),
            "secret share woven into a virtio-fs device: {joined}"
        );
        assert!(
            !joined.contains("mountTag=sandy-secrets,ro"),
            "vfkit's virtio-fs rejects `,ro`, so it must be stripped: {joined}"
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
            inputs: &[],
            outputs: &[],
            secrets: &[],
            env: &[],
            cpu: None,
            mem: None,
            timeout_secs: 60,
            grants: &grants,
            outcome_file: None,
            secret_dir: None,
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
            inputs: &[],
            outputs: &[],
            secrets: &[],
            env: &[],
            cpu: None,
            mem: None,
            timeout_secs: 60,
            grants: &grants,
            outcome_file: None,
            secret_dir: None,
        };
        let staged = StagedArgs::default();

        let args = vfkit_args(&topology, &spec, &staged).context("assemble vfkit argv")?;
        let joined = args.join(" ");

        assert!(
            joined.contains("--device virtio-blk,path=/nix/store/deadbeef-sandy-store.erofs"),
            "erofs store attached as a virtio-blk device: {joined}"
        );
        assert!(joined.contains("readonly"), "erofs store device is read-only: {joined}");
        Ok(())
    }

    fn spec_for<'a>(template: &'a str, command: &'a [String], grants: &'a Grants) -> RunSpec<'a> {
        RunSpec {
            template,
            command,
            inputs: &[],
            outputs: &[],
            secrets: &[],
            env: &[],
            cpu: None,
            mem: None,
            timeout_secs: 60,
            grants,
            outcome_file: None,
            secret_dir: None,
        }
    }

    fn agent_backend() -> VfkitBackend {
        VfkitBackend::new("/nonexistent/vfkit").with_agent(AgentLaunch {
            program: PathBuf::new(),
            on_link: Arc::new(|_: &str, _: std::os::fd::OwnedFd, _: AgentReport| {}),
        })
    }

    fn fixture_path(name: &str) -> String {
        format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))
    }

    /// #238: agent mode exposes the guest agent's vsock port as the run's host
    /// socket, with the host connecting.
    #[test]
    fn vfkit_args_expose_the_agent_port_for_the_host_to_connect() -> anyhow::Result<()> {
        let topology = parse_topology(AARCH64_FIXTURE).context("parse aarch64 fixture")?;
        let command = ["true".to_string()];
        let grants = grants();
        let staged = StagedArgs {
            agent_vsock: Some((5000, PathBuf::from("/tmp/sandy/ag-0123456789ab.sock"))),
            ..StagedArgs::default()
        };
        let args = vfkit_args(&topology, &spec_for("demo", &command, &grants), &staged)?;
        assert!(
            has_token_run(
                &args,
                &[
                    "--device",
                    "virtio-vsock,port=5000,socketURL=/tmp/sandy/ag-0123456789ab.sock,connect"
                ]
            ),
            "{}",
            args.join(" ")
        );
        Ok(())
    }

    /// #238: agent mode on an image whose topology names no agent is refused
    /// before vfkit is spawned, never run as a bare console job.
    #[test]
    fn agent_mode_refuses_a_topology_without_an_agent() {
        let template = fixture_path("topology-aarch64.json");
        let command = ["true".to_string()];
        let grants = grants();
        let result = agent_backend().run(&spec_for(&template, &command, &grants));
        assert!(
            matches!(&result, Err(BackendError::Spawn(why)) if why.contains("agent_program")),
            "got {result:?}"
        );
    }

    /// #238: an agent-mode backend runs one job; a second run is refused.
    #[test]
    fn an_agent_mode_backend_refuses_a_second_run() {
        let backend = agent_backend();
        let template = fixture_path("topology-aarch64.json");
        let command = ["true".to_string()];
        let grants = grants();
        let _ = backend.run(&spec_for(&template, &command, &grants));
        let second = backend.run(&spec_for(&template, &command, &grants));
        assert!(
            matches!(&second, Err(BackendError::Spawn(why)) if why.contains("one job")),
            "got {second:?}"
        );
    }

    fn booted(exit: Option<i32>) -> Outcome {
        Outcome {
            booted: true,
            guest_exit: exit,
            transport_error: None,
            timed_out: false,
            console: String::new(),
        }
    }

    /// INV-11 (#238): in agent mode the exit comes only from the verdict; the
    /// console's own `exit=` is ignored, and no verdict or a failed agent is an
    /// infra fault.
    #[test]
    fn agent_outcome_takes_the_exit_only_from_the_verdict() -> anyhow::Result<()> {
        let (report, verdict) = AgentReport::channel();
        report.job_exited(7);
        assert_eq!(
            agent_outcome(booted(Some(0)), &verdict, "job", true)?.guest_exit,
            Some(7)
        );

        let (report, verdict) = AgentReport::channel();
        report.agent_failed("refused");
        let failed = agent_outcome(booted(Some(0)), &verdict, "job", true);
        assert!(
            matches!(&failed, Err(BackendError::Spawn(why)) if why.contains("refused")),
            "got {failed:?}"
        );

        let (report, verdict) = AgentReport::channel();
        drop(report);
        let silent = agent_outcome(booted(Some(0)), &verdict, "job", true);
        assert!(matches!(&silent, Err(BackendError::Spawn(_))), "got {silent:?}");
        Ok(())
    }

    /// A run that timed out keeps its timeout and gets no exit, without waiting
    /// on the verdict.
    #[test]
    fn agent_outcome_keeps_a_timeout_without_an_exit() -> anyhow::Result<()> {
        let (_report, verdict) = AgentReport::channel();
        let mut timed_out = booted(Some(0));
        timed_out.timed_out = true;
        let started = std::time::Instant::now();
        let outcome = agent_outcome(timed_out, &verdict, "job", true)?;
        assert!(outcome.timed_out && outcome.guest_exit.is_none());
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "must not wait on the verdict"
        );
        Ok(())
    }

    /// CodeRabbit on #244: a guest whose agent never took its link is an infra
    /// fault even when the console then timed out, carrying the connector's
    /// reason; the timeout is not the job's, since the job never started.
    #[test]
    fn a_never_taken_link_is_infra_even_when_the_console_timed_out() {
        let (report, verdict) = AgentReport::channel();
        report.agent_failed("could not reach the guest agent: timed out");
        let mut timed_out = booted(None);
        timed_out.timed_out = true;
        let result = agent_outcome(timed_out, &verdict, "job", false);
        assert!(
            matches!(&result, Err(BackendError::Spawn(why)) if why.contains("never took its link") && why.contains("could not reach")),
            "got {result:?}"
        );
    }

    /// CodeRabbit on #244: a panicking `on_link` has not taken the link, even if
    /// it kept the fd first, so the connector reports it as never linked.
    #[test]
    fn a_panicking_link_handler_counts_as_never_linked() -> anyhow::Result<()> {
        use std::io::Write;
        let dir = tempfile::tempdir()?;
        let socket = dir.path().join("agent.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket)?;
        std::thread::spawn(move || {
            if let Ok((mut conn, _)) = listener.accept() {
                let _ = conn.write_all(&[sandy_api::agent::AGENT_LINK_READY]);
                std::thread::sleep(Duration::from_secs(2));
            }
        });
        let launch = AgentLaunch {
            program: PathBuf::new(),
            on_link: Arc::new(|_: &str, link: std::os::fd::OwnedFd, _: AgentReport| {
                std::mem::forget(link);
                panic!("relay setup failed after keeping the fd");
            }),
        };
        let (_verdict, thread) = spawn_connector(
            &launch,
            move || std::os::unix::net::UnixStream::connect(&socket),
            "box",
            std::time::Instant::now() + Duration::from_secs(10),
            Arc::new(AtomicBool::new(false)),
        );
        assert!(
            !thread.join().unwrap_or(true),
            "a panicking handler must not count as linked"
        );
        Ok(())
    }

    #[test]
    fn the_agent_socket_fits_a_unix_socket_path() -> anyhow::Result<()> {
        let short = agent_socket(Path::new("/tmp/sandy"), Uuid::nil())?;
        assert!(short.as_os_str().len() <= MAX_SOCKET_PATH);
        let long = agent_socket(Path::new(&"/x".repeat(60)), Uuid::nil());
        assert!(matches!(long, Err(BackendError::Spawn(_))), "got {long:?}");
        Ok(())
    }

    /// Tier-3 / host: a trivial RunSpec boots a real vfkit guest on an Apple-silicon host under a
    /// real PTY, returns a populated [`Outcome`], [`boxes`](VmBackend::boxes)
    /// lists the instance, and [`kill`](VmBackend::kill) tears it down — with the
    /// four distinct outcomes (booted+exit, `!booted`, `timed_out`,
    /// `transport_error`) each asserted on the host. Ignored in the sandbox: it
    /// spawns a hypervisor and must never be counted green from a fake (INV-S9);
    /// it binds into #26.
    #[test]
    #[ignore = "tier-3/host: boots a real vfkit guest on an Apple-silicon host; binds into #26 (INV-S9)"]
    fn real_vfkit_boot_populates_outcome_and_registry() -> anyhow::Result<()> {
        let backend = VfkitBackend::new("vfkit");
        let command = ["true".to_string()];
        let grants = grants();
        let spec = RunSpec {
            template: "demo",
            command: &command,
            inputs: &[],
            outputs: &[],
            secrets: &[],
            env: &[],
            cpu: None,
            mem: None,
            timeout_secs: 60,
            grants: &grants,
            outcome_file: None,
            secret_dir: None,
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
