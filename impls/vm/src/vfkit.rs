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
    collect_outputs, ensure_sandy_staging_base, plan_shares, topology_until, wipe, with_digests,
};
use sandy_api::{
    agent::{AGENT_VSOCK_PORT, AgentLaunch, PORT_RELAY_VSOCK_PORT},
    egress::NetworkMode,
    share::{GuestShareTransport, ShareSpec},
};
use uuid::Uuid;

use crate::{
    agent::{agent_outcome, spawn_connector},
    console::{Markers, PtyTransport, run_console},
    egress_proxy::{EGRESS_VSOCK_PORT, EgressLaunch, ProxyHandle, console_command},
    orphans::{BoxRecorder, SweepReport, unrecorded, wipe_staging},
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
    /// Egress-proxy mode (#405): the host unix socket vfkit dials for each guest
    /// connection to the fixed egress vsock port. The proxy listens there.
    pub egress_socket: Option<PathBuf>,
    /// Service bridge (#590): the host unix socket vfkit exposes the guest port relay's vsock port at, for the host
    /// to connect to.
    pub service_vsock: Option<PathBuf>,
    /// The guest network profile (#602). [`NetworkMode::Nic`] adds a NAT `virtio-net` with no egress
    /// boundary, and is refused beside an egress policy; the default emits none.
    pub network: NetworkMode,
}

impl StagedArgs {
    /// A [`StagedArgs`] carrying the given virtio-fs shares.
    #[must_use]
    pub fn new(shares: Vec<ShareSpec>) -> Self {
        Self {
            shares,
            agent_vsock: None,
            egress_socket: None,
            service_vsock: None,
            network: NetworkMode::None,
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
/// - service bridge ([`StagedArgs::service_vsock`], #590): `--device
///   virtio-vsock,port=1000,socketURL=<socket>,connect`, the guest port relay's port, with the host connecting.
/// - proxy mode ([`StagedArgs::egress_socket`], #405): `--device virtio-vsock,port=5001,socketURL=<socket>,listen`, so
///   vfkit dials the proxy's unix socket for each guest-initiated connection. It coexists with the agent link's
///   `connect` device on port 5000. No `virtio-net` is emitted in either mode: the guest has no NIC unless
///   [`StagedArgs::network`] is `nic` (#602).
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

    // Service bridge (#590): the same `connect` shape as the agent port, for the guest port relay.
    if let Some(socket) = &staged.service_vsock {
        args.push("--device".to_string());
        args.push(format!(
            "virtio-vsock,port={PORT_RELAY_VSOCK_PORT},socketURL={},connect",
            socket.display()
        ));
    }

    // Proxy mode (#405): `listen` makes vfkit the dialer: it connects to the proxy's unix socket for each
    // guest-initiated connection to the egress port.
    if let Some(socket) = &staged.egress_socket {
        args.push("--device".to_string());
        args.push(format!(
            "virtio-vsock,port={EGRESS_VSOCK_PORT},socketURL={},listen",
            socket.display()
        ));
    }

    // vfkit has no per-VM egress boundary (no nftables on macOS), so a NAT NIC is trusted-only (#602). A
    // policy beside it would read as filtered while permitting all, so the pair is refused.
    if staged.network == NetworkMode::Nic {
        if spec.egress.is_some() {
            return Err(BackendError::Spawn(
                "network = nic on vfkit has no egress boundary, so it cannot carry an egress policy; refusing the run \
                 rather than booting a NIC that looks filtered"
                    .to_string(),
            ));
        }
        tracing::warn!("network = nic on vfkit: the guest has direct NAT egress and no egress boundary");
        args.push("--device".to_string());
        args.push("virtio-net,nat".to_string());
    }

    Ok(args)
}

/// The guest network profile from [`NETWORK_ENV`] (#602); unset means no NIC.
fn network_from_env() -> Result<NetworkMode, BackendError> {
    NetworkMode::from_env().map_err(BackendError::Spawn)
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
    /// When set, vfkit exposes the guest port relay at this host socket (#590).
    service_socket: Option<PathBuf>,
    /// Set by a service-socket backend's one run: the socket path serves one VM, so a second run would unlink the
    /// first one's live socket.
    service_used: AtomicBool,
}

impl VfkitBackend {
    /// Stop the VMs that a killed host process (`sandyd` or a `sandy run`) left behind, and remove their staging
    /// directories (#666). Call it once at start-up, before launching. It reads the records under the staging base, so
    /// it sweeps a box whichever hypervisor wrote it, and it stops only a process that a record proves is ours, for a
    /// box whose owner is gone. See [`sweep_orphaned_vms`](crate::sweep_orphaned_vms).
    #[must_use]
    pub fn sweep_orphans() -> SweepReport {
        crate::orphans::sweep_orphaned_vms()
    }

    /// A backend that launches the `vfkit` binary at `vfkit_bin`, with an empty
    /// instance registry.
    #[must_use]
    pub fn new(vfkit_bin: impl Into<PathBuf>) -> Self {
        Self {
            vfkit_bin: vfkit_bin.into(),
            instances: Mutex::new(Vec::new()),
            agent: None,
            agent_used: AtomicBool::new(false),
            service_socket: None,
            service_used: AtomicBool::new(false),
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

    /// Expose the guest port relay (#590) at the host unix socket `socket`.
    ///
    /// vfkit must declare the vsock device before boot, so the caller picks the path (short enough for
    /// `sun_path`, no comma, in a private directory such as `sandy_fsutil`'s staging base: the backend does not check
    /// who else can write there) and dials it with `sandy-conn`'s `UnixDialer`. Without it the guest has no service
    /// channel. The backend serves ONE run, like agent mode: build one per environment. The path must be unique per
    /// environment: a second backend on the same path would find the first run's live socket and unlink it.
    #[must_use]
    pub fn with_service_socket(mut self, socket: impl Into<PathBuf>) -> Self {
        self.service_socket = Some(socket.into());
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
    ///
    /// In proxy mode (`egress`, #405) the proxy starts first, so a start failure
    /// returns before vfkit spawns. At teardown it is health-checked with
    /// `try_wait` BEFORE it is killed: one that died first is an
    /// [`BackendError::EgressProxyDied`], which takes precedence over the guest's
    /// own result and the agent verdict (the guest lost its network).
    #[allow(clippy::too_many_arguments, reason = "one launch attempt's inputs, all distinct")]
    fn boot(
        &self,
        topology: &Topology,
        spec: &RunSpec,
        run_id: Uuid,
        box_id: &str,
        inst_dir: &Path,
        shares: Vec<ShareSpec>,
        agent: Option<&AgentRun>,
        egress: Option<&EgressLaunch<'_>>,
        service: Option<&Path>,
    ) -> Result<Outcome, BackendError> {
        // The shares (secret/input/output, their read-only flags, the #49 secret_dir
        // rule) are staged by `plan_shares` in `run`; here they only become argv. The
        // guest mounts each by tag with `nofail`, so order is irrelevant. The
        // `socket` field is unused by vfkit (no daemon). INV-1: only share metadata
        // travels here, never secret bytes.
        let mut staged = StagedArgs::new(shares);
        // Agent mode: vfkit exposes the agent's vsock port as the run's host socket.
        if let Some(agent) = agent {
            staged.agent_vsock = Some((AGENT_VSOCK_PORT, agent.socket.clone()));
        }
        // Service bridge: a stale socket from a killed run would make vfkit's bind fail, so clear it first.
        staged.service_vsock = service.map(Path::to_path_buf);
        // Proxy mode: vfkit dials the proxy's unix socket for the egress port.
        staged.egress_socket = egress.and_then(EgressLaunch::unix_socket).map(Path::to_path_buf);
        staged.network = network_from_env()?;
        let args = vfkit_args(topology, spec, &staged)?;

        // The proxy belongs to this attempt and starts before vfkit. `ProxyHandle` kills on
        // drop, so every early return below stops it too.
        // Each helper process is recorded as it spawns, before any wait: a kill during the proxy's READY wait must
        // still leave a record of it (#666). `run_with` wrote the owner before staging; this adopts that record.
        let mut record = BoxRecorder::open(inst_dir).map_err(|err| unrecorded(&err))?;
        let mut proxy = egress
            .map(|launch| launch.start_recorded(&mut |pid| record.add(pid)))
            .transpose()?;
        // The console launches the image's agent around the job (agent mode) and the egress
        // relay around that (proxy mode).
        let console_command = console_command(
            spec.command,
            spec.env,
            agent.map(|agent| agent.program.as_path()),
            egress.zip(proxy.as_ref()).map(|(e, p)| (e.relay_program, p.port())),
        );
        let console_spec = RunSpec {
            digests: false,
            command: &console_command,
            ..*spec
        };

        let mut transport = PtyTransport::open()?;
        // The PTY read timeout is a short poll quantum, not the run budget:
        // `run_console` enforces the deadline (and `spec.control`'s live
        // cancellation/suspension, #340/#185) itself on every idle tick, so a
        // silent guest resolves through its timeout path instead of blocking
        // the driver for the whole run.
        transport.set_read_timeout(crate::console::POLL_QUANTUM);
        let pid = transport.spawn(&self.vfkit_bin, &args)?;
        if let Err(err) = record.add(pid) {
            transport.shutdown();
            return Err(unrecorded(&err));
        }
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
        let outcome = run_console(&mut transport, &console_spec, &markers);

        // The guest is done: stop connecting, check the proxy BEFORE killing it (our own
        // kill is never a death), then tear the proxy and vfkit down and deregister.
        stop.store(true, Ordering::SeqCst);
        let verdict = connector.map(|(verdict, thread)| (verdict, thread.join().unwrap_or(false)));
        let proxy_exit = proxy.as_mut().and_then(ProxyHandle::exited);
        drop(proxy);
        transport.shutdown();
        self.lock_registry()?.retain(|state| state.box_id != box_id);
        if let Some(status) = proxy_exit {
            return Err(BackendError::EgressProxyDied {
                status,
                booted: outcome.booted,
                guest_exit: outcome.guest_exit,
            });
        }
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

/// The service socket path, checked and cleared of a stale socket (#590).
///
/// The path must fit `sun_path` and hold no comma (vfkit splits its option string on commas). vfkit is SIGKILLed at
/// teardown and cannot unlink its own socket, so a socket left by an earlier run would make the next bind fail: that
/// one file type is removed, but only when nothing answers on it. A socket that answers belongs to a live VM (such as
/// an orphan of a killed host) and is refused, so a second VM never replaces it. Anything else at the path (a file,
/// directory or symlink) is refused, never deleted.
fn prepare_service_socket(socket: &Path) -> Result<PathBuf, BackendError> {
    use std::os::unix::fs::FileTypeExt as _;

    let shown = socket.display();
    if socket.as_os_str().len() > MAX_SOCKET_PATH {
        return Err(BackendError::Spawn(format!(
            "the service socket path {shown} is longer than a unix socket allows ({MAX_SOCKET_PATH} bytes)"
        )));
    }
    let Some(text) = socket.to_str() else {
        return Err(BackendError::Spawn(format!(
            "the service socket path {shown} is not UTF-8, so vfkit's argument would name another path"
        )));
    };
    if text.chars().any(|c| c == ',' || c.is_control()) {
        return Err(BackendError::Spawn(format!(
            "the service socket path {shown} holds a comma or a control character, which vfkit's option parser would \
             split"
        )));
    }
    match std::fs::symlink_metadata(socket) {
        Ok(meta) if meta.file_type().is_socket() => {
            match std::os::unix::net::UnixStream::connect(socket) {
                Ok(_) => {
                    return Err(BackendError::Spawn(format!(
                        "the service socket {shown} answers: a VM of this environment is still running"
                    )));
                }
                Err(err)
                    if matches!(
                        err.kind(),
                        std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::NotFound
                    ) => {}
                Err(err) => {
                    return Err(BackendError::Spawn(format!(
                        "could not tell whether the service socket {shown} is stale: {err}"
                    )));
                }
            }
            std::fs::remove_file(socket)
                .map_err(|err| BackendError::Spawn(format!("clear the stale service socket {shown}: {err}")))?;
        }
        Ok(_) => {
            return Err(BackendError::Spawn(format!(
                "the service socket path {shown} holds something that is not a socket; refusing to remove it"
            )));
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(BackendError::Spawn(format!(
                "inspect the service socket path {shown}: {err}"
            )));
        }
    }
    Ok(socket.to_path_buf())
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

/// A run's `<prefix>-<id>.sock` in the private staging base, short enough for
/// `sun_path`.
fn run_socket(base: &Path, run_id: Uuid, prefix: &str, what: &str) -> Result<PathBuf, BackendError> {
    let id = run_id.simple().to_string();
    let socket = base.join(format!("{prefix}-{}.sock", &id[..12]));
    if socket.as_os_str().len() > MAX_SOCKET_PATH {
        return Err(BackendError::Spawn(format!(
            "the {what} socket path {} is longer than a unix socket allows ({MAX_SOCKET_PATH} bytes)",
            socket.display()
        )));
    }
    Ok(socket)
}

/// The run's agent socket in the private staging base.
fn agent_socket(base: &Path, run_id: Uuid) -> Result<PathBuf, BackendError> {
    run_socket(base, run_id, "ag", "agent")
}

/// The run's egress proxy socket in the private staging base, beside the agent socket.
fn egress_socket(base: &Path, run_id: Uuid) -> Result<PathBuf, BackendError> {
    run_socket(base, run_id, "eg", "egress proxy")
}

impl VmBackend for VfkitBackend {
    fn run(&self, spec: &RunSpec) -> Result<Outcome, BackendError> {
        self.run_with(spec, None)
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

impl VfkitBackend {
    /// [`run`](VmBackend::run), with `proxy_override` replacing the egress proxy binary and its `READY`
    /// deadline (tests drive a stub).
    fn run_with(&self, spec: &RunSpec, proxy_override: Option<(&Path, Duration)>) -> Result<Outcome, BackendError> {
        if self.agent.is_some() && self.agent_used.swap(true, Ordering::SeqCst) {
            return Err(BackendError::Spawn(
                "this agent-mode backend already ran its one job; build one per sandbox run".to_string(),
            ));
        }
        if self.service_socket.is_some() && self.service_used.swap(true, Ordering::SeqCst) {
            return Err(BackendError::Spawn(
                "this service-socket backend already ran its one job; build one per environment".to_string(),
            ));
        }
        // The eval can take minutes on a cold store: a cancel during it (SIGTERM to `sandy run`, #687) kills it and
        // boots nothing.
        let Some(topology) = topology_until(spec.template, || spec.control.is_cancelled())? else {
            return Ok(crate::cancelled_before_boot());
        };
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
        // Proxy mode: the relay runs the image's own `sandy-agent`, so the topology must name it.
        let egress = match spec.egress {
            Some(policy) => {
                let program = topology.agent_program.as_deref().ok_or_else(|| {
                    BackendError::Spawn(
                        "the egress proxy needs a topology that names its agent (agent_program) to run the relay; \
                         this image carries no sandy-agent"
                            .to_string(),
                    )
                })?;
                let mut launch = EgressLaunch::new_unix(policy, egress_socket(&base, run_id)?, program);
                if let Some((bin, ready_deadline)) = proxy_override {
                    launch.bin = bin.to_path_buf();
                    launch.ready_deadline = ready_deadline;
                }
                Some(launch)
            }
            None => None,
        };
        let inst_dir = base.join(&box_id);
        let inputs_dir = base.join(format!("{box_id}-inputs"));
        let outputs_dir = base.join(format!("{box_id}-outputs"));

        // Record the owner before anything sensitive exists. Staging writes the secret share into `inst_dir`, so a kill
        // from here on must leave a record that names this process, or the next sweep never finds the directory (#666).
        // `boot` adds each process it starts.
        sandy_fsutil::OwnedDir::open_or_create(&inst_dir)
            .map_err(|err| BackendError::Spawn(format!("create instance dir {}: {err}", inst_dir.display())))?;
        let _owner_record = BoxRecorder::open(&inst_dir).map_err(|err| {
            // Nothing sensitive is staged yet.
            let _ = wipe(&inst_dir);
            unrecorded(&err)
        })?;

        // Stage the shares via the shared policy, then boot on them. A staging
        // failure skips the boot but still wipes below (INV-1).
        let mut input_digests = None;
        let mut service_prepared: Option<PathBuf> = None;
        let outcome = plan_shares(
            spec,
            &ShareDirs {
                inst_dir: &inst_dir,
                inputs_dir: &inputs_dir,
                outputs_dir: &outputs_dir,
            },
        )
        .and_then(|plan| {
            input_digests = plan.input_digests;
            // Prepared only now: teardown removes a service socket only when this run cleared its path, so a run that
            // failed earlier never deletes what sits there.
            service_prepared = self.service_socket.as_deref().map(prepare_service_socket).transpose()?;
            self.boot(
                &topology,
                spec,
                run_id,
                &box_id,
                &inst_dir,
                plan.shares,
                agent.as_ref(),
                egress.as_ref(),
                service_prepared.as_deref(),
            )
        });

        // Collect outputs before wiping, only if the guest booted; a collection
        // failure surfaces as an infra fault rather than silently dropping output.
        let collected = if outcome.as_ref().is_ok_and(|o| o.booted) {
            collect_outputs(spec.outputs, &outputs_dir, spec.digests)
        } else {
            Ok(None)
        };

        // Wipe staging on every path so secret bytes never outlive the run (INV-1).
        wipe_staging(&inst_dir, &inputs_dir, &outputs_dir, "on teardown");
        let sockets = agent
            .as_ref()
            .map(|agent| agent.socket.as_path())
            .into_iter()
            .chain(egress.as_ref().and_then(EgressLaunch::unix_socket))
            .chain(service_prepared.as_deref());
        for socket in sockets {
            if let Err(err) = std::fs::remove_file(socket)
                && err.kind() != std::io::ErrorKind::NotFound
            {
                tracing::warn!(socket = %socket.display(), %err, "failed to remove a run socket");
            }
        }
        with_digests(outcome, input_digests, collected)
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

    /// #602: the default emits no NIC; `nic` adds an unenforced NAT `virtio-net` and is refused beside an egress policy.
    #[test]
    fn vfkit_args_gate_the_nic_on_network_mode() -> anyhow::Result<()> {
        let topology = parse_topology(AARCH64_FIXTURE).context("parse aarch64 fixture")?;
        let command = ["true".to_string()];
        let grants = grants();
        let allow = sandy_api::egress::AllowList::default();
        let plain = vfkit_args(&topology, &spec_for("demo", &command, &grants), &StagedArgs::default())?;
        anyhow::ensure!(!plain.iter().any(|a| a.contains("virtio-net")), "default: {plain:?}");
        let nic = StagedArgs {
            network: NetworkMode::Nic,
            ..StagedArgs::default()
        };
        let args = vfkit_args(&topology, &spec_for("demo", &command, &grants), &nic)?;
        anyhow::ensure!(has_token_run(&args, &["--device", "virtio-net,nat"]), "nic: {args:?}");
        let spec = RunSpec {
            egress: Some(&allow),
            ..spec_for("demo", &command, &grants)
        };
        let refused = vfkit_args(&topology, &spec, &nic);
        anyhow::ensure!(
            matches!(&refused, Err(BackendError::Spawn(m)) if m.contains("no egress boundary")),
            "policy + nic: {refused:?}"
        );
        Ok(())
    }

    /// A shared, reusable control handle for tests that don't exercise
    /// cancellation/deadline behavior themselves (#340).
    fn test_control() -> &'static sandy_api::backend::RunControl {
        static CONTROL: std::sync::OnceLock<sandy_api::backend::RunControl> = std::sync::OnceLock::new();
        CONTROL.get_or_init(|| sandy_api::backend::RunControl::with_timeout_secs(60))
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
            digests: false,
            egress: None,
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
            control: test_control(),
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
            digests: false,
            egress: None,
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
            control: test_control(),
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
            digests: false,
            egress: None,
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
            control: test_control(),
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
            digests: false,
            egress: None,
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
            control: test_control(),
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
            digests: false,
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
            control: test_control(),
            egress: None,
        }
    }

    /// #405: in proxy mode vfkit dials the proxy's unix socket for guest connections to port 5001,
    /// and no NIC is attached.
    #[test]
    fn vfkit_args_in_proxy_mode_listen_on_the_egress_socket_and_attach_no_nic() -> anyhow::Result<()> {
        let topology = parse_topology(AARCH64_FIXTURE).context("parse aarch64 fixture")?;
        let command = ["true".to_string()];
        let grants = grants();
        let staged = StagedArgs {
            egress_socket: Some(PathBuf::from("/tmp/sandy/eg-0123456789ab.sock")),
            ..StagedArgs::default()
        };
        let args = vfkit_args(&topology, &spec_for("demo", &command, &grants), &staged)?;
        assert!(
            has_token_run(
                &args,
                &[
                    "--device",
                    "virtio-vsock,port=5001,socketURL=/tmp/sandy/eg-0123456789ab.sock,listen"
                ]
            ),
            "{}",
            args.join(" ")
        );
        assert!(
            !args.iter().any(|arg| arg.contains("virtio-net")),
            "no NIC in proxy mode: {}",
            args.join(" ")
        );
        let plain = vfkit_args(&topology, &spec_for("demo", &command, &grants), &StagedArgs::default())?;
        assert!(
            !plain
                .iter()
                .any(|arg| arg.contains("listen") || arg.contains("virtio-net")),
            "no egress device without a proxy: {}",
            plain.join(" ")
        );
        Ok(())
    }

    /// #405: the agent link (`connect`, 5000) and the egress proxy (`listen`, 5001) coexist on distinct
    /// ports, each with its own socket.
    #[test]
    fn the_agent_link_and_the_egress_proxy_coexist_on_distinct_ports() -> anyhow::Result<()> {
        let topology = parse_topology(AARCH64_FIXTURE).context("parse aarch64 fixture")?;
        let command = ["true".to_string()];
        let grants = grants();
        let staged = StagedArgs {
            agent_vsock: Some((AGENT_VSOCK_PORT, PathBuf::from("/tmp/sandy/ag-0123456789ab.sock"))),
            egress_socket: Some(PathBuf::from("/tmp/sandy/eg-0123456789ab.sock")),
            ..StagedArgs::default()
        };
        let args = vfkit_args(&topology, &spec_for("demo", &command, &grants), &staged)?;
        let devices: Vec<&String> = args.iter().filter(|a| a.starts_with("virtio-vsock,port=")).collect();
        assert_eq!(
            devices,
            [
                "virtio-vsock,port=5000,socketURL=/tmp/sandy/ag-0123456789ab.sock,connect",
                "virtio-vsock,port=5001,socketURL=/tmp/sandy/eg-0123456789ab.sock,listen"
            ]
        );
        Ok(())
    }

    /// #405: the console command starts with the relay wrapper on port 5001, in console-only and agent mode.
    #[test]
    fn the_console_command_starts_with_the_relay_on_the_constant_port() {
        let job = ["sh".to_string(), "-c".to_string(), "env".to_string()];
        let program = Path::new("/nix/store/a-sandy-agent/bin/sandy-agent");
        let relay = Some((program, EGRESS_VSOCK_PORT));
        let prefix = [
            "/nix/store/a-sandy-agent/bin/sandy-agent",
            "egress-relay",
            "--vsock-port",
            "5001",
            "--",
        ];
        let console_only = console_command(&job, &[], None, relay);
        assert_eq!(console_only[..5], prefix);
        assert_eq!(console_only[5..], job);
        let agent_mode = console_command(&job, &[], Some(program), relay);
        assert_eq!(agent_mode[..5], prefix);
        assert_eq!(
            agent_mode[5..8],
            ["/nix/store/a-sandy-agent/bin/sandy-agent", "--vsock-listen", "5000"],
            "the agent invocation is the relay's rest"
        );
    }

    /// #405: both run sockets fit macOS's 104-byte `sun_path` under a realistic staging base.
    #[test]
    fn the_run_sockets_fit_a_macos_sun_path() -> anyhow::Result<()> {
        let base = Path::new("/var/folders/xx/yyyyyyyyyyyyyyyyyyyyyyyyyyyyyy/T/sandy");
        let run_id = Uuid::new_v4();
        for socket in [egress_socket(base, run_id)?, agent_socket(base, run_id)?] {
            assert!(
                socket.as_os_str().len() <= MAX_SOCKET_PATH,
                "{} is {} bytes",
                socket.display(),
                socket.as_os_str().len()
            );
        }
        let egress = egress_socket(base, run_id)?;
        assert_eq!(
            egress.parent(),
            Some(base),
            "beside the agent socket, in the staging base"
        );
        let name = egress
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_owned();
        assert!(name.starts_with("eg-") && name.ends_with(".sock"), "{name}");
        let too_long = egress_socket(Path::new(&"/x".repeat(60)), run_id);
        assert!(
            matches!(&too_long, Err(BackendError::Spawn(why)) if why.contains("egress proxy socket")),
            "got {too_long:?}"
        );
        Ok(())
    }

    /// Single-quote a path for a stub script.
    fn quote(path: &Path) -> String {
        format!("'{}'", path.display().to_string().replace('\'', r"'\''"))
    }

    /// The aarch64 fixture with an `agent_program`, written to `dir`: the template a proxy-mode run needs.
    fn topology_with_agent(dir: &Path) -> anyhow::Result<String> {
        let mut json: serde_json::Value = serde_json::from_slice(AARCH64_FIXTURE).context("fixture json")?;
        json["agent_program"] = "/nix/store/a-sandy-agent/bin/sandy-agent".into();
        let path = dir.join("topology.json");
        std::fs::write(&path, serde_json::to_vec(&json)?).context("write topology")?;
        Ok(path.display().to_string())
    }

    fn pid_alive(pid: u32) -> bool {
        std::process::Command::new("kill")
            .args(["-0", &pid.to_string()])
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    }

    /// A fixture for a proxy-mode `run_with` against stubs: the proxy stub creates its socket (as the real
    /// proxy does) and records its argv and pid; the vfkit stub records its argv, whether the egress
    /// socket already existed when it started, and never boots.
    struct StubRun {
        dir: tempfile::TempDir,
        template: String,
        vfkit: PathBuf,
        proxy: PathBuf,
    }

    impl StubRun {
        fn new(proxy_tail: &str) -> anyhow::Result<Self> {
            let dir = tempfile::tempdir()?;
            let template = topology_with_agent(dir.path())?;
            let d = dir.path();
            let vfkit = crate::egress_proxy::tests::stub(
                d,
                "vfkit",
                &format!(
                    "echo spawned > {spawned}; echo \"$@\" > {args}; for a in \"$@\"; do case \"$a\" in \
                     *socketURL=*,listen) s=${{a#*socketURL=}}; s=${{s%,listen}}; [ -e \"$s\" ] && echo present > \
                     {present};; esac; done; exec sleep 30",
                    spawned = quote(&d.join("vfkit-ran")),
                    args = quote(&d.join("vfkit-args")),
                    present = quote(&d.join("socket-present")),
                ),
            )?;
            let proxy = crate::egress_proxy::tests::stub(
                d,
                "proxy",
                &format!(
                    "echo $$ > {pid}; echo \"$@\" > {args}; touch \"$2\"; cat >/dev/null; {proxy_tail}",
                    pid = quote(&d.join("proxy-pid")),
                    args = quote(&d.join("proxy-args")),
                ),
            )?;
            Ok(Self {
                dir,
                template,
                vfkit,
                proxy,
            })
        }

        fn path(&self, name: &str) -> PathBuf {
            self.dir.path().join(name)
        }

        /// The socket the proxy stub was told to listen on.
        fn proxy_socket(&self) -> anyhow::Result<PathBuf> {
            let args = std::fs::read_to_string(self.path("proxy-args")).context("proxy args")?;
            let socket = args.trim().strip_prefix("--unix ").context("--unix flag")?;
            Ok(PathBuf::from(socket))
        }

        fn run(&self, ready: Duration) -> Result<Outcome, BackendError> {
            let allow = sandy_api::egress::AllowList::default();
            let command = ["true".to_string()];
            let grants = grants();
            let control = sandy_api::backend::RunControl::with_timeout_secs(1);
            let spec = RunSpec {
                timeout_secs: 1,
                control: &control,
                egress: Some(&allow),
                ..spec_for(&self.template, &command, &grants)
            };
            VfkitBackend::new(&self.vfkit).run_with(&spec, Some((&self.proxy, ready)))
        }
    }

    /// #405: a proxy that never prints READY fails the run as `Spawn` before vfkit spawns, and leaves
    /// neither a process nor a socket behind.
    #[test]
    fn a_proxy_that_never_becomes_ready_fails_before_vfkit_and_leaves_nothing() -> anyhow::Result<()> {
        let stub = StubRun::new("exec sleep 30")?;
        let result = stub.run(crate::egress_proxy::tests::NEVER_READY);
        let Err(BackendError::Spawn(message)) = result else {
            anyhow::bail!("expected Spawn, got {result:?}");
        };
        anyhow::ensure!(
            message.starts_with("egress proxy did not start: no READY within"),
            "{message}"
        );
        anyhow::ensure!(!stub.path("vfkit-ran").exists(), "vfkit must not spawn");
        let pid: u32 = std::fs::read_to_string(stub.path("proxy-pid"))?.trim().parse()?;
        anyhow::ensure!(!pid_alive(pid), "the stuck proxy must be killed");
        let socket = stub.proxy_socket()?;
        anyhow::ensure!(!socket.exists(), "the socket must be removed: {}", socket.display());
        Ok(())
    }

    /// #405: a proxy that exits after READY makes the run an `EgressProxyDied` (the guest never booted
    /// here), and no socket outlives the run.
    #[test]
    fn a_proxy_that_exits_early_makes_the_run_egress_proxy_died() -> anyhow::Result<()> {
        let stub = StubRun::new("echo READY; exit 3")?;
        let result = stub.run(crate::egress_proxy::tests::PROXY_STARTS);
        anyhow::ensure!(
            matches!(
                result,
                Err(BackendError::EgressProxyDied {
                    status: Some(3),
                    booted: false,
                    guest_exit: None
                })
            ),
            "expected EgressProxyDied, got {result:?}"
        );
        anyhow::ensure!(stub.path("vfkit-ran").exists(), "vfkit did spawn in this scenario");
        let socket = stub.proxy_socket()?;
        anyhow::ensure!(!socket.exists(), "the socket must be removed: {}", socket.display());
        Ok(())
    }

    /// #405: a healthy proxy is not read as dead, the egress socket is created in the private staging
    /// base before vfkit starts and named in vfkit's `listen` device, and teardown kills the proxy and
    /// removes the socket.
    #[test]
    fn a_live_proxy_is_not_a_death_and_its_socket_is_staged_then_removed() -> anyhow::Result<()> {
        let stub = StubRun::new("echo READY; exec sleep 30")?;
        let outcome = stub
            .run(crate::egress_proxy::tests::PROXY_STARTS)
            .context("a live proxy must not fail the run")?;
        anyhow::ensure!(!outcome.booted, "the stub vfkit never boots: {outcome:?}");
        let socket = stub.proxy_socket()?;
        let base = ensure_sandy_staging_base()?;
        anyhow::ensure!(
            socket.parent() == Some(base.as_path()),
            "{} not in {}",
            socket.display(),
            base.display()
        );
        let name = socket.file_name().and_then(|n| n.to_str()).unwrap_or_default();
        anyhow::ensure!(name.starts_with("eg-") && name.ends_with(".sock"), "{name}");
        anyhow::ensure!(
            stub.path("socket-present").exists(),
            "the socket must exist before vfkit starts"
        );
        let argv = std::fs::read_to_string(stub.path("vfkit-args"))?;
        anyhow::ensure!(
            argv.contains(&format!("virtio-vsock,port=5001,socketURL={},listen", socket.display())),
            "{argv}"
        );
        anyhow::ensure!(!argv.contains("virtio-net"), "{argv}");
        let pid: u32 = std::fs::read_to_string(stub.path("proxy-pid"))?.trim().parse()?;
        anyhow::ensure!(!pid_alive(pid), "the proxy must be killed at teardown");
        anyhow::ensure!(!socket.exists(), "the socket must be removed: {}", socket.display());
        Ok(())
    }

    /// #405: a policy-carrying spec on an image whose topology names no agent is refused before the
    /// proxy or vfkit starts: the relay runs the image's own `sandy-agent`.
    #[test]
    fn proxy_mode_refuses_a_topology_without_an_agent() -> anyhow::Result<()> {
        let allow = sandy_api::egress::AllowList::default();
        let template = fixture_path("topology-aarch64.json");
        let command = ["true".to_string()];
        let grants = grants();
        let spec = RunSpec {
            egress: Some(&allow),
            ..spec_for(&template, &command, &grants)
        };
        let result = VfkitBackend::new("/nonexistent/vfkit").run(&spec);
        let Err(BackendError::Spawn(message)) = result else {
            anyhow::bail!("expected Spawn, got {result:?}");
        };
        anyhow::ensure!(message.contains("agent_program"), "{message}");
        Ok(())
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

    /// #590: the service socket path is checked at the limit, refused when it could split vfkit's options, and only a
    /// stale socket is removed.
    #[test]
    fn a_service_socket_path_is_checked_and_only_a_stale_socket_is_cleared() -> anyhow::Result<()> {
        use std::os::unix::net::UnixListener;

        let dir = PathBuf::from(format!("/tmp/sv-{}", &Uuid::new_v4().simple().to_string()[..8]));
        std::fs::create_dir_all(&dir).context("create dir")?;
        let refused = |path: &Path, why: &str| {
            assert!(
                matches!(prepare_service_socket(path), Err(BackendError::Spawn(m)) if m.contains(why)),
                "{path:?} should be refused with {why:?}"
            );
        };

        // A socket left by a killed run is removed.
        let socket = dir.join("s.sock");
        drop(UnixListener::bind(&socket).context("bind stale socket")?);
        assert_eq!(prepare_service_socket(&socket)?, socket);
        assert!(!socket.exists(), "the stale socket must be removed");
        // A missing path is fine.
        assert_eq!(prepare_service_socket(&socket)?, socket);

        // Anything else is kept and refused.
        let regular = dir.join("regular");
        std::fs::write(&regular, b"data").context("write regular")?;
        refused(&regular, "not a socket");
        assert!(regular.exists());
        let sub = dir.join("sub");
        std::fs::create_dir(&sub).context("create dir")?;
        refused(&sub, "not a socket");
        let link = dir.join("link");
        std::os::unix::fs::symlink(&regular, &link).context("symlink")?;
        refused(&link, "not a socket");
        assert!(regular.exists() && link.symlink_metadata().is_ok());

        // The exact limit passes and one byte more fails.
        let pad = MAX_SOCKET_PATH - dir.as_os_str().len() - 1;
        let at_limit = dir.join("x".repeat(pad));
        assert_eq!(at_limit.as_os_str().len(), MAX_SOCKET_PATH);
        assert_eq!(prepare_service_socket(&at_limit)?, at_limit);
        refused(&dir.join("x".repeat(pad + 1)), "longer");

        // A comma or a control character would split or corrupt vfkit's option string.
        refused(&dir.join("a,b"), "comma");
        refused(&dir.join("a\tb"), "control character");
        // A non-UTF-8 name would reach vfkit's argument with U+FFFD in place of the bytes, naming another path.
        {
            use std::os::unix::ffi::OsStrExt as _;
            refused(&dir.join(std::ffi::OsStr::from_bytes(b"a\xffb")), "UTF-8");
        }

        // A symlink to a live socket is refused and left in place.
        let live = dir.join("live.sock");
        let _listener = UnixListener::bind(&live).context("bind live socket")?;
        let to_live = dir.join("to-live");
        std::os::unix::fs::symlink(&live, &to_live).context("symlink to socket")?;
        refused(&to_live, "not a socket");
        assert!(live.exists() && to_live.symlink_metadata().is_ok());
        std::fs::remove_dir_all(&dir).context("cleanup")?;
        Ok(())
    }

    /// A socket that answers belongs to a live VM (an orphan of a killed host, or another run): it is refused and
    /// kept, never unlinked from under the VM.
    #[test]
    fn a_service_socket_that_answers_is_refused_and_kept() -> anyhow::Result<()> {
        use std::os::unix::net::UnixListener;

        let dir = PathBuf::from(format!("/tmp/sv-{}", &Uuid::new_v4().simple().to_string()[..8]));
        std::fs::create_dir_all(&dir).context("create dir")?;
        let socket = dir.join("live.sock");
        let listener = UnixListener::bind(&socket).context("bind live socket")?;
        let got = prepare_service_socket(&socket);
        assert!(
            matches!(&got, Err(BackendError::Spawn(m)) if m.contains("answers") && m.contains("live.sock")),
            "{got:?}"
        );
        assert!(socket.exists(), "a live socket must not be unlinked");
        // Once nothing listens, the same path is stale and is cleared.
        drop(listener);
        assert_eq!(prepare_service_socket(&socket)?, socket);
        assert!(!socket.exists());
        std::fs::remove_dir_all(&dir).context("cleanup")?;
        Ok(())
    }

    /// #590: one service-socket backend runs one job.
    #[test]
    fn a_service_socket_backend_refuses_a_second_run() {
        let backend = VfkitBackend::new("/nonexistent/vfkit")
            .with_service_socket(format!("/tmp/sv-{}.sock", &Uuid::new_v4().simple().to_string()[..8]));
        let template = fixture_path("topology-aarch64.json");
        let command = ["true".to_string()];
        let grants = grants();
        let spec = spec_for(&template, &command, &grants);
        let _first = backend.run(&spec);
        assert!(
            matches!(backend.run(&spec), Err(BackendError::Spawn(why)) if why.contains("already ran its one job")),
            "the second run must be refused"
        );
    }

    /// #590: agent, service and egress devices coexist on distinct ports.
    #[test]
    fn vfkit_args_carry_the_agent_service_and_egress_devices_together() -> anyhow::Result<()> {
        let topology = parse_topology(AARCH64_FIXTURE).context("parse aarch64 fixture")?;
        let command = ["true".to_string()];
        let grants = grants();
        let staged = StagedArgs {
            agent_vsock: Some((5000, PathBuf::from("/tmp/sandy/ag.sock"))),
            service_vsock: Some(PathBuf::from("/tmp/sandy/sv.sock")),
            egress_socket: Some(PathBuf::from("/tmp/sandy/eg.sock")),
            ..StagedArgs::default()
        };
        let args = vfkit_args(&topology, &spec_for("demo", &command, &grants), &staged)?;
        let devices: Vec<&String> = args.iter().filter(|a| a.starts_with("virtio-vsock,port=")).collect();
        assert_eq!(
            devices,
            [
                "virtio-vsock,port=5000,socketURL=/tmp/sandy/ag.sock,connect",
                "virtio-vsock,port=1000,socketURL=/tmp/sandy/sv.sock,connect",
                "virtio-vsock,port=5001,socketURL=/tmp/sandy/eg.sock,listen"
            ]
        );
        Ok(())
    }

    /// #590: a service socket declares the relay's vsock port for the host to connect, and no socket declares none.
    #[test]
    fn vfkit_args_expose_the_service_relay_port_only_when_a_socket_is_set() -> anyhow::Result<()> {
        let topology = parse_topology(AARCH64_FIXTURE).context("parse aarch64 fixture")?;
        let command = ["true".to_string()];
        let grants = grants();
        let spec = spec_for("demo", &command, &grants);
        let with_socket = StagedArgs {
            service_vsock: Some(PathBuf::from("/tmp/sandy/sv-0123456789ab.sock")),
            ..StagedArgs::default()
        };
        let args = vfkit_args(&topology, &spec, &with_socket)?;
        assert!(
            has_token_run(
                &args,
                &[
                    "--device",
                    "virtio-vsock,port=1000,socketURL=/tmp/sandy/sv-0123456789ab.sock,connect"
                ]
            ),
            "{}",
            args.join(" ")
        );
        let without = vfkit_args(&topology, &spec, &StagedArgs::default())?;
        assert!(
            !without.iter().any(|a| a.starts_with("virtio-vsock,port=1000")),
            "{}",
            without.join(" ")
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
            digests: None,
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
            digests: false,
            egress: None,
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
            control: test_control(),
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

    /// Tier-3 (#185/#340): suspending a real vfkit-backed job's `RunControl`
    /// deadline before it runs lets it survive well past its own declared
    /// `timeout_secs`, proving the fix end to end (argv → vfkit → PTY console →
    /// `run_console`), not just at the `run_console` unit level.
    #[test]
    #[ignore = "tier-3/host: boots a real vfkit guest on an Apple-silicon host; binds into #185/#340 (INV-S9)"]
    fn suspending_the_control_survives_past_the_jobs_timeout_on_vfkit() -> anyhow::Result<()> {
        let backend = VfkitBackend::new("vfkit");
        let command = ["sh".to_string(), "-c".to_string(), "sleep 20; echo done".to_string()];
        let grants = grants();
        let control = sandy::RunControl::with_timeout_secs(5);
        control.suspend_deadline();
        let spec = RunSpec {
            digests: false,
            egress: None,
            template: "demo",
            command: &command,
            inputs: &[],
            outputs: &[],
            secrets: &[],
            env: &[],
            cpu: None,
            mem: None,
            timeout_secs: 5,
            grants: &grants,
            outcome_file: None,
            secret_dir: None,
            control: &control,
        };

        let outcome = backend.run(&spec).context("boot vfkit guest")?;
        assert!(
            !outcome.timed_out,
            "a suspended deadline must survive well past the 5s budget: {outcome:?}"
        );
        assert_eq!(outcome.guest_exit, Some(0), "console: {}", outcome.console);
        Ok(())
    }

    /// Tier-3 (#185/#340): `daemon cancel` ends a real vfkit-backed job
    /// promptly, well before its own long declared `timeout_secs`.
    #[test]
    #[ignore = "tier-3/host: boots a real vfkit guest on an Apple-silicon host; binds into #185/#340 (INV-S9)"]
    fn cancelling_the_control_ends_a_running_job_on_vfkit() -> anyhow::Result<()> {
        let backend = VfkitBackend::new("vfkit");
        let command = ["sh".to_string(), "-c".to_string(), "sleep 60".to_string()];
        let grants = grants();
        let control = sandy::RunControl::with_timeout_secs(120);
        let spec = RunSpec {
            digests: false,
            egress: None,
            template: "demo",
            command: &command,
            inputs: &[],
            outputs: &[],
            secrets: &[],
            env: &[],
            cpu: None,
            mem: None,
            timeout_secs: 120,
            grants: &grants,
            outcome_file: None,
            secret_dir: None,
            control: &control,
        };

        let start = Instant::now();
        let (outcome, run_duration) = std::thread::scope(|scope| {
            // Measure `backend.run`'s own internal duration, not the
            // thread::scope block's wall time — the main thread's 5s sleep
            // below happens unconditionally before it ever calls `join()`,
            // so timing the block itself would always read >=5s regardless
            // of how fast the run inside actually finished, proving nothing
            // about whether cancellation was what ended it.
            let handle = scope.spawn(|| {
                let run_start = Instant::now();
                (backend.run(&spec), run_start.elapsed())
            });
            std::thread::sleep(Duration::from_secs(5));
            control.cancel();
            handle.join().expect("run thread panicked")
        });
        let outcome = outcome.context("boot vfkit guest")?;

        // The fixed 5s sleep before cancelling can't be synchronized against
        // real boot completion (`run_console`'s own boot-ready signal isn't
        // observable from outside the blocking `backend.run()` call), so a
        // slow boot can land the cancel during the boot phase rather than the
        // command phase. Both are a correct "cancel ended it" outcome —
        // `booted: false, timed_out: false` (cancelled before the guest ever
        // reported ready) or `booted: true, timed_out: true` (cancelled mid
        // command) — the test only needs to prove cancellation ends the run
        // promptly, not which phase it landed in. `transport_error` must be
        // None either way, ruling out an unrelated infra fault as a false
        // positive (CodeRabbit on #366).
        assert!(
            outcome.transport_error.is_none(),
            "an unrelated transport fault must not be mistaken for cancellation: {outcome:?}"
        );
        // `run_duration` below 5s means the guest closed its console (or
        // `backend.run` otherwise returned) before cancel() was even sent —
        // an early exit unrelated to cancellation, proving nothing about it
        // (CodeRabbit on #366).
        assert!(
            run_duration >= Duration::from_secs(5),
            "the run finished after {run_duration:?}, before cancel() was even sent, proving nothing: {outcome:?}"
        );
        assert!(
            !outcome.booted || outcome.timed_out,
            "cancellation must end the job, either before boot or mid-command: {outcome:?}"
        );
        assert!(
            start.elapsed() < Duration::from_secs(60),
            "cancellation must end the run promptly, not wait near the 120s budget"
        );
        Ok(())
    }

    /// #666: a run records its owner before staging and each process it starts as it spawns (the proxy, then vfkit), so
    /// a restart can find them after a SIGKILL. The recording vfkit stub waits until a record under the staging base
    /// names its own pid, keeps a copy, and the run then fails because the stub never boots; only the record matters.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn a_run_records_its_owner_and_every_process_it_starts() -> anyhow::Result<()> {
        let mut stub = StubRun::new("echo READY; exec sleep 30")?;
        let base = ensure_sandy_staging_base()?;
        let capture = stub.path("record-seen");
        stub.vfkit = crate::egress_proxy::tests::stub(
            stub.dir.path(),
            "vfkit-recording",
            &format!(
                "i=0; while :; do for f in {base}/inst-*/box.json; do if [ -f \"$f\" ] && grep -q \"\\\"pid\\\":$$\" \
                 \"$f\"; then cp \"$f\" {capture}; exec sleep 30; fi; done; i=$((i+1)); [ \"$i\" -gt 100 ] && exit 9; \
                 sleep 0.05; done",
                base = quote(&base),
                capture = quote(&capture),
            ),
        )?;

        let _ = stub.run(crate::egress_proxy::tests::PROXY_STARTS);

        let seen = std::fs::read(&capture).context("the stub vfkit never saw its own pid in a record")?;
        let record: crate::orphans::BoxRecord = serde_json::from_slice(&seen).context("decode the record")?;
        assert_eq!(
            record.owner.pid,
            std::process::id(),
            "the owner is the launching process"
        );
        let proxy_pid: u32 = std::fs::read_to_string(stub.path("proxy-pid"))?.trim().parse()?;
        let pids: Vec<u32> = record.procs.iter().map(|p| p.pid).collect();
        assert_eq!(pids.len(), 2, "the proxy and vfkit: {pids:?}");
        assert!(pids.contains(&proxy_pid), "{pids:?} lacks the proxy {proxy_pid}");
        Ok(())
    }
}
