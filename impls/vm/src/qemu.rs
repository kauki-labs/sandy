//! The native qemu/KVM backend (Block 35): assemble the hypervisor argv from a
//! [`Topology`] and run it with its serial console over a Unix socket (#33).
//!
//! This is the Linux/CI counterpart to the vfkit backend (#32). It is split so
//! the argv assembly stays pure and tier-1 testable:
//!
//! - [`qemu_args`] — the pure assembler. Given a [`Topology`], a [`RunSpec`], and the already-[`StagedArgs`] (the
//!   secret share), it builds the `qemu-system-<arch>` command vector with no IO. Proven live on an x86_64 Linux/KVM
//!   host (`/dev/kvm` world-rw): `sandy run` boots this argv to a `succeeded`/exit-0 result in ~10s with `-nographic
//!   -serial chardev:sandy-serial console=ttyS0` and the sentinels on the serial socket.
//! - [`QemuBackend`] — the [`VmBackend`] seam. `run` stages secrets, calls [`qemu_args`], spawns qemu with serial on
//!   the #33 [`PipeTransport`](crate::PipeTransport), drives [`run_console`](crate::run_console), and populates the
//!   pinned [`Outcome`]. The spawn/boot is host-tier (tier-3), not unit-tested in the sandbox.
//!
//! The module is private; `sandy-backend`'s `lib.rs` re-exports only
//! [`QemuBackend`], [`qemu_args`], and [`StagedArgs`].

use std::{
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant, SystemTime},
};

use sandy::{
    BackendError, BoxState, Hypervisor, Outcome, RunSpec, ShareDirs, SharePlan, StoreBacking, Topology, VmBackend,
    collect_outputs, ensure_sandy_staging_base, kill_children, plan_shares, topology as eval_topology, wipe,
    with_digests,
};
// Only `spawn_vsock_connector` below (the sole user) is Linux-only
// (`#[cfg(target_os = "linux")]`); a plain import here is unused, and so a
// clippy warning, on every other target.
#[cfg(target_os = "linux")]
use sandy_api::agent::AGENT_VSOCK_PORT;
use sandy_api::{
    agent::AgentLaunch,
    egress::{NETWORK_ENV, NetworkMode, is_valid_tap_name},
    share::{GuestShareTransport, ShareSpec},
};
use uuid::Uuid;

use crate::{
    agent::agent_outcome,
    console::{Markers, PipeTransport, run_console},
    egress_proxy::{EgressLaunch, ProxyHandle, console_command},
    share::VirtiofsdTransport,
};

/// The `-sandbox` value: qemu's seccomp filter, denying the obsolete syscalls, privilege elevation, `fork`/`exec`
/// and resource-control changes (#392).
const QEMU_SANDBOX: &str = "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny";

/// The chardev id the guest serial console binds to. `qemu_args` emits
/// `-serial chardev:<SERIAL_CHARDEV_ID>`; `run` adds the matching
/// `-chardev socket,…` and drives it over the #33 [`PipeTransport`].
const SERIAL_CHARDEV_ID: &str = "sandy-serial";

/// The boot-ready marker scanned for before the command is injected: the guest's
/// login shell prints it once it is up and reading (the guest's `loginShellInit`),
/// so the injected frame lands in a reading shell rather than the login handoff.
const READY_MARKER: &str = "SANDY-READY";

/// The fixed MAC for the guest's virtio NIC. It is a locally-administered,
/// unicast address (the `02:` prefix), stable so the guest's network config can
/// match it by MAC and DHCP the interface (the guest flake's
/// `microvm.interfaces` uses this same address). Only ever one guest NIC, so a
/// constant is enough.
const GUEST_MAC: &str = "02:00:00:00:00:01";

/// The environment variable naming the host tap the guest's NIC attaches to. Set
/// by the operator (or the #29 live gate) after creating and configuring the tap;
/// unset means the guest boots with no NIC (the default, isolated boot).
const TAP_ENV: &str = "SANDY_TAP";

/// The already-staged inputs [`qemu_args`] needs, kept out of the pure assembler so
/// argv assembly does no IO and stays tier-1 testable. `run` produces it before
/// calling [`qemu_args`]; the backend launches a virtiofsd per [`shares`](Self::shares)
/// entry and `kvm` records whether `/dev/kvm` was usable (probed by `run`, so the
/// assembler itself touches no host state).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct StagedArgs {
    /// The guest filesystem shares (secrets, inputs, outputs), each served as
    /// virtiofs. Empty when the run carries none.
    pub shares: Vec<ShareSpec>,
    /// Whether `/dev/kvm` is usable → emit `-enable-kvm -cpu host`.
    pub kvm: bool,
    /// The host tap the guest's NIC attaches to, when networking is requested.
    /// `Some(tap)` emits a `-netdev tap,…,ifname=<tap>` + `virtio-net-pci` pair so
    /// the guest has egress to filter (#29); `None` emits no NIC (the default,
    /// isolated boot). The tap itself (and any NAT / forwarding / egress rules
    /// around it) is the host/operator's to set up — the assembler only wires the
    /// guest onto it.
    pub tap: Option<String>,
    /// Agent mode (#238) or egress-proxy mode (#404): the vsock CID this launch claims
    /// for the guest, so the host can connect to the guest agent and the proxy can
    /// serve it. Overrides [`Topology::vsock_cid`].
    pub agent_cid: Option<u32>,
    /// The guest network profile (#602). The tap NIC is emitted only under [`NetworkMode::Nic`], which needs
    /// a bound tap and no egress proxy: the caller then owns the nftables boundary on that tap. A tap without
    /// `nic`, and `nic` without a tap, are refused.
    pub network: NetworkMode,
}

/// Refuse a tap NIC that has no declared boundary, and any tap name that cannot be scoped (#602).
///
/// The tap NIC is filtered only when the caller applied the nftables ruleset on it, which `nic` declares. A NIC
/// without that declaration, or `nic` with no tap to filter, would boot unfiltered. The tap name goes into the
/// `-netdev` argument and the ruleset, so it must be a bare interface name. Pure, so `run` can call it before staging.
fn check_nic_profile(network: NetworkMode, tap: Option<&str>) -> Result<(), BackendError> {
    if let Some(tap) = tap.filter(|t| !is_valid_tap_name(t)) {
        return Err(BackendError::Spawn(format!(
            "${TAP_ENV}={tap:?} is not a valid interface name (1 to 15 of A-Z a-z 0-9 _ - .)"
        )));
    }
    match (network == NetworkMode::Nic, tap) {
        (true, None) => Err(BackendError::Spawn(format!(
            "network = nic needs a bound tap (${TAP_ENV}) carrying the host egress boundary"
        ))),
        (false, Some(_)) => Err(BackendError::Spawn(format!(
            "${TAP_ENV} binds a guest NIC, which needs {NETWORK_ENV}=nic; refusing an unfiltered NIC"
        ))),
        _ => Ok(()),
    }
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
/// - the store ([`StoreBacking::ErofsImage`](sandy::StoreBacking::ErofsImage)) as a read-only virtio-blk drive, e.g.
///   `-drive file=<image>,if=virtio,format=raw,readonly=on`.
/// - `-smp <topology.cpu>` / `-m <topology.mem>` — vCPUs and memory in MiB (a [`RunSpec`] `cpu`/`mem` may narrow them).
/// - `-nographic` and `-serial chardev:<id>` — the guest serial console; `run` adds the matching `-chardev socket,…`
///   that binds `<id>` to the #33 [`PipeTransport`] (the socket path is a host detail, so it is not emitted here).
/// - `-enable-kvm -cpu host` when `staged.kvm`.
/// - for each [`staged.shares`](StagedArgs::shares) entry, a client `-chardev socket` on the share's virtiofsd socket
///   plus a `-device vhost-user-fs-pci,…,tag=<mount_tag>` the guest mounts as virtiofs; when any share is present, a
///   one-time `-object memory-backend-memfd,…,share=on` + `-numa node,memdev=…` so virtio-fs has shareable guest RAM.
///   The matching `virtiofsd` daemons are launched by [`QemuBackend::boot`] (new run dependency: `virtiofsd` on PATH).
/// - a `-netdev tap,…,ifname=<tap> -device virtio-net-pci,…` NIC pair when `staged.tap` is set together with
///   `staged.network = nic` (so the guest has egress to filter, #29); `-nic none` otherwise (the default isolated
///   boot).
/// - `-device vhost-vsock-pci,guest-cid=<cid>` when `topology.vsock_cid` is set. A run with an egress policy
///   ([`RunSpec::egress`]) needs that CID, and no NIC: it is refused with a tap or without a CID.
///
/// # Errors
///
/// Returns a [`BackendError`] when `topology.hypervisor` is not
/// [`Hypervisor::Qemu`](sandy::Hypervisor::Qemu) — this backend is
/// qemu-only and refuses to emit argv for a vfkit topology rather than producing
/// a wrong-hypervisor command — or when the store backing cannot be expressed as
/// a qemu drive.
pub fn qemu_args(topology: &Topology, spec: &RunSpec, staged: &StagedArgs) -> Result<Vec<String>, BackendError> {
    if topology.hypervisor != Hypervisor::Qemu {
        return Err(BackendError::Spawn(format!(
            "qemu backend refuses a {:?} topology (qemu-only)",
            topology.hypervisor
        )));
    }

    // Proxy mode (#404): the guest's only egress is its vsock to the host proxy, so it has no
    // NIC, and it needs a CID to be served on.
    let nic = staged.network == NetworkMode::Nic;
    if spec.egress.is_some() {
        if nic {
            return Err(BackendError::Spawn(
                "network = nic and the egress proxy are exclusive: the proxy guest has no NIC".to_string(),
            ));
        }
        if staged.tap.is_some() {
            return Err(BackendError::Spawn(format!(
                "the egress proxy and ${TAP_ENV} are exclusive: the proxy guest has no NIC"
            )));
        }
        if staged.agent_cid.or(topology.vsock_cid).is_none() {
            return Err(BackendError::Spawn(
                "the egress proxy needs the guest to claim a vsock CID, and none was set".to_string(),
            ));
        }
    }

    check_nic_profile(staged.network, staged.tap.as_deref())?;

    let mut args = vec![qemu_system_binary(&topology.kernel)];

    args.push("-kernel".to_string());
    args.push(topology.kernel.display().to_string());
    args.push("-initrd".to_string());
    args.push(topology.initrd.display().to_string());
    args.push("-append".to_string());
    args.push(kernel_cmdline(&topology.kernel_cmdline));
    args.push("-nographic".to_string());
    args.push("-serial".to_string());
    args.push(format!("chardev:{SERIAL_CHARDEV_ID}"));

    // A RunSpec cpu/mem may narrow the topology's budget.
    let cpu = spec.cpu.unwrap_or(topology.cpu);
    let mem = spec.mem.unwrap_or(topology.mem);
    args.push("-smp".to_string());
    args.push(cpu.to_string());
    args.push("-m".to_string());
    args.push(mem.to_string());

    // The read-only Nix store as a virtio-blk drive. Only an erofs image can be
    // expressed as a qemu drive; a virtiofs store carries only a tag (no host
    // path), so it cannot and is refused rather than emitting a broken drive.
    match &topology.store {
        StoreBacking::ErofsImage(image) => {
            args.push("-drive".to_string());
            args.push(format!("file={},if=virtio,format=raw,readonly=on", image.display()));
        }
        StoreBacking::Virtiofs(tag) => {
            return Err(BackendError::Spawn(format!(
                "qemu store backing virtiofs(tag={tag}) cannot be expressed as a qemu drive"
            )));
        }
    }

    if staged.kvm {
        args.push("-enable-kvm".to_string());
        args.push("-cpu".to_string());
        args.push("host".to_string());
    }

    // A tap NIC when one is bound, so the guest has network egress to filter (#29).
    // `script=no,downscript=no`: qemu must not run its default ifup/ifdown — the
    // tap is created and configured by the host/operator, not qemu. No tap → no
    // NIC, so the default isolated boot is unchanged.
    if let Some(tap) = &staged.tap {
        args.push("-netdev".to_string());
        args.push(format!("tap,id=net0,ifname={tap},script=no,downscript=no"));
        args.push("-device".to_string());
        args.push(format!("virtio-net-pci,netdev=net0,mac={GUEST_MAC}"));
    } else {
        // Without this qemu adds a default NIC on user-mode (NAT) networking: a guest with root could then
        // reach the internet around the egress boundary.
        args.push("-nic".to_string());
        args.push("none".to_string());
    }

    // Confine the qemu process with seccomp (#392): a guest-to-host escape through a device bug would otherwise get
    // the sandy user's full syscall surface. The qemu live suite passes under this filter on qemu/KVM x86_64 with
    // virtio-fs, vhost-user and vsock devices; other architectures are untested.
    args.push("-sandbox".to_string());
    args.push(QEMU_SANDBOX.to_string());

    // The virtio-fs shares: a shared memfd memory backend plus a client chardev +
    // `vhost-user-fs-pci` device per share. The matching virtiofsd daemons are
    // launched by [`QemuBackend::boot`]. readonly is a virtiofsd flag, not a qemu arg.
    args.extend(VirtiofsdTransport.plan(&staged.shares, mem).into_vm_args());

    // An agent-mode launch claims its own CID (#238), in place of the topology's.
    if let Some(cid) = staged.agent_cid.or(topology.vsock_cid) {
        args.push("-device".to_string());
        args.push(format!("vhost-vsock-pci,guest-cid={cid}"));
    }

    Ok(args)
}

/// Derive the `qemu-system-<arch>` binary from the kernel store path, falling
/// back to the host architecture — unless `SANDY_QEMU_BIN` names an absolute
/// path to exec directly instead, which takes priority over arch derivation
/// entirely.
///
/// microvm.nix kernel paths carry the arch in the linux derivation name
/// (`…-linux-6.6-aarch64/Image`); when none is present (the x86_64 kernel is just
/// `…-linux-6.6/bzImage`), the host arch ([`std::env::consts::ARCH`]) is used,
/// since a native qemu boot runs on the matching host.
///
/// `SANDY_QEMU_BIN` is the same escape hatch `SANDY_VIRTIOFSD_BIN` gives
/// [`spawn_virtiofsd`](crate::share::spawn_virtiofsd): bypassing a bare-name
/// `PATH` lookup entirely, needed on a host whose environment setup (PAM,
/// systemd session handling, etc.) does not reliably carry the unit's own
/// `Environment=PATH=` through to the spawned child — confirmed on the remote host
/// (#335 follow-up): the deployed unit's resolved PATH silently reverted to
/// a stock per-user NixOS profile path with no qemu on it, despite the
/// unit's own `path =` correctly listing it.
fn qemu_system_binary(kernel: &Path) -> String {
    qemu_system_binary_with_override(kernel, qemu_bin_override().as_deref())
}

/// `SANDY_QEMU_BIN`, read directly. Exported so `sandy-host-executor`'s
/// capability probe checks the exact same override this backend's own spawn
/// does — never a probe/boot-time definition drift.
#[must_use]
pub fn qemu_bin_override() -> Option<String> {
    std::env::var("SANDY_QEMU_BIN").ok()
}

/// [`qemu_system_binary`]'s pure core, taking the override as a plain
/// argument rather than reading the environment directly — this workspace
/// forbids `unsafe_code`, so a test cannot call `std::env::set_var` (unsafe
/// as of edition 2024) to exercise the override; this split keeps the logic
/// unit-testable without it.
fn qemu_system_binary_with_override(kernel: &Path, override_bin: Option<&str>) -> String {
    if let Some(bin) = override_bin {
        return bin.to_string();
    }
    let path = kernel.to_string_lossy();
    let arch = if path.contains("aarch64") || path.contains("arm64") {
        "aarch64"
    } else if path.contains("x86_64") || path.contains("amd64") {
        "x86_64"
    } else {
        std::env::consts::ARCH
    };
    format!("qemu-system-{arch}")
}

/// Ensure the guest command line drives the serial console, prepending
/// `console=ttyS0` only when the topology's cmdline does not already set it.
fn kernel_cmdline(cmdline: &str) -> String {
    if cmdline.contains("console=ttyS0") {
        cmdline.to_string()
    } else {
        format!("console=ttyS0 {cmdline}")
    }
}

/// The native qemu/KVM [`VmBackend`] (Linux).
///
/// Owns its running-instance registry so [`boxes`](VmBackend::boxes) reports live
/// state without a direct supervisor read (INV-3), mirroring the seam contract in
/// [`sandy::VmBackend`]. Construct with [`QemuBackend::new`].
#[derive(Debug, Default)]
pub struct QemuBackend {
    /// Called once per run with `(box_id, cid)` after the agent link connects (#587).
    guest_cid_hook: HookCell,
    /// The boxes this backend has launched and not yet reaped, read by
    /// [`boxes`](VmBackend::boxes) and pruned by [`kill`](VmBackend::kill).
    instances: Mutex<Vec<BoxState>>,
    /// When set, the job runs as the child of the image's sandbox agent (#238).
    agent: Option<AgentLaunch>,
    /// Set by an agent-mode backend's one run: its cap and channel serve one job.
    agent_used: AtomicBool,
}

impl QemuBackend {
    /// A backend with an empty instance registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Tell `hook` the vsock CID a guest holds, once per run, with the run's box id (#587).
    ///
    /// It fires only when the host holds the agent link AND this attempt's own guest has booted. A CID that collided
    /// with another VM and was retried never reaches it, so a consumer that dials the CID (the service bridge) cannot
    /// reach a foreign VM. Agent mode only: a run without [`with_agent`](Self::with_agent) never calls it.
    ///
    /// The hook runs on the console thread (inside the boot read loop) or the connector thread, so it must hand off
    /// and not block: a blocked hook stalls the run's deadline, cancel and serial reads, or the agent link. The
    /// consumer must stop using the CID when [`run`](VmBackend::run) returns: qemu is gone by then, and a later VM
    /// can take the same CID.
    #[must_use]
    pub fn with_guest_cid_hook(mut self, hook: impl Fn(&str, u32) + Send + Sync + 'static) -> Self {
        self.guest_cid_hook = HookCell(Some(Arc::new(hook)));
        self
    }

    /// Run the job behind the guest's sandbox agent (#238). The console launches
    /// the agent the topology names (`agent_program`; `agent.program` is not used
    /// by a VM backend), each launch claims a random vsock CID (retried with a new
    /// one when another VM holds it), the host connects to the agent over
    /// `AF_VSOCK`, and `agent.on_link` gets the link from a connector thread. The
    /// job's exit comes only from the relay's report. Linux hosts only
    /// (vhost-vsock).
    ///
    /// An agent-mode backend runs ONE job; build one per sandbox run.
    #[must_use]
    pub fn with_agent(mut self, agent: AgentLaunch) -> Self {
        self.agent = Some(agent);
        self
    }

    /// Lock the instance registry, mapping a poisoned mutex to a typed error
    /// rather than panicking (no `.unwrap()` in library code).
    fn registry(&self) -> Result<MutexGuard<'_, Vec<BoxState>>, BackendError> {
        self.instances
            .lock()
            .map_err(|_| BackendError::Protocol("qemu instance registry mutex poisoned".to_string()))
    }

    /// Spawn qemu with its serial console on a Unix-socket chardev, register the
    /// instance, drive the sentinel protocol, then tear qemu down and deregister.
    ///
    /// The run is synchronous: the box lives only for this call. A spawn/dir fault
    /// is a [`BackendError::Spawn`]; a connect/transport/timeout fault during the
    /// run lands in the returned [`Outcome`] (never a fabricated `guest_exit`,
    /// INV-OUTCOME).
    #[allow(clippy::too_many_arguments, reason = "one launch attempt's inputs, all distinct")]
    fn boot(
        &self,
        spec: &RunSpec,
        args: &[String],
        shares: &[ShareSpec],
        run_id: Uuid,
        inst_dir: &Path,
        agent: Option<(&Path, u32)>,
        egress: Option<&EgressLaunch<'_>>,
    ) -> Result<Outcome, BackendError> {
        sandy_fsutil::OwnedDir::open_or_create(inst_dir)
            .map_err(|err| BackendError::Spawn(format!("create instance dir {}: {err}", inst_dir.display())))?;

        // Launch a virtiofsd per share and wait for its socket before qemu starts:
        // qemu connects to each as a client chardev, so the socket must exist first.
        // A launch or socket fault kills any daemon already up and fails the boot.
        let virtiofsds = VirtiofsdTransport.activate(shares)?;
        self.launch(spec, args, run_id, inst_dir, agent, egress, virtiofsds)
    }

    /// Start the egress proxy (when `egress` is set) beside the already-running
    /// `virtiofsds`, spawn qemu, drive the console, and tear everything down in
    /// order: proxy, qemu, virtiofsd daemons.
    ///
    /// The proxy is health-checked with `try_wait` BEFORE it is killed. One that died
    /// first is an [`BackendError::EgressProxyDied`], which takes precedence over the
    /// guest's own result: the guest lost its network, so its result is not what the
    /// submitter asked for.
    #[allow(clippy::too_many_arguments, reason = "one launch attempt's inputs, all distinct")]
    fn launch(
        &self,
        spec: &RunSpec,
        args: &[String],
        run_id: Uuid,
        inst_dir: &Path,
        agent: Option<(&Path, u32)>,
        egress: Option<&EgressLaunch<'_>>,
        mut virtiofsds: Vec<std::process::Child>,
    ) -> Result<Outcome, BackendError> {
        let sock = inst_dir.join("serial.sock");

        // The proxy belongs to this attempt. A start failure kills the daemons
        // already up and returns before qemu launches. `ProxyHandle` kills on drop,
        // so every later exit path stops it too.
        let mut proxy: Option<ProxyHandle> = match egress.map(EgressLaunch::start).transpose() {
            Ok(proxy) => proxy,
            Err(err) => {
                kill_children(&mut virtiofsds);
                return Err(err);
            }
        };

        // qemu_args emits `-serial chardev:<id>`; bind that id to a Unix-socket
        // chardev qemu creates (server=on, wait=off so the spawn doesn't block).
        let mut argv = args.to_vec();
        argv.push("-chardev".to_string());
        argv.push(format!(
            "socket,id={SERIAL_CHARDEV_ID},path={},server=on,wait=off",
            sock.display()
        ));

        tracing::debug!(?argv, run_id = %run_id, "spawning qemu");
        let spawned = Command::new(&argv[0])
            .args(&argv[1..])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn();
        let mut child = match spawned {
            Ok(child) => child,
            Err(err) => {
                kill_children(&mut virtiofsds);
                return Err(BackendError::Spawn(format!("spawn qemu `{}`: {err}", argv[0])));
            }
        };

        // Drain qemu's stderr on a thread. An un-read `piped` stderr deadlocks the
        // boot: once qemu writes past the pipe buffer it blocks, never opens the
        // serial socket, and the run times out with an empty console. Draining also
        // captures the reason a boot that never reached the serial failed.
        let stderr_drain = child.stderr.take().map(drain_stderr);

        let box_id = run_id.to_string();
        self.registry()?.push(BoxState {
            box_id: box_id.clone(),
            box_name: spec.template.to_string(),
            pid: child.id(),
            started: SystemTime::now(),
            rvport: None,
        });

        // Agent mode: the console launches the image's agent around the job, and a
        // connector thread dials it over vsock while the console drives the run.
        let console_command = console_command(
            spec.command,
            spec.env,
            agent.map(|(program, _)| program),
            egress.zip(proxy.as_ref()).map(|(e, p)| (e.relay_program, p.port())),
        );
        let console_spec = RunSpec {
            digests: false,
            command: &console_command,
            ..*spec
        };
        let console_spec = &console_spec;
        let stop = Arc::new(AtomicBool::new(false));
        let report = self
            .guest_cid_hook
            .0
            .clone()
            .zip(agent)
            .map(|(hook, (_, cid))| Arc::new(CidReport::new(hook, &box_id, cid)));
        let connector = self.agent.as_ref().zip(agent).and_then(|(launch, (_, cid))| {
            spawn_vsock_connector(
                launch,
                report.clone(),
                cid,
                &box_id,
                // The console's command budget only starts once the guest has
                // booted, so allow for the boot too; the stop flag still ends the
                // connector as soon as the console run does.
                Instant::now() + Duration::from_secs(u64::from(spec.timeout_secs.max(1)) * 2 + 120),
                Arc::clone(&stop),
            )
        });

        let mut outcome = drive_console(console_spec, run_id, &sock, report);
        stop.store(true, Ordering::SeqCst);
        let verdict = connector.map(|(verdict, thread)| (verdict, thread.join().unwrap_or(false)));

        // Teardown: check the proxy BEFORE killing it, then stop it, qemu, and the
        // virtiofsd daemons, and deregister. Best-effort kills — qemu may already
        // have exited (e.g. a guest `poweroff`).
        let proxy_exit = proxy.as_mut().and_then(ProxyHandle::exited);
        drop(proxy);
        let _ = child.kill();
        let _ = child.wait();
        kill_children(&mut virtiofsds);
        self.registry()?.retain(|state| state.box_id != box_id);

        // When the guest never booted (e.g. qemu exited before opening the serial),
        // the console is empty; surface qemu's own stderr there so the fault is
        // diagnosable from the result envelope rather than silent.
        let qemu_stderr = stderr_drain.and_then(|h| h.join().ok()).unwrap_or_default();
        if !outcome.booted && outcome.console.is_empty() {
            let tail = qemu_stderr.trim();
            if !tail.is_empty() {
                outcome.console = format!("[qemu stderr]\n{tail}");
            }
        }
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
}

/// [`plan_shares`], wiping the sandy-owned staging dirs if it fails.
///
/// It stages the secret first and the inputs after, so a late failure (a missing input, or with
/// digests on a failed digest read) would leave the staged secret on disk: `run` returns on the
/// error before its teardown loop (INV-1). A caller-owned `secret_dir` is not touched, it keeps its
/// own lifecycle.
fn plan_shares_or_wipe(spec: &RunSpec, dirs: &ShareDirs<'_>) -> Result<SharePlan, BackendError> {
    plan_shares(spec, dirs).inspect_err(|_| {
        for dir in [dirs.inst_dir, dirs.inputs_dir, dirs.outputs_dir] {
            if let Err(err) = wipe(dir) {
                tracing::warn!(dir = %dir.display(), %err, "failed to wipe staging after a staging error");
            }
        }
    })
}

/// Refuse a policy-carrying spec off Linux: the proxy listens on `AF_VSOCK` (vhost-vsock).
fn require_proxy_host(spec: &RunSpec, linux: bool) -> Result<(), BackendError> {
    if spec.egress.is_some() && !linux {
        return Err(BackendError::Spawn(
            "the qemu egress proxy needs a Linux host: the guest reaches it over AF_VSOCK (vhost-vsock); refusing the \
             run rather than booting without the egress boundary"
                .to_string(),
        ));
    }
    Ok(())
}

/// A random vsock CID for one agent-mode launch, never a reserved value (0 the
/// hypervisor, 1 local, 2 the host, `u32::MAX` any). Claimed by launching: a CID
/// another VM holds fails the launch ([`cid_in_use`]), which then retries.
pub(crate) fn random_agent_cid() -> u32 {
    #[allow(clippy::cast_possible_truncation, reason = "any 32 random bits will do")]
    let bits = Uuid::new_v4().as_u128() as u32;
    3 + bits % (u32::MAX - 3)
}

/// Whether a launch that never booted failed because its vsock CID was taken.
pub(crate) fn cid_in_use(outcome: &Outcome) -> bool {
    !outcome.booted && outcome.console.contains("unable to set guest cid") && outcome.console.contains("in use")
}

/// A callback told which vsock CID a launched guest holds, see [`QemuBackend::with_guest_cid_hook`].
pub type GuestCidHook = Arc<dyn Fn(&str, u32) + Send + Sync>;

/// A [`GuestCidHook`] slot; a closure has no `Debug`, so the backend's derive needs this.
#[derive(Default)]
struct HookCell(Option<GuestCidHook>);

impl std::fmt::Debug for HookCell {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(if self.0.is_some() {
            "GuestCidHook(set)"
        } else {
            "GuestCidHook(none)"
        })
    }
}

/// Fires a [`GuestCidHook`] once, when the host holds the agent link AND this attempt's own guest has booted.
///
/// The link alone proves nothing: on a CID collision the connect reaches the VM that holds the CID, and that VM's agent
/// may accept it. The boot is the proof: this attempt reads its own serial socket, so the ready marker it sees comes
/// from the guest it launched, and a qemu that lost the CID never boots. A consumer that dials the CID therefore
/// never reaches a foreign VM.
struct CidReport {
    hook: GuestCidHook,
    box_id: String,
    cid: u32,
    state: Mutex<ReportState>,
}

#[derive(Default)]
struct ReportState {
    linked: bool,
    booted: bool,
    fired: bool,
}

impl CidReport {
    fn new(hook: GuestCidHook, box_id: &str, cid: u32) -> Self {
        Self {
            hook,
            box_id: box_id.to_string(),
            cid,
            state: Mutex::new(ReportState::default()),
        }
    }

    /// The host connected to the agent at the CID.
    fn linked(&self) {
        self.step(|state| state.linked = true);
    }

    /// The guest answered the console with this run's marker.
    fn booted(&self) {
        self.step(|state| state.booted = true);
    }

    fn step(&self, set: impl FnOnce(&mut ReportState)) {
        let fire = {
            let Ok(mut state) = self.state.lock() else { return };
            set(&mut state);
            let fire = state.linked && state.booted && !state.fired;
            state.fired |= fire;
            fire
        };
        // A panicking hook must not unwind the connector thread or the console driver: the run is not its fault.
        if fire
            && std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| (self.hook)(&self.box_id, self.cid))).is_err()
        {
            tracing::warn!(box_id = self.box_id, "the guest CID hook panicked");
        }
    }
}

/// Wrap `connect` so a success marks the link in `report`.
#[cfg_attr(
    not(target_os = "linux"),
    allow(dead_code, reason = "only the Linux vsock connector calls it")
)]
fn mark_link_on_connect<S>(
    mut connect: impl FnMut() -> std::io::Result<S>,
    report: Option<Arc<CidReport>>,
) -> impl FnMut() -> std::io::Result<S> {
    move || {
        let stream = connect()?;
        if let Some(report) = &report {
            report.linked();
        }
        Ok(stream)
    }
}

/// A console [`Transport`](sandy_api::console::Transport) that tells `report` the guest booted when the command frame
/// goes out: the protocol writes it only after the run's own ready marker.
struct BootWatch<T> {
    inner: T,
    report: Option<Arc<CidReport>>,
}

impl<T: sandy_api::console::Transport> sandy_api::console::Transport for BootWatch<T> {
    fn read(&mut self, buf: &mut [u8]) -> Result<sandy_api::console::ReadEvent, BackendError> {
        self.inner.read(buf)
    }

    fn write(&mut self, bytes: &[u8]) -> Result<(), BackendError> {
        self.inner.write(bytes)?;
        if let Some(report) = &self.report {
            report.booted();
        }
        Ok(())
    }
}

/// How many fresh CIDs an agent-mode run tries before giving up.
const CID_ATTEMPTS: usize = 8;

/// The connector thread that dials the guest agent at `cid` over `AF_VSOCK`.
#[cfg(target_os = "linux")]
fn spawn_vsock_connector(
    launch: &AgentLaunch,
    report: Option<Arc<CidReport>>,
    cid: u32,
    box_id: &str,
    deadline: Instant,
    stop: Arc<AtomicBool>,
) -> Option<(
    std::sync::mpsc::Receiver<sandy_api::agent::AgentVerdict>,
    std::thread::JoinHandle<bool>,
)> {
    Some(crate::agent::spawn_connector(
        launch,
        mark_link_on_connect(
            move || vsock::VsockStream::connect_with_cid_port(cid, AGENT_VSOCK_PORT),
            report,
        ),
        box_id,
        deadline,
        stop,
    ))
}

/// No host `AF_VSOCK` off Linux: [`QemuBackend::run`] refuses agent mode first.
#[cfg(not(target_os = "linux"))]
fn spawn_vsock_connector(
    _launch: &AgentLaunch,
    _report: Option<Arc<CidReport>>,
    _cid: u32,
    _box_id: &str,
    _deadline: Instant,
    _stop: Arc<AtomicBool>,
) -> Option<(
    std::sync::mpsc::Receiver<sandy_api::agent::AgentVerdict>,
    std::thread::JoinHandle<bool>,
)> {
    None
}

/// The most recent bytes of a child's stderr to retain for diagnostics (64 KiB).
const QEMU_STDERR_CAP: usize = 64 * 1024;

/// Drain `stderr` on a thread so a chatty qemu never blocks on a full, un-read pipe
/// (the classic deadlock: an un-read [`Stdio::piped`] stalls the writer). Keeps only
/// the last [`QEMU_STDERR_CAP`] bytes, returned lossily for the failure diagnostic.
fn drain_stderr(mut stderr: std::process::ChildStderr) -> std::thread::JoinHandle<String> {
    std::thread::spawn(move || {
        use std::io::Read;
        let mut buf = Vec::new();
        let mut chunk = [0u8; 8192];
        while let Ok(n) = stderr.read(&mut chunk) {
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
            if buf.len() > QEMU_STDERR_CAP {
                buf.drain(..buf.len() - QEMU_STDERR_CAP);
            }
        }
        String::from_utf8_lossy(&buf).into_owned()
    })
}

/// An infra transport fault as an [`Outcome`] (no fabricated exit, INV-OUTCOME).
fn transport_outcome(err: &BackendError) -> Outcome {
    Outcome {
        digests: None,
        booted: false,
        guest_exit: None,
        transport_error: Some(err.to_string()),
        timed_out: false,
        console: String::new(),
    }
}

/// Connect to `sock`, retrying until it exists or the (bounded) budget elapses —
/// qemu creates the socket asynchronously after spawn.
fn connect_serial(sock: &Path, budget: Duration) -> Result<UnixStream, BackendError> {
    let deadline = Instant::now() + budget.min(Duration::from_secs(10));
    loop {
        match UnixStream::connect(sock) {
            Ok(stream) => return Ok(stream),
            Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(50)),
            Err(err) => {
                return Err(BackendError::Transport(format!(
                    "connect qemu serial {}: {err}",
                    sock.display()
                )));
            }
        }
    }
}

/// Connect the guest serial socket and drive the console protocol to an
/// [`Outcome`]. The socket read timeout is a short poll quantum, not the run
/// deadline: `run_console` enforces the deadline (and `spec.control`'s live
/// cancellation/suspension, #340/#185) itself on every idle tick, so a silent
/// guest resolves through its timeout path rather than blocking.
fn drive_console(spec: &RunSpec, run_id: Uuid, sock: &Path, report: Option<Arc<CidReport>>) -> Outcome {
    let connect_budget = Duration::from_secs(u64::from(spec.timeout_secs.max(1)));
    let stream = match connect_serial(sock, connect_budget) {
        Ok(stream) => stream,
        Err(err) => return transport_outcome(&err),
    };
    if let Err(err) = stream.set_read_timeout(Some(crate::console::POLL_QUANTUM)) {
        return transport_outcome(&BackendError::Transport(format!("set serial read timeout: {err}")));
    }
    let reader = match stream.try_clone() {
        Ok(reader) => reader,
        Err(err) => return transport_outcome(&BackendError::Transport(format!("clone serial socket: {err}"))),
    };
    let mut transport = BootWatch {
        inner: PipeTransport::new(Box::new(reader), Box::new(stream)),
        report,
    };
    let markers = Markers::for_run(READY_MARKER, run_id);
    run_console(&mut transport, spec, &markers)
}

impl VmBackend for QemuBackend {
    fn run(&self, spec: &RunSpec) -> Result<Outcome, BackendError> {
        require_proxy_host(spec, cfg!(target_os = "linux"))?;
        if self.agent.is_some() && self.agent_used.swap(true, Ordering::SeqCst) {
            return Err(BackendError::Spawn(
                "this agent-mode backend already ran its one job; build one per sandbox run".to_string(),
            ));
        }
        if self.agent.is_some() && !cfg!(target_os = "linux") {
            return Err(BackendError::Spawn(
                "qemu agent mode needs a Linux host: the host reaches the guest agent over AF_VSOCK (vhost-vsock)"
                    .to_string(),
            ));
        }
        let topology = eval_topology(spec.template)?;
        // Parsed and checked before any staging: a refused profile must not return past the shares' teardown wipe
        // (INV-1).
        let network = NetworkMode::from_env().map_err(BackendError::Spawn)?;
        let tap = std::env::var(TAP_ENV).ok().filter(|t| !t.is_empty());
        check_nic_profile(network, tap.as_deref())?;
        let agent_program: Option<PathBuf> = match &self.agent {
            Some(_) => Some(topology.agent_program.clone().ok_or_else(|| {
                BackendError::Spawn(
                    "agent mode needs a topology that names its agent (agent_program); this image carries no \
                     sandy-agent"
                        .to_string(),
                )
            })?),
            None => None,
        };
        // Proxy mode runs the relay in the guest, so the image must carry sandy-agent.
        let relay_program: Option<&Path> = match spec.egress {
            Some(_) => Some(topology.agent_program.as_deref().ok_or_else(|| {
                BackendError::Spawn(
                    "the egress proxy needs a topology that names its agent (agent_program) to run the relay; this \
                     image carries no sandy-agent"
                        .to_string(),
                )
            })?),
            None => None,
        };
        let run_id = Uuid::new_v4();
        let base = ensure_sandy_staging_base()?;
        let inst_dir = base.join(run_id.to_string());
        let inputs_dir = base.join(format!("{run_id}-inputs"));
        let outputs_dir = base.join(format!("{run_id}-outputs"));

        // Stage the shares via the shared policy (secret/input/output, read-only
        // flags, the #49 secret_dir rule). Each virtiofsd socket lives in inst_dir
        // (sandy-owned, created in `boot`); the read-only flag is enforced at the
        // virtiofsd boundary below.
        let SharePlan { shares, input_digests } = plan_shares_or_wipe(
            spec,
            &ShareDirs {
                inst_dir: &inst_dir,
                inputs_dir: &inputs_dir,
                outputs_dir: &outputs_dir,
            },
        )?;

        let mut staged = StagedArgs {
            shares,
            kvm: kvm_available(),
            // A tap is opt-in via $SANDY_TAP: the operator (or the #29 live gate)
            // creates and firewalls the tap, then names it here so the guest's NIC
            // attaches to it. Unset → no NIC, the default isolated boot.
            tap,
            agent_cid: None,
            network,
        };

        // Agent mode claims a CID by launching with it; a CID another VM holds fails
        // that launch, which is retried with a fresh one.
        let mut outcome;
        let mut attempt = 0;
        loop {
            attempt += 1;
            // Agent mode and proxy mode both need the guest to claim a CID.
            let cid = (agent_program.is_some() || spec.egress.is_some()).then(random_agent_cid);
            let agent = agent_program.as_deref().zip(cid);
            let egress = spec
                .egress
                .zip(relay_program)
                .zip(cid)
                .map(|((policy, program), cid)| EgressLaunch::new(policy, cid, program));
            staged.agent_cid = cid;
            outcome = qemu_args(&topology, spec, &staged)
                .and_then(|args| self.boot(spec, &args, &staged.shares, run_id, &inst_dir, agent, egress.as_ref()));
            let collided = cid.is_some() && outcome.as_ref().is_ok_and(cid_in_use);
            if !collided {
                break;
            }
            if attempt == CID_ATTEMPTS {
                outcome = Err(BackendError::Spawn(format!(
                    "every vsock CID tried for the agent was taken ({CID_ATTEMPTS} attempts)"
                )));
                break;
            }
            tracing::debug!(attempt, "vsock CID taken by another VM; relaunching with a new one");
        }

        // Collect outputs before wiping, but only if the guest actually booted
        // (nothing was produced otherwise). A collection failure surfaces as an
        // infra fault rather than silently dropping the output.
        let collected = if outcome.as_ref().is_ok_and(|o| o.booted) {
            collect_outputs(spec.outputs, &outputs_dir, spec.digests)
        } else {
            Ok(None)
        };

        // Teardown clears staging on every path so secret bytes never outlive
        // the run (INV-1), including the error path. The inputs/outputs dirs too.
        for dir in [&inst_dir, &inputs_dir, &outputs_dir] {
            if let Err(err) = wipe(dir) {
                tracing::warn!(dir = %dir.display(), %err, "failed to wipe staging on teardown");
            }
        }
        with_digests(outcome, input_digests, collected)
    }

    fn kill(&self, box_id: &str) -> Result<(), BackendError> {
        // Dropping the instance from the registry is the sandbox-visible effect;
        // signalling the qemu child process is host-tier (#26).
        self.registry()?.retain(|state| state.box_id != box_id);
        tracing::debug!(box_id, "dropped qemu instance from the registry");
        Ok(())
    }

    fn boxes(&self) -> Result<Vec<BoxState>, BackendError> {
        Ok(self.registry()?.clone())
    }
}

/// Whether `/dev/kvm` is usable, so the assembler can emit `-enable-kvm`.
///
/// A presence check is enough for the argv decision; the real accelerator probe
/// (open + `KVM_GET_API_VERSION`) is a host-tier concern (#26).
fn kvm_available() -> bool {
    Path::new("/dev/kvm").exists()
}

#[cfg(test)]
mod tests {
    use anyhow::Context;
    use sandy::{Grants, Hypervisor, Input, SECRET_MOUNT_TAG, SecretRef, SecretSource, parse_topology};

    use super::*;

    type Seen = Arc<Mutex<Vec<(String, u32)>>>;

    fn counting_report() -> (Arc<CidReport>, Seen) {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let hook: GuestCidHook = {
            let seen = Arc::clone(&seen);
            Arc::new(move |box_id, cid| seen.lock().expect("seen").push((box_id.to_string(), cid)))
        };
        (Arc::new(CidReport::new(hook, "box-1", 77)), seen)
    }

    /// A guest that holds the CID's agent answers the link but never boots under this run's marker (a collision).
    #[test]
    fn a_link_without_a_boot_never_reports_the_cid() {
        let (report, seen) = counting_report();
        let mut connect = mark_link_on_connect(|| Ok::<_, std::io::Error>(()), Some(Arc::clone(&report)));
        assert!(connect().is_ok());
        assert!(connect().is_ok());
        assert!(seen.lock().expect("seen").is_empty());
    }

    /// A console that replays `chunks`, then reports it closed; every write is kept.
    struct ReplayConsole {
        chunks: std::collections::VecDeque<Vec<u8>>,
        written: Vec<Vec<u8>>,
    }

    impl ReplayConsole {
        fn new(chunks: &[&str]) -> Self {
            Self {
                chunks: chunks.iter().map(|c| c.as_bytes().to_vec()).collect(),
                written: Vec::new(),
            }
        }
    }

    impl sandy_api::console::Transport for ReplayConsole {
        fn read(&mut self, buf: &mut [u8]) -> Result<sandy_api::console::ReadEvent, BackendError> {
            let Some(chunk) = self.chunks.pop_front() else {
                return Ok(sandy_api::console::ReadEvent::Closed);
            };
            buf[..chunk.len()].copy_from_slice(&chunk);
            Ok(sandy_api::console::ReadEvent::Data(chunk.len()))
        }

        fn write(&mut self, bytes: &[u8]) -> Result<(), BackendError> {
            self.written.push(bytes.to_vec());
            Ok(())
        }
    }

    /// The wiring, not only the state machine: the console driver writes the command frame once the run's ready marker
    /// arrives, and that write is what marks the boot.
    #[test]
    fn a_console_that_reaches_the_ready_marker_reports_the_cid() {
        let (report, seen) = counting_report();
        report.linked();
        let command = ["true".to_string()];
        let mut console = BootWatch {
            inner: ReplayConsole::new(&[&format!("{READY_MARKER}\n")]),
            report: Some(report),
        };
        let outcome = run_console(
            &mut console,
            &demo_spec(&command),
            &Markers::for_run(READY_MARKER, Uuid::new_v4()),
        );
        assert!(outcome.booted, "{outcome:?}");
        assert_eq!(*seen.lock().expect("seen"), vec![("box-1".to_string(), 77)]);
    }

    /// A qemu that lost the CID never prints the ready marker, so its console closes unbooted and nothing is reported
    /// even though the connect reached another VM.
    #[test]
    fn a_console_that_never_boots_does_not_report_the_cid() {
        let (report, seen) = counting_report();
        report.linked();
        let command = ["true".to_string()];
        let mut console = BootWatch {
            inner: ReplayConsole::new(&["qemu: unable to set guest cid: in use\n"]),
            report: Some(report),
        };
        let outcome = run_console(
            &mut console,
            &demo_spec(&command),
            &Markers::for_run(READY_MARKER, Uuid::new_v4()),
        );
        assert!(!outcome.booted, "{outcome:?}");
        assert!(seen.lock().expect("seen").is_empty());
    }

    #[test]
    fn a_boot_without_a_link_never_reports_the_cid() {
        let (report, seen) = counting_report();
        report.booted();
        assert!(seen.lock().expect("seen").is_empty());
    }

    #[test]
    fn the_cid_is_reported_once_whatever_the_order() {
        for boot_first in [true, false] {
            let (report, seen) = counting_report();
            if boot_first {
                report.booted();
                report.linked();
            } else {
                report.linked();
                report.booted();
            }
            report.linked();
            report.booted();
            assert_eq!(*seen.lock().expect("seen"), vec![("box-1".to_string(), 77)]);
        }
    }

    #[test]
    fn a_failed_connect_does_not_mark_the_link() {
        let (report, seen) = counting_report();
        let mut connect = mark_link_on_connect(
            || Err::<(), _>(std::io::Error::other("refused")),
            Some(Arc::clone(&report)),
        );
        assert!(connect().is_err());
        report.booted();
        assert!(seen.lock().expect("seen").is_empty());
    }

    #[test]
    fn a_panicking_hook_does_not_unwind_the_caller() {
        let report = CidReport::new(Arc::new(|_, _| panic!("hook bug")), "b", 1);
        report.linked();
        report.booted();
    }

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

    /// A shared, reusable control handle for tests that don't exercise
    /// cancellation/deadline behavior themselves (#340).
    fn test_control() -> &'static sandy_api::backend::RunControl {
        static CONTROL: std::sync::OnceLock<sandy_api::backend::RunControl> = std::sync::OnceLock::new();
        CONTROL.get_or_init(|| sandy_api::backend::RunControl::with_timeout_secs(60))
    }

    /// An override takes priority over arch derivation entirely, whatever
    /// the kernel path says.
    #[test]
    fn qemu_system_binary_override_wins_over_arch_derivation() {
        assert_eq!(
            qemu_system_binary_with_override(Path::new("/nix/store/x-linux-6.6-aarch64/Image"), Some("/abs/qemu")),
            "/abs/qemu"
        );
    }

    /// No override: falls back to the existing arch-derived bare name.
    #[test]
    fn qemu_system_binary_falls_back_to_arch_derivation_without_an_override() {
        assert_eq!(
            qemu_system_binary_with_override(Path::new("/nix/store/x-linux-6.6-x86_64/Image"), None),
            "qemu-system-x86_64"
        );
    }

    /// Tier-1: `qemu_args` over the x86_64 fixture and a trivial spec emits the
    /// key boot flags (`-kernel`/`-initrd`/`-append`/`-nographic`/`-serial`/
    /// `-smp`/`-m`), the topology's cpu/mem, and the erofs store as a read-only
    /// virtio-blk drive. RED until `qemu_args` is implemented (todo!() panics).
    #[test]
    fn qemu_args_from_x86_64_topology() -> anyhow::Result<()> {
        let topology = parse_topology(X86_64_FIXTURE).context("parse x86_64 fixture")?;
        let command = ["true".to_string()];
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
            grants: &NO_GRANTS,
            outcome_file: None,
            secret_dir: None,
            control: test_control(),
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

    /// Tier-1: with `/dev/kvm` usable and a secret, `qemu_args` emits
    /// `-enable-kvm -cpu host` and threads the secret share into the argv.
    #[test]
    fn qemu_args_enables_kvm_and_threads_secret_share() -> anyhow::Result<()> {
        let topology = parse_topology(X86_64_FIXTURE).context("parse x86_64 fixture")?;
        let staged = StagedArgs {
            shares: vec![ShareSpec {
                host_dir: "/tmp/inst".into(),
                tag: SECRET_MOUNT_TAG.to_string(),
                readonly: true,
                socket: "/tmp/inst/vfsd-secrets.sock".into(),
            }],
            kvm: true,
            tap: None,
            agent_cid: None,
            network: NetworkMode::None,
        };
        let command = ["true".to_string()];
        let grants = Grants {
            secrets: true,
            agent: false,
            shares: false,
        };
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

        let args = qemu_args(&topology, &spec, &staged).context("assemble qemu argv")?;

        let joined = args.join(" ");
        assert!(
            args.iter().any(|arg| arg == "-enable-kvm"),
            "KVM acceleration flag: {args:?}"
        );
        assert!(args.iter().any(|arg| arg == "-cpu"), "-cpu flag present: {args:?}");
        assert!(joined.contains("host"), "-cpu host passthrough: {joined}");
        assert!(
            joined.contains(SECRET_MOUNT_TAG),
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
            grants: &NO_GRANTS,
            outcome_file: None,
            secret_dir: None,
            control: test_control(),
        };
        let staged = StagedArgs::default();

        let result = qemu_args(&topology, &spec, &staged);

        assert!(
            result.is_err(),
            "a vfkit topology must be rejected by the qemu-only backend, got {result:?}"
        );
        Ok(())
    }

    /// #373 review: `plan_shares` stages the secret first and the inputs after, so a late failure
    /// (here a missing input; with digests on, a failed digest read) leaves the staged secret on disk
    /// unless the staging is wiped (INV-1). The control shows the plain call leaks; the helper must not.
    #[test]
    fn a_staging_failure_wipes_the_qemu_owned_staging_with_its_secret() -> anyhow::Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir()?;
        let secret_src = tmp.path().join("secret-src");
        std::fs::write(&secret_src, b"S")?;
        std::fs::set_permissions(&secret_src, std::fs::Permissions::from_mode(0o600))?;
        let secrets = [SecretRef {
            name: "TOK".to_string(),
            source: SecretSource::File(secret_src),
        }];
        let inputs = [Input {
            host: tmp.path().join("no-such-input"),
            name: "in".to_string(),
            guest_path: None,
        }];
        let command = ["true".to_string()];
        let spec = RunSpec {
            secrets: &secrets,
            inputs: &inputs,
            ..demo_spec(&command)
        };
        let dirs_under = |name: &str| {
            (
                tmp.path().join(name),
                tmp.path().join(format!("{name}-in")),
                tmp.path().join(format!("{name}-out")),
            )
        };

        // Control: the plain call fails after staging the secret and leaves it behind.
        let (inst, inputs_dir, outputs_dir) = dirs_under("plain");
        let plain = plan_shares(
            &spec,
            &ShareDirs {
                inst_dir: &inst,
                inputs_dir: &inputs_dir,
                outputs_dir: &outputs_dir,
            },
        );
        anyhow::ensure!(plain.is_err(), "a missing input must fail staging");
        anyhow::ensure!(
            inst.join("TOK").exists(),
            "the control must leave the staged secret behind, or this test proves nothing"
        );

        // The helper fails the same way and leaves no staging behind.
        let (inst, inputs_dir, outputs_dir) = dirs_under("wiped");
        let wiped = plan_shares_or_wipe(
            &spec,
            &ShareDirs {
                inst_dir: &inst,
                inputs_dir: &inputs_dir,
                outputs_dir: &outputs_dir,
            },
        );
        anyhow::ensure!(wiped.is_err(), "the helper must return the staging error");
        for dir in [&inst, &inputs_dir, &outputs_dir] {
            anyhow::ensure!(!dir.exists(), "{} must be wiped after a staging error", dir.display());
        }
        Ok(())
    }

    fn demo_spec<'a>(command: &'a [String]) -> RunSpec<'a> {
        RunSpec {
            digests: false,
            template: "demo",
            command,
            inputs: &[],
            outputs: &[],
            secrets: &[],
            env: &[],
            cpu: None,
            mem: None,
            timeout_secs: 60,
            grants: &NO_GRANTS,
            outcome_file: None,
            secret_dir: None,
            control: test_control(),
            egress: None,
        }
    }

    fn allow_all_github() -> sandy_api::egress::AllowList {
        sandy_api::egress::AllowList {
            rules: vec![sandy_api::egress::EgressRule {
                host: "github.com".to_string(),
                port: 443,
            }],
        }
    }

    /// #404: the proxy listens on AF_VSOCK, so a policy-carrying spec is refused off Linux, before
    /// anything boots. A spec without a policy is never refused.
    #[test]
    fn a_policy_carrying_spec_is_refused_off_linux() -> anyhow::Result<()> {
        let allow = allow_all_github();
        let command = ["true".to_string()];
        let spec = RunSpec {
            digests: false,
            egress: Some(&allow),
            ..demo_spec(&command)
        };
        let refused = require_proxy_host(&spec, false);
        let Err(BackendError::Spawn(message)) = refused else {
            anyhow::bail!("expected a Spawn refusal, got {refused:?}");
        };
        anyhow::ensure!(message.contains("egress proxy"), "unexpected refusal: {message}");
        anyhow::ensure!(require_proxy_host(&spec, true).is_ok(), "Linux must be accepted");
        anyhow::ensure!(
            require_proxy_host(&demo_spec(&command), false).is_ok(),
            "no policy, no refusal"
        );
        Ok(())
    }

    /// #404: proxy mode claims a vsock CID and emits no NIC.
    #[test]
    fn qemu_args_in_proxy_mode_attach_the_cid_and_no_nic() -> anyhow::Result<()> {
        let topology = parse_topology(X86_64_FIXTURE).context("parse x86_64 fixture")?;
        let allow = allow_all_github();
        let command = ["true".to_string()];
        let spec = RunSpec {
            egress: Some(&allow),
            ..demo_spec(&command)
        };
        let staged = StagedArgs {
            agent_cid: Some(1234),
            ..StagedArgs::default()
        };
        let args = qemu_args(&topology, &spec, &staged)?;
        let joined = args.join(" ");
        let vsock: Vec<&String> = args.iter().filter(|a| a.starts_with("vhost-vsock-pci")).collect();
        assert_eq!(vsock, vec!["vhost-vsock-pci,guest-cid=1234"], "{joined}");
        assert!(!joined.contains("-netdev"), "{joined}");
        assert!(!joined.contains("virtio-net"), "{joined}");
        assert_nic_none(&args)?;
        Ok(())
    }

    /// #602: the default emits no NIC; the tap NIC needs `nic` and a tap together, and never the proxy.
    #[test]
    fn qemu_args_gate_the_nic_on_network_mode() -> anyhow::Result<()> {
        let topology = parse_topology(X86_64_FIXTURE).context("parse x86_64 fixture")?;
        let command = ["true".to_string()];
        let plain = qemu_args(&topology, &demo_spec(&command), &StagedArgs::default())?;
        anyhow::ensure!(!plain.join(" ").contains("virtio-net"), "default: {plain:?}");
        assert_nic_none(&plain)?;
        let refusal = |staged: &StagedArgs, spec: &RunSpec<'_>| match qemu_args(&topology, spec, staged) {
            Err(BackendError::Spawn(m)) => Ok(m),
            other => Err(anyhow::anyhow!("expected a refusal, got {other:?}")),
        };
        let tap = Some("tap0".to_string());
        let nic_no_tap = StagedArgs {
            network: NetworkMode::Nic,
            ..StagedArgs::default()
        };
        anyhow::ensure!(refusal(&nic_no_tap, &demo_spec(&command))?.contains("bound tap"));
        let tap_no_nic = StagedArgs {
            tap: tap.clone(),
            ..StagedArgs::default()
        };
        anyhow::ensure!(refusal(&tap_no_nic, &demo_spec(&command))?.contains("needs SANDY_NETWORK=nic"));
        let bad_tap = StagedArgs {
            tap: Some("tap0,vhost=on".to_string()),
            network: NetworkMode::Nic,
            ..StagedArgs::default()
        };
        anyhow::ensure!(refusal(&bad_tap, &demo_spec(&command))?.contains("valid interface name"));
        let nic_tap = StagedArgs {
            tap,
            network: NetworkMode::Nic,
            ..StagedArgs::default()
        };
        let allow = allow_all_github();
        let proxy_spec = RunSpec {
            egress: Some(&allow),
            ..demo_spec(&command)
        };
        anyhow::ensure!(refusal(&nic_tap, &proxy_spec)?.contains("exclusive"));
        let args = qemu_args(&topology, &demo_spec(&command), &nic_tap)?;
        anyhow::ensure!(
            args.windows(2)
                .any(|w| w[0] == "-netdev" && w[1] == "tap,id=net0,ifname=tap0,script=no,downscript=no"),
            "nic + tap: {args:?}"
        );
        anyhow::ensure!(
            !args.windows(2).any(|w| w[0] == "-nic"),
            "no `-nic none` with a NIC: {args:?}"
        );
        Ok(())
    }

    /// qemu adds a default user-mode NIC unless told otherwise, so a "no NIC" argv must say `-nic none`
    /// (#406: the live gate found `ens3` in a proxy-mode guest).
    fn assert_nic_none(args: &[String]) -> anyhow::Result<()> {
        anyhow::ensure!(
            args.windows(2).any(|w| w[0] == "-nic" && w[1] == "none"),
            "no tap must pass `-nic none`: {args:?}"
        );
        Ok(())
    }

    /// #404: proxy mode and `$SANDY_TAP` are exclusive, and the proxy needs a CID.
    #[test]
    fn qemu_args_refuse_proxy_mode_with_a_tap_or_without_a_cid() -> anyhow::Result<()> {
        let mut topology = parse_topology(X86_64_FIXTURE).context("parse x86_64 fixture")?;
        let allow = allow_all_github();
        let command = ["true".to_string()];
        let spec = RunSpec {
            egress: Some(&allow),
            ..demo_spec(&command)
        };
        let with_tap = StagedArgs {
            agent_cid: Some(9),
            tap: Some("tap0".to_string()),
            ..StagedArgs::default()
        };
        let refused = qemu_args(&topology, &spec, &with_tap);
        anyhow::ensure!(
            matches!(&refused, Err(BackendError::Spawn(m)) if m.contains("exclusive")),
            "tap: {refused:?}"
        );
        topology.vsock_cid = None;
        let refused = qemu_args(&topology, &spec, &StagedArgs::default());
        anyhow::ensure!(
            matches!(&refused, Err(BackendError::Spawn(m)) if m.contains("vsock CID")),
            "cid: {refused:?}"
        );
        Ok(())
    }

    /// A stub qemu that never opens the serial socket, so the console fails to connect within the
    /// 1 s test budget. Writes a marker so a test can prove qemu was (not) spawned.
    fn stub_qemu(dir: &Path, marker: &Path) -> anyhow::Result<PathBuf> {
        crate::egress_proxy::tests::stub(
            dir,
            "qemu",
            &format!("echo spawned > {}; exec sleep 30", marker.display()),
        )
    }

    fn pid_alive(pid: u32) -> bool {
        Command::new("kill")
            .args(["-0", &pid.to_string()])
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    }

    fn quick_spec<'a>(command: &'a [String], allow: &'a sandy_api::egress::AllowList) -> RunSpec<'a> {
        RunSpec {
            timeout_secs: 1,
            egress: Some(allow),
            ..demo_spec(command)
        }
    }

    /// #404: a proxy that never prints READY fails the launch before qemu spawns, and the
    /// virtiofsd daemons already up are killed.
    #[test]
    fn a_proxy_that_never_becomes_ready_fails_before_qemu_and_kills_the_daemons() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let marker = dir.path().join("qemu-ran");
        let qemu = stub_qemu(dir.path(), &marker)?;
        let proxy_bin = crate::egress_proxy::tests::stub(dir.path(), "proxy", "cat >/dev/null; exec sleep 30")?;
        let allow = allow_all_github();
        let command = ["true".to_string()];
        let spec = quick_spec(&command, &allow);
        let program = PathBuf::from("/nix/store/a-sandy-agent/bin/sandy-agent");
        let mut egress = EgressLaunch::new(&allow, 77, &program);
        egress.bin = proxy_bin;
        egress.ready_deadline = Duration::from_millis(300);
        let daemon = Command::new("sleep")
            .arg("30")
            .spawn()
            .context("spawn stand-in virtiofsd")?;
        let daemon_pid = daemon.id();
        let backend = QemuBackend::new();
        let inst = dir.path().join("inst");
        let args = vec![qemu.display().to_string()];
        let result = backend.launch(&spec, &args, Uuid::new_v4(), &inst, None, Some(&egress), vec![daemon]);
        let Err(BackendError::Spawn(message)) = result else {
            anyhow::bail!("expected Spawn, got {result:?}");
        };
        anyhow::ensure!(message.starts_with("egress proxy did not start"), "{message}");
        anyhow::ensure!(!marker.exists(), "qemu must not spawn after a proxy start failure");
        anyhow::ensure!(!pid_alive(daemon_pid), "the virtiofsd daemon must be killed");
        Ok(())
    }

    /// #404: a proxy that exits after READY makes the run an `EgressProxyDied`, whatever the guest
    /// did, and no process outlives the run.
    #[test]
    fn a_proxy_that_exits_early_makes_the_run_egress_proxy_died() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let marker = dir.path().join("qemu-ran");
        let qemu = stub_qemu(dir.path(), &marker)?;
        let proxy_bin = crate::egress_proxy::tests::stub(dir.path(), "proxy", "cat >/dev/null; echo READY; exit 3")?;
        let allow = allow_all_github();
        let command = ["true".to_string()];
        let spec = quick_spec(&command, &allow);
        let program = PathBuf::from("/nix/store/a-sandy-agent/bin/sandy-agent");
        let mut egress = EgressLaunch::new(&allow, 77, &program);
        egress.bin = proxy_bin;
        let daemon = Command::new("sleep")
            .arg("30")
            .spawn()
            .context("spawn stand-in virtiofsd")?;
        let daemon_pid = daemon.id();
        let backend = QemuBackend::new();
        let inst = dir.path().join("inst");
        sandy_fsutil::OwnedDir::open_or_create(&inst).context("inst dir")?;
        let args = vec![qemu.display().to_string()];
        let result = backend.launch(&spec, &args, Uuid::new_v4(), &inst, None, Some(&egress), vec![daemon]);
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
        anyhow::ensure!(marker.exists(), "qemu did spawn in this scenario");
        anyhow::ensure!(!pid_alive(daemon_pid), "the virtiofsd daemon must be killed");
        Ok(())
    }

    /// #404: a healthy proxy is not read as dead, and the backend's own kill stops it.
    #[test]
    fn a_live_proxy_is_not_a_death_and_is_killed_at_teardown() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let marker = dir.path().join("qemu-ran");
        let pidfile = dir.path().join("proxy-pid");
        let qemu = stub_qemu(dir.path(), &marker)?;
        let proxy_bin = crate::egress_proxy::tests::stub(
            dir.path(),
            "proxy",
            &format!(
                "echo $$ > {}; cat >/dev/null; echo READY; exec sleep 30",
                pidfile.display()
            ),
        )?;
        let allow = allow_all_github();
        let command = ["true".to_string()];
        let spec = quick_spec(&command, &allow);
        let program = PathBuf::from("/nix/store/a-sandy-agent/bin/sandy-agent");
        let mut egress = EgressLaunch::new(&allow, 77, &program);
        egress.bin = proxy_bin;
        let backend = QemuBackend::new();
        let inst = dir.path().join("inst");
        sandy_fsutil::OwnedDir::open_or_create(&inst).context("inst dir")?;
        let args = vec![qemu.display().to_string()];
        let outcome = backend
            .launch(&spec, &args, Uuid::new_v4(), &inst, None, Some(&egress), Vec::new())
            .context("a live proxy must not fail the run")?;
        anyhow::ensure!(!outcome.booted, "the stub qemu never boots: {outcome:?}");
        let pid: u32 = std::fs::read_to_string(&pidfile)?.trim().parse().context("proxy pid")?;
        anyhow::ensure!(!pid_alive(pid), "the proxy must be killed at teardown");
        Ok(())
    }

    /// #238: an agent-mode launch claims its CID on the vhost-vsock device, in
    /// place of any CID the topology names; only one vsock device is attached.
    #[test]
    fn qemu_args_attach_the_agent_cid() -> anyhow::Result<()> {
        let topology = parse_topology(X86_64_FIXTURE).context("parse x86_64 fixture")?;
        let command = ["true".to_string()];
        let staged = StagedArgs {
            agent_cid: Some(77),
            ..StagedArgs::default()
        };
        let args = qemu_args(&topology, &demo_spec(&command), &staged)?;
        let vsock: Vec<&String> = args.iter().filter(|a| a.starts_with("vhost-vsock-pci")).collect();
        assert_eq!(vsock, vec!["vhost-vsock-pci,guest-cid=77"], "{}", args.join(" "));
        Ok(())
    }

    #[test]
    fn a_random_agent_cid_is_never_reserved() {
        for _ in 0..10_000 {
            let cid = random_agent_cid();
            assert!((3..u32::MAX).contains(&cid), "reserved cid {cid}");
        }
    }

    fn never_booted(console: &str) -> Outcome {
        Outcome {
            digests: None,
            booted: false,
            guest_exit: None,
            transport_error: None,
            timed_out: false,
            console: console.to_string(),
        }
    }

    /// #238: a launch whose CID another VM holds is recognised (and retried with
    /// a new one); any other boot failure is not.
    #[test]
    fn a_taken_cid_is_recognised_and_nothing_else_is() {
        let taken = "[qemu stderr]\nqemu-system-x86_64: -device vhost-vsock-pci,guest-cid=77: vhost-vsock: unable to \
                     set guest cid: Address already in use";
        assert!(cid_in_use(&never_booted(taken)));
        assert!(!cid_in_use(&never_booted(
            "[qemu stderr]\nCould not access KVM kernel module"
        )));
        let mut booted = never_booted(taken);
        booted.booted = true;
        assert!(!cid_in_use(&booted), "a booted guest did not fail on its cid");
    }

    /// Tier-1 (#29): with a tap bound, `qemu_args` emits the `-netdev tap,…,
    /// ifname=<tap>` + `virtio-net-pci` NIC pair so the guest has egress to filter.
    #[test]
    fn qemu_args_emits_a_tap_nic_when_a_tap_is_bound() -> anyhow::Result<()> {
        let topology = parse_topology(X86_64_FIXTURE).context("parse x86_64 fixture")?;
        let command = ["true".to_string()];
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
            grants: &NO_GRANTS,
            outcome_file: None,
            secret_dir: None,
            control: test_control(),
        };
        let staged = StagedArgs {
            tap: Some("sandytap0".to_string()),
            network: NetworkMode::Nic,
            ..StagedArgs::default()
        };

        let args = qemu_args(&topology, &spec, &staged).context("assemble qemu argv")?;

        assert!(
            args.windows(2)
                .any(|w| w[0] == "-netdev" && w[1] == "tap,id=net0,ifname=sandytap0,script=no,downscript=no"),
            "a bound tap must emit the `-netdev tap,…,ifname=<tap>` pair: {args:?}"
        );
        assert!(
            args.windows(2)
                .any(|w| w[0] == "-device" && w[1].starts_with("virtio-net-pci,netdev=net0,mac=")),
            "a bound tap must emit the virtio-net device: {args:?}"
        );
        Ok(())
    }

    /// Tier-1 (#29): with NO tap (the default), `qemu_args` emits no NIC — the
    /// existing isolated boot is unchanged.
    #[test]
    fn qemu_args_emits_no_nic_without_a_tap() -> anyhow::Result<()> {
        let topology = parse_topology(X86_64_FIXTURE).context("parse x86_64 fixture")?;
        let command = ["true".to_string()];
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
            grants: &NO_GRANTS,
            outcome_file: None,
            secret_dir: None,
            control: test_control(),
        };
        let staged = StagedArgs::default();

        let args = qemu_args(&topology, &spec, &staged).context("assemble qemu argv")?;

        let joined = args.join(" ");
        assert!(
            !joined.contains("-netdev") && !joined.contains("virtio-net"),
            "no tap must emit no NIC: {joined}"
        );
        assert_nic_none(&args)?;
        Ok(())
    }

    /// Tier-3 (host-gated, a Linux/KVM host): a trivial job boots on a real Linux/KVM node
    /// over the #33 pipe transport, returns a populated [`Outcome`], and
    /// `boxes`/`kill` work across the four distinct outcomes. Never run in the
    /// sandbox (INV-S9: no green from a fake); binds into #26/#27.
    #[test]
    #[ignore = "tier-3: real qemu/KVM boot on a Linux node over the pipe transport; host-gated, binds into #26/#27"]
    fn boots_a_trivial_job_on_kvm() -> anyhow::Result<()> {
        let backend = QemuBackend::new();
        let command = ["true".to_string()];
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
            grants: &NO_GRANTS,
            outcome_file: None,
            secret_dir: None,
            control: test_control(),
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

    /// Tier-3 (#185/#340): suspending a real KVM-backed job's `RunControl`
    /// deadline before it runs lets it survive well past its own declared
    /// `timeout_secs`, proving the fix end to end (argv → qemu → serial console
    /// → `run_console`), not just at the `run_console` unit level.
    #[test]
    #[ignore = "tier-3: real qemu/KVM boot on a Linux node; host-gated (INV-S9), binds into #185/#340"]
    fn suspending_the_control_survives_past_the_jobs_timeout_on_kvm() -> anyhow::Result<()> {
        let backend = QemuBackend::new();
        let command = ["sh".to_string(), "-c".to_string(), "sleep 20; echo done".to_string()];
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
            grants: &NO_GRANTS,
            outcome_file: None,
            secret_dir: None,
            control: &control,
        };

        let outcome = backend.run(&spec).context("boot the job on KVM")?;
        assert!(
            !outcome.timed_out,
            "a suspended deadline must survive well past the 5s budget: {outcome:?}"
        );
        assert_eq!(outcome.guest_exit, Some(0), "console: {}", outcome.console);
        Ok(())
    }

    /// Tier-3 (#185/#340): `daemon cancel` ends a real KVM-backed job promptly,
    /// well before its own long declared `timeout_secs`.
    #[test]
    #[ignore = "tier-3: real qemu/KVM boot on a Linux node; host-gated (INV-S9), binds into #185/#340"]
    fn cancelling_the_control_ends_a_running_job_on_kvm() -> anyhow::Result<()> {
        let backend = QemuBackend::new();
        let command = ["sh".to_string(), "-c".to_string(), "sleep 60".to_string()];
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
            grants: &NO_GRANTS,
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
        let outcome = outcome.context("boot the job on KVM")?;

        // The fixed 5s sleep before cancelling can't be synchronized against
        // real boot completion (`run_console`'s own boot-ready signal isn't
        // observable from outside the blocking `backend.run()` call), so a
        // slow boot can land the cancel during the boot phase rather than the
        // command phase. Both are a correct "cancel ended it" outcome —
        // `booted: false, timed_out: false` (cancelled before the guest ever
        // reported ready) or `booted: true, timed_out: true` (cancelled mid
        // command) — the test only needs to prove cancellation ends the run
        // promptly, not which phase it landed in. `transport_error` must be
        // None either way: a genuine pre-boot infra fault (QEMU never opened
        // its serial socket) also produces `booted: false`, which would
        // otherwise let an unrelated boot failure pass as proof of
        // cancellation (CodeRabbit on #366) — `transport_fault` is the only
        // path that ever sets this field, and cancellation never goes
        // through it.
        assert!(
            outcome.transport_error.is_none(),
            "an unrelated transport fault must not be mistaken for cancellation: {outcome:?}"
        );
        // `run_duration` below 5s means `backend.run` returned before
        // cancel() was even sent — it ended on its own, so this run proves
        // nothing about cancellation (CodeRabbit on #366).
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

    /// Regression: an un-drained `piped` stderr deadlocks a chatty child once it
    /// writes past the pipe buffer (the bug behind qemu booting to an empty console
    /// and a band-3 fault). `drain_stderr` consumes it so the child always finishes,
    /// and keeps the last `QEMU_STDERR_CAP` bytes for the fault diagnostic.
    #[test]
    fn drain_stderr_consumes_a_flood_without_blocking() -> anyhow::Result<()> {
        use std::process::{Command, Stdio};

        // ~200 KiB to stderr, far past the ~64 KiB pipe buffer: an un-drained pipe
        // would block this child indefinitely.
        let mut child = Command::new("sh")
            .args(["-c", "head -c 200000 /dev/zero | tr '\\0' x 1>&2"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .context("spawn flood child")?;
        let drain = super::drain_stderr(child.stderr.take().context("stderr was piped")?);
        let status = child.wait().context("wait flood child")?;
        let captured = drain.join().map_err(|_| anyhow::anyhow!("drain thread panicked"))?;

        assert!(
            status.success(),
            "a drained child must finish, not block on a full pipe"
        );
        assert_eq!(captured.len(), super::QEMU_STDERR_CAP, "retain exactly the last 64 KiB");
        assert!(
            captured.bytes().all(|b| b == b'x'),
            "the captured bytes are the stderr flood"
        );
        Ok(())
    }
}
