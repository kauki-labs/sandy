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
//!   the #33 [`PipeTransport`](sandy::PipeTransport), drives [`run_console`](sandy::run_console), and populates the
//!   pinned [`Outcome`]. The spawn/boot is host-tier (tier-3), not unit-tested in the sandbox.
//!
//! The module is private; `sandy-backend`'s `lib.rs` re-exports only
//! [`QemuBackend`], [`qemu_args`], and [`StagedArgs`].

use std::{
    os::unix::net::UnixStream,
    path::Path,
    process::{Command, Stdio},
    sync::{Mutex, MutexGuard},
    time::{Duration, Instant, SystemTime},
};

use sandy::{
    BackendError, BoxState, Hypervisor, Markers, Outcome, PipeTransport, RunSpec, StoreBacking, Topology, VmBackend,
    collect_outputs, run_console, topology as eval_topology, wipe,
};
use uuid::Uuid;

use crate::share::{GuestShareTransport, ShareDirs, ShareSpec, VirtiofsdTransport, kill_children, plan_shares};

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
/// - a `-netdev tap,…,ifname=<tap> -device virtio-net-pci,…` NIC pair when `staged.tap` is set (so the guest has egress
///   to filter, #29); nothing when it is `None` (the default isolated boot).
/// - `-device vhost-vsock-pci,guest-cid=<cid>` when `topology.vsock_cid` is set.
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
    }

    // The virtio-fs shares: a shared memfd memory backend plus a client chardev +
    // `vhost-user-fs-pci` device per share. The matching virtiofsd daemons are
    // launched by [`QemuBackend::boot`]. readonly is a virtiofsd flag, not a qemu arg.
    args.extend(VirtiofsdTransport.device_args(&staged.shares, mem));

    if let Some(cid) = topology.vsock_cid {
        args.push("-device".to_string());
        args.push(format!("vhost-vsock-pci,guest-cid={cid}"));
    }

    Ok(args)
}

/// Derive the `qemu-system-<arch>` binary from the kernel store path, falling
/// back to the host architecture.
///
/// microvm.nix kernel paths carry the arch in the linux derivation name
/// (`…-linux-6.6-aarch64/Image`); when none is present (the x86_64 kernel is just
/// `…-linux-6.6/bzImage`), the host arch ([`std::env::consts::ARCH`]) is used,
/// since a native qemu boot runs on the matching host.
fn qemu_system_binary(kernel: &Path) -> String {
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
    /// The boxes this backend has launched and not yet reaped, read by
    /// [`boxes`](VmBackend::boxes) and pruned by [`kill`](VmBackend::kill).
    instances: Mutex<Vec<BoxState>>,
}

impl QemuBackend {
    /// A backend with an empty instance registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
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
    fn boot(
        &self,
        spec: &RunSpec,
        args: &[String],
        shares: &[ShareSpec],
        run_id: Uuid,
        inst_dir: &Path,
    ) -> Result<Outcome, BackendError> {
        std::fs::create_dir_all(inst_dir)
            .map_err(|err| BackendError::Spawn(format!("create instance dir {}: {err}", inst_dir.display())))?;
        let sock = inst_dir.join("serial.sock");

        // Launch a virtiofsd per share and wait for its socket before qemu starts:
        // qemu connects to each as a client chardev, so the socket must exist first.
        // A launch or socket fault kills any daemon already up and fails the boot.
        let mut virtiofsds = VirtiofsdTransport.launch(shares)?;

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

        let mut outcome = drive_console(spec, run_id, &sock);

        // Teardown: stop qemu, then the virtiofsd daemons, and deregister. Best-effort
        // kills — qemu may already have exited (e.g. a guest `poweroff`).
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
        Ok(outcome)
    }
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
/// [`Outcome`]. The socket read timeout carries the run deadline, so a silent
/// guest resolves through the protocol's timeout path rather than blocking.
fn drive_console(spec: &RunSpec, run_id: Uuid, sock: &Path) -> Outcome {
    let budget = Duration::from_secs(u64::from(spec.timeout_secs.max(1)));
    let stream = match connect_serial(sock, budget) {
        Ok(stream) => stream,
        Err(err) => return transport_outcome(&err),
    };
    if let Err(err) = stream.set_read_timeout(Some(budget)) {
        return transport_outcome(&BackendError::Transport(format!("set serial read timeout: {err}")));
    }
    let reader = match stream.try_clone() {
        Ok(reader) => reader,
        Err(err) => return transport_outcome(&BackendError::Transport(format!("clone serial socket: {err}"))),
    };
    let mut transport = PipeTransport::new(Box::new(reader), Box::new(stream));
    let markers = Markers::for_run(READY_MARKER, run_id);
    run_console(&mut transport, spec, &markers)
}

impl VmBackend for QemuBackend {
    fn run(&self, spec: &RunSpec) -> Result<Outcome, BackendError> {
        let topology = eval_topology(spec.template)?;
        let run_id = Uuid::new_v4();
        let base = std::env::temp_dir().join("sandy");
        let inst_dir = base.join(run_id.to_string());
        let inputs_dir = base.join(format!("{run_id}-inputs"));
        let outputs_dir = base.join(format!("{run_id}-outputs"));

        // Stage the shares via the shared policy (secret/input/output, read-only
        // flags, the #49 secret_dir rule). Each virtiofsd socket lives in inst_dir
        // (sandy-owned, created in `boot`); the read-only flag is enforced at the
        // virtiofsd boundary below.
        let shares = plan_shares(
            spec,
            &ShareDirs {
                inst_dir: &inst_dir,
                inputs_dir: &inputs_dir,
                outputs_dir: &outputs_dir,
            },
        )?;

        let staged = StagedArgs {
            shares,
            kvm: kvm_available(),
            // A tap is opt-in via $SANDY_TAP: the operator (or the #29 live gate)
            // creates and firewalls the tap, then names it here so the guest's NIC
            // attaches to it. Unset → no NIC, the default isolated boot.
            tap: std::env::var(TAP_ENV).ok().filter(|t| !t.is_empty()),
        };

        let outcome = qemu_args(&topology, spec, &staged)
            .and_then(|args| self.boot(spec, &args, &staged.shares, run_id, &inst_dir));

        // Collect outputs before wiping, but only if the guest actually booted
        // (nothing was produced otherwise). A collection failure surfaces as an
        // infra fault rather than silently dropping the output.
        let collected = if outcome.as_ref().is_ok_and(|o| o.booted) {
            collect_outputs(spec.outputs, &outputs_dir)
        } else {
            Ok(())
        };

        // Teardown clears staging on every path so secret bytes never outlive
        // the run (INV-1), including the error path. The inputs/outputs dirs too.
        for dir in [&inst_dir, &inputs_dir, &outputs_dir] {
            if let Err(err) = wipe(dir) {
                tracing::warn!(dir = %dir.display(), %err, "failed to wipe staging on teardown");
            }
        }
        collected.and(outcome)
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
    use sandy::{Grants, Hypervisor, SECRET_MOUNT_TAG, parse_topology};

    use super::*;

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
        };
        let command = ["true".to_string()];
        let grants = Grants {
            secrets: true,
            agent: false,
            shares: false,
        };
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
        };
        let staged = StagedArgs::default();

        let result = qemu_args(&topology, &spec, &staged);

        assert!(
            result.is_err(),
            "a vfkit topology must be rejected by the qemu-only backend, got {result:?}"
        );
        Ok(())
    }

    /// Tier-1 (#29): with a tap bound, `qemu_args` emits the `-netdev tap,…,
    /// ifname=<tap>` + `virtio-net-pci` NIC pair so the guest has egress to filter.
    #[test]
    fn qemu_args_emits_a_tap_nic_when_a_tap_is_bound() -> anyhow::Result<()> {
        let topology = parse_topology(X86_64_FIXTURE).context("parse x86_64 fixture")?;
        let command = ["true".to_string()];
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
            grants: &NO_GRANTS,
            outcome_file: None,
            secret_dir: None,
        };
        let staged = StagedArgs {
            tap: Some("sandytap0".to_string()),
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
        };
        let staged = StagedArgs::default();

        let args = qemu_args(&topology, &spec, &staged).context("assemble qemu argv")?;

        let joined = args.join(" ");
        assert!(
            !joined.contains("-netdev") && !joined.contains("virtio-net"),
            "no tap must emit no NIC: {joined}"
        );
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
