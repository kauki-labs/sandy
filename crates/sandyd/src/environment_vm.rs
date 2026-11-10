//! The `vm-qemu` and `vm-vfkit` environment backends: composition only (#587, slices C3b and C3c).
//!
//! [`VmEnvironmentBackend`] holds one agent-mode run per environment. This module supplies what that run needs
//! around it:
//!
//! 1. **The agent link.** [`relay_link`] serves the host end of the link on the daemon's runtime and reports the
//!    verdict. A service never exits on its own, so the link stays up until the run is cancelled.
//! 2. **The service bridge.** The qemu backend calls [`cid_hook`] once the guest has booted and linked. It starts a
//!    loopback [`Bridge`] to the guest's port relay and registers its address with the [`HttpServiceProbe`], so Ready
//!    names an endpoint a client can reach. Both are held in the run's [`RunGuards`] and end with the run.
//!
//!    vfkit has no CID: it exposes the guest relay as a host unix socket. [`bridge_on_link`] starts the same bridge
//!    over a unix-socket dialer when the agent link comes up (the bridge dials the guest only after a client's
//!    first byte, so an early start is safe).
//!
//! Only the factories ([`backend`], Linux; [`vfkit_backend`], macOS) are platform-gated; the wiring is generic
//! over the [`Dialer`], so it is tested with a fake one on any host.
//!
//! Open: nothing consumes the channel the agent's TTY output lands in. `InMem` keeps every envelope, so a
//! service that prints forever grows the daemon's memory for as long as the environment lives.

use std::{
    io,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use sandy_api::{
    agent::{OnLink, SERVICE_ENV},
    backend::BackendError,
    environment::EnvironmentSpec,
};
use sandy_conn::bridge::{Bridge, BridgeConfig, Dialer};
use sandy_environment::{
    BackendFactory, HeldBackend, HttpServiceProbe, RunGuards, VmEnvironmentBackend, VmEnvironmentConfig,
};
use sandy_fabric::{
    capauth::{CapAuthority, CapRights, CapScope},
    types::{ChannelId, PeerId},
};
use sandy_fabric_local::{LocalCapAuthority, channel::Channel, inmem::InMem, link::serve_agent_link};

/// How long the agent's cap stays valid. An environment lives until it is killed, and the cap is checked when the
/// agent joins, so it must outlive any realistic run.
const CAP_TTL: Duration = Duration::from_secs(10 * 365 * 24 * 3600);

const CHANNEL: &str = "environment";

/// Serve one environment's agent link on `rt`, then report the run's verdict.
///
/// Each call builds its own channel and cap authority: an agent-mode backend runs one job, so nothing is shared.
pub fn relay_link(rt: tokio::runtime::Handle, environment_id: String) -> OnLink {
    Arc::new(move |_box_id, link, report| {
        let environment_id = environment_id.clone();
        rt.spawn(async move {
            let verdict = serve(link).await;
            match verdict {
                Ok(Some(code)) => report.job_exited(code),
                Ok(None) => report.agent_failed("the agent ended without reporting the service's exit"),
                Err(why) => {
                    tracing::warn!(environment = %environment_id, error = %why, "an environment's agent link failed");
                    report.agent_failed(why);
                }
            }
        });
    })
}

async fn serve(link: std::os::fd::OwnedFd) -> Result<Option<i32>, String> {
    let authority = LocalCapAuthority::new(CAP_TTL).map_err(|e| format!("cap authority: {e}"))?;
    let cap = authority
        .mint(CapScope {
            peer: PeerId::from("agent"),
            channel: ChannelId::from(CHANNEL),
            rights: CapRights {
                post: true,
                read: true,
                invite: false,
            },
            expires_at: None,
        })
        .map_err(|e| format!("mint the agent cap: {e}"))?;
    let channel = Channel::new(ChannelId::from(CHANNEL), InMem::default(), authority)
        .await
        .map_err(|e| format!("open the channel: {e}"))?;
    let stream = std::os::unix::net::UnixStream::from(link);
    stream.set_nonblocking(true).map_err(|e| format!("link: {e}"))?;
    let stream = tokio::net::UnixStream::from_std(stream).map_err(|e| format!("link: {e}"))?;
    serve_agent_link(Arc::new(channel), &cap, stream)
        .await
        .map_err(|e| e.to_string())
}

/// The hook that runs when the guest `cid` is up: bridge to its port relay and register the bridge with `probe`.
///
/// `dialer_for` builds the dialer for a CID; production passes a vsock dialer. The work runs on `rt`, so the hook
/// never blocks the backend thread that calls it. A failure leaves the environment `Starting`, which the driver's
/// provision timeout ends.
pub fn cid_hook<D: Dialer>(
    rt: tokio::runtime::Handle,
    probe: Arc<HttpServiceProbe>,
    guards: RunGuards,
    environment_id: String,
    dialer_for: impl Fn(u32) -> io::Result<D> + Send + Sync + 'static,
) -> impl Fn(&str, u32) + Send + Sync + 'static {
    move |_box_id, cid| drop(spawn_bridge(&rt, &probe, &guards, &environment_id, dialer_for(cid)))
}

/// Start the bridge on `rt` and, if the run is still open, hold it and its probe registration in `guards`. The task
/// resolves to whether it registered: `false` for a run that ended first or a bridge that did not start.
fn spawn_bridge<D: Dialer>(
    rt: &tokio::runtime::Handle,
    probe: &Arc<HttpServiceProbe>,
    guards: &RunGuards,
    environment_id: &str,
    dialer: io::Result<D>,
) -> tokio::task::JoinHandle<bool> {
    let (probe, guards, environment_id) = (Arc::clone(probe), guards.clone(), environment_id.to_owned());
    rt.spawn(async move {
        match start_bridge(dialer).await {
            Ok(bridge) => {
                // Registered under the slot's lock, so a run that already ended registers nothing, and the
                // bridge drops here instead.
                guards.hold_if_open(|| {
                    let registration = probe.register(&environment_id, bridge.addr());
                    Box::new((registration, bridge))
                })
            }
            Err(e) => {
                tracing::warn!(environment = %environment_id, error = %e, "could not start the service bridge");
                false
            }
        }
    })
}

/// [`relay_link`] plus the service bridge, for a backend with no CID hook (vfkit): the bridge starts when the
/// agent link is up. `dialer` builds the run's dialer; production passes a unix-socket dialer.
pub fn bridge_on_link<D: Dialer>(
    rt: tokio::runtime::Handle,
    probe: Arc<HttpServiceProbe>,
    guards: RunGuards,
    environment_id: String,
    dialer: impl Fn() -> io::Result<D> + Send + Sync + 'static,
) -> OnLink {
    let relay = relay_link(rt.clone(), environment_id.clone());
    Arc::new(move |box_id, link, report| {
        drop(spawn_bridge(&rt, &probe, &guards, &environment_id, dialer()));
        relay(box_id, link, report);
    })
}

/// File-name prefix of a vfkit service socket under the staging base.
const SOCKET_PREFIX: &str = "env-svc-";

/// The longest a unix socket path may be (`sun_path` on macOS is 104 bytes with the NUL).
const MAX_SOCKET_PATH: usize = 103;

/// A service socket path that would not fit `sun_path`.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("the service socket path {path} is {len} bytes, over the {MAX_SOCKET_PATH} a unix socket allows")]
pub struct SocketPathTooLong {
    path: String,
    len: usize,
}

/// The host socket vfkit exposes environment `environment_id`'s guest relay at, under `base` (the private staging
/// base).
///
/// The name is a hash of the id: short, safe whatever the id holds, stable across restarts (a stale socket is
/// found and cleared) and, at 96 bits, unique per environment. Two backends on one path would unlink each
/// other's live socket.
///
/// # Errors
/// [`SocketPathTooLong`] when the path would not fit `sun_path`.
pub fn service_socket_path(base: &Path, environment_id: &str) -> Result<PathBuf, SocketPathTooLong> {
    use sha2::{Digest, Sha256};
    let digest = hex::encode(Sha256::digest(environment_id.as_bytes()));
    let path = base.join(format!("{SOCKET_PREFIX}{}.sock", &digest[..24]));
    let len = path.as_os_str().len();
    if len > MAX_SOCKET_PATH {
        return Err(SocketPathTooLong {
            path: path.display().to_string(),
            len,
        });
    }
    Ok(path)
}

/// Start the bridge to the guest's port relay. The caller registers it, so the registration drops before the bridge
/// and Ready is withdrawn before the port closes.
async fn start_bridge<D: Dialer>(dialer: io::Result<D>) -> io::Result<Bridge> {
    Bridge::start(dialer?, BridgeConfig::default()).await
}

/// A box the start-up sweep left undecided (a failed kill, an unknown owner, another pid namespace, or a process that
/// outlived the stop wait) stays: the driver may then launch next to the survivor, so an operator needs to see it.
fn warn_undecided(undecided: usize) {
    if undecided > 0 {
        tracing::warn!(
            undecided,
            "the orphan sweep left VMs undecided; a restarted environment may run beside one"
        );
    }
}

/// Compose the environment backend: run `sweep` once, now, then build each environment's backend with `per_env`.
///
/// The sweep belongs here and not in `per_env`: it stops what a killed host left behind, and a launch must never
/// run it (it can block for seconds per box).
pub fn assemble(
    settings: &crate::environment_backend::VmSettings,
    probe: Arc<HttpServiceProbe>,
    sweep: impl FnOnce(),
    per_env: impl Fn(&EnvironmentSpec, &RunGuards) -> Result<HeldBackend, BackendError> + Send + Sync + 'static,
) -> VmEnvironmentBackend {
    sweep();
    let factory: BackendFactory = Box::new(move |spec| per_env(spec, &RunGuards::new()));
    let mut config = VmEnvironmentConfig::new(settings.command.clone());
    config.env = vec![(SERVICE_ENV.to_owned(), settings.service_env.clone())];
    config.boot_timeout_secs = settings.boot_timeout_secs;
    VmEnvironmentBackend::new(factory, config).with_service_probe(probe)
}

/// The environment backend that boots each environment as a qemu microVM.
#[cfg(target_os = "linux")]
pub fn backend(settings: &crate::environment_backend::VmSettings, rt: tokio::runtime::Handle) -> VmEnvironmentBackend {
    use sandy_api::agent::{AgentLaunch, PORT_RELAY_VSOCK_PORT};
    use sandy_backend::QemuBackend;
    use sandy_conn::dial::VsockDialer;
    use sandy_environment::{ConsoleTaps, guarded};

    let probe = Arc::new(HttpServiceProbe::new());
    // The console copy a failed provision reports (#727); vfkit has no console sink yet.
    let taps = Arc::new(ConsoleTaps::new());
    let per_env = {
        let probe = Arc::clone(&probe);
        let taps = Arc::clone(&taps);
        move |spec: &EnvironmentSpec, guards: &RunGuards| {
            let qemu = QemuBackend::new()
                .with_console_sink(taps.sink_for(&spec.environment_id))
                .with_agent(AgentLaunch {
                    // A VM backend takes the agent's path from the topology.
                    program: PathBuf::new(),
                    on_link: relay_link(rt.clone(), spec.environment_id.clone()),
                })
                .with_guest_cid_hook(cid_hook(
                    rt.clone(),
                    Arc::clone(&probe),
                    guards.clone(),
                    spec.environment_id.clone(),
                    |cid| VsockDialer::new(cid, PORT_RELAY_VSOCK_PORT),
                ));
            Ok(Box::new(guarded(qemu, guards)) as HeldBackend)
        }
    };
    // `sweep_orphans` logs its own report. Safe beside a live daemon or CLI run.
    assemble(
        settings,
        probe,
        || {
            warn_undecided(QemuBackend::sweep_orphans().undecided);
        },
        per_env,
    )
    .with_console_taps(taps)
}

/// Why the vfkit backend cannot start. Each one stops the daemon at start-up, not at the first environment.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum VfkitSetupError {
    /// `SANDY_VFKIT_BIN` holds bytes that are not UTF-8.
    #[error("SANDY_VFKIT_BIN is not valid UTF-8")]
    BinNotUtf8,
    /// `SANDY_VFKIT_BIN` is set but blank.
    #[error("SANDY_VFKIT_BIN is set but empty")]
    BinEmpty,
    /// No executable `vfkit` was found.
    #[error("the vfkit binary {0:?} is not an executable file{1}")]
    BinNotFound(String, &'static str),
    /// The staging base is too deep for a socket path.
    #[error(transparent)]
    SocketPath(#[from] SocketPathTooLong),
}

/// Resolve the vfkit binary from `SANDY_VFKIT_BIN` (`var`; unset means `vfkit`) and `PATH` (`path`).
///
/// A name with a `/` must be an executable file; a bare name is searched for in `path`.
///
/// # Errors
/// [`VfkitSetupError`] for a non-UTF-8, blank or unresolvable value.
pub fn resolve_vfkit_bin(
    var: Option<std::ffi::OsString>,
    path: Option<std::ffi::OsString>,
) -> Result<PathBuf, VfkitSetupError> {
    use std::os::unix::fs::PermissionsExt as _;
    let name = match var {
        None => "vfkit".to_owned(),
        Some(v) => v.into_string().map_err(|_| VfkitSetupError::BinNotUtf8)?,
    };
    if name.trim().is_empty() {
        return Err(VfkitSetupError::BinEmpty);
    }
    let executable = |p: &Path| {
        p.metadata()
            .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
    };
    if name.contains('/') {
        let p = PathBuf::from(&name);
        return if executable(&p) {
            Ok(p)
        } else {
            Err(VfkitSetupError::BinNotFound(name, ""))
        };
    }
    path.iter()
        .flat_map(std::env::split_paths)
        .map(|dir| dir.join(&name))
        .find(|p| executable(p))
        .ok_or(VfkitSetupError::BinNotFound(name, " on PATH"))
}

/// The vfkit binary and staging base the backend runs with, checked once.
#[derive(Debug, PartialEq, Eq)]
pub struct VfkitSetup {
    /// The resolved `vfkit` binary.
    pub bin: PathBuf,
    /// The private staging base the service sockets live under.
    pub base: PathBuf,
}

/// Check what every environment will need, so a bad setting stops the daemon instead of failing each environment:
/// the binary resolves, and a service socket path under `base` fits `sun_path` (the name has the same length for
/// every id).
///
/// # Errors
/// [`VfkitSetupError`].
pub fn check_vfkit_setup(
    bin_var: Option<std::ffi::OsString>,
    path_var: Option<std::ffi::OsString>,
    base: PathBuf,
) -> Result<VfkitSetup, VfkitSetupError> {
    let bin = resolve_vfkit_bin(bin_var, path_var)?;
    service_socket_path(&base, "probe")?;
    Ok(VfkitSetup { bin, base })
}

/// Remove the service sockets in `base` that no VM answers on, and return how many. A daemon killed with SIGKILL
/// leaves a socket for each environment that never ran again (its row went `Failed`, so nothing relaunches it and
/// clears the path). A socket that answers belongs to a live VM and stays.
pub fn sweep_stale_service_sockets(base: &Path) -> usize {
    use std::os::unix::{fs::FileTypeExt as _, net::UnixStream};
    let Ok(entries) = std::fs::read_dir(base) else {
        return 0;
    };
    let mut removed = 0;
    for entry in entries.flatten() {
        let path = entry.path();
        let ours = entry
            .file_name()
            .to_str()
            .is_some_and(|n| n.starts_with(SOCKET_PREFIX) && n.ends_with(".sock"));
        let is_socket = std::fs::symlink_metadata(&path).is_ok_and(|m| m.file_type().is_socket());
        if !ours || !is_socket {
            continue;
        }
        let stale = matches!(
            UnixStream::connect(&path),
            Err(e) if matches!(e.kind(), io::ErrorKind::ConnectionRefused | io::ErrorKind::NotFound)
        );
        if stale && std::fs::remove_file(&path).is_ok() {
            removed += 1;
        }
    }
    tracing::debug!(removed, "removed the stale vfkit service sockets");
    removed
}

/// What one vfkit environment's backend needs: the service socket and the link hook that dials that same socket.
pub struct VfkitWiring {
    /// Where vfkit exposes the guest relay.
    pub socket: PathBuf,
    /// The agent-link hook: serves the link and starts the bridge to `socket`.
    pub on_link: OnLink,
}

/// Wire environment `environment_id` under `base`. `dialer_at` builds the dialer for the socket path; the same path
/// is returned for the backend, so the bridge cannot dial another socket than the one vfkit binds.
///
/// # Errors
/// [`SocketPathTooLong`] when the path would not fit `sun_path`.
pub fn vfkit_wiring<D: Dialer>(
    rt: tokio::runtime::Handle,
    probe: Arc<HttpServiceProbe>,
    guards: RunGuards,
    base: &Path,
    environment_id: &str,
    dialer_at: impl Fn(&Path) -> io::Result<D> + Send + Sync + 'static,
) -> Result<VfkitWiring, SocketPathTooLong> {
    let socket = service_socket_path(base, environment_id)?;
    let dial_path = socket.clone();
    let on_link = bridge_on_link(rt, probe, guards, environment_id.to_owned(), move || {
        dialer_at(&dial_path)
    });
    Ok(VfkitWiring { socket, on_link })
}

/// The environment backend that boots each environment as a vfkit microVM.
///
/// Each environment gets its own service socket under the private staging base ([`service_socket_path`]); vfkit
/// owns it and the bridge dials it. Stale sockets of a killed daemon are removed first.
///
/// # Errors
/// The reason, as text, when the staging base cannot be opened or the vfkit binary or a socket path is unusable.
#[cfg(target_os = "macos")]
pub fn vfkit_backend(
    settings: &crate::environment_backend::VmSettings,
    rt: tokio::runtime::Handle,
) -> Result<VmEnvironmentBackend, String> {
    use sandy_api::agent::AgentLaunch;
    use sandy_backend::VfkitBackend;
    use sandy_conn::dial::UnixDialer;
    use sandy_environment::guarded;

    let base = sandy_fsutil::ensure_sandy_staging_base().map_err(|e| format!("the staging base: {e}"))?;
    let setup = check_vfkit_setup(std::env::var_os("SANDY_VFKIT_BIN"), std::env::var_os("PATH"), base)
        .map_err(|e| e.to_string())?;
    let probe = Arc::new(HttpServiceProbe::new());
    let sweep_base = setup.base.clone();
    let per_env = {
        let probe = Arc::clone(&probe);
        move |spec: &EnvironmentSpec, guards: &RunGuards| {
            let wiring = vfkit_wiring(
                rt.clone(),
                Arc::clone(&probe),
                guards.clone(),
                &setup.base,
                &spec.environment_id,
                |socket| Ok(UnixDialer::new(socket)),
            )
            .map_err(|e| BackendError::Spawn(e.to_string()))?;
            let vfkit = VfkitBackend::new(setup.bin.clone())
                .with_service_socket(wiring.socket)
                .with_agent(AgentLaunch {
                    // A VM backend takes the agent's path from the topology.
                    program: PathBuf::new(),
                    on_link: wiring.on_link,
                });
            Ok(Box::new(guarded(vfkit, guards)) as HeldBackend)
        }
    };
    Ok(assemble(
        settings,
        probe,
        || {
            // Stop the VMs a killed daemon left behind first, then clear the sockets nothing answers on.
            warn_undecided(VfkitBackend::sweep_orphans().undecided);
            let _ = sweep_stale_service_sockets(&sweep_base);
        },
        per_env,
    ))
}

#[cfg(test)]
mod tests {
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        time::Instant,
    };

    use anyhow::Context;
    use sandy_api::{
        agent::{AgentReport, AgentVerdict, PORT_RELAY_READY},
        environment::Probe,
    };
    use sandy_environment::ServiceProbe;
    use tokio::{io::AsyncWriteExt, net::TcpStream};

    use super::*;

    /// Plays the guest relay: the ready byte, then drains the request and answers `200`.
    struct FakeRelay;

    impl Dialer for FakeRelay {
        type Stream = tokio::io::DuplexStream;

        async fn dial(&self) -> io::Result<Self::Stream> {
            let (host, mut guest) = tokio::io::duplex(4096);
            tokio::spawn(async move {
                let _ = guest.write_all(&[PORT_RELAY_READY]).await;
                let mut buf = [0u8; 64];
                let _ = tokio::io::AsyncReadExt::read(&mut guest, &mut buf).await;
                let _ = guest.write_all(b"HTTP/1.0 200 OK\r\n\r\n").await;
                let _ = guest.shutdown().await;
            });
            Ok(host)
        }
    }

    async fn probe_off_runtime(probe: &Arc<HttpServiceProbe>, id: &'static str) -> anyhow::Result<Probe> {
        let probe = Arc::clone(probe);
        Ok(tokio::task::spawn_blocking(move || probe.probe(id)).await??)
    }

    async fn until_ready(probe: &Arc<HttpServiceProbe>, id: &'static str) -> anyhow::Result<Probe> {
        let start = Instant::now();
        loop {
            let got = probe_off_runtime(probe, id).await?;
            if matches!(got, Probe::Ready { .. }) || start.elapsed() > Duration::from_secs(5) {
                return Ok(got);
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// The guest CID arriving makes the environment Ready at the bridge, and the end of the run takes both away.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_cid_hook_makes_the_environment_ready_until_the_run_ends() -> anyhow::Result<()> {
        let probe = Arc::new(HttpServiceProbe::new());
        let guards = RunGuards::new();
        assert!(matches!(
            probe_off_runtime(&probe, "env-1").await?,
            Probe::Starting { .. }
        ));

        let hook = cid_hook(
            tokio::runtime::Handle::current(),
            Arc::clone(&probe),
            guards.clone(),
            "env-1".to_owned(),
            |cid| {
                assert_eq!(cid, 77, "the hook passes the guest CID to the dialer");
                Ok(FakeRelay)
            },
        );
        hook("env-1", 77);

        let Probe::Ready { endpoint } = until_ready(&probe, "env-1").await? else {
            anyhow::bail!("the environment never became Ready after the CID hook");
        };
        assert_eq!(endpoint.host, "127.0.0.1");

        // `guarded` closes the guards when `run()` returns; dropping it does the same.
        drop(sandy_environment::guarded(NullBackend, &guards));
        let addr = format!("{}:{}", endpoint.host, endpoint.port);
        let start = Instant::now();
        while TcpStream::connect(&addr).await.is_ok() {
            anyhow::ensure!(
                start.elapsed() < Duration::from_secs(5),
                "the bridge still listens after the run ended"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        // Ready is withdrawn with the bridge: the probe is back to Starting, not Ready at a dead port.
        let got = probe_off_runtime(&probe, "env-1").await?;
        assert!(matches!(got, Probe::Starting { .. }), "{got:?}");
        Ok(())
    }

    /// A hook that fires after the run ended must not leave a bridge or a registration behind.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_hook_that_fires_after_the_run_ended_leaves_nothing_registered() -> anyhow::Result<()> {
        let probe = Arc::new(HttpServiceProbe::new());
        let guards = RunGuards::new();
        let dialed = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&dialed);
        let hook = cid_hook(
            tokio::runtime::Handle::current(),
            Arc::clone(&probe),
            guards.clone(),
            "env-2".to_owned(),
            move |_| {
                counter.fetch_add(1, Ordering::SeqCst);
                Ok(FakeRelay)
            },
        );
        // `guarded` closes the slot when the run returns; mirror that, then fire the hook.
        drop(sandy_environment::guarded(NullBackend, &guards));
        hook("env-2", 5);
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(dialed.load(Ordering::SeqCst), 1, "the hook must have run");
        assert!(
            matches!(probe_off_runtime(&probe, "env-2").await?, Probe::Starting { .. }),
            "a late hook's registration must be dropped"
        );
        Ok(())
    }

    /// A late hook of an ended run must not replace or withdraw the registration of the run that replaced it.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_late_hook_of_an_old_run_leaves_the_new_runs_registration_alone() -> anyhow::Result<()> {
        let probe = Arc::new(HttpServiceProbe::new());
        let rt = tokio::runtime::Handle::current();
        let (old, new) = (RunGuards::new(), RunGuards::new());
        let hook = |guards: &RunGuards| {
            cid_hook(
                rt.clone(),
                Arc::clone(&probe),
                guards.clone(),
                "env-5".to_owned(),
                |_| Ok(FakeRelay),
            )
        };
        let (old_hook, new_hook) = (hook(&old), hook(&new));
        // The old run was killed, the id relaunched, and the new run's bridge is up.
        drop(sandy_environment::guarded(NullBackend, &old));
        new_hook("env-5", 6);
        let Probe::Ready { endpoint } = until_ready(&probe, "env-5").await? else {
            anyhow::bail!("the new run never became Ready");
        };
        // The old run's hook fires late.
        old_hook("env-5", 5);
        let start = Instant::now();
        while start.elapsed() < Duration::from_millis(500) {
            let got = probe_off_runtime(&probe, "env-5").await?;
            anyhow::ensure!(
                got == Probe::Ready {
                    endpoint: endpoint.clone()
                },
                "the late hook disturbed the new run: {got:?}"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        Ok(())
    }

    /// With no CID hook (vfkit), the agent link coming up starts the bridge, and the end of the run takes it away.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_agent_link_coming_up_makes_the_environment_ready_until_the_run_ends() -> anyhow::Result<()> {
        let probe = Arc::new(HttpServiceProbe::new());
        let guards = RunGuards::new();
        let on_link = bridge_on_link(
            tokio::runtime::Handle::current(),
            Arc::clone(&probe),
            guards.clone(),
            "env-6".to_owned(),
            || Ok(FakeRelay),
        );
        assert!(matches!(
            probe_off_runtime(&probe, "env-6").await?,
            Probe::Starting { .. }
        ));
        let (host, _guest) = std::os::unix::net::UnixStream::pair().context("socket pair")?;
        on_link("env-6", host.into(), AgentReport::channel().0);
        let Probe::Ready { endpoint } = until_ready(&probe, "env-6").await? else {
            anyhow::bail!("the environment never became Ready after the link came up");
        };
        drop(sandy_environment::guarded(NullBackend, &guards));
        let addr = format!("{}:{}", endpoint.host, endpoint.port);
        let start = Instant::now();
        while TcpStream::connect(&addr).await.is_ok() {
            anyhow::ensure!(
                start.elapsed() < Duration::from_secs(5),
                "the bridge still listens after the run ended"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let got = probe_off_runtime(&probe, "env-6").await?;
        assert!(matches!(got, Probe::Starting { .. }), "{got:?}");
        Ok(())
    }

    /// A bridge that finishes starting after the run ended must never have registered with the probe: the task
    /// reports it did not, which a hold that registers first and drops after cannot say.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_bridge_that_starts_after_the_run_ended_is_never_registered() -> anyhow::Result<()> {
        let probe = Arc::new(HttpServiceProbe::new());
        let rt = tokio::runtime::Handle::current();
        let ended = RunGuards::new();
        drop(sandy_environment::guarded(NullBackend, &ended));
        assert!(
            !spawn_bridge(&rt, &probe, &ended, "env-7", Ok(FakeRelay)).await?,
            "a closed run must not register"
        );
        assert!(matches!(
            probe_off_runtime(&probe, "env-7").await?,
            Probe::Starting { .. }
        ));
        // The same call on a run that is up registers, so the assertion above is not a no-op.
        let up = RunGuards::new();
        assert!(spawn_bridge(&rt, &probe, &up, "env-8", Ok(FakeRelay)).await?);
        assert!(matches!(until_ready(&probe, "env-8").await?, Probe::Ready { .. }));
        Ok(())
    }

    /// The agent link coming up after the run ended starts nothing that stays.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_link_that_comes_up_after_the_run_ended_leaves_nothing_registered() -> anyhow::Result<()> {
        let probe = Arc::new(HttpServiceProbe::new());
        let guards = RunGuards::new();
        let on_link = bridge_on_link(
            tokio::runtime::Handle::current(),
            Arc::clone(&probe),
            guards.clone(),
            "env-9".to_owned(),
            || Ok(FakeRelay),
        );
        drop(sandy_environment::guarded(NullBackend, &guards));
        let (host, _guest) = std::os::unix::net::UnixStream::pair().context("socket pair")?;
        on_link("env-9", host.into(), AgentReport::channel().0);
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(matches!(
            probe_off_runtime(&probe, "env-9").await?,
            Probe::Starting { .. }
        ));
        Ok(())
    }

    fn vm_settings() -> crate::environment_backend::VmSettings {
        crate::environment_backend::VmSettings {
            command: vec!["t3".to_owned()],
            service_env: "{}".to_owned(),
            boot_timeout_secs: 5,
        }
    }

    /// The orphan sweep runs once when the backend is composed, before any launch, and the per-environment factory
    /// never runs it.
    #[test]
    fn the_orphan_sweep_runs_once_at_construction_and_not_per_launch() {
        let (swept, built) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
        let (s, b) = (Arc::clone(&swept), Arc::clone(&built));
        let backend = assemble(
            &vm_settings(),
            Arc::new(HttpServiceProbe::new()),
            move || {
                assert_eq!(
                    b.load(Ordering::SeqCst),
                    0,
                    "the sweep must run before any backend is built"
                );
                s.fetch_add(1, Ordering::SeqCst);
            },
            move |_, _| {
                built.fetch_add(1, Ordering::SeqCst);
                Err(sandy_api::backend::BackendError::Spawn("unused".to_owned()))
            },
        );
        assert_eq!(swept.load(Ordering::SeqCst), 1);
        drop(backend);
        assert_eq!(
            swept.load(Ordering::SeqCst),
            1,
            "dropping or using it must not sweep again"
        );
    }

    fn executable(dir: &Path, name: &str, mode: u32) -> anyhow::Result<PathBuf> {
        use std::os::unix::fs::PermissionsExt as _;
        let path = dir.join(name);
        std::fs::write(&path, b"#!/bin/sh\n").context("write")?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).context("chmod")?;
        Ok(path)
    }

    /// A vfkit binary the daemon cannot use stops it at start-up, whatever form the setting has.
    #[test]
    fn an_unusable_vfkit_binary_setting_is_refused_at_startup() -> anyhow::Result<()> {
        use std::{ffi::OsString, os::unix::ffi::OsStringExt as _};
        let dir = tempfile::tempdir().context("tempdir")?;
        let path = Some(OsString::from(dir.path()));
        let os = |s: &str| Some(OsString::from(s));
        assert_eq!(
            resolve_vfkit_bin(Some(OsString::from_vec(b"vf\xffkit".to_vec())), path.clone()),
            Err(VfkitSetupError::BinNotUtf8)
        );
        for blank in ["", "  "] {
            assert_eq!(
                resolve_vfkit_bin(os(blank), path.clone()),
                Err(VfkitSetupError::BinEmpty)
            );
        }
        assert!(matches!(
            resolve_vfkit_bin(os("/nonexistent/vfkit"), path.clone()),
            Err(VfkitSetupError::BinNotFound(..))
        ));
        assert!(matches!(
            resolve_vfkit_bin(None, path.clone()),
            Err(VfkitSetupError::BinNotFound(_, " on PATH"))
        ));
        // A file without the execute bit is no binary.
        let plain = executable(dir.path(), "plain", 0o644)?;
        assert!(matches!(
            resolve_vfkit_bin(Some(plain.into_os_string()), path.clone()),
            Err(VfkitSetupError::BinNotFound(..))
        ));
        // A bare name resolves on PATH, and an explicit path to an executable is taken as it is.
        let vfkit = executable(dir.path(), "vfkit", 0o755)?;
        assert_eq!(resolve_vfkit_bin(None, path.clone())?, vfkit);
        assert_eq!(resolve_vfkit_bin(Some(vfkit.clone().into_os_string()), None)?, vfkit);
        Ok(())
    }

    /// A staging base too deep for a socket path stops the daemon once, not each environment.
    #[test]
    fn a_staging_base_too_deep_for_a_socket_fails_the_setup() -> anyhow::Result<()> {
        use std::ffi::OsString;
        let dir = tempfile::tempdir().context("tempdir")?;
        let vfkit = executable(dir.path(), "vfkit", 0o755)?;
        let bin = Some(vfkit.clone().into_os_string());
        let ok = check_vfkit_setup(bin.clone(), None, PathBuf::from("/tmp/sandy")).context("short base")?;
        assert_eq!(
            ok,
            VfkitSetup {
                bin: vfkit,
                base: PathBuf::from("/tmp/sandy")
            }
        );
        let deep = PathBuf::from(format!("/{}", "d".repeat(MAX_SOCKET_PATH)));
        assert!(matches!(
            check_vfkit_setup(bin, Some(OsString::new()), deep),
            Err(VfkitSetupError::SocketPath(_))
        ));
        Ok(())
    }

    /// A fresh short directory: a unix socket path must fit `sun_path`, which a tempdir under `$TMPDIR` may not.
    fn short_dir() -> anyhow::Result<PathBuf> {
        let dir = PathBuf::from(format!("/tmp/sv-{}", &uuid::Uuid::new_v4().simple().to_string()[..8]));
        std::fs::create_dir_all(&dir).context("create dir")?;
        Ok(dir)
    }

    /// The start-up sweep removes the service sockets nothing answers on, and only those.
    #[test]
    fn the_start_up_sweep_removes_only_stale_service_sockets() -> anyhow::Result<()> {
        use std::os::unix::net::UnixListener;
        let dir = short_dir()?;
        let named = |id: &str| service_socket_path(&dir, id).context("path");
        let stale = named("stale")?;
        drop(UnixListener::bind(&stale).context("bind stale")?);
        let live = named("live")?;
        let _listener = UnixListener::bind(&live).context("bind live")?;
        // A stale socket that is not ours by name, and a regular file that is, stay.
        let foreign = dir.join("other.sock");
        drop(UnixListener::bind(&foreign).context("bind foreign")?);
        let file = named("file")?;
        std::fs::write(&file, b"x").context("write")?;

        assert_eq!(sweep_stale_service_sockets(&dir), 1);
        assert!(!stale.exists(), "a socket nothing answers on is removed");
        assert!(live.exists(), "a socket that answers is a live VM and stays");
        assert!(foreign.exists() && file.exists(), "only our own sockets are touched");
        assert_eq!(sweep_stale_service_sockets(&dir), 0, "a second sweep finds nothing");
        assert_eq!(sweep_stale_service_sockets(&dir.join("missing")), 0);
        std::fs::remove_dir_all(&dir).context("cleanup")?;
        Ok(())
    }

    /// The bridge dials the socket the backend is told to bind, and a path too long for a socket is the typed error.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_bridge_dials_the_socket_the_backend_binds() -> anyhow::Result<()> {
        let rt = tokio::runtime::Handle::current();
        let probe = Arc::new(HttpServiceProbe::new());
        let dialed = Arc::new(std::sync::Mutex::new(Vec::<PathBuf>::new()));
        let record = Arc::clone(&dialed);
        let wiring = vfkit_wiring(
            rt.clone(),
            Arc::clone(&probe),
            RunGuards::new(),
            Path::new("/tmp/sandy"),
            "env-10",
            move |path| {
                record
                    .lock()
                    .map_err(|_| io::Error::other("poisoned"))?
                    .push(path.to_path_buf());
                Ok(FakeRelay)
            },
        )
        .context("short base")?;
        assert_eq!(
            Some(wiring.socket.as_path()),
            service_socket_path(Path::new("/tmp/sandy"), "env-10").ok().as_deref()
        );
        let (host, _guest) = std::os::unix::net::UnixStream::pair().context("socket pair")?;
        (wiring.on_link)("env-10", host.into(), AgentReport::channel().0);
        let _ = until_ready(&probe, "env-10").await?;
        let seen = dialed.lock().map_err(|_| anyhow::anyhow!("poisoned"))?.clone();
        assert_eq!(seen, [wiring.socket], "the dialer must get the path the backend binds");

        let deep = PathBuf::from(format!("/{}", "d".repeat(MAX_SOCKET_PATH)));
        let long = vfkit_wiring(rt, probe, RunGuards::new(), &deep, "env-11", |_| Ok(FakeRelay));
        assert!(matches!(long, Err(SocketPathTooLong { .. })));
        Ok(())
    }

    /// A base directory path of exactly `len` bytes.
    fn base_of_len(len: usize) -> PathBuf {
        PathBuf::from(format!("/{}", "b".repeat(len - 1)))
    }

    /// A socket path of exactly 103 bytes is accepted and one of 104 is refused, before vfkit is spawned.
    #[test]
    fn a_service_socket_path_is_refused_one_byte_over_the_unix_limit() -> anyhow::Result<()> {
        // `<base>/env-svc-<24 hex>.sock`: the base, a separator and the file name.
        let tail = 1 + SOCKET_PREFIX.len() + 24 + ".sock".len();
        let at_limit = service_socket_path(&base_of_len(MAX_SOCKET_PATH - tail), "env-a").context("103 must fit")?;
        assert_eq!(at_limit.as_os_str().len(), MAX_SOCKET_PATH);
        let err = service_socket_path(&base_of_len(MAX_SOCKET_PATH - tail + 1), "env-a").err();
        assert!(matches!(&err, Some(e) if e.len == MAX_SOCKET_PATH + 1), "{err:?}");
        Ok(())
    }

    /// Two environments never share a socket, and one id always maps to the same path.
    #[test]
    fn two_environments_never_share_a_service_socket() -> anyhow::Result<()> {
        let base = Path::new("/tmp/sandy");
        let mut seen = std::collections::HashSet::new();
        for id in ["a", "b", "A", "a ", "env-1", "env-2", "", "\u{e9}", "a/b", "a\0b"] {
            let path = service_socket_path(base, id).context("short base")?;
            assert!(seen.insert(path.clone()), "{id:?} collides: {path:?}");
            assert_eq!(
                service_socket_path(base, id).context("again")?,
                path,
                "stable for {id:?}"
            );
        }
        Ok(())
    }

    /// An id with separators, commas, control bytes or great length cannot shape the path: it stays one short, safe
    /// component under the base.
    #[test]
    fn an_environment_id_with_odd_characters_yields_a_safe_socket_path() -> anyhow::Result<()> {
        let base = Path::new("/tmp/sandy");
        for id in [
            "../../etc/passwd",
            "a,b",
            "a\nb",
            "a/b/c",
            &"x".repeat(5000),
            "e\u{301}",
        ] {
            let path = service_socket_path(base, id).context("odd id")?;
            assert_eq!(path.parent(), Some(base), "{id:?}");
            let name = path.file_name().and_then(|n| n.to_str()).context("name")?;
            assert!(
                name.starts_with(SOCKET_PREFIX)
                    && name
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.'),
                "{id:?} -> {name:?}"
            );
        }
        Ok(())
    }

    /// A CID the dialer refuses starts no bridge, and the environment stays Starting.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_refused_cid_starts_no_bridge() -> anyhow::Result<()> {
        let probe = Arc::new(HttpServiceProbe::new());
        let asked = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&asked);
        let hook = cid_hook::<FakeRelay>(
            tokio::runtime::Handle::current(),
            Arc::clone(&probe),
            RunGuards::new(),
            "env-3".to_owned(),
            move |_| {
                counter.fetch_add(1, Ordering::SeqCst);
                Err(io::Error::new(io::ErrorKind::InvalidInput, "not a guest CID"))
            },
        );
        hook("env-3", 1);
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(asked.load(Ordering::SeqCst), 1, "the hook must have run");
        assert!(matches!(
            probe_off_runtime(&probe, "env-3").await?,
            Probe::Starting { .. }
        ));
        Ok(())
    }

    /// A link whose far end closes without an exit frame is an agent failure, never a job result (INV-11).
    #[tokio::test(flavor = "multi_thread")]
    async fn a_link_closed_without_an_exit_reports_an_agent_failure() -> anyhow::Result<()> {
        let (host, guest) = std::os::unix::net::UnixStream::pair().context("socket pair")?;
        drop(guest);
        let (report, verdict) = AgentReport::channel();
        let on_link = relay_link(tokio::runtime::Handle::current(), "env-4".to_owned());
        on_link("env-4", host.into(), report);
        let verdict = tokio::task::spawn_blocking(move || verdict.recv_timeout(Duration::from_secs(5))).await??;
        assert!(matches!(verdict, AgentVerdict::AgentFailed(_)), "{verdict:?}");
        Ok(())
    }

    /// A backend that does nothing, so `guarded` has something to wrap.
    struct NullBackend;

    impl sandy_api::backend::VmBackend for NullBackend {
        fn run(
            &self,
            _spec: &sandy_api::backend::RunSpec,
        ) -> Result<sandy_api::backend::Outcome, sandy_api::backend::BackendError> {
            Err(sandy_api::backend::BackendError::Spawn("unused".to_owned()))
        }

        fn kill(&self, _box_id: &str) -> Result<(), sandy_api::backend::BackendError> {
            Ok(())
        }

        fn boxes(&self) -> Result<Vec<sandy_api::backend::BoxState>, sandy_api::backend::BackendError> {
            Ok(Vec::new())
        }

        fn kind(&self) -> sandy_api::backend::SandboxKind {
            sandy_api::backend::SandboxKind::Vm
        }
    }
}
