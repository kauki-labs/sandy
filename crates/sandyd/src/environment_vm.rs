//! The `vm-qemu` environment backend: composition only (#587, slice C3b).
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
//! Only the qemu factory ([`backend`]) is Linux-only; the wiring is generic over the [`Dialer`], so it is tested
//! with a fake one on any host.
//!
//! Open: nothing consumes the channel the agent's TTY output lands in. `InMem` keeps every envelope, so a
//! service that prints forever grows the daemon's memory for as long as the environment lives.

use std::{io, sync::Arc, time::Duration};

use sandy_api::agent::OnLink;
use sandy_conn::bridge::{Bridge, BridgeConfig, Dialer};
use sandy_environment::{HttpServiceProbe, RunGuards};
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
    move |_box_id, cid| {
        let (probe, guards, environment_id) = (Arc::clone(&probe), guards.clone(), environment_id.clone());
        let dialer = dialer_for(cid);
        rt.spawn(async move {
            match start_bridge(dialer).await {
                Ok(bridge) => {
                    // Registered under the slot's lock, so a run that already ended registers nothing, and the
                    // bridge drops here instead.
                    guards.hold_if_open(|| {
                        let registration = probe.register(&environment_id, bridge.addr());
                        Box::new((registration, bridge))
                    });
                }
                Err(e) => {
                    tracing::warn!(environment = %environment_id, error = %e, "could not start the service bridge");
                }
            }
        });
    }
}

/// Start the bridge to the guest's port relay. The caller registers it, so the registration drops before the bridge
/// and Ready is withdrawn before the port closes.
async fn start_bridge<D: Dialer>(dialer: io::Result<D>) -> io::Result<Bridge> {
    Bridge::start(dialer?, BridgeConfig::default()).await
}

/// The environment backend that boots each environment as a qemu microVM.
#[cfg(target_os = "linux")]
pub fn backend(
    settings: &crate::environment_backend::VmQemuSettings,
    rt: tokio::runtime::Handle,
) -> sandy_environment::VmEnvironmentBackend {
    use sandy_api::agent::{AgentLaunch, PORT_RELAY_VSOCK_PORT, SERVICE_ENV};
    use sandy_backend::QemuBackend;
    use sandy_conn::dial::VsockDialer;
    use sandy_environment::{BackendFactory, HeldBackend, VmEnvironmentBackend, VmEnvironmentConfig, guarded};

    // Stop the VMs a killed daemon left behind before the driver can launch a second one for the same environment.
    // `sweep_orphans` logs its own report and is safe beside a live daemon or CLI run.
    let _ = QemuBackend::sweep_orphans();
    let probe = Arc::new(HttpServiceProbe::new());
    let factory: BackendFactory = {
        let probe = Arc::clone(&probe);
        Box::new(move |spec| {
            let guards = RunGuards::new();
            let qemu = QemuBackend::new()
                .with_agent(AgentLaunch {
                    // A VM backend takes the agent's path from the topology.
                    program: std::path::PathBuf::new(),
                    on_link: relay_link(rt.clone(), spec.environment_id.clone()),
                })
                .with_guest_cid_hook(cid_hook(
                    rt.clone(),
                    Arc::clone(&probe),
                    guards.clone(),
                    spec.environment_id.clone(),
                    |cid| VsockDialer::new(cid, PORT_RELAY_VSOCK_PORT),
                ));
            Ok(Box::new(guarded(qemu, &guards)) as HeldBackend)
        })
    };
    let mut config = VmEnvironmentConfig::new(settings.command.clone());
    config.env = vec![(SERVICE_ENV.to_owned(), settings.service_env.clone())];
    config.boot_timeout_secs = settings.boot_timeout_secs;
    VmEnvironmentBackend::new(factory, config).with_service_probe(probe)
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
