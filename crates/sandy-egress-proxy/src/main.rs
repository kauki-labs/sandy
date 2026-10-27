//! `sandy-egress-proxy`: one unprivileged proxy per VM launch.
//!
//! Reads the policy as JSON on stdin, binds, writes `READY`, then serves
//! CONNECT requests until killed. See `docs/decisions/egress-proxy.md`.

mod conn;

use std::{
    io::{Read, Write},
    path::PathBuf,
    process::ExitCode,
    sync::Arc,
};

use sandy_api::egress::AllowList;
use sandy_egress_proxy::Policy;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::Semaphore,
};

/// Concurrent connections per run; one over is closed at accept.
const MAX_CONNECTIONS: usize = 256;

enum Listen {
    Unix(PathBuf),
    #[cfg(target_os = "linux")]
    Vsock {
        port: u32,
        peer_cid: u32,
    },
}

fn parse_args(mut args: impl Iterator<Item = String>) -> Result<Listen, String> {
    let mut unix = None;
    let mut port = None;
    let mut cid = None;
    while let Some(arg) = args.next() {
        let mut value = |name: &str| args.next().ok_or_else(|| format!("{name} needs a value"));
        match arg.as_str() {
            "--unix" => unix = Some(PathBuf::from(value("--unix")?)),
            "--vsock-port" => {
                port = Some(
                    value("--vsock-port")?
                        .parse::<u32>()
                        .map_err(|e| format!("--vsock-port: {e}"))?,
                )
            }
            "--peer-cid" => {
                cid = Some(
                    value("--peer-cid")?
                        .parse::<u32>()
                        .map_err(|e| format!("--peer-cid: {e}"))?,
                )
            }
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    match (unix, port, cid) {
        (Some(path), None, None) => Ok(Listen::Unix(path)),
        #[cfg(target_os = "linux")]
        (None, Some(port), Some(peer_cid)) => Ok(Listen::Vsock { port, peer_cid }),
        _ => Err(
            "usage: sandy-egress-proxy --unix <path> | --vsock-port <P> --peer-cid <CID> (vsock is Linux only)".into(),
        ),
    }
}

/// Read the whole policy from stdin, then drop it (closing stdin).
fn read_policy() -> Result<Policy, String> {
    let mut json = String::new();
    std::io::stdin()
        .read_to_string(&mut json)
        .map_err(|e| format!("reading policy: {e}"))?;
    let list: AllowList = serde_json::from_str(&json).map_err(|e| format!("policy is not valid JSON: {e}"))?;
    Policy::from_allow_list(&list).map_err(|e| e.to_string())
}

fn ready() -> std::io::Result<()> {
    let mut out = std::io::stdout().lock();
    out.write_all(b"READY\n")?;
    out.flush()
}

/// Serve one accepted stream unless the run is at its connection cap.
fn spawn_conn<S>(stream: S, policy: &Arc<Policy>, slots: &Arc<Semaphore>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let Ok(permit) = Arc::clone(slots).try_acquire_owned() else {
        tracing::warn!("connection cap reached; closing at accept");
        return;
    };
    let policy = Arc::clone(policy);
    tokio::spawn(async move {
        conn::handle(stream, policy).await;
        drop(permit);
    });
}

async fn serve(listen: Listen, policy: Policy) -> Result<(), String> {
    let policy = Arc::new(policy);
    let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    match listen {
        Listen::Unix(path) => {
            let listener =
                tokio::net::UnixListener::bind(&path).map_err(|e| format!("bind {}: {e}", path.display()))?;
            ready().map_err(|e| format!("writing READY: {e}"))?;
            loop {
                let (stream, _) = listener.accept().await.map_err(|e| format!("accept: {e}"))?;
                spawn_conn(stream, &policy, &slots);
            }
        }
        #[cfg(target_os = "linux")]
        Listen::Vsock { port, peer_cid } => {
            let addr = tokio_vsock::VsockAddr::new(tokio_vsock::VMADDR_CID_ANY, port);
            let mut listener =
                tokio_vsock::VsockListener::bind(addr).map_err(|e| format!("bind vsock port {port}: {e}"))?;
            ready().map_err(|e| format!("writing READY: {e}"))?;
            loop {
                let (stream, peer) = listener.accept().await.map_err(|e| format!("accept: {e}"))?;
                if peer.cid() != peer_cid {
                    tracing::warn!(cid = peer.cid(), "refused a vsock peer with the wrong CID");
                    continue;
                }
                spawn_conn(stream, &policy, &slots);
            }
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    let result = async {
        let listen = parse_args(std::env::args().skip(1))?;
        let policy = read_policy()?;
        serve(listen, policy).await
    }
    .await;
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!("{e}");
            ExitCode::from(2)
        }
    }
}
