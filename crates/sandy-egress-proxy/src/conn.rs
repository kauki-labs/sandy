//! One accepted connection: read the head, decide, connect, tunnel.

use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use nix::ifaddrs::getifaddrs;
use sandy_egress_proxy::{HeadRead, Policy, ResolveError, Resolver, Status, Verdict, decide, parse_head, read_head};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    time::{sleep, timeout},
};

/// Deadline for the request head.
const HEAD_DEADLINE: Duration = Duration::from_secs(10);
/// Deadline for name resolution, and for one connect attempt.
const STEP_DEADLINE: Duration = Duration::from_secs(10);
/// A tunnel with no bytes in either direction this long is closed.
const IDLE_TIMEOUT: Duration = Duration::from_secs(10 * 60);

/// `getaddrinfo` through the host resolver (A and AAAA).
struct SystemResolver;

impl Resolver for SystemResolver {
    fn resolve(&self, name: &str) -> Result<Vec<IpAddr>, ResolveError> {
        use std::net::ToSocketAddrs;
        let mut out: Vec<IpAddr> = Vec::new();
        for addr in (name, 0).to_socket_addrs().map_err(|_| ResolveError::Failed)? {
            if !out.contains(&addr.ip()) {
                out.push(addr.ip());
            }
        }
        Ok(out)
    }
}

/// Every address on one of the host's own interfaces, read on each CONNECT.
fn host_interface_addrs() -> Vec<IpAddr> {
    let Ok(ifaces) = getifaddrs() else {
        // Unreadable interface set: fail closed is not possible per address,
        // so log and continue with the loopback and unspecified refusals.
        tracing::warn!("getifaddrs failed; host-interface refusal is skipped for this CONNECT");
        return Vec::new();
    };
    ifaces
        .filter_map(|i| {
            let a = i.address?;
            a.as_sockaddr_in()
                .map(|s| IpAddr::V4(s.ip()))
                .or_else(|| a.as_sockaddr_in6().map(|s| IpAddr::V6(s.ip())))
        })
        .collect()
}

/// Read until the head ends. `None` closes the connection unanswered
/// (over the cap, past the deadline, or the peer hung up).
async fn read_request<S: AsyncRead + Unpin>(stream: &mut S) -> Option<(Vec<u8>, usize)> {
    let read = async {
        let mut buf = Vec::with_capacity(512);
        let mut chunk = [0u8; 1024];
        loop {
            match read_head(&buf) {
                HeadRead::Complete(end) => return Some((buf, end)),
                HeadRead::TooLarge => return None,
                HeadRead::Incomplete => {}
            }
            match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => return None,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
        }
    };
    timeout(HEAD_DEADLINE, read).await.ok().flatten()
}

async fn respond<S: AsyncWrite + Unpin>(stream: &mut S, verdict: &Verdict) {
    let _ = stream.write_all(&verdict.to_response()).await;
    let _ = stream.shutdown().await;
}

/// Serve one connection to completion.
pub async fn handle<S>(mut stream: S, policy: Arc<Policy>)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let Some((buf, end)) = read_request(&mut stream).await else {
        tracing::info!(
            target = "malformed",
            verdict = "closed",
            "head over cap, late, or incomplete"
        );
        return;
    };
    let target = match parse_head(&buf[..end]) {
        Ok(t) => t,
        Err(v) => {
            tracing::info!(target = "malformed", verdict = %v, "refused");
            respond(&mut stream, &v).await;
            return;
        }
    };
    let label = target.label();

    let decided = {
        let (t, p) = (target.clone(), Arc::clone(&policy));
        let work = tokio::task::spawn_blocking(move || decide(&t, &p, &SystemResolver, &host_interface_addrs()));
        match timeout(STEP_DEADLINE, work).await {
            Ok(Ok(r)) => r,
            Ok(Err(_)) => Err(Verdict::new(Status::BadGateway, format!("{label}: lookup task failed"))),
            Err(_) => Err(Verdict::new(
                Status::GatewayTimeout,
                format!("{label}: name resolution timed out"),
            )),
        }
    };
    let addrs = match decided {
        Ok(a) => a,
        Err(v) => {
            tracing::info!(target = %label, verdict = %v, "refused");
            respond(&mut stream, &v).await;
            return;
        }
    };

    let upstream = match connect_first(&addrs, target.port, &label).await {
        Ok(s) => s,
        Err(v) => {
            tracing::info!(target = %label, verdict = %v, "refused");
            respond(&mut stream, &v).await;
            return;
        }
    };
    tracing::info!(target = %label, verdict = "200", "tunnel open");
    if stream
        .write_all(&Verdict::new(Status::Ok, "").to_response())
        .await
        .is_err()
    {
        return;
    }
    tunnel(stream, upstream, &buf[end..]).await;
}

/// Try each kept address in order, one at a time. Never resolves again.
async fn connect_first(addrs: &[IpAddr], port: u16, label: &str) -> Result<TcpStream, Verdict> {
    let mut timed_out = false;
    for ip in addrs {
        match timeout(STEP_DEADLINE, TcpStream::connect(SocketAddr::new(*ip, port))).await {
            Ok(Ok(s)) => return Ok(s),
            Ok(Err(_)) => {}
            Err(_) => timed_out = true,
        }
    }
    let (status, what) = if timed_out {
        (Status::GatewayTimeout, "connect timed out")
    } else {
        (Status::BadGateway, "connect failed")
    };
    Err(Verdict::new(status, format!("{label}: {what}")))
}

/// Copy bytes both ways. The idle timer resets on any byte in either direction.
async fn tunnel<S>(client: S, upstream: TcpStream, early: &[u8])
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut cr, mut cw) = tokio::io::split(client);
    let (mut ur, mut uw) = upstream.into_split();
    if !early.is_empty() && write_idle(&mut uw, early).await.is_err() {
        return;
    }
    let (mut cbuf, mut ubuf) = ([0u8; 16 * 1024], [0u8; 16 * 1024]);
    let (mut client_open, mut upstream_open) = (true, true);
    while client_open || upstream_open {
        tokio::select! {
            r = cr.read(&mut cbuf), if client_open => match r {
                Ok(0) => { client_open = false; let _ = uw.shutdown().await; }
                Ok(n) => if write_idle(&mut uw, &cbuf[..n]).await.is_err() { return },
                Err(_) => return,
            },
            r = ur.read(&mut ubuf), if upstream_open => match r {
                Ok(0) => { upstream_open = false; let _ = cw.shutdown().await; }
                Ok(n) => if write_idle(&mut cw, &ubuf[..n]).await.is_err() { return },
                Err(_) => return,
            },
            () = sleep(IDLE_TIMEOUT) => return,
        }
    }
}

async fn write_idle<W: AsyncWrite + Unpin>(w: &mut W, bytes: &[u8]) -> Result<(), ()> {
    match timeout(IDLE_TIMEOUT, w.write_all(bytes)).await {
        Ok(Ok(())) => Ok(()),
        _ => Err(()),
    }
}
