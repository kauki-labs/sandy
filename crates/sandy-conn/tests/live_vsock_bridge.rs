//! live_vsock_bridge: the host half of the service bridge against a real guest (#590, epic #597).
//!
//! Tier-3. Per INV-S9 it is never counted green from a fake: the whole file is behind the `live` feature, and it
//! fails, rather than skips, when it is not pointed at a guest.
//!
//! The guest runs `sandy-agent port-relay --vsock-port 5100 --to 127.0.0.1:3773` and a service on that port (for
//! example `service serve`). This test starts a [`Bridge`] over a [`VsockDialer`] to that guest's CID, makes an HTTP
//! request through the bridge's loopback address, and checks the guest service answered. The dial window is long enough
//! for the guest to boot, so it also exercises the readiness retry (the relay is not bound, then the service is not up,
//! until it is).
//!
//! On macOS the vfkit leg (KSB4) runs the same check over a [`UnixDialer`] to the host socket of vfkit's `connect`
//! device, which `scripts/dev/live-vfkit-bridge.sh` sets up.
//!
//! ```text
//! SANDY_LIVE_GUEST_CID=<cid> cargo nextest run -p sandy-conn --features live --test live_vsock_bridge --no-capture
//! SANDY_LIVE_GUEST_SOCKET=<path> cargo nextest run -p sandy-conn --features live --test live_vsock_bridge --no-capture
//! ```
#![cfg(all(feature = "live", any(target_os = "linux", target_os = "macos")))]

use std::time::Duration;

use anyhow::{Context, bail};
use sandy_conn::bridge::{Bridge, BridgeConfig, Dialer};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};

#[cfg(target_os = "linux")]
fn guest_cid() -> anyhow::Result<u32> {
    let raw = std::env::var("SANDY_LIVE_GUEST_CID")
        .context("refusing: SANDY_LIVE_GUEST_CID is unset; point this test at a running guest's vsock CID")?;
    raw.parse()
        .with_context(|| format!("SANDY_LIVE_GUEST_CID must be a number, got {raw:?}"))
}

/// The HTTP status of a raw response head, or an error naming what came back.
fn status_of(head: &[u8]) -> anyhow::Result<u16> {
    let text = String::from_utf8_lossy(head);
    let line = text.lines().next().unwrap_or_default();
    let mut parts = line.split_whitespace();
    match (parts.next(), parts.next().and_then(|code| code.parse::<u16>().ok())) {
        (Some(version), Some(code)) if version.starts_with("HTTP/") => Ok(code),
        _ => bail!("not an HTTP response: {line:?}"),
    }
}

/// One `GET /` through the bridge, returning the HTTP status.
async fn get(addr: std::net::SocketAddr) -> anyhow::Result<u16> {
    let mut client = TcpStream::connect(addr).await.context("connect to the bridge")?;
    client
        .write_all(b"GET / HTTP/1.0\r\nHost: guest\r\nConnection: close\r\n\r\n")
        .await?;
    let mut response = Vec::new();
    // The bridge accepts at once and dials for up to its window (180 s) plus one attempt bound (5 s).
    timeout(Duration::from_secs(185), client.read_to_end(&mut response))
        .await
        .context("no answer from the guest service within 185 s")??;
    status_of(&response)
}

/// A client on the bridge's loopback address reaches the guest's service through the vsock relay.
///
/// The bridge reaches the relay as soon as the relay is up, which can be before the service is ready: a service may
/// answer 503 while it starts. So, as the environment probe will, poll through the bridge until the status is below
/// 500.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn http_reaches_a_guest_service_through_the_vsock_bridge() -> anyhow::Result<()> {
    let cid = guest_cid()?;
    let dialer = sandy_conn::dial::VsockDialer::new(cid, sandy_api::agent::PORT_RELAY_VSOCK_PORT)?;
    through_the_bridge(dialer, &format!("guest cid {cid}")).await
}

/// The same check on macOS: vfkit's `connect` device exposes the guest's relay port at a host unix socket.
#[cfg(target_os = "macos")]
#[tokio::test]
async fn http_reaches_a_guest_service_through_the_vfkit_socket_bridge() -> anyhow::Result<()> {
    let path = std::env::var("SANDY_LIVE_GUEST_SOCKET")
        .context("refusing: SANDY_LIVE_GUEST_SOCKET is unset; point this test at a running vfkit guest's socket")?;
    through_the_bridge(
        sandy_conn::dial::UnixDialer::new(&path),
        &format!("guest socket {path}"),
    )
    .await
}

async fn through_the_bridge<D: Dialer>(dialer: D, label: &str) -> anyhow::Result<()> {
    let config = BridgeConfig {
        // The guest may still be booting: the relay is not bound, then the service is not up.
        dial_window: Duration::from_secs(180),
        ..BridgeConfig::default()
    };
    let bridge = Bridge::start(dialer, config).await?;
    let addr = bridge.addr();

    let started = std::time::Instant::now();
    let mut requests = 0u32;
    let mut statuses = Vec::new();
    let code = loop {
        requests += 1;
        let code = get(addr).await?;
        statuses.push(code);
        if code < 500 {
            break code;
        }
        anyhow::ensure!(
            started.elapsed() < Duration::from_secs(120),
            "never below 500: {statuses:?}"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    };
    println!(
        "live_vsock_bridge: {label}, HTTP {code} after {:?} and {requests} request(s), statuses {statuses:?}",
        started.elapsed()
    );
    assert!(
        (100..500).contains(&code),
        "the guest service must answer below 500, got {code}"
    );

    // A stopped environment refuses connections: after shutdown nothing listens on the bridge's address.
    bridge.shutdown().await;
    assert!(
        TcpStream::connect(addr).await.is_err(),
        "a new connection must be refused after shutdown"
    );
    Ok(())
}
