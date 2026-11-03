//! live_vsock_bridge: the host half of the service bridge against a real guest (#590, epic #597).
//!
//! Tier-3. Per INV-S9 it is never counted green from a fake: the whole file is behind the `live` feature, and it
//! fails, rather than skips, when it is not pointed at a guest.
//!
//! The guest runs `sandy-agent port-relay --vsock-port 5100 --to 127.0.0.1:3773` and a service on that port (for
//! example `t3 serve`). This test starts a [`Bridge`] over a [`VsockDialer`] to that guest's CID, makes an HTTP request
//! through the bridge's loopback address, and checks the guest service answered. The dial window is long enough for
//! the guest to boot, so it also exercises the readiness retry (the relay is not bound, then the service is not up,
//! until it is).
//!
//! ```text
//! SANDY_LIVE_GUEST_CID=<cid> cargo nextest run -p sandy-conn --features live --test live_vsock_bridge --no-capture
//! ```
#![cfg(all(feature = "live", target_os = "linux"))]

use std::time::Duration;

use anyhow::{Context, bail};
use sandy_api::agent::PORT_RELAY_VSOCK_PORT;
use sandy_conn::{
    bridge::{Bridge, BridgeConfig},
    dial::VsockDialer,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};

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
    timeout(Duration::from_secs(60), client.read_to_end(&mut response))
        .await
        .context("no answer from the guest service within 60 s")??;
    status_of(&response)
}

/// A client on the bridge's loopback address reaches the guest's service through the vsock relay.
///
/// The bridge reaches the relay as soon as the relay is up, which can be before the service is ready: t3 answers 503
/// while it starts. So, as the environment probe will, poll through the bridge until the status is below 500.
#[tokio::test]
async fn http_reaches_a_guest_service_through_the_vsock_bridge() -> anyhow::Result<()> {
    let cid = guest_cid()?;
    let config = BridgeConfig {
        // The guest may still be booting: the relay is not bound, then the service is not up.
        dial_window: Duration::from_secs(180),
        ..BridgeConfig::default()
    };
    let bridge = Bridge::start(VsockDialer::new(cid, PORT_RELAY_VSOCK_PORT)?, config).await?;
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
        "live_vsock_bridge: guest cid {cid}, HTTP {code} after {:?} and {requests} request(s), statuses {statuses:?}",
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
