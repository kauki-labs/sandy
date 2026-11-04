//! Acceptance tests for the HTTP readiness probe, over a one-shot loopback server.

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener},
    thread::JoinHandle,
    time::Duration,
};

use anyhow::{Context, Result};
use sandy_api::environment::Probe;
use sandy_environment::{HttpServiceProbe, ServiceProbe};

/// Answers one request with `reply` (split into two writes when `split`), then exits.
fn serve_once(reply: &'static str, split: bool) -> Result<(SocketAddr, JoinHandle<()>)> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let t = std::thread::spawn(move || {
        if let Ok((mut s, _)) = listener.accept() {
            let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
            let mut buf = [0u8; 256];
            let _ = s.read(&mut buf);
            if split {
                let (a, b) = reply.split_at(7);
                let _ = s.write_all(a.as_bytes());
                let _ = s.flush();
                std::thread::sleep(Duration::from_millis(100));
                let _ = s.write_all(b.as_bytes());
            } else {
                let _ = s.write_all(reply.as_bytes());
            }
        }
    });
    Ok((addr, t))
}

fn probe_at(addr: SocketAddr) -> Result<Probe> {
    let p = HttpServiceProbe::new();
    p.register("env-a", addr);
    Ok(p.probe("env-a")?)
}

#[test]
fn an_unregistered_environment_is_starting_until_the_guest_link_is_up() -> Result<()> {
    let p = HttpServiceProbe::new();
    assert!(matches!(p.probe("env-a")?, Probe::Starting { step } if step.contains("guest link")));
    Ok(())
}

#[test]
fn a_status_below_500_is_ready_at_the_registered_address() -> Result<()> {
    for reply in ["HTTP/1.1 200 OK\r\n\r\n", "HTTP/1.1 401 Unauthorized\r\n\r\n"] {
        let (addr, t) = serve_once(reply, false)?;
        let out = probe_at(addr)?;
        let Probe::Ready { endpoint } = out else {
            anyhow::bail!("{reply:?}: expected Ready, got {out:?}")
        };
        assert_eq!((endpoint.host.as_str(), endpoint.port), ("127.0.0.1", addr.port()));
        t.join().map_err(|_| anyhow::anyhow!("server panicked"))?;
    }
    Ok(())
}

#[test]
fn a_503_is_still_starting() -> Result<()> {
    let (addr, t) = serve_once("HTTP/1.1 503 Service Unavailable\r\n\r\n", false)?;
    assert!(matches!(probe_at(addr)?, Probe::Starting { step } if step == "starting"));
    t.join().map_err(|_| anyhow::anyhow!("server panicked"))?;
    Ok(())
}

#[test]
fn a_status_line_split_across_segments_is_read_whole() -> Result<()> {
    let (addr, t) = serve_once("HTTP/1.1 200 OK\r\n\r\n", true)?;
    assert!(matches!(probe_at(addr)?, Probe::Ready { .. }));
    t.join().map_err(|_| anyhow::anyhow!("server panicked"))?;
    Ok(())
}

#[test]
fn nothing_listening_and_a_non_http_answer_are_both_starting() -> Result<()> {
    let free = TcpListener::bind("127.0.0.1:0")?.local_addr()?; // listener dropped: connection refused
    assert!(matches!(probe_at(free)?, Probe::Starting { step } if step == "boot"));
    let (addr, t) = serve_once("SSH-2.0-not-http\r\n", false)?;
    assert!(matches!(probe_at(addr)?, Probe::Starting { step } if step == "boot"));
    t.join().map_err(|_| anyhow::anyhow!("server panicked"))?;
    Ok(())
}

#[test]
fn unregister_returns_the_probe_to_starting() -> Result<()> {
    let (addr, t) = serve_once("HTTP/1.1 200 OK\r\n\r\n", false)?;
    let p = HttpServiceProbe::new();
    p.register("env-a", addr);
    assert!(matches!(p.probe("env-a")?, Probe::Ready { .. }));
    p.unregister("env-a");
    let again = p.probe("env-a")?;
    assert!(
        matches!(&again, Probe::Starting { step } if step.contains("guest link")),
        "{again:?}"
    );
    t.join().map_err(|_| anyhow::anyhow!("server panicked"))?;
    Ok(())
}

#[test]
fn the_probe_is_usable_as_a_vm_backends_service_probe() -> Result<()> {
    let p: std::sync::Arc<dyn ServiceProbe> = std::sync::Arc::new(HttpServiceProbe::new());
    let _ = p.probe("env-a").context("probe")?;
    Ok(())
}
