//! Acceptance tests for the HTTP readiness probe, over a one-shot loopback server.

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener},
    thread::JoinHandle,
    time::{Duration, Instant},
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
    let _registered = p.register("env-a", addr);
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
    // Port 1 (tcpmux) has no listener on a developer or CI host: connection refused, with no bind race.
    assert!(matches!(probe_at("127.0.0.1:1".parse()?)?, Probe::Starting { step } if step == "boot"));
    let (addr, t) = serve_once("SSH-2.0-not-http\r\n", false)?;
    assert!(matches!(probe_at(addr)?, Probe::Starting { step } if step == "boot"));
    t.join().map_err(|_| anyhow::anyhow!("server panicked"))?;
    Ok(())
}

#[test]
fn dropping_the_registration_returns_the_probe_to_starting() -> Result<()> {
    let (addr, t) = serve_once("HTTP/1.1 200 OK\r\n\r\n", false)?;
    let p = HttpServiceProbe::new();
    let registration = p.register("env-a", addr);
    assert!(matches!(p.probe("env-a")?, Probe::Ready { .. }));
    drop(registration);
    let again = p.probe("env-a")?;
    assert!(
        matches!(&again, Probe::Starting { step } if step.contains("guest link")),
        "{again:?}"
    );
    t.join().map_err(|_| anyhow::anyhow!("server panicked"))?;
    Ok(())
}

#[test]
fn an_older_registration_dropping_does_not_undo_a_newer_one() -> Result<()> {
    let (addr, t) = serve_once("HTTP/1.1 200 OK\r\n\r\n", false)?;
    let p = HttpServiceProbe::new();
    let old = p.register("env-a", "127.0.0.1:1".parse()?); // the previous run's bridge
    let _new = p.register("env-a", addr); // the relaunch
    drop(old);
    assert!(
        matches!(p.probe("env-a")?, Probe::Ready { .. }),
        "the relaunch must stay registered"
    );
    t.join().map_err(|_| anyhow::anyhow!("server panicked"))?;
    Ok(())
}

#[test]
fn the_500_boundary_and_other_statuses() -> Result<()> {
    for (reply, ready) in [
        ("HTTP/1.1 499 X\r\n\r\n", true),
        ("HTTP/1.1 500 X\r\n\r\n", false),
        ("HTTP/1.1 404 Not Found\r\n\r\n", true),
        ("HTTP/1.1 302 Found\r\n\r\n", true),
        ("HTTP/1.1 +99 X\r\n\r\n", false),
        ("HTTP/1.1 2xx X\r\n\r\n", false),
        ("HTTP/1.1200 OK\r\n\r\n", false),
        ("HTTP/1.1 2000 X\r\n\r\n", false),
        ("HTTP/1.1 200garbage\r\n\r\n", false),
        ("HTTP/1.1 200\r\n\r\n", true),
        ("HTTP/1.1 200", true), // the status at the very end of input
        ("HTTP/2 200\r\n\r\n", false),
        ("HTTP/1.", false), // early EOF
    ] {
        let (addr, t) = serve_once(reply, false)?;
        let out = probe_at(addr)?;
        assert_eq!(matches!(out, Probe::Ready { .. }), ready, "{reply:?}: {out:?}");
        t.join().map_err(|_| anyhow::anyhow!("server panicked"))?;
    }
    Ok(())
}

/// Accepts, then sends `byte` every `every` for up to `total`, or nothing at all when `byte` is `None`.
fn serve_slowly(byte: Option<u8>, every: Duration, total: Duration) -> Result<(SocketAddr, JoinHandle<()>)> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let t = std::thread::spawn(move || {
        if let Ok((mut s, _)) = listener.accept() {
            let start = Instant::now();
            while start.elapsed() < total {
                if let Some(b) = byte
                    && s.write_all(&[b]).is_err()
                {
                    break;
                }
                std::thread::sleep(every);
            }
        }
    });
    Ok((addr, t))
}

#[test]
fn a_server_that_never_answers_or_trickles_cannot_hold_the_probe_past_its_budget() -> Result<()> {
    for byte in [None, Some(b'H')] {
        let (addr, t) = serve_slowly(byte, Duration::from_millis(900), Duration::from_secs(8))?;
        let start = Instant::now();
        let out = probe_at(addr)?;
        assert!(matches!(&out, Probe::Starting { .. }), "{byte:?}: {out:?}");
        assert!(
            start.elapsed() < Duration::from_millis(2000),
            "{byte:?}: the probe took {:?}",
            start.elapsed()
        );
        drop(t); // the server thread ends by itself; do not wait for it
    }
    Ok(())
}

#[test]
fn the_probe_is_usable_as_a_vm_backends_service_probe() -> Result<()> {
    let p: std::sync::Arc<dyn ServiceProbe> = std::sync::Arc::new(HttpServiceProbe::new());
    let _ = p.probe("env-a").context("probe")?;
    Ok(())
}
