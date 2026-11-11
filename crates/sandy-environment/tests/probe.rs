//! Acceptance tests for the HTTP readiness probe, over a one-shot loopback server.

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use sandy_api::environment::Probe;
use sandy_environment::{HostCheck, HttpServiceProbe, ServiceProbe};

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
        ("HTTP/1.1 000 X\r\n\r\n", false),
        ("HTTP/1.1 099 X\r\n\r\n", false),
        ("HTTP/1.1 100 Continue\r\n\r\n", true),
        ("HTTP/1.1 +99 X\r\n\r\n", false),
        ("HTTP/1.1 2xx X\r\n\r\n", false),
        ("HTTP/1.1200 OK\r\n\r\n", false),
        ("HTTP/1.1 2000 X\r\n\r\n", false),
        ("HTTP/1.1 200garbage\r\n\r\n", false),
        ("HTTP/1.1 200\r\n\r\n", true),
        ("HTTP/1.1 200", false), // the status at the very end of input: no delimiter, no answer
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
            start.elapsed() < Duration::from_millis(3000),
            "{byte:?}: the probe took {:?}",
            start.elapsed()
        );
        drop(t); // the server thread ends by itself; do not wait for it
    }
    Ok(())
}

#[test]
fn a_status_line_that_stalls_before_its_delimiter_is_starting_not_ready() -> Result<()> {
    // Exactly "HTTP/1.1 200", then silence past the probe's budget: a read timeout, not an end of input.
    let (addr, t) = serve_slowly_after(b"HTTP/1.1 200", Duration::from_secs(3))?;
    let start = Instant::now();
    let out = probe_at(addr)?;
    assert!(matches!(&out, Probe::Starting { step } if step == "boot"), "{out:?}");
    assert!(
        start.elapsed() < Duration::from_millis(3000),
        "took {:?}",
        start.elapsed()
    );
    drop(t);
    Ok(())
}

/// Accepts, writes `head`, then holds the connection open and silent for `hold`.
fn serve_slowly_after(head: &'static [u8], hold: Duration) -> Result<(SocketAddr, JoinHandle<()>)> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let t = std::thread::spawn(move || {
        if let Ok((mut s, _)) = listener.accept() {
            let mut buf = [0u8; 256];
            let _ = s.read(&mut buf);
            let _ = s.write_all(head);
            let _ = s.flush();
            std::thread::sleep(hold);
        }
    });
    Ok((addr, t))
}

#[test]
fn the_probe_is_usable_as_a_vm_backends_service_probe() -> Result<()> {
    let p: std::sync::Arc<dyn ServiceProbe> = std::sync::Arc::new(HttpServiceProbe::new());
    let out = p.probe("env-a").context("probe")?;
    assert!(
        matches!(out, Probe::Starting { .. }),
        "an unregistered id is Starting: {out:?}"
    );
    Ok(())
}

// ---- the host check mode (#732) ----------------------------------------------------------------------------------

/// A stand-in for the host bridge in front of a guest service: it accepts, reads the client's first byte, and (when
/// `dials`) counts one ready dial, as the real bridge does once the guest relay answers. It then sends `reply` and
/// keeps the connection open for `hold`, so the probe sees the same silence a real bridge shows after a good dial.
fn fake_bridge(
    dials: bool,
    reply: &'static [u8],
    hold: Duration,
) -> Result<(SocketAddr, Arc<AtomicU64>, JoinHandle<()>)> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let counter = Arc::new(AtomicU64::new(0));
    let count = Arc::clone(&counter);
    let t = std::thread::spawn(move || {
        if let Ok((mut s, _)) = listener.accept() {
            let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
            let mut first = [0u8; 1];
            if s.read(&mut first).is_ok_and(|n| n == 1) && dials {
                count.fetch_add(1, Ordering::SeqCst);
            }
            let _ = s.write_all(reply);
            std::thread::sleep(hold);
        }
    });
    Ok((addr, counter, t))
}

fn connect_probe(addr: SocketAddr, dials: &Arc<AtomicU64>) -> Result<Probe> {
    let p = HttpServiceProbe::with_check(HostCheck::Connect);
    let _registered = p.register_bridge("env-a", addr, Arc::clone(dials));
    Ok(p.probe("env-a")?)
}

#[test]
fn the_default_host_check_is_http() {
    assert_eq!(HostCheck::default(), HostCheck::Http);
}

#[test]
fn a_host_check_name_is_http_or_connect_and_anything_else_is_refused() {
    assert_eq!("http".parse::<HostCheck>(), Ok(HostCheck::Http));
    assert_eq!("connect".parse::<HostCheck>(), Ok(HostCheck::Connect));
    for bad in ["", "tcp", "HTTP", "Connect", " connect", "http,connect", "0"] {
        let err = bad.parse::<HostCheck>().expect_err(bad);
        assert!(err.contains("http") && err.contains("connect"), "{bad:?}: {err}");
    }
}

/// An echo service speaks no HTTP. Connect mode needs no answer, only a dial that got through.
#[test]
fn connect_mode_is_ready_on_a_tcp_echo_that_never_speaks_http() -> Result<()> {
    let (addr, dials, t) = fake_bridge(true, b"x", Duration::from_millis(300))?;
    let out = connect_probe(addr, &dials)?;
    let Probe::Ready { endpoint } = out else {
        anyhow::bail!("expected Ready, got {out:?}")
    };
    assert_eq!((endpoint.host.as_str(), endpoint.port), ("127.0.0.1", addr.port()));
    t.join().map_err(|_| anyhow::anyhow!("server panicked"))?;
    Ok(())
}

/// The same echo, HTTP mode: no `HTTP/1.x NNN` line, so not Ready.
#[test]
fn http_mode_on_the_same_echo_is_not_ready() -> Result<()> {
    let (addr, _dials, t) = fake_bridge(true, b"x", Duration::from_millis(100))?;
    let p = HttpServiceProbe::with_check(HostCheck::Http);
    let _registered = p.register("env-a", addr);
    assert!(matches!(p.probe("env-a")?, Probe::Starting { step } if step == "boot"));
    t.join().map_err(|_| anyhow::anyhow!("server panicked"))?;
    Ok(())
}

/// The bridge listens at once but dials only after a first byte, so an accepted connection proves nothing. No ready
/// dial in the budget means Starting, and the probe does not outlast its budget.
#[test]
fn connect_mode_is_starting_while_the_bridge_has_not_got_a_dial_through() -> Result<()> {
    let (addr, dials, t) = fake_bridge(false, b"", Duration::from_secs(3))?;
    let start = Instant::now();
    let out = connect_probe(addr, &dials)?;
    assert!(matches!(out, Probe::Starting { ref step } if step == "boot"), "{out:?}");
    assert!(
        start.elapsed() < Duration::from_millis(2500),
        "the probe kept to its budget"
    );
    t.join().map_err(|_| anyhow::anyhow!("server panicked"))?;
    Ok(())
}

/// A dial that already got through is proof that the service port accepted, and the probe does not touch the
/// service again: the driver probes every Ready environment each pass, so a repeat byte would reach the service for
/// the environment's whole life (#748 review). Here nothing listens at the address at all.
#[test]
fn connect_mode_stays_ready_on_an_earlier_dial_without_touching_the_service() -> Result<()> {
    let dials = Arc::new(AtomicU64::new(1));
    let out = connect_probe("127.0.0.1:1".parse()?, &dials)?;
    assert!(matches!(out, Probe::Ready { .. }), "{out:?}");
    Ok(())
}

/// A dial that finished between two probes (a late success of the previous probe's byte) reads Ready at the next
/// probe at once, without a new byte.
#[test]
fn connect_mode_sends_one_byte_only_while_no_dial_has_got_through() -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    listener.set_nonblocking(true)?;
    let dials = Arc::new(AtomicU64::new(0));
    // First probe: no dial gets through, so it connects and sends one byte, and reads Starting.
    assert!(matches!(connect_probe(addr, &dials)?, Probe::Starting { .. }));
    let (mut first, _) = loop {
        match listener.accept() {
            Ok(accepted) => break accepted,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => std::thread::sleep(Duration::from_millis(10)),
            Err(e) => return Err(e.into()),
        }
    };
    first.set_read_timeout(Some(Duration::from_secs(1)))?;
    let mut byte = [0u8; 1];
    assert_eq!(first.read(&mut byte)?, 1, "the first probe sent its one byte");
    // The dial then succeeds late. The next probe reads Ready and opens no new connection.
    dials.store(1, Ordering::SeqCst);
    assert!(matches!(connect_probe(addr, &dials)?, Probe::Ready { .. }));
    assert!(
        matches!(listener.accept(), Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock),
        "no second connection"
    );
    Ok(())
}

#[test]
fn connect_mode_with_nothing_listening_is_starting() -> Result<()> {
    let dials = Arc::new(AtomicU64::new(0));
    assert!(matches!(connect_probe("127.0.0.1:1".parse()?, &dials)?, Probe::Starting { step } if step == "boot"));
    Ok(())
}

#[test]
fn connect_mode_without_a_registered_bridge_is_starting_for_the_guest_link() -> Result<()> {
    let p = HttpServiceProbe::with_check(HostCheck::Connect);
    assert!(matches!(p.probe("env-a")?, Probe::Starting { step } if step.contains("guest link")));
    Ok(())
}

/// Connect mode must see the bridge's dial count. A plain address registration has none, so the probe cannot
/// prove anything: that is an error, not a Ready.
#[test]
fn connect_mode_on_a_registration_without_a_dial_count_is_an_error() -> Result<()> {
    let (addr, _dials, t) = fake_bridge(true, b"", Duration::from_millis(100))?;
    let p = HttpServiceProbe::with_check(HostCheck::Connect);
    let _registered = p.register("env-a", addr);
    let err = p.probe("env-a").expect_err("must not read Ready without a dial count");
    assert!(err.to_string().contains("dial"), "{err}");
    drop(t);
    Ok(())
}

/// An HTTP service answers fine in connect mode too: the mode asks only whether the service port accepted.
#[test]
fn connect_mode_is_also_ready_on_an_http_service() -> Result<()> {
    let (addr, dials, t) = fake_bridge(
        true,
        b"HTTP/1.1 503 Service Unavailable\r\n\r\n",
        Duration::from_millis(300),
    )?;
    assert!(matches!(connect_probe(addr, &dials)?, Probe::Ready { .. }));
    t.join().map_err(|_| anyhow::anyhow!("server panicked"))?;
    Ok(())
}
