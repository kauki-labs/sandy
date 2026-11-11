//! The HTTP readiness probe shared by the backends (#587): one `GET /` against a loopback address, read as a status.
//!
//! [`HttpServiceProbe`] is the [`ServiceProbe`] for a VM environment (slice C3b). The host bridge listens on a
//! loopback address and dials the guest only after a client's first byte, so a probe that sends a request is
//! what makes the bridge dial. Until an address is registered for an environment the guest link is not up, and the
//! probe reports `Starting`.

use std::{
    collections::BTreeMap,
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use sandy_api::{
    backend::BackendError,
    environment::{Endpoint, Probe},
};

use crate::ServiceProbe;

/// The whole probe, connect to last byte, gives up after this. A server that trickles one byte at a time cannot
/// hold the driver's pass longer.
const PROBE_BUDGET: Duration = Duration::from_millis(1500);

/// The HTTP status a service answers on `/`, or `None` if nothing answers or the answer is not `HTTP/1.x NNN`.
pub(crate) fn http_status(addr: SocketAddr) -> Option<u16> {
    let start = Instant::now();
    let left = || PROBE_BUDGET.checked_sub(start.elapsed()).filter(|d| !d.is_zero());
    let mut stream = TcpStream::connect_timeout(&addr, left()?.min(Duration::from_millis(500))).ok()?;
    stream.set_write_timeout(Some(left()?)).ok()?;
    stream
        .write_all(b"GET / HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .ok()?;
    // "HTTP/1.x NNN" plus one delimiter byte; a service may send it in segments.
    let mut buf = [0u8; 13];
    let mut filled = 0;
    while filled < buf.len() {
        stream.set_read_timeout(Some(left()?)).ok()?;
        match stream.read(&mut buf[filled..]) {
            Ok(0) => break,
            // A timeout is not end of input: a stalled, incomplete status line is no answer.
            Err(_) => return None,
            Ok(n) => filled += n,
        }
    }
    let line = &buf[..filled];
    let rest = line.strip_prefix(b"HTTP/1.")?;
    // "<digit> NNN": one version digit, a space, then exactly three digits.
    match rest {
        [v, b' ', a, b, c, delim @ ..]
            if v.is_ascii_digit()
                && [a, b, c].iter().all(|d| d.is_ascii_digit())
                && delim.first().is_some_and(|&d| matches!(d, b' ' | b'\r' | b'\n')) =>
        {
            // "000" to "099" are no HTTP status: a non-HTTP listener must not read as Ready.
            std::str::from_utf8(&[*a, *b, *c])
                .ok()?
                .parse()
                .ok()
                .filter(|code| *code >= 100)
        }
        _ => None,
    }
}

/// How the host decides a VM environment's service is Ready (#732).
///
/// The guest runs the service's declared probe on its own; this is the host's check through the bridge, and the one
/// that decides Ready.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum HostCheck {
    /// One `GET /`; an `HTTP/1.x NNN` answer below 500 is Ready. The default: t3 answers 503 while it starts and
    /// 401 once auth is on, so Ready proves an HTTP listener.
    #[default]
    Http,
    /// The service port accepted a connection through the bridge, whatever the service then says. For a generic
    /// service that does not speak HTTP.
    Connect,
}

impl std::str::FromStr for HostCheck {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "http" => Ok(Self::Http),
            "connect" => Ok(Self::Connect),
            other => Err(format!("{other:?} is not a host check: use `http` or `connect`")),
        }
    }
}

/// The connect check. The bridge's count of ready dials is per bridge, and a bridge lives as long as one run, so a
/// count above zero is proof that the service port accepted a connection at some point in this run. The relay
/// answers ready only after it connected to the service port. The probe then does not touch the service again: the
/// driver probes every Ready environment each pass, and a repeat byte would reach the service for the environment's
/// whole life.
///
/// With no ready dial yet, the probe sends the bridge one byte, which makes it dial the guest relay (it dials only
/// after a client's first byte), and waits for the count to rise within the probe budget. The byte is a newline, the
/// least likely byte to confuse a line-oriented service. A dial that succeeds after the budget (the bridge keeps
/// dialing for its window) is counted by the next probe, which sends nothing then.
fn dial_gets_through(addr: SocketAddr, ready_dials: &AtomicU64) -> bool {
    if ready_dials.load(Ordering::SeqCst) > 0 {
        return true;
    }
    let start = Instant::now();
    let left = || PROBE_BUDGET.checked_sub(start.elapsed()).filter(|d| !d.is_zero());
    let Some(connect_budget) = left().map(|d| d.min(Duration::from_millis(500))) else {
        return false;
    };
    let Ok(mut stream) = TcpStream::connect_timeout(&addr, connect_budget) else {
        return false;
    };
    let Some(write_budget) = left() else {
        return false;
    };
    if stream.set_write_timeout(Some(write_budget)).is_err() || stream.write_all(b"\n").is_err() {
        return false;
    }
    // The connection stays open until the wait ends, so the bridge's dial is not racing a closed client.
    while left().is_some() {
        if ready_dials.load(Ordering::SeqCst) > 0 {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    ready_dials.load(Ordering::SeqCst) > 0
}

type Registry = Arc<Mutex<BTreeMap<String, Entry>>>;

/// One registered environment: the registration generation, the bridge address and, for the connect check, the
/// bridge's count of ready dials.
type Entry = (u64, SocketAddr, Option<Arc<AtomicU64>>);

/// Reads readiness from an HTTP service behind a registered loopback address.
///
/// A status below 500 is Ready: t3 answers 503 while it starts and 401 once auth is on, so Ready proves an HTTP
/// listener, not that t3's API is up (as `sandy-t3-ready` in the guest image). Any HTTP answer counts, a 404 too,
/// so an address must only stay registered while the bridge that owns it lives: see [`Registration`].
#[derive(Debug, Default)]
pub struct HttpServiceProbe {
    addrs: Registry,
    next: Mutex<u64>,
    check: HostCheck,
}

/// Keeps one environment's address registered. Dropping it unregisters the address, so a bridge that closes cannot
/// leave its port behind for another local process to reuse and be reported Ready. A later registration for the
/// same environment is not undone by an older guard dropping.
#[must_use = "dropping the registration unregisters the address"]
#[derive(Debug)]
pub struct Registration {
    addrs: Registry,
    environment_id: String,
    generation: u64,
}

impl HttpServiceProbe {
    /// A probe with no environment registered, using the HTTP check.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A probe with no environment registered, deciding Ready by `check`.
    #[must_use]
    pub fn with_check(check: HostCheck) -> Self {
        Self {
            check,
            ..Self::default()
        }
    }

    /// Probe environment `environment_id` at `addr` for as long as the returned guard lives. Hold it with the
    /// bridge that listens on `addr`. Enough for the HTTP check; the connect check needs
    /// [`register_bridge`](Self::register_bridge).
    pub fn register(&self, environment_id: &str, addr: SocketAddr) -> Registration {
        self.insert(environment_id, addr, None)
    }

    /// [`register`](Self::register) with the bridge's count of ready dials (`Bridge::ready_dials`), which the
    /// connect check reads. Logs the check that will decide Ready for this environment.
    pub fn register_bridge(&self, environment_id: &str, addr: SocketAddr, ready_dials: Arc<AtomicU64>) -> Registration {
        tracing::info!(environment = %environment_id, check = ?self.check, %addr, "registered the service bridge for the host readiness check");
        self.insert(environment_id, addr, Some(ready_dials))
    }

    fn insert(&self, environment_id: &str, addr: SocketAddr, ready_dials: Option<Arc<AtomicU64>>) -> Registration {
        // The generation is taken under the registry lock, so two concurrent registrations for one id insert in
        // generation order and the newer address is the one that stays.
        let mut addrs = self.addrs.lock().unwrap_or_else(PoisonError::into_inner);
        let generation = {
            let mut next = self.next.lock().unwrap_or_else(PoisonError::into_inner);
            *next += 1;
            *next
        };
        addrs.insert(environment_id.to_owned(), (generation, addr, ready_dials));
        drop(addrs);
        Registration {
            addrs: Arc::clone(&self.addrs),
            environment_id: environment_id.to_owned(),
            generation,
        }
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        let mut addrs = self.addrs.lock().unwrap_or_else(PoisonError::into_inner);
        if addrs
            .get(&self.environment_id)
            .is_some_and(|(g, ..)| *g == self.generation)
        {
            addrs.remove(&self.environment_id);
        }
    }
}

impl ServiceProbe for HttpServiceProbe {
    fn probe(&self, environment_id: &str) -> Result<Probe, BackendError> {
        let entry = self
            .addrs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(environment_id)
            .map(|(_, addr, dials)| (*addr, dials.clone()));
        Ok(match entry {
            None => Probe::Starting {
                step: "waiting for the guest link".to_owned(),
            },
            Some((addr, dials)) if self.check == HostCheck::Connect => {
                let dials = dials.ok_or_else(|| {
                    BackendError::Protocol(
                        "the connect check needs the bridge's ready-dial count, none is registered".to_owned(),
                    )
                })?;
                if dial_gets_through(addr, &dials) {
                    Probe::Ready {
                        endpoint: Endpoint {
                            host: addr.ip().to_string(),
                            port: addr.port(),
                        },
                    }
                } else {
                    Probe::Starting {
                        step: "boot".to_owned(),
                    }
                }
            }
            Some((addr, _)) => match http_status(addr) {
                None => Probe::Starting {
                    step: "boot".to_owned(),
                },
                Some(status) if status >= 500 => Probe::Starting {
                    step: "starting".to_owned(),
                },
                Some(_) => Probe::Ready {
                    endpoint: Endpoint {
                        host: addr.ip().to_string(),
                        port: addr.port(),
                    },
                },
            },
        })
    }
}
