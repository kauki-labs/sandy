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
    sync::{Arc, Mutex, PoisonError},
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
                && delim.first().is_none_or(|&d| matches!(d, b' ' | b'\r' | b'\n')) =>
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

type Registry = Arc<Mutex<BTreeMap<String, (u64, SocketAddr)>>>;

/// Reads readiness from an HTTP service behind a registered loopback address.
///
/// A status below 500 is Ready: t3 answers 503 while it starts and 401 once auth is on, so Ready proves an HTTP
/// listener, not that t3's API is up (as `sandy-t3-ready` in the guest image). Any HTTP answer counts, a 404 too,
/// so an address must only stay registered while the bridge that owns it lives: see [`Registration`].
#[derive(Debug, Default)]
pub struct HttpServiceProbe {
    addrs: Registry,
    next: Mutex<u64>,
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
    /// A probe with no environment registered.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Probe environment `environment_id` at `addr` for as long as the returned guard lives. Hold it with the
    /// bridge that listens on `addr`.
    pub fn register(&self, environment_id: &str, addr: SocketAddr) -> Registration {
        // The generation is taken under the registry lock, so two concurrent registrations for one id insert in
        // generation order and the newer address is the one that stays.
        let mut addrs = self.addrs.lock().unwrap_or_else(PoisonError::into_inner);
        let generation = {
            let mut next = self.next.lock().unwrap_or_else(PoisonError::into_inner);
            *next += 1;
            *next
        };
        addrs.insert(environment_id.to_owned(), (generation, addr));
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
            .is_some_and(|(g, _)| *g == self.generation)
        {
            addrs.remove(&self.environment_id);
        }
    }
}

impl ServiceProbe for HttpServiceProbe {
    fn probe(&self, environment_id: &str) -> Result<Probe, BackendError> {
        let addr = self
            .addrs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(environment_id)
            .map(|(_, addr)| *addr);
        Ok(match addr {
            None => Probe::Starting {
                step: "waiting for the guest link".to_owned(),
            },
            Some(addr) => match http_status(addr) {
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
