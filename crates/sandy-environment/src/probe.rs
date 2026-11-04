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
    sync::{Mutex, PoisonError},
    time::Duration,
};

use sandy_api::{
    backend::BackendError,
    environment::{Endpoint, Probe},
};

use crate::ServiceProbe;

/// The HTTP status a service answers on `/`, or `None` if nothing answers.
pub(crate) fn http_status(addr: SocketAddr) -> Option<u16> {
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_millis(500)).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(1))).ok()?;
    stream.set_write_timeout(Some(Duration::from_secs(1))).ok()?;
    stream
        .write_all(b"GET / HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .ok()?;
    // "HTTP/1.x NNN" is 12 bytes; a service may send it in segments.
    let mut buf = [0u8; 12];
    let mut filled = 0;
    while filled < buf.len() {
        match stream.read(&mut buf[filled..]) {
            Ok(0) | Err(_) => break,
            Ok(n) => filled += n,
        }
    }
    let line = std::str::from_utf8(&buf[..filled]).ok()?;
    let rest = line.strip_prefix("HTTP/1.")?;
    rest.get(2..5)?.parse().ok()
}

/// Reads readiness from an HTTP service behind a registered loopback address.
///
/// A status below 500 is Ready: t3 answers 503 while it starts and 401 once auth is on, so Ready proves an HTTP
/// listener, not that t3's API is up (as `sandy-t3-ready` in the guest image).
#[derive(Debug, Default)]
pub struct HttpServiceProbe {
    addrs: Mutex<BTreeMap<String, SocketAddr>>,
}

impl HttpServiceProbe {
    /// A probe with no environment registered.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Probe environment `environment_id` at `addr` from now on.
    pub fn register(&self, environment_id: &str, addr: SocketAddr) {
        self.addrs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(environment_id.to_owned(), addr);
    }

    /// Forget `environment_id`: its probe is `Starting` again until a new address is registered.
    pub fn unregister(&self, environment_id: &str) {
        self.addrs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(environment_id);
    }
}

impl ServiceProbe for HttpServiceProbe {
    fn probe(&self, environment_id: &str) -> Result<Probe, BackendError> {
        let addr = self
            .addrs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(environment_id)
            .copied();
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
