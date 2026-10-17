//! Where the agent link comes from (#238): stdin on the process backend, or a
//! vsock listener inside a VM guest.
//!
//! In a guest the host connects to the agent, so the relay only ever dials its
//! own VM. The agent accepts the first connection from the host (CID 2) and
//! rejects any other peer while it keeps listening, so a guest-local process on
//! vsock loopback cannot take or burn the link. The listener is closed once the
//! host is accepted, before the job is spawned.

use std::{ffi::OsString, future::Future};

/// The vsock CID of the host, the only peer allowed to open the agent link.
#[cfg_attr(
    not(target_os = "linux"),
    allow(dead_code, reason = "vsock is Linux-only; tests drive the seam")
)]
pub const HOST_CID: u32 = 2;

/// How the agent gets its link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkSource {
    /// The process backend's socket on stdin (`AGENT_LINK_FD`).
    Stdin,
    /// Listen on this vsock port inside a VM guest.
    Vsock(u32),
}

/// Parse `[--vsock-listen PORT] -- <job> [args...]`.
pub fn parse_args(args: Vec<OsString>) -> Result<(LinkSource, Vec<OsString>), String> {
    const USAGE: &str = "usage: sandy-agent [--vsock-listen PORT] -- <job> [args...]";
    let (source, rest) = match args.split_first() {
        Some((flag, rest)) if flag == "--vsock-listen" => {
            let (port, rest) = rest.split_first().ok_or(USAGE)?;
            let port = port
                .to_str()
                .and_then(|p| p.parse::<u32>().ok())
                .ok_or_else(|| format!("--vsock-listen needs a port number; {USAGE}"))?;
            (LinkSource::Vsock(port), rest)
        }
        _ => (LinkSource::Stdin, args.as_slice()),
    };
    match rest.split_first() {
        Some((dashdash, job)) if dashdash == "--" && !job.is_empty() => Ok((source, job.to_vec())),
        _ => Err(USAGE.to_string()),
    }
}

/// A listener that yields connections with the peer's vsock CID.
#[cfg_attr(
    not(target_os = "linux"),
    allow(dead_code, reason = "vsock is Linux-only; tests drive the seam")
)]
pub trait Acceptor {
    /// One accepted connection.
    type Stream;
    /// Wait for the next connection and its peer CID.
    fn accept(&mut self) -> impl Future<Output = std::io::Result<(Self::Stream, u32)>> + Send;
}

/// Accept the first connection from the host, rejecting every other peer, and
/// close the listener (it is consumed) before returning the host's stream.
#[cfg_attr(
    not(target_os = "linux"),
    allow(dead_code, reason = "vsock is Linux-only; tests drive the seam")
)]
pub async fn accept_host<A: Acceptor>(mut acceptor: A) -> std::io::Result<A::Stream> {
    loop {
        let (stream, cid) = acceptor.accept().await?;
        if cid == HOST_CID {
            return Ok(stream);
        }
        // Closed at once; keep listening for the host.
        drop(stream);
        eprintln!(
            "sandy-agent: refused an agent-link connection from vsock cid {cid}; only the host (cid {HOST_CID}) may \
             connect"
        );
    }
}

/// The guest's vsock listener.
#[cfg(target_os = "linux")]
pub struct VsockAcceptor(tokio_vsock::VsockListener);

#[cfg(target_os = "linux")]
impl VsockAcceptor {
    /// Listen on `port` on every guest CID.
    pub fn bind(port: u32) -> std::io::Result<Self> {
        tokio_vsock::VsockListener::bind(tokio_vsock::VsockAddr::new(tokio_vsock::VMADDR_CID_ANY, port)).map(Self)
    }
}

#[cfg(target_os = "linux")]
impl Acceptor for VsockAcceptor {
    type Stream = tokio_vsock::VsockStream;

    async fn accept(&mut self) -> std::io::Result<(Self::Stream, u32)> {
        let (stream, peer) = self.0.accept().await?;
        Ok((stream, peer.cid()))
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        sync::{Arc, Mutex},
    };

    use super::*;

    fn args(v: &[&str]) -> Vec<OsString> {
        v.iter().map(OsString::from).collect()
    }

    #[test]
    fn parses_stdin_and_vsock_link_sources() {
        assert_eq!(
            parse_args(args(&["--", "echo", "hi"])),
            Ok((LinkSource::Stdin, args(&["echo", "hi"])))
        );
        assert_eq!(
            parse_args(args(&["--vsock-listen", "5000", "--", "echo"])),
            Ok((LinkSource::Vsock(5000), args(&["echo"])))
        );
        for bad in [
            &["--vsock-listen", "x", "--", "echo"][..],
            &["--vsock-listen"],
            &["--vsock-listen", "5000", "echo"],
            &["--"],
            &[],
        ] {
            assert!(parse_args(args(bad)).is_err(), "{bad:?} must be refused");
        }
    }

    /// A scripted listener: yields the queued (stream id, peer cid) pairs in
    /// order and records which streams were dropped.
    struct Script {
        queue: VecDeque<(u32, u32)>,
        dropped: Arc<Mutex<Vec<u32>>>,
    }

    struct Conn {
        id: u32,
        dropped: Arc<Mutex<Vec<u32>>>,
    }

    impl Drop for Conn {
        fn drop(&mut self) {
            self.dropped
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(self.id);
        }
    }

    impl Acceptor for Script {
        type Stream = Conn;

        async fn accept(&mut self) -> std::io::Result<(Conn, u32)> {
            let (id, cid) = self
                .queue
                .pop_front()
                .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::ConnectionAborted))?;
            Ok((
                Conn {
                    id,
                    dropped: Arc::clone(&self.dropped),
                },
                cid,
            ))
        }
    }

    /// Adversarial (#238, infra-f3): a guest-local peer that connects first is
    /// rejected and does not burn the accept; the host still gets the link.
    #[tokio::test]
    async fn a_guest_local_peer_is_rejected_and_the_host_still_connects() -> anyhow::Result<()> {
        let dropped = Arc::new(Mutex::new(Vec::new()));
        let script = Script {
            queue: VecDeque::from([(1, 1), (2, 3), (3, HOST_CID)]),
            dropped: Arc::clone(&dropped),
        };
        let link = accept_host(script).await?;
        assert_eq!(link.id, 3, "the host's connection must be the link");
        let mut refused = dropped
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        refused.sort_unstable();
        assert_eq!(refused, vec![1, 2], "every non-host peer must be closed");
        Ok(())
    }

    /// A listener fault is an error, never a link from someone else.
    #[tokio::test]
    async fn a_listener_fault_without_a_host_is_an_error() {
        let script = Script {
            queue: VecDeque::from([(1, 1)]),
            dropped: Arc::new(Mutex::new(Vec::new())),
        };
        assert!(
            accept_host(script).await.is_err(),
            "no host connection must not yield a link"
        );
    }
}
