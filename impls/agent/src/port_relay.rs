//! `sandy-agent port-relay --vsock-port <P> --to <127.0.0.1:T>` (#590): the guest half of the host-side
//! bridge to a guest service port.
//!
//! The service (for example `t3 serve`) listens on guest loopback, which the host cannot reach. The relay listens
//! on vsock port `P` and, for each connection from the host, dials `127.0.0.1:T` and copies bytes both ways. It
//! parses nothing: the host bridge owns TLS and auth. It admits only the host (CID 2), so a guest-local process on
//! vsock loopback, or another guest, cannot use it. This is the egress relay run in the other direction
//! (`docs/decisions/egress-proxy.md` decision 1).

#![cfg_attr(
    not(target_os = "linux"),
    allow(dead_code, reason = "the relay runs only in a Linux guest; tests drive the seam")
)]

use std::{ffi::OsString, net::SocketAddr};

use tokio::io::{AsyncRead, AsyncWrite};

use crate::link_source::Acceptor;

/// Parse `--vsock-port PORT --to ADDR` (the arguments after `port-relay`).
pub fn parse_args(_args: &[OsString]) -> Result<(u32, SocketAddr), String> {
    Err("not implemented".to_string())
}

/// Accept connections on `acceptor` and relay each host connection to `target`. Runs until its task is dropped.
pub async fn serve<A>(_acceptor: A, _target: SocketAddr)
where
    A: Acceptor + Send + 'static,
    A::Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
}

/// The `port-relay` entry point: bind the vsock listener, then relay until killed.
#[cfg(target_os = "linux")]
pub fn cli(args: &[OsString]) -> std::process::ExitCode {
    let _ = parse_args(args);
    crate::fail("port-relay is not implemented")
}

/// vsock exists only inside a Linux guest.
#[cfg(not(target_os = "linux"))]
pub fn cli(args: &[OsString]) -> std::process::ExitCode {
    let _ = parse_args(args);
    crate::fail("port-relay: vsock is only available inside a Linux guest")
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        net::Ipv4Addr,
        sync::{Arc, Mutex},
        time::Duration,
    };

    use anyhow::Context;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt, DuplexStream, duplex},
        net::TcpListener,
        time::timeout,
    };

    use super::*;
    use crate::link_source::HOST_CID;

    const WAIT: Duration = Duration::from_secs(5);

    fn args(list: &[&str]) -> Vec<OsString> {
        list.iter().map(OsString::from).collect()
    }

    /// An acceptor that yields scripted `(stream, cid)` pairs, then never yields again.
    struct Script(Arc<Mutex<VecDeque<(DuplexStream, u32)>>>);

    impl Acceptor for Script {
        type Stream = DuplexStream;

        async fn accept(&mut self) -> std::io::Result<(Self::Stream, u32)> {
            loop {
                let next = self
                    .0
                    .lock()
                    .map_err(|_| std::io::Error::other("poisoned"))?
                    .pop_front();
                match next {
                    Some(item) => return Ok(item),
                    None => tokio::time::sleep(Duration::from_millis(10)).await,
                }
            }
        }
    }

    /// A connection as the host would open it: the guest side goes to the acceptor, the host side to the test.
    fn connection(queue: &Arc<Mutex<VecDeque<(DuplexStream, u32)>>>, cid: u32) -> anyhow::Result<DuplexStream> {
        let (guest, host) = duplex(4096);
        queue
            .lock()
            .map_err(|_| anyhow::anyhow!("poisoned"))?
            .push_back((guest, cid));
        Ok(host)
    }

    /// A loopback echo server. Returns its address and a count of accepted connections.
    async fn echo_target() -> anyhow::Result<(SocketAddr, Arc<Mutex<u32>>)> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.context("bind echo")?;
        let addr = listener.local_addr()?;
        let accepted = Arc::new(Mutex::new(0u32));
        let count = Arc::clone(&accepted);
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                if let Ok(mut n) = count.lock() {
                    *n += 1;
                }
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    while let Ok(n) = socket.read(&mut buf).await {
                        if n == 0 || socket.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
        Ok((addr, accepted))
    }

    async fn echoes(host: &mut DuplexStream, word: &[u8]) -> anyhow::Result<bool> {
        host.write_all(word).await?;
        let mut got = vec![0u8; word.len()];
        match timeout(WAIT, host.read_exact(&mut got)).await {
            Ok(Ok(_)) => Ok(got == word),
            _ => Ok(false),
        }
    }

    /// The relay's job: bytes from the host reach the loopback service and its answer comes back.
    #[tokio::test]
    async fn a_host_connection_is_spliced_to_the_target() -> anyhow::Result<()> {
        let (target, _) = echo_target().await?;
        let queue = Arc::new(Mutex::new(VecDeque::new()));
        let mut host = connection(&queue, HOST_CID)?;
        let relay = tokio::spawn(serve(Script(Arc::clone(&queue)), target));

        assert!(
            echoes(&mut host, b"ping").await?,
            "the echo must come back through the relay"
        );
        relay.abort();
        Ok(())
    }

    /// The "second environment cannot reach this port" row: a peer that is not the host is closed unanswered and
    /// never causes a dial to the service. The host connection behind it is still served.
    #[tokio::test]
    async fn a_peer_that_is_not_the_host_is_closed_and_never_dials_the_target() -> anyhow::Result<()> {
        let (target, accepted) = echo_target().await?;
        let queue = Arc::new(Mutex::new(VecDeque::new()));
        let mut intruder = connection(&queue, HOST_CID + 1)?;
        let relay = tokio::spawn(serve(Script(Arc::clone(&queue)), target));

        let mut buf = [0u8; 1];
        let closed = timeout(WAIT, intruder.read(&mut buf))
            .await
            .context("intruder read timed out")?;
        assert!(
            matches!(closed, Ok(0) | Err(_)),
            "a non-host peer must be closed, got {closed:?}"
        );
        assert_eq!(
            *accepted.lock().map_err(|_| anyhow::anyhow!("poisoned"))?,
            0,
            "no dial for a non-host peer"
        );

        let mut host = connection(&queue, HOST_CID)?;
        assert!(
            echoes(&mut host, b"after").await?,
            "the host is still served after a refusal"
        );
        relay.abort();
        Ok(())
    }

    /// A long-lived connection (t3 holds a websocket) must not block a second one.
    #[tokio::test]
    async fn connections_are_served_concurrently() -> anyhow::Result<()> {
        let (target, _) = echo_target().await?;
        let queue = Arc::new(Mutex::new(VecDeque::new()));
        let mut first = connection(&queue, HOST_CID)?;
        let mut second = connection(&queue, HOST_CID)?;
        let relay = tokio::spawn(serve(Script(Arc::clone(&queue)), target));

        assert!(echoes(&mut first, b"one").await?, "first connection");
        assert!(
            echoes(&mut second, b"two").await?,
            "second connection while the first is open"
        );
        assert!(echoes(&mut first, b"again").await?, "first connection still open");
        relay.abort();
        Ok(())
    }

    /// A service that is down closes that connection only; the relay keeps accepting.
    #[tokio::test]
    async fn an_unreachable_target_closes_only_that_connection() -> anyhow::Result<()> {
        let dead = {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
            listener.local_addr()?
        };
        let queue = Arc::new(Mutex::new(VecDeque::new()));
        let mut host = connection(&queue, HOST_CID)?;
        let relay = tokio::spawn(serve(Script(Arc::clone(&queue)), dead));

        let mut buf = [0u8; 1];
        let closed = timeout(WAIT, host.read(&mut buf)).await.context("read timed out")?;
        assert!(
            matches!(closed, Ok(0) | Err(_)),
            "a dead target must close the connection, got {closed:?}"
        );
        assert!(
            !relay.is_finished(),
            "the relay must keep serving after one failed dial"
        );
        relay.abort();
        Ok(())
    }

    #[test]
    fn the_arguments_name_a_port_and_a_loopback_target() {
        let parsed = parse_args(&args(&["--vsock-port", "5100", "--to", "127.0.0.1:3773"]));
        assert_eq!(parsed, Ok((5100, SocketAddr::from((Ipv4Addr::LOCALHOST, 3773)))));
    }

    #[test]
    fn a_bad_argument_list_is_refused() {
        for bad in [
            &["--vsock-port", "5100"][..],
            &["--to", "127.0.0.1:3773"][..],
            &["--vsock-port", "x", "--to", "127.0.0.1:3773"][..],
            // u32::MAX is VMADDR_PORT_ANY: the kernel would bind some other port.
            &["--vsock-port", "4294967295", "--to", "127.0.0.1:3773"][..],
            // The relay never forwards off the guest's loopback.
            &["--vsock-port", "5100", "--to", "10.0.0.5:3773"][..],
            &["--vsock-port", "5100", "--to", "0.0.0.0:3773"][..],
            &["--vsock-port", "5100", "--to", "[::1]:3773"][..],
            &["--vsock-port", "5100", "--to", "127.0.0.1:0"][..],
            &["--vsock-port", "5100", "--to", "127.0.0.1:3773", "extra"][..],
        ] {
            assert!(parse_args(&args(bad)).is_err(), "{bad:?} must be refused");
        }
    }
}
