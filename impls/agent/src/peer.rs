//! The job's door to its peer channels (#238 slice 4b).
//!
//! When the agent joined peer channels, it serves a unix socket in a private
//! (0700) directory and starts the job with `SANDY_PEER_SOCKET` naming it. The
//! path is not a secret: the caps stay in the agent, which authorizes each send
//! against the channels it joined (the relay checks again).
//!
//! One request per connection, one newline-terminated JSON line each way:
//! `send` posts one message, `recv` drains the inbox (`wait` blocks for at least
//! one message) and reports how many deliveries the full inbox dropped. One
//! client at a time: a connection that arrives while another is open is closed
//! at once, and the client helper retries briefly.

use std::{
    future::Future,
    io::{self, BufRead, Write},
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};

use base64::{Engine, engine::general_purpose::STANDARD as B64};
use sandy_fabric_local::agent::PeerDelivery;
use tokio::{
    net::UnixListener,
    sync::{Mutex, mpsc::Receiver},
};

/// The environment variable that names the peer socket for the job.
pub const PEER_SOCKET_ENV: &str = "SANDY_PEER_SOCKET";

/// The longest request or reply line either side accepts.
pub const MAX_LINE: usize = 4 << 20;

/// How long the client keeps retrying while another connection is open.
const BUSY_RETRY: Duration = Duration::from_secs(5);

/// A request from the job.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    /// Post one message on a peer channel.
    Send {
        /// The peer channel.
        channel: String,
        /// Its content type.
        content_type: String,
        /// Base64 of the bytes.
        payload: String,
    },
    /// Drain the received messages; with `wait`, block for at least one.
    Recv {
        /// Block until at least one message is there.
        #[serde(default)]
        wait: bool,
    },
}

/// One received message, as the job sees it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Message {
    /// The peer channel it arrived on.
    pub channel: String,
    /// Its content type.
    pub content_type: String,
    /// Base64 of the bytes.
    pub payload: String,
}

/// The agent's reply.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "reply", rename_all = "snake_case")]
pub enum Reply {
    /// The message was posted.
    Sent,
    /// The drained messages, and how many deliveries the full inbox has dropped
    /// in total.
    Messages {
        /// The messages, oldest first.
        messages: Vec<Message>,
        /// The running count of dropped deliveries.
        dropped: u64,
    },
    /// The request failed.
    Error {
        /// Why.
        error: String,
    },
}

/// What the server needs from the agent: posting on a joined peer channel, and
/// the inbox overflow count.
pub trait PeerPort: Send + Sync + 'static {
    /// Post on peer channel `channel`, refusing one the agent did not join.
    fn post(
        &self,
        channel: String,
        content_type: String,
        payload: Vec<u8>,
    ) -> impl Future<Output = Result<(), String>> + Send;
    /// Deliveries the full inbox has dropped so far.
    fn dropped(&self) -> u64;
}

/// Serve the job's peer requests on `listener` until it is dropped.
pub async fn serve_peers<P: PeerPort>(_listener: UnixListener, _port: Arc<P>, _inbox: Receiver<PeerDelivery>) {
    let _ = (MAX_LINE, Mutex::new(()), B64.encode([]));
}

/// Send one request to the agent at `socket` and read its reply, retrying
/// briefly while another connection is open.
///
/// # Errors
/// The connection or the exchange failed, or the agent stayed busy.
pub fn request(_socket: &Path, _request: &Request) -> io::Result<Reply> {
    let _ = (BUSY_RETRY, Instant::now());
    let _: Option<&dyn BufRead> = None;
    let _: Option<&dyn Write> = None;
    Err(io::Error::other("not implemented"))
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex as StdMutex;

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        sync::mpsc,
        time::timeout,
    };

    use super::*;

    const WAIT: Duration = Duration::from_secs(5);

    #[derive(Default)]
    struct FakePort {
        posted: StdMutex<Vec<(String, String, Vec<u8>)>>,
        refuse: bool,
    }

    impl PeerPort for FakePort {
        async fn post(&self, channel: String, content_type: String, payload: Vec<u8>) -> Result<(), String> {
            if self.refuse {
                return Err(format!("not a member of peer channel {channel}"));
            }
            self.posted
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push((channel, content_type, payload));
            Ok(())
        }

        fn dropped(&self) -> u64 {
            3
        }
    }

    fn delivery(n: u8) -> PeerDelivery {
        PeerDelivery {
            channel: "group-a".to_string(),
            content_type: "text/plain".to_string(),
            payload: vec![n],
        }
    }

    /// A server on a fresh socket, with a sender to feed its inbox.
    fn server(
        port: FakePort,
    ) -> anyhow::Result<(
        tempfile::TempDir,
        std::path::PathBuf,
        mpsc::Sender<PeerDelivery>,
        Arc<FakePort>,
    )> {
        let dir = tempfile::tempdir()?;
        let socket = dir.path().join("peer.sock");
        let listener = UnixListener::bind(&socket)?;
        let (tx, rx) = mpsc::channel(16);
        let port = Arc::new(port);
        tokio::spawn(serve_peers(listener, Arc::clone(&port), rx));
        Ok((dir, socket, tx, port))
    }

    async fn ask(socket: &Path, request: Request) -> anyhow::Result<Reply> {
        let socket = socket.to_path_buf();
        Ok(tokio::task::spawn_blocking(move || request_owned(&socket, &request)).await??)
    }

    fn request_owned(socket: &Path, request: &Request) -> io::Result<Reply> {
        super::request(socket, request)
    }

    #[tokio::test]
    async fn a_job_sends_and_drains_its_peer_messages() -> anyhow::Result<()> {
        let (_dir, socket, tx, port) = server(FakePort::default())?;
        let reply = ask(
            &socket,
            Request::Send {
                channel: "group-a".to_string(),
                content_type: "text/plain".to_string(),
                payload: B64.encode(b"hi"),
            },
        )
        .await?;
        assert_eq!(reply, Reply::Sent);
        assert_eq!(
            *port.posted.lock().unwrap_or_else(std::sync::PoisonError::into_inner),
            [("group-a".to_string(), "text/plain".to_string(), b"hi".to_vec())]
        );

        tx.send(delivery(1)).await?;
        tx.send(delivery(2)).await?;
        let reply = ask(&socket, Request::Recv { wait: false }).await?;
        let Reply::Messages { messages, dropped } = reply else {
            anyhow::bail!("expected messages, got {reply:?}");
        };
        assert_eq!(dropped, 3, "the overflow count is reported with every drain");
        let payloads: Vec<Vec<u8>> = messages
            .iter()
            .map(|m| B64.decode(&m.payload))
            .collect::<Result<_, _>>()?;
        assert_eq!(payloads, [vec![1], vec![2]], "drained oldest first");
        let reply = ask(&socket, Request::Recv { wait: false }).await?;
        assert!(
            matches!(reply, Reply::Messages { ref messages, .. } if messages.is_empty()),
            "drained: {reply:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn recv_wait_blocks_for_a_message() -> anyhow::Result<()> {
        let (_dir, socket, tx, _) = server(FakePort::default())?;
        let pending = tokio::spawn({
            let socket = socket.clone();
            async move { ask(&socket, Request::Recv { wait: true }).await }
        });
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(!pending.is_finished(), "recv --wait must block on an empty inbox");
        tx.send(delivery(7)).await?;
        let reply = timeout(WAIT, pending).await???;
        assert!(
            matches!(reply, Reply::Messages { ref messages, .. } if messages.len() == 1),
            "got {reply:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_refused_send_is_reported_to_the_job() -> anyhow::Result<()> {
        let (_dir, socket, ..) = server(FakePort {
            refuse: true,
            ..FakePort::default()
        })?;
        let reply = ask(
            &socket,
            Request::Send {
                channel: "group-z".to_string(),
                content_type: "text/plain".to_string(),
                payload: B64.encode(b"x"),
            },
        )
        .await?;
        assert!(
            matches!(reply, Reply::Error { ref error } if error.contains("group-z")),
            "got {reply:?}"
        );
        Ok(())
    }

    /// One client at a time: a second connection while one is open is closed
    /// without a reply, and the client helper retries until it gets through.
    #[tokio::test]
    async fn a_second_connection_is_closed_while_one_is_open() -> anyhow::Result<()> {
        let (_dir, socket, ..) = server(FakePort::default())?;
        let mut first = tokio::net::UnixStream::connect(&socket).await?;
        tokio::time::sleep(Duration::from_millis(100)).await;
        let mut second = tokio::net::UnixStream::connect(&socket).await?;
        let mut buf = [0_u8; 1];
        let read = timeout(WAIT, second.read(&mut buf)).await??;
        assert_eq!(read, 0, "the second connection must be closed at once");

        let retried = tokio::spawn({
            let socket = socket.clone();
            async move { ask(&socket, Request::Recv { wait: false }).await }
        });
        tokio::time::sleep(Duration::from_millis(300)).await;
        first.write_all(b"{\"op\":\"recv\"}\n").await?;
        let mut line = String::new();
        first.read_to_string(&mut line).await?;
        assert!(line.contains("messages"), "the open connection is served: {line}");
        let reply = timeout(WAIT, retried).await???;
        assert!(
            matches!(reply, Reply::Messages { .. }),
            "the retrying client gets through: {reply:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_malformed_request_gets_an_error_reply() -> anyhow::Result<()> {
        let (_dir, socket, ..) = server(FakePort::default())?;
        let mut conn = tokio::net::UnixStream::connect(&socket).await?;
        conn.write_all(b"not json\n").await?;
        let mut line = String::new();
        timeout(WAIT, conn.read_to_string(&mut line)).await??;
        let reply: Reply = serde_json::from_str(line.trim())?;
        assert!(matches!(reply, Reply::Error { .. }), "got {reply:?}");
        Ok(())
    }
}
