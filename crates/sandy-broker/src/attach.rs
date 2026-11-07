//! Attach over HTTP (#616, `docs/decisions/broker-api.md` decision 7).
//!
//! `POST /v1/jobs/{id}/attach` mints a single-use ticket, held in memory only. `GET
//! /v1/jobs/{id}/stream/{ticket}` redeems it with the client's bearer, does the attach RPC and the
//! join on sandyd's attach socket, and streams the job's output as NDJSON. The attach token and the
//! cap never leave this process.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    time::{Duration, Instant},
};

use base64::{Engine, engine::general_purpose::STANDARD};
use hyper::{
    Response, StatusCode,
    body::Bytes,
    header::{CACHE_CONTROL, CONTENT_TYPE, HeaderValue},
};
use sandy_control_proto::{
    AttachRequest, JobStatus, StatusRequest, attach_socket_path, control_request, control_response,
};
use sandy_fabric_local::{
    agent::{TTY_STDERR, TTY_STDOUT},
    link::{LinkFrame, read_frame, write_frame},
};
use serde::Serialize;
use serde_json::json;
use tokio::{net::UnixStream, sync::mpsc};

use crate::{
    Client,
    body::Body,
    server::{ApiError, NOT_FOUND, Reply, State, UNAVAILABLE, error, rpc, status_of},
};

/// Most tickets plus live streams one client holds at once.
const MAX_PER_CLIENT: usize = 4;
/// Most tickets plus live streams the broker holds at once.
const MAX_TOTAL: usize = 32;
/// Bytes of a ticket before hex encoding (256 bits).
const TICKET_BYTES: usize = 32;
/// How long the attach RPC, the connect and the join may take together.
pub(crate) const JOIN_TIMEOUT: Duration = Duration::from_secs(10);
/// How often a stream checks whether the job ended.
pub(crate) const POLL: Duration = Duration::from_secs(1);
/// After the job ended, a stream ends once the data plane is quiet this long.
pub(crate) const QUIET: Duration = Duration::from_millis(500);
/// Consecutive failed status polls after which a stream ends with `fault:status unavailable`.
pub(crate) const MAX_FAILED_POLLS: u32 = 5;
/// The most a stream drains after the job ended, however much keeps arriving.
pub(crate) const DRAIN_CAP: Duration = Duration::from_secs(30);
/// Chunks buffered between the producer and the HTTP body.
const CHUNK_DEPTH: usize = 8;

const OVER_CAP: ApiError = ApiError {
    status: StatusCode::TOO_MANY_REQUESTS,
    code: "quota_exceeded",
    message: "too many open attach streams",
};

struct Entry {
    client: String,
    job: String,
    expires: Instant,
}

#[derive(Default)]
struct Table {
    tickets: HashMap<String, Entry>,
    /// Open streams per client.
    live: HashMap<String, usize>,
}

impl Table {
    fn sweep(&mut self, now: Instant) {
        self.tickets.retain(|_, e| e.expires > now);
    }

    fn held_by(&self, client: &str) -> usize {
        self.tickets.values().filter(|e| e.client == client).count() + self.live.get(client).copied().unwrap_or(0)
    }

    fn total(&self) -> usize {
        self.tickets.len() + self.live.values().sum::<usize>()
    }
}

/// Why a ticket could not be issued.
pub(crate) enum IssueError {
    /// The client or the broker is at its cap.
    OverCap,
    /// The system RNG failed.
    Rng,
}

/// The in-memory ticket table. A ticket is never written to disk.
pub(crate) struct Tickets {
    ttl: Duration,
    table: Arc<Mutex<Table>>,
}

fn lock(table: &Mutex<Table>) -> MutexGuard<'_, Table> {
    table.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Tickets {
    pub(crate) fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            table: Arc::default(),
        }
    }

    /// Mints a ticket for `client` to open `job`'s stream.
    pub(crate) fn issue(&self, client: &str, job: &str) -> Result<String, IssueError> {
        let mut bytes = [0_u8; TICKET_BYTES];
        getrandom::fill(&mut bytes).map_err(|e| {
            tracing::error!(error = %e, "cannot draw a ticket");
            IssueError::Rng
        })?;
        let ticket = hex::encode(bytes);
        let now = Instant::now();
        let mut table = lock(&self.table);
        table.sweep(now);
        if table.held_by(client) >= MAX_PER_CLIENT || table.total() >= MAX_TOTAL {
            return Err(IssueError::OverCap);
        }
        table.tickets.insert(
            ticket.clone(),
            Entry {
                client: client.to_owned(),
                job: job.to_owned(),
                expires: now + self.ttl,
            },
        );
        Ok(ticket)
    }

    /// Spends `ticket` if it is live and was issued to `client` for `job`. A ticket presented by
    /// another client or for another job is not spent. The slot the ticket held stays taken by
    /// the returned guard until the stream ends.
    fn redeem(&self, ticket: &str, client: &str, job: &str) -> Option<StreamSlot> {
        let mut table = lock(&self.table);
        table.sweep(Instant::now());
        let entry = table.tickets.get(ticket)?;
        if entry.client != client || entry.job != job {
            return None;
        }
        table.tickets.remove(ticket);
        *table.live.entry(client.to_owned()).or_default() += 1;
        Some(StreamSlot {
            table: Arc::clone(&self.table),
            client: client.to_owned(),
        })
    }
}

/// Holds one stream's share of the caps until it drops.
struct StreamSlot {
    table: Arc<Mutex<Table>>,
    client: String,
}

impl Drop for StreamSlot {
    fn drop(&mut self) {
        let mut table = lock(&self.table);
        if let Some(n) = table.live.get_mut(&self.client) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                table.live.remove(&self.client);
            }
        }
    }
}

/// One line of the stream.
#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Event {
    /// A chunk of job output, base64 (standard alphabet). Stdout and stderr are merged.
    Output { data: String },
    /// The last line: `closed`, `job_terminal:<STATUS>` or `fault:<fixed text>`.
    Exit { reason: String },
}

fn line(event: &Event) -> Bytes {
    let mut buf = serde_json::to_vec(event).unwrap_or_default();
    buf.push(b'\n');
    Bytes::from(buf)
}

/// `POST /v1/jobs/{id}/attach`: a ticket for the caller's own live job.
pub(crate) async fn issue(state: &State, client: &Client, id: &str) -> Reply {
    if !state.owners.owns(id, &client.id) {
        return Err(NOT_FOUND);
    }
    let status = status_of(state, id).await?;
    if !matches!(status["state"].as_str(), Some("pending" | "running")) {
        return Err(UNAVAILABLE);
    }
    let ticket = state.tickets.issue(&client.id, id).map_err(|e| match e {
        IssueError::OverCap => OVER_CAP,
        IssueError::Rng => UNAVAILABLE,
    })?;
    Ok((
        StatusCode::OK,
        json!({
            "stream_url": format!("/v1/jobs/{id}/stream/{ticket}"),
            "expires_in_s": state.tickets.ttl.as_secs(),
        }),
    ))
}

/// `GET /v1/jobs/{id}/stream/{ticket}`: spends the ticket, joins, and streams NDJSON.
pub(crate) async fn stream(state: Arc<State>, client: &Client, id: &str, ticket: &str) -> Response<Body> {
    let Some(slot) = state.tickets.redeem(ticket, &client.id, id) else {
        return error(&NOT_FOUND);
    };
    let Some(token) = state.owners.token_for(id, &client.id) else {
        return error(&NOT_FOUND);
    };
    let joined = match tokio::time::timeout(JOIN_TIMEOUT, join(&state, id, Some(token))).await {
        Ok(Ok(conn)) => conn,
        Ok(Err(e)) => return error(&e),
        Err(_) => {
            tracing::warn!("attach join timed out");
            return error(&UNAVAILABLE);
        }
    };
    let (tx, rx) = mpsc::channel(CHUNK_DEPTH);
    tokio::spawn(pump(state, id.to_owned(), joined, tx, slot));
    let mut response = Response::new(Body::Stream(rx));
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/x-ndjson"));
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// The attach RPC, then the join on the attach socket. Any failure is a fixed `unavailable`.
/// With a `token` the caller joins as the submitter. Without one sandyd hands out its read-only
/// observer cap, a membership (and cursor) apart from every submitter's.
pub(crate) async fn join(state: &State, id: &str, token: Option<Vec<u8>>) -> Result<UnixStream, ApiError> {
    let op = control_request::Op::Attach(AttachRequest {
        job_id: id.to_owned(),
        attach_token: token,
        collector: false,
    });
    let control_response::Result::Attach(attach) = rpc(state, op).await? else {
        return Err(UNAVAILABLE);
    };
    let mut conn = UnixStream::connect(attach_socket_path(&state.control_socket))
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "cannot reach sandyd's attach socket");
            UNAVAILABLE
        })?;
    let join = LinkFrame::Join {
        cap: hex::encode(&attach.cap),
        channel: None,
        cols: None,
        rows: None,
    };
    write_frame(&mut conn, &join).await.map_err(|e| {
        tracing::warn!(error = %e, "cannot send the join");
        UNAVAILABLE
    })?;
    match read_frame(&mut conn).await {
        Ok(Some(LinkFrame::Joined { .. })) => Ok(conn),
        Ok(_) => {
            tracing::warn!("sandyd refused the join");
            Err(UNAVAILABLE)
        }
        Err(e) => {
            tracing::warn!(error = %e, "the join handshake failed");
            Err(UNAVAILABLE)
        }
    }
}

/// Aborts its task on drop, so a finished stream closes the data-plane read half.
pub(crate) struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub(crate) type Frames = mpsc::Receiver<Result<Option<LinkFrame>, ()>>;

/// Frames buffered between the data-plane reader and the pump. Small, so a stalled client pins
/// little memory (a frame can be 1 MiB).
const FRAME_DEPTH: usize = 2;

/// Reads frames off `read_half` on its own task, so a select over the result never cancels a
/// half-read frame. The task stops with the returned guard.
pub(crate) fn spawn_reader(mut read_half: tokio::io::ReadHalf<UnixStream>) -> (Frames, AbortOnDrop) {
    let (frames_tx, frames): (_, Frames) = mpsc::channel(FRAME_DEPTH);
    let reader = AbortOnDrop(tokio::spawn(async move {
        loop {
            let next = match read_frame(&mut read_half).await {
                Ok(Some(frame)) => Ok(Some(frame)),
                Ok(None) => Ok(None),
                Err(_) => Err(()),
            };
            let last = !matches!(next, Ok(Some(_)));
            if frames_tx.send(next).await.is_err() || last {
                return;
            }
        }
    }));
    (frames, reader)
}

/// How a stream ended.
enum End {
    /// The client went away or stopped reading: send nothing more.
    ClientGone,
    /// Send this `exit` reason.
    Exit(String),
}

/// Runs one stream to its end. The write half of the connection is held but never written or
/// shut down: a client EOF makes sandyd's relay leave the channel.
async fn pump(state: Arc<State>, id: String, conn: UnixStream, tx: mpsc::Sender<Bytes>, _slot: StreamSlot) {
    let (read_half, _write_half) = tokio::io::split(conn);
    let (mut frames, _reader) = spawn_reader(read_half);
    if let End::Exit(reason) = run(&state, &id, &tx, &mut frames).await {
        let _ = tokio::time::timeout(state.send_timeout, tx.send(line(&Event::Exit { reason }))).await;
    }
}

async fn run(state: &State, id: &str, tx: &mpsc::Sender<Bytes>, frames: &mut Frames) -> End {
    // The first poll waits a full period: the job's replay is already flowing by then.
    let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + POLL, POLL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut failed_polls = 0_u32;
    loop {
        tokio::select! {
            () = tx.closed() => return End::ClientGone,
            frame = frames.recv() => match frame {
                Some(Ok(Some(frame))) => {
                    if !forward(tx, frame, state.send_timeout).await {
                        return End::ClientGone;
                    }
                }
                Some(Ok(None)) | None => return End::Exit("closed".to_owned()),
                Some(Err(())) => return End::Exit("fault:data plane error".to_owned()),
            },
            _ = tick.tick() => {
                let status = tokio::select! {
                    () = tx.closed() => return End::ClientGone,
                    status = terminal_status(state, id) => status,
                };
                match status {
                    Ok(Some(status)) => return drain(state, tx, frames, status).await,
                    Ok(None) => failed_polls = 0,
                    Err(()) => {
                        failed_polls += 1;
                        if failed_polls >= MAX_FAILED_POLLS {
                            return End::Exit("fault:status unavailable".to_owned());
                        }
                    }
                }
            }
        }
    }
}

/// After the job ended: keeps forwarding until the data plane is quiet for [`QUIET`], or ends
/// with `job_terminal_truncated` if frames still flow at [`DRAIN_CAP`].
async fn drain(state: &State, tx: &mpsc::Sender<Bytes>, frames: &mut Frames, status: &str) -> End {
    let deadline = tokio::time::Instant::now() + DRAIN_CAP;
    loop {
        let next = tokio::select! {
            () = tx.closed() => return End::ClientGone,
            next = tokio::time::timeout(QUIET, frames.recv()) => next,
        };
        match next {
            // Quiet, or the data plane closed cleanly: everything sandyd had is out.
            Err(_) | Ok(None | Some(Ok(None))) => return End::Exit(format!("job_terminal:{status}")),
            // A read error may have cost output.
            Ok(Some(Err(()))) => return End::Exit("fault:data plane error".to_owned()),
            Ok(Some(Ok(Some(frame)))) => {
                match tokio::time::timeout_at(deadline, forward(tx, frame, state.send_timeout)).await {
                    Ok(true) => {}
                    Ok(false) => return End::ClientGone,
                    Err(_) => return End::Exit(format!("job_terminal_truncated:{status}")),
                }
                if tokio::time::Instant::now() >= deadline {
                    return End::Exit(format!("job_terminal_truncated:{status}"));
                }
            }
        }
    }
}

/// The job output a frame carries: the decoded stdout or stderr payload of a `Deliver`. Archive
/// frames, other frame kinds and a payload that is not hex give `None`.
pub(crate) fn output_bytes(frame: LinkFrame) -> Option<Vec<u8>> {
    let LinkFrame::Deliver {
        content_type, payload, ..
    } = frame
    else {
        return None;
    };
    if content_type != TTY_STDOUT && content_type != TTY_STDERR {
        return None;
    }
    hex::decode(payload)
        .inspect_err(|_| tracing::warn!("sandyd delivered a chunk that is not hex"))
        .ok()
}

/// Sends a delivered chunk as an `output` line, waiting at most `send_timeout` for room. `false`
/// when the client is gone or stopped reading. Archive frames and anything else are dropped.
async fn forward(tx: &mpsc::Sender<Bytes>, frame: LinkFrame, send_timeout: Duration) -> bool {
    let Some(bytes) = output_bytes(frame) else {
        return true;
    };
    let data = STANDARD.encode(bytes);
    match tokio::time::timeout(send_timeout, tx.send(line(&Event::Output { data }))).await {
        Ok(sent) => sent.is_ok(),
        Err(_) => {
            tracing::info!("an attach client stopped reading; ending its stream");
            false
        }
    }
}

/// The `STATUS` name once a job left `Pending` and `Running`. An unknown or unspecified number
/// reads as failed, as the status route does.
fn terminal_name(status: i32) -> Option<&'static str> {
    match JobStatus::try_from(status) {
        Ok(JobStatus::Pending | JobStatus::Running) => None,
        Ok(s @ (JobStatus::Succeeded | JobStatus::Failed | JobStatus::Cancelled)) => Some(s.as_str_name()),
        _ => Some(JobStatus::Failed.as_str_name()),
    }
}

/// The job's status name once it left `Pending` and `Running`, `None` while it runs, `Err` when
/// the status call failed. sandyd's relay does not close the data plane when a job ends, so the
/// caller counts failures instead of waiting for it.
async fn terminal_status(state: &State, id: &str) -> Result<Option<&'static str>, ()> {
    let op = control_request::Op::Status(StatusRequest { job_id: id.to_owned() });
    let Ok(control_response::Result::Status(status)) = rpc(state, op).await else {
        return Err(());
    };
    Ok(terminal_name(status.status))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_broker_wide_cap_holds_across_clients() {
        let tickets = Tickets::new(Duration::from_secs(30));
        for n in 0..MAX_TOTAL {
            let client = format!("c{}", n / MAX_PER_CLIENT);
            assert!(tickets.issue(&client, "job").is_ok(), "ticket {n}");
        }
        assert!(matches!(tickets.issue("fresh", "job"), Err(IssueError::OverCap)));
    }

    /// A control socket that accepts and never answers: every status poll hangs to the deadline.
    fn silent_state(dir: &std::path::Path) -> anyhow::Result<State> {
        let socket = dir.join("silent.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket)?;
        std::thread::spawn(move || {
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept() {
                held.push(stream);
            }
        });
        Ok(State {
            control_socket: socket,
            rpc_deadline: Duration::from_secs(30),
            clients: Vec::new(),
            owners: crate::owners::Owners::open(&dir.join("state"))?,
            tickets: Tickets::new(Duration::from_secs(30)),
            outputs: crate::output::Outputs::new(1024, 4096, Duration::from_secs(60)),
            send_timeout: Duration::from_secs(30),
            env_create: HashMap::new(),
        })
    }

    /// A state whose control socket does not exist: every status call fails at once.
    fn dead_state(dir: &std::path::Path) -> anyhow::Result<State> {
        Ok(State {
            control_socket: dir.join("absent.sock"),
            rpc_deadline: Duration::from_secs(30),
            clients: Vec::new(),
            owners: crate::owners::Owners::open(&dir.join("state"))?,
            tickets: Tickets::new(Duration::from_secs(30)),
            outputs: crate::output::Outputs::new(1024, 4096, Duration::from_secs(60)),
            send_timeout: Duration::from_secs(30),
            env_create: HashMap::new(),
        })
    }

    #[tokio::test]
    async fn a_data_plane_error_while_draining_is_a_fault_not_a_terminal_exit() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let state = dead_state(dir.path())?;
        let (tx, _rx) = mpsc::channel(4);
        let (frames_tx, mut frames): (mpsc::Sender<Result<Option<LinkFrame>, ()>>, Frames) = mpsc::channel(2);
        frames_tx.send(Err(())).await?;
        let end = drain(&state, &tx, &mut frames, "JOB_STATUS_SUCCEEDED").await;
        assert!(
            matches!(&end, End::Exit(r) if r == "fault:data plane error"),
            "got {:?}",
            exit_reason(&end)
        );
        // A clean close and a quiet plane still end as terminal.
        frames_tx.send(Ok(None)).await?;
        let end = drain(&state, &tx, &mut frames, "JOB_STATUS_SUCCEEDED").await;
        assert!(matches!(&end, End::Exit(r) if r == "job_terminal:JOB_STATUS_SUCCEEDED"));
        Ok(())
    }

    fn exit_reason(end: &End) -> Option<&str> {
        match end {
            End::Exit(r) => Some(r),
            End::ClientGone => None,
        }
    }

    #[tokio::test]
    async fn a_status_path_that_keeps_failing_ends_the_stream_with_a_fault() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let state = dead_state(dir.path())?;
        let (tx, _rx) = mpsc::channel(1);
        let (_frames_tx, mut frames): (mpsc::Sender<Result<Option<LinkFrame>, ()>>, Frames) = mpsc::channel(1);
        let end = tokio::time::timeout(Duration::from_secs(12), run(&state, "job", &tx, &mut frames))
            .await
            .map_err(|_| anyhow::anyhow!("the stream held its slot while status kept failing"))?;
        assert_eq!(exit_reason(&end), Some("fault:status unavailable"));
        Ok(())
    }

    #[tokio::test]
    async fn a_hang_up_is_noticed_while_a_status_poll_is_stuck() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let state = silent_state(dir.path())?;
        let (tx, rx) = mpsc::channel(1);
        let (_frames_tx, mut frames): (mpsc::Sender<Result<Option<LinkFrame>, ()>>, Frames) = mpsc::channel(1);
        let running = tokio::spawn(async move { run(&state, "job", &tx, &mut frames).await });
        // The first poll starts after POLL and then hangs for the whole rpc deadline.
        tokio::time::sleep(POLL + Duration::from_millis(300)).await;
        drop(rx);
        let ended = tokio::time::timeout(Duration::from_millis(500), running).await;
        assert!(
            matches!(ended, Ok(Ok(End::ClientGone))),
            "the hang-up was not noticed while the status call hung"
        );
        Ok(())
    }

    #[test]
    fn an_unknown_or_unspecified_status_reads_as_failed() {
        assert_eq!(terminal_name(0), Some("JOB_STATUS_FAILED"));
        assert_eq!(terminal_name(99), Some("JOB_STATUS_FAILED"));
        assert_eq!(terminal_name(JobStatus::Running as i32), None);
        assert_eq!(terminal_name(JobStatus::Cancelled as i32), Some("JOB_STATUS_CANCELLED"));
    }

    #[test]
    fn a_ticket_lapses_and_frees_its_slot() {
        let tickets = Tickets::new(Duration::from_millis(1));
        for _ in 0..MAX_PER_CLIENT {
            assert!(tickets.issue("a", "job").is_ok());
        }
        std::thread::sleep(Duration::from_millis(20));
        assert!(tickets.issue("a", "job").is_ok(), "expired tickets must not count");
    }
}
