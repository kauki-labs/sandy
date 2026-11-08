//! Job output retention (#643, `docs/decisions/broker-api.md` decision 8).
//!
//! sandyd keeps no job output. It reaches the broker only on the attach socket, which ends when
//! the job does. So the broker starts one collector per accepted job. The collector attaches with
//! the stored attach token as sandyd's collector (a read-only cap that attach counting ignores) and
//! appends each chunk to a bounded in-memory buffer. `GET
//! /v1/jobs/{id}/output` serves that buffer by absolute offset, during the run and for a window
//! after it. Nothing here is written to disk: a broker restart loses every buffer.

use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    time::{Duration, Instant},
};

use base64::{Engine, engine::general_purpose::STANDARD};
use hyper::StatusCode;
use serde_json::json;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::{
    Client,
    attach::{DRAIN_CAP, Frames, JOIN_TIMEOUT, MAX_FAILED_POLLS, POLL, QUIET, join, output_bytes, spawn_reader},
    server::{INVALID, NOT_FOUND, Reply, State, status_of},
};

/// Bytes one read returns when the caller sets no `limit`.
const DEFAULT_READ: usize = 64 * 1024;
/// The most bytes one read returns, whatever `limit` says.
const MAX_READ: usize = 256 * 1024;
/// Tries to attach before the collector gives up on a job.
const JOIN_ATTEMPTS: u32 = 5;

/// How a job's collection ended.
#[derive(Debug)]
struct Ended {
    at: Instant,
    /// The job's terminal state name, when the broker could read it.
    state: Option<String>,
    /// Why the buffer may be missing output, when it may be.
    fault: Option<&'static str>,
}

#[derive(Debug)]
struct Buf {
    /// The owning client: its bytes count against that client's share only.
    client: String,
    data: VecDeque<u8>,
    /// Absolute offset of `data[0]`.
    base: u64,
    ended: Option<Ended>,
}

impl Buf {
    fn end(&self) -> u64 {
        self.base + self.data.len() as u64
    }

    fn trim_to(&mut self, cap: usize) {
        let extra = self.data.len().saturating_sub(cap);
        self.data.drain(..extra);
        self.base += extra as u64;
    }
}

/// What one read returned.
pub(crate) struct Read {
    bytes: Vec<u8>,
    /// Absolute offset of the first returned byte.
    offset: u64,
    next_offset: u64,
    dropped: u64,
    ended: Option<(Option<String>, Option<&'static str>)>,
}

/// The bounded in-memory output buffers, one per job, and the collector tasks that fill them.
#[derive(Debug)]
pub(crate) struct Outputs {
    job_cap: usize,
    /// Bytes one client may hold: the total cap split evenly over the known clients, so the
    /// sum over all clients stays within the total cap and no client can evict another's.
    client_cap: usize,
    retention: Duration,
    jobs: Mutex<HashMap<String, Buf>>,
    /// Collector slots: sandyd serves 256 attach connections at once, so the broker bounds the
    /// ones its collectors hold, per client and in all. A job past the bound waits for a slot.
    collectors_per_client: usize,
    client_slots: Mutex<HashMap<String, Arc<Semaphore>>>,
    total_slots: Arc<Semaphore>,
    /// `None` once the broker shut down: a collector tracked after that is aborted at once.
    collectors: Mutex<Option<Vec<tokio::task::JoinHandle<()>>>>,
}

impl Outputs {
    pub(crate) fn new(
        job_cap: usize,
        total_cap: usize,
        clients: usize,
        retention: Duration,
        collectors: (usize, usize),
    ) -> Self {
        Self {
            collectors_per_client: collectors.0,
            client_slots: Mutex::default(),
            total_slots: Arc::new(Semaphore::new(collectors.1)),
            job_cap,
            client_cap: total_cap / clients.max(1),
            retention,
            jobs: Mutex::default(),
            collectors: Mutex::new(Some(Vec::new())),
        }
    }

    /// Waits for a collector slot for `client`: one of its own, then one of the broker's. Both
    /// free when the permits drop.
    async fn collector_slot(&self, client: &str) -> Option<(OwnedSemaphorePermit, OwnedSemaphorePermit)> {
        let per_client = Arc::clone(
            self.client_slots
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .entry(client.to_owned())
                .or_insert_with(|| Arc::new(Semaphore::new(self.collectors_per_client))),
        );
        let mine = per_client.acquire_owned().await.ok()?;
        let all = Arc::clone(&self.total_slots).acquire_owned().await.ok()?;
        Some((mine, all))
    }

    /// Keeps `collector` so [`Outputs::abort_collectors`] can stop it. Finished handles drop.
    /// After shutdown the collector is aborted at once.
    pub(crate) fn track(&self, collector: tokio::task::JoinHandle<()>) {
        let mut guard = self.collectors.lock().unwrap_or_else(PoisonError::into_inner);
        match guard.as_mut() {
            Some(collectors) => {
                collectors.retain(|c| !c.is_finished());
                collectors.push(collector);
            }
            None => collector.abort(),
        }
    }

    /// Stops every collector, which closes their attach connections, and refuses later ones.
    pub(crate) fn abort_collectors(&self) {
        let taken = self.collectors.lock().unwrap_or_else(PoisonError::into_inner).take();
        for collector in taken.into_iter().flatten() {
            collector.abort();
        }
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<String, Buf>> {
        self.jobs.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn sweep(&self, jobs: &mut HashMap<String, Buf>, now: Instant) {
        // An absurd retention overflows `Instant`: that buffer never expires.
        jobs.retain(|_, b| {
            b.ended
                .as_ref()
                .is_none_or(|e| e.at.checked_add(self.retention).is_none_or(|expires| expires > now))
        });
    }

    /// Starts an empty buffer for `id`, owned by `client`.
    pub(crate) fn register(&self, id: &str, client: &str) {
        let mut jobs = self.lock();
        self.sweep(&mut jobs, Instant::now());
        jobs.insert(
            id.to_owned(),
            Buf {
                client: client.to_owned(),
                data: VecDeque::new(),
                base: 0,
                ended: None,
            },
        );
    }

    /// Appends `bytes` to `id`'s buffer. Over the per-job cap the oldest bytes drop. Over the
    /// client's share, that client's own oldest finished job goes first, then its growing job
    /// drops its oldest bytes. Another client's buffers are never touched.
    fn append(&self, id: &str, bytes: &[u8]) {
        let mut jobs = self.lock();
        let Some(buf) = jobs.get_mut(id) else {
            return;
        };
        buf.data.extend(bytes);
        buf.trim_to(self.job_cap);
        let client = buf.client.clone();
        loop {
            let held: usize = jobs.values().filter(|b| b.client == client).map(|b| b.data.len()).sum();
            if held <= self.client_cap {
                return;
            }
            let oldest = jobs
                .iter()
                .filter(|(_, b)| b.client == client)
                .filter_map(|(k, b)| b.ended.as_ref().map(|e| (e.at, k.clone())))
                .min();
            match oldest {
                Some((_, key)) => {
                    jobs.remove(&key);
                }
                None => {
                    if let Some(buf) = jobs.get_mut(id) {
                        buf.trim_to(buf.data.len().saturating_sub(held - self.client_cap));
                    }
                    return;
                }
            }
        }
    }

    fn finish(&self, id: &str, state: Option<String>, fault: Option<&'static str>) {
        if let Some(buf) = self.lock().get_mut(id) {
            buf.ended = Some(Ended {
                at: Instant::now(),
                state,
                fault,
            });
        }
    }

    /// Up to `limit` bytes of `id` from `offset`. `None` when the broker holds no buffer for the
    /// job (never started, expired, evicted or lost in a restart). `Some(Err(()))` when `offset`
    /// is past the end.
    fn read(&self, id: &str, offset: u64, limit: usize) -> Option<Result<Read, ()>> {
        let mut jobs = self.lock();
        self.sweep(&mut jobs, Instant::now());
        let buf = jobs.get(id)?;
        if offset > buf.end() {
            return Some(Err(()));
        }
        let start = offset.max(buf.base);
        let skip = usize::try_from(start - buf.base).unwrap_or(usize::MAX);
        let bytes: Vec<u8> = buf.data.iter().skip(skip).take(limit).copied().collect();
        Some(Ok(Read {
            next_offset: start + bytes.len() as u64,
            bytes,
            offset: start,
            dropped: start - offset,
            ended: buf.ended.as_ref().map(|e| (e.state.clone(), e.fault)),
        }))
    }
}

/// The query of an output read: `offset` and `limit`, nothing else.
fn parse_query(query: Option<&str>) -> Result<(u64, usize), ()> {
    let (mut offset, mut limit) = (None, None);
    for pair in query.unwrap_or_default().split('&').filter(|p| !p.is_empty()) {
        let (key, value) = pair.split_once('=').ok_or(())?;
        match key {
            "offset" if offset.is_none() => offset = Some(value.parse::<u64>().map_err(|_| ())?),
            "limit" if limit.is_none() => limit = Some(value.parse::<i64>().map_err(|_| ())?),
            _ => return Err(()),
        }
    }
    // A limit below 1 clamps up to 1, as the contract says; only a non-integer is invalid.
    let limit = limit.map_or(DEFAULT_READ, |l| usize::try_from(l.max(1)).unwrap_or(usize::MAX));
    Ok((offset.unwrap_or(0), limit.clamp(1, MAX_READ)))
}

/// `GET /v1/jobs/{id}/output`: the caller's own job, or the same 404 as for an unknown one.
pub(crate) fn get(state: &State, client: &Client, id: &str, query: Option<&str>) -> Reply {
    if !state.owners.owns(id, &client.id) {
        return Err(NOT_FOUND);
    }
    let (offset, limit) = parse_query(query).map_err(|()| INVALID)?;
    let read = state
        .outputs
        .read(id, offset, limit)
        .ok_or(NOT_FOUND)?
        .map_err(|()| INVALID)?;
    let mut body = json!({
        "data": STANDARD.encode(&read.bytes),
        "offset": read.offset,
        "next_offset": read.next_offset,
        "dropped": read.dropped,
        "done": read.ended.is_some(),
    });
    if let Some((job_state, fault)) = read.ended {
        if let Some(job_state) = job_state {
            body["state"] = json!(job_state);
        }
        if let Some(fault) = fault {
            body["fault"] = json!(fault);
        }
    }
    Ok((StatusCode::OK, body))
}

/// The job's state name once it left `pending` and `running`, `None` while it runs, `Err` when
/// the status call failed.
async fn terminal_state(state: &State, id: &str) -> Result<Option<String>, ()> {
    let status = status_of(state, id).await.map_err(|_| ())?;
    Ok(match status["state"].as_str() {
        Some("pending" | "running") | None => None,
        Some(other) => Some(other.to_owned()),
    })
}

/// Collects `id`'s output until it ends, then marks the buffer finished. Runs as one detached
/// task per accepted job.
///
/// The collector asks sandyd for its dedicated collector cap, which needs the attach token. That
/// cap is read-only, is a membership of its own (a submitter attach mints the shared `operator`
/// one, and two readers on one membership would split the messages), and is not counted as an
/// attach: it sends no `AttachStateChanged`, so a remote host never lifts the job's deadline for
/// it.
pub(crate) async fn collect(state: Arc<State>, id: String, token: Vec<u8>, client: String) {
    // Past the bound the job waits here. sandyd replays the channel from the start on join, so a
    // late collector still gets the whole output while the channel is retained; if the channel
    // is gone by then, `attach` fails and the buffer ends with a fault.
    let Some(_slot) = state.outputs.collector_slot(&client).await else {
        state.outputs.finish(&id, None, Some("collector could not start"));
        return;
    };
    match run(&state, &id, &token).await {
        Ok(job_state) => state.outputs.finish(&id, Some(job_state), None),
        Err(fault) => {
            tracing::warn!(job_id = %id, fault, "output collection ended with a fault");
            let job_state = terminal_state(&state, &id).await.ok().flatten();
            state.outputs.finish(&id, job_state, Some(fault));
        }
    }
}

async fn attach(state: &State, id: &str, token: &[u8]) -> Result<tokio::net::UnixStream, &'static str> {
    for attempt in 0..JOIN_ATTEMPTS {
        if attempt > 0 {
            tokio::time::sleep(state.join_backoff).await;
        }
        if let Ok(Ok(conn)) = tokio::time::timeout(JOIN_TIMEOUT, join(state, id, Some(token.to_vec()), true)).await {
            return Ok(conn);
        }
    }
    // sandyd may keep the channel after the job ends, so a failed join is retried whatever the
    // job's state. Only after the last try does the job's state pick the fault text.
    if matches!(terminal_state(state, id).await, Ok(Some(_))) {
        return Err("job ended before the collector attached");
    }
    Err("collector could not attach")
}

/// The job's terminal state name, or a fixed fault text.
async fn run(state: &State, id: &str, token: &[u8]) -> Result<String, &'static str> {
    let conn = attach(state, id, token).await?;
    // The write half is held, never written: a client EOF would make sandyd's relay leave.
    let (read_half, _write_half) = tokio::io::split(conn);
    let (mut frames, _reader) = spawn_reader(read_half);
    let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + POLL, POLL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut failed_polls = 0_u32;
    loop {
        tokio::select! {
            frame = frames.recv() => match frame {
                Some(Ok(Some(frame))) => {
                    if let Some(bytes) = output_bytes(frame) {
                        state.outputs.append(id, &bytes);
                    }
                }
                // sandyd closes a collector's connection only on a delivery fault, so EOF
                // may have cost output.
                Some(Ok(None)) | None => return Err("data plane closed"),
                Some(Err(())) => return Err("data plane error"),
            },
            _ = tick.tick() => match terminal_state(state, id).await {
                Ok(Some(job_state)) => return drain(state, id, &mut frames, job_state).await,
                Ok(None) => failed_polls = 0,
                Err(()) => {
                    failed_polls += 1;
                    if failed_polls >= MAX_FAILED_POLLS {
                        return Err("status unavailable");
                    }
                }
            },
        }
    }
}

/// After the job ended: keeps collecting until the data plane is quiet for [`QUIET`], or for at
/// most [`DRAIN_CAP`].
async fn drain(state: &State, id: &str, frames: &mut Frames, job_state: String) -> Result<String, &'static str> {
    let deadline = tokio::time::Instant::now() + DRAIN_CAP;
    loop {
        match tokio::time::timeout(QUIET, frames.recv()).await {
            Err(_) => return Ok(job_state),
            Ok(None | Some(Ok(None))) => return Err("data plane closed"),
            Ok(Some(Err(()))) => return Err("data plane error"),
            Ok(Some(Ok(Some(frame)))) => {
                if let Some(bytes) = output_bytes(frame) {
                    state.outputs.append(id, &bytes);
                }
                if tokio::time::Instant::now() >= deadline {
                    return Err("output still arriving when collection stopped");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outputs(job_cap: usize, total_cap: usize, clients: usize) -> Outputs {
        Outputs::new(job_cap, total_cap, clients, Duration::from_secs(60), (4, 4))
    }

    #[test]
    fn a_client_over_its_share_loses_its_own_oldest_finished_job_first_and_nobody_elses() {
        let o = outputs(8, 20, 2);
        for (id, client) in [("b", "b"), ("old", "a"), ("new", "a")] {
            o.register(id, client);
        }
        o.append("b", b"bbbbbbbb");
        o.finish("b", Some("succeeded".into()), None);
        o.append("old", b"aaaaaa");
        o.finish("old", Some("succeeded".into()), None);
        std::thread::sleep(Duration::from_millis(5));
        o.append("new", b"cccccc");
        assert!(o.read("old", 0, 8).is_none(), "a's own oldest finished job goes first");
        assert!(o.read("b", 0, 8).is_some(), "b's buffer is untouched");
        assert!(o.read("new", 0, 8).is_some());
    }

    #[test]
    fn with_no_finished_job_the_client_share_trims_the_job_that_grew() -> anyhow::Result<()> {
        let o = outputs(8, 10, 1);
        o.register("a", "x");
        o.register("b", "x");
        o.append("a", b"aaaaaaaa");
        o.append("b", b"bbbbbb");
        let a = o
            .read("a", 0, 16)
            .context("a")?
            .map_err(|()| anyhow::anyhow!("offset"))?;
        let b = o
            .read("b", 0, 16)
            .context("b")?
            .map_err(|()| anyhow::anyhow!("offset"))?;
        assert_eq!((a.bytes.len(), b.bytes.len()), (8, 2));
        assert_eq!((b.offset, b.dropped), (4, 4), "offsets stay absolute after a trim");
        Ok(())
    }

    #[test]
    fn a_retention_that_overflows_the_clock_never_expires_and_never_panics() -> anyhow::Result<()> {
        let o = Outputs::new(8, 100, 1, Duration::MAX, (4, 4));
        o.register("a", "x");
        o.finish("a", None, None);
        assert!(o.read("a", 0, 8).context("kept")?.is_ok());
        Ok(())
    }

    #[tokio::test]
    async fn a_collector_tracked_after_shutdown_is_aborted() {
        let o = outputs(8, 100, 1);
        o.abort_collectors();
        let late = tokio::spawn(std::future::pending::<()>());
        let watch = late.abort_handle();
        o.track(late);
        tokio::task::yield_now().await;
        assert!(watch.is_finished(), "the late collector must be aborted at once");
        assert!(o.collectors.lock().unwrap().is_none(), "nothing is kept after shutdown");
    }

    #[test]
    fn a_read_can_resume_at_the_end_but_not_past_it() {
        let o = outputs(8, 100, 1);
        o.register("a", "x");
        o.append("a", b"abc");
        assert!(matches!(o.read("a", 3, 8), Some(Ok(r)) if r.bytes.is_empty() && r.next_offset == 3));
        assert!(matches!(o.read("a", 4, 8), Some(Err(()))));
    }

    #[test]
    fn the_query_takes_offset_and_limit_only() {
        assert_eq!(parse_query(None), Ok((0, DEFAULT_READ)));
        assert_eq!(parse_query(Some("offset=5&limit=0")), Ok((5, 1)));
        assert_eq!(parse_query(Some("limit=-9")), Ok((0, 1)));
        assert_eq!(parse_query(Some("limit=99999999999")), Ok((0, MAX_READ)));
        for bad in ["offset=-1", "offset=1&offset=2", "x=1", "offset", "limit=1.5"] {
            assert_eq!(parse_query(Some(bad)), Err(()), "{bad}");
        }
    }

    use anyhow::Context;
}
