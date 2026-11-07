//! Job output retention (#643, `docs/decisions/broker-api.md` decision 8).
//!
//! sandyd keeps no job output. It reaches the broker only on the attach socket, which ends when
//! the job does. So the broker starts one collector per accepted job. The collector attaches with
//! the stored attach token and appends each chunk to a bounded in-memory buffer. `GET
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
/// Wait between attach tries.
const JOIN_BACKOFF: Duration = Duration::from_millis(200);

/// How a job's collection ended.
struct Ended {
    at: Instant,
    /// The job's terminal state name, when the broker could read it.
    state: Option<String>,
    /// Why the buffer may be missing output, when it may be.
    fault: Option<&'static str>,
}

struct Buf {
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

/// The bounded in-memory output buffers, one per job.
pub(crate) struct Outputs {
    job_cap: usize,
    total_cap: usize,
    retention: Duration,
    jobs: Mutex<HashMap<String, Buf>>,
}

impl Outputs {
    pub(crate) fn new(job_cap: usize, total_cap: usize, retention: Duration) -> Self {
        Self {
            job_cap,
            total_cap,
            retention,
            jobs: Mutex::default(),
        }
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<String, Buf>> {
        self.jobs.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn sweep(&self, jobs: &mut HashMap<String, Buf>, now: Instant) {
        jobs.retain(|_, b| b.ended.as_ref().is_none_or(|e| e.at + self.retention > now));
    }

    /// Starts an empty buffer for `id`.
    pub(crate) fn register(&self, id: &str) {
        let mut jobs = self.lock();
        self.sweep(&mut jobs, Instant::now());
        jobs.insert(
            id.to_owned(),
            Buf {
                data: VecDeque::new(),
                base: 0,
                ended: None,
            },
        );
    }

    /// Appends `bytes` to `id`'s buffer. Over the per-job cap the oldest bytes drop. Over the
    /// total cap the oldest finished job goes first; with none finished, this job's oldest bytes
    /// drop.
    fn append(&self, id: &str, bytes: &[u8]) {
        let mut jobs = self.lock();
        let Some(buf) = jobs.get_mut(id) else {
            return;
        };
        buf.data.extend(bytes);
        buf.trim_to(self.job_cap);
        loop {
            let total: usize = jobs.values().map(|b| b.data.len()).sum();
            if total <= self.total_cap {
                return;
            }
            let oldest = jobs
                .iter()
                .filter_map(|(k, b)| b.ended.as_ref().map(|e| (e.at, k.clone())))
                .min();
            match oldest {
                Some((_, key)) => {
                    jobs.remove(&key);
                }
                None => {
                    if let Some(buf) = jobs.get_mut(id) {
                        let over = total - self.total_cap;
                        buf.trim_to(buf.data.len().saturating_sub(over));
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
            "limit" if limit.is_none() => limit = Some(value.parse::<u64>().map_err(|_| ())?),
            _ => return Err(()),
        }
    }
    let limit = limit.map_or(DEFAULT_READ, |l| usize::try_from(l).unwrap_or(usize::MAX));
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
/// The collector attaches without the attach token, so sandyd gives it the read-only observer
/// cap. That is a membership of its own: a submitter attach (`POST .../attach`) mints the shared
/// `operator` membership, and two readers on one membership would split the messages between
/// them. It also keeps the token out of this task.
pub(crate) async fn collect(state: Arc<State>, id: String) {
    match run(&state, &id).await {
        Ok(job_state) => state.outputs.finish(&id, Some(job_state), None),
        Err(fault) => {
            tracing::warn!(job_id = %id, fault, "output collection ended with a fault");
            let job_state = terminal_state(&state, &id).await.ok().flatten();
            state.outputs.finish(&id, job_state, Some(fault));
        }
    }
}

async fn attach(state: &State, id: &str) -> Result<tokio::net::UnixStream, &'static str> {
    for attempt in 0..JOIN_ATTEMPTS {
        if attempt > 0 {
            if matches!(terminal_state(state, id).await, Ok(Some(_))) {
                return Err("job ended before the collector attached");
            }
            tokio::time::sleep(JOIN_BACKOFF).await;
        }
        if let Ok(Ok(conn)) = tokio::time::timeout(JOIN_TIMEOUT, join(state, id, None)).await {
            return Ok(conn);
        }
    }
    Err("collector could not attach")
}

/// The job's terminal state name, or a fixed fault text.
async fn run(state: &State, id: &str) -> Result<String, &'static str> {
    let conn = attach(state, id).await?;
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
                Some(Ok(None)) | None => {
                    return match terminal_state(state, id).await {
                        Ok(Some(job_state)) => Ok(job_state),
                        _ => Err("data plane closed while the job ran"),
                    };
                }
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
            Err(_) | Ok(None | Some(Ok(None))) => return Ok(job_state),
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

    fn outputs(job_cap: usize, total_cap: usize) -> Outputs {
        Outputs::new(job_cap, total_cap, Duration::from_secs(60))
    }

    #[test]
    fn the_total_cap_evicts_the_oldest_finished_job_before_any_live_one() {
        let o = outputs(8, 10);
        for id in ["old", "new", "live"] {
            o.register(id);
        }
        o.append("old", b"aaaaaa");
        o.finish("old", Some("succeeded".into()), None);
        std::thread::sleep(Duration::from_millis(5));
        o.append("new", b"bbbb");
        o.finish("new", Some("succeeded".into()), None);
        o.append("live", b"cc");
        assert!(o.read("old", 0, 8).is_none(), "the oldest finished job goes first");
        assert!(o.read("new", 0, 8).is_some());
        assert!(o.read("live", 0, 8).is_some());
    }

    #[test]
    fn with_no_finished_job_the_total_cap_trims_the_job_that_grew() -> anyhow::Result<()> {
        let o = outputs(8, 10);
        o.register("a");
        o.register("b");
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
    fn a_read_can_resume_at_the_end_but_not_past_it() {
        let o = outputs(8, 100);
        o.register("a");
        o.append("a", b"abc");
        assert!(matches!(o.read("a", 3, 8), Some(Ok(r)) if r.bytes.is_empty() && r.next_offset == 3));
        assert!(matches!(o.read("a", 4, 8), Some(Err(()))));
    }

    #[test]
    fn the_query_takes_offset_and_limit_only() {
        assert_eq!(parse_query(None), Ok((0, DEFAULT_READ)));
        assert_eq!(parse_query(Some("offset=5&limit=0")), Ok((5, 1)));
        assert_eq!(parse_query(Some("limit=99999999999")), Ok((0, MAX_READ)));
        for bad in ["offset=-1", "offset=1&offset=2", "x=1", "offset", "limit=1.5"] {
            assert_eq!(parse_query(Some(bad)), Err(()), "{bad}");
        }
    }

    use anyhow::Context;
}
