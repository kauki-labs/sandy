//! The host-executor's main loop (#288): register once, then receive
//! `Dispatch` frames off the same connection until it closes or shutdown is
//! requested. Pure protocol logic over any `AsyncRead + AsyncWrite`, kept
//! separate from `main.rs`'s real I/O (the mesh dial, the real
//! `SystemdRunContainment` probe, signal handling) so it's unit-testable
//! without a real socket or a real sandbox — the same "test the logic, defer
//! the wiring" split `sandyd::host_conn` already uses.
//!
//! Dispatches are handled strictly sequentially (decision 14): one `Dispatch`
//! runs to completion before the next is read. `Capabilities` declares no
//! concurrency slot, and M2's stage-1 acceptance is cross-machine, not
//! multiple concurrent jobs on one host — see the decision record for why
//! this isn't just an implementation shortcut.

use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use sandy_api::backend::{Outcome, RunControl};
use sandy_control_proto::{read_frame, write_frame};
use sandy_executor_proto::{
    Capabilities, Dispatch, HostExecutorMessage, JobResult, OrchestratorMessage, host_executor_message,
    orchestrator_message,
};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::dispatch::STAGE1_TIMEOUT_SECS;

/// How long [`register`] waits for the orchestrator's `Registered`/
/// `RegisterRefused` response before giving up, in production (`main.rs`
/// passes this; tests pass a much shorter bound so they don't take 10 real
/// seconds to prove the timeout fires). Without this, an orchestrator that
/// accepts the TCP connection and then stalls (or is only half brought up)
/// would block this process forever — contradicting the whole point of
/// exiting non-zero on failure so the supervisor restarts it (CodeRabbit
/// finding on #294).
pub const REGISTER_RESPONSE_TIMEOUT: Duration = Duration::from_secs(10);

/// A [`register`] failure: the orchestrator refused, or the exchange itself
/// didn't complete.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RegisterError {
    /// The orchestrator replied `RegisterRefused`, naming `reason`.
    #[error("the orchestrator refused registration: {0}")]
    Refused(String),
    /// The connection closed before any response frame arrived.
    #[error("the connection closed before a Register response arrived")]
    ClosedBeforeResponse,
    /// No response arrived within [`REGISTER_RESPONSE_TIMEOUT`].
    #[error("no Register response arrived within {REGISTER_RESPONSE_TIMEOUT:?}")]
    ResponseTimedOut,
    /// Writing the `Register` frame failed.
    #[error("writing Register failed: {0}")]
    Write(String),
    /// Reading the response frame failed (a malformed frame, an I/O error).
    #[error("reading the Register response failed: {0}")]
    Read(String),
    /// The orchestrator's response was neither `Registered` nor
    /// `RegisterRefused` — stage 1 has no other message it could legitimately
    /// send first.
    #[error("the orchestrator's response was neither Registered nor RegisterRefused")]
    UnexpectedResponse,
}

/// Send `Register { host_id, capabilities }` over `conn` and wait for the
/// orchestrator's one response frame, bounded by `response_timeout`
/// (production callers pass [`REGISTER_RESPONSE_TIMEOUT`]).
///
/// # Errors
/// See [`RegisterError`]'s variants.
pub async fn register(
    conn: &mut (impl AsyncRead + AsyncWrite + Unpin),
    host_id: &str,
    capabilities: Capabilities,
    response_timeout: Duration,
) -> Result<(), RegisterError> {
    let message = HostExecutorMessage {
        op: Some(host_executor_message::Op::Register(sandy_executor_proto::Register {
            host_id: host_id.to_owned(),
            capabilities: Some(capabilities),
        })),
    };
    write_frame(conn, &message)
        .await
        .map_err(|e| RegisterError::Write(e.to_string()))?;

    let response: OrchestratorMessage = tokio::time::timeout(response_timeout, read_frame(conn))
        .await
        .map_err(|_elapsed| RegisterError::ResponseTimedOut)?
        .map_err(|e| RegisterError::Read(e.to_string()))?
        .ok_or(RegisterError::ClosedBeforeResponse)?;
    match response.op {
        Some(orchestrator_message::Op::Registered(_)) => Ok(()),
        Some(orchestrator_message::Op::Refused(refused)) => Err(RegisterError::Refused(refused.reason)),
        _ => Err(RegisterError::UnexpectedResponse),
    }
}

/// The last `AttachStateChanged` applied, or pending application, for one
/// job_id — see [`run_dispatch_loop`]'s own doc on reordering and
/// pre-registration handling.
#[derive(Debug, Clone, Copy)]
struct AttachState {
    sequence: u64,
    attached: bool,
}

/// Why [`run_dispatch_loop`] stopped reading dispatches — `main` uses this to
/// decide its exit code: [`Shutdown`](Self::Shutdown) is an ordinary,
/// requested stop (exit 0), while [`Closed`](Self::Closed) and
/// [`Faulted`](Self::Faulted) mean the connection died out from under the
/// host-executor and it should exit non-zero for its supervisor to restart it
/// (CodeRabbit finding on #294: returning `()` unconditionally made a
/// disconnected host-executor exit 0, exactly the case the module's own "the
/// supervisor restarts it" design depends on *not* happening).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DispatchLoopExit {
    /// `shutdown` resolved.
    Shutdown,
    /// The orchestrator closed the connection cleanly.
    Closed,
    /// The connection faulted: a malformed frame, an I/O error, or a job
    /// result that failed to write back (CodeRabbit on #344: silently
    /// logging and continuing left later dispatches running with no
    /// connection left to ever report their own result to, and could even
    /// surface as a misleadingly clean `Shutdown`/`Closed`).
    Faulted(String),
}

/// Read `OrchestratorMessage` frames off `conn` until it closes, faults, or
/// `shutdown` resolves, demultiplexing by frame type rather than handling
/// everything inline in one blocking read loop (#340, decision 14
/// amendment — see `docs/decisions/sandyd.md`'s own record of why this
/// changed and what it still preserves):
///
/// - `Dispatch` is pushed onto an internal, unbounded queue and run by a SEPARATE sequential worker task — one dispatch
///   runs to completion before the next is dequeued, preserving decision 14's actual guarantee (one job executing at a
///   time), just no longer by blocking this function's own frame-reading loop while it runs. The queue send here is a
///   plain, synchronous, never-blocking push (an unbounded channel's `send` never awaits) — a second or third queued
///   `Dispatch` can never stall this loop from reading the NEXT frame, which matters because...
/// - `AttachStateChanged` (#340) is routed DIRECTLY to the named job_id's live [`RunControl`] (if that job is currently
///   running), applying `suspend_deadline()`/`set_deadline(now + STAGE1_TIMEOUT_SECS)` for `attached: true`/`false`
///   respectively. Its `sequence` is tracked per job_id and a frame whose sequence is not strictly greater than the
///   last one applied is ignored, so a frame reordered in flight can never overwrite newer attachment state with stale
///   state. A frame for a job_id this host hasn't registered a `RunControl` for yet (the dispatch hasn't arrived, or
///   has already finished) is still recorded as that job's pending attach state rather than dropped: the worker applies
///   it the moment it registers that job_id's `RunControl`, so a frame that outraces its own job's `Dispatch` still
///   takes effect instead of being silently lost. This is exactly the frame type that MUST keep being read promptly
///   even while a dispatch is running — the whole reason this function no longer blocks on `Dispatch` handling the way
///   it used to.
/// - Any other frame shape is logged and ignored, as before.
///
/// `handle` returns the result message to send back for that dispatch
/// (#292): a dedicated writer (shared with this function's own use of
/// `conn` for reading, via `tokio::io::split`) sends it on the SAME
/// connection the Dispatch arrived on. A `None` return sends nothing. A
/// failed write (CodeRabbit on #344) is never just logged and swallowed:
/// the connection is presumed broken for writes from that point on, so the
/// worker stops there rather than running further queued dispatches whose
/// results could never be delivered either, and the failure is reported as
/// [`DispatchLoopExit::Faulted`] — overriding whatever exit reason the
/// reader side had already concluded (even an ordinary `Shutdown`), since a
/// write fault is the more serious, more truthful reason this function is
/// ending.
///
/// FAIL-SAFE ON EVERY EXIT (#340): once this function's own read loop ends — for ANY reason, including an ordinary
/// requested [`DispatchLoopExit::Shutdown`], not only [`DispatchLoopExit::Closed`]/[`DispatchLoopExit::Faulted`] —
/// no further `AttachStateChanged` frame can ever arrive on this connection again, so:
/// - every job still running at that moment has its `RunControl` moved to a grace deadline (`now +
///   STAGE1_TIMEOUT_SECS`) rather than left suspended forever, since nothing could ever end an "unlimited while
///   attached" suspension from here on — a clean shutdown while a job was attached is exactly as unable to deliver a
///   future detach as a sandyd crash or network partition is.
/// - a shared stopping flag is set so the worker skips any dispatch still sitting in its queue, unstarted, rather than
///   beginning it: a job that hasn't started yet can never receive the `AttachStateChanged` frames its own execution
///   might need either, for the same reason.
/// - on an ordinary requested [`DispatchLoopExit::Shutdown`] specifically — never on `Closed`/`Faulted` — every job
///   still running also has `cancel()` called on its `RunControl` (#300). `systemctl stop` sends SIGTERM here and
///   SIGKILLs the whole process after `TimeoutStopSec`, which is shorter than a job's own up-to-`STAGE1_TIMEOUT_SECS`
///   budget; without an explicit cancel a still-running job's sandbox (reparented under `user@<uid>.service` by design,
///   see `nix/modules/sandy-executor.nix`) would be killed out from under this process with no clean teardown, left
///   running with nothing left tracking it. `Closed`/`Faulted` don't cancel: nothing is racing a systemd kill there —
///   this process keeps running and `main.rs` lets the drain finish on its own time before exiting non-zero for the
///   supervisor to restart it (decision 12), so cutting a job short there would only lose work for no benefit.
///
/// A dispatch already in flight when the loop ends is left to finish (respecting its own, possibly now-grace-bounded
/// or now-cancelled deadline) rather than skipped, so its result is still reported if there's anywhere left to report
/// it to, and `main.rs`'s "exit non-zero, let the supervisor restart" contract only fires once nothing is still
/// running.
pub async fn run_dispatch_loop<F, Fut>(
    conn: &mut (impl AsyncRead + AsyncWrite + Unpin + Send),
    handle: F,
    shutdown: impl std::future::Future<Output = ()>,
) -> DispatchLoopExit
where
    F: FnMut(Dispatch, RunControl) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Option<HostExecutorMessage>> + Send,
{
    let (mut read_half, write_half) = tokio::io::split(conn);
    let write_half = Arc::new(tokio::sync::Mutex::new(write_half));

    // job_id -> its live RunControl, for AttachStateChanged routing and the
    // fail-safe above. A plain std::sync::Mutex: every access here is a
    // quick insert/remove/lookup, never held across an await.
    let controls: Arc<Mutex<HashMap<String, RunControl>>> = Arc::new(Mutex::new(HashMap::new()));

    // job_id -> the highest-sequence AttachStateChanged seen for it, whether
    // or not that job has a live RunControl yet. Serves two purposes: (1) a
    // frame whose sequence isn't strictly greater than what's stored here is
    // a reordered duplicate and is ignored, so stale state can never
    // overwrite newer state; (2) a frame for a job_id with no RunControl yet
    // stays recorded here as that job's pending attach state, applied by the
    // worker the moment it registers that job_id's RunControl below.
    let attach_states: Arc<Mutex<HashMap<String, AttachState>>> = Arc::new(Mutex::new(HashMap::new()));

    // Set once this function's own read loop ends, for any reason — see the
    // FAIL-SAFE ON EVERY EXIT doc above. The worker checks this before
    // starting each still-queued dispatch so it skips, rather than begins,
    // dispatches that can never receive an AttachStateChanged frame once the
    // loop has stopped reading.
    let stopping = Arc::new(AtomicBool::new(false));

    // Unbounded: the reader below must never block pushing a Dispatch
    // (its own doc above explains why) — the worker draining this one at a
    // time, awaiting each `handle` call to completion, IS decision 14's
    // real guarantee, just moved off the frame-reading path.
    //
    // Run as a locally pinned future selected on below, NOT `tokio::spawn`:
    // `conn` (and so `write_half`, split from it) is a borrow with this
    // function's own lifetime, not `'static`, which `tokio::spawn` requires.
    // `tokio::select!` polling a pinned future repeatedly, alongside the
    // frame reader, gets the identical "both make progress concurrently"
    // property a spawned task would, without that bound — this future
    // itself never completes during normal operation (it loops on
    // `dispatch_rx.recv()`, which only yields `None` once `dispatch_tx` is
    // dropped, below).
    let (dispatch_tx, mut dispatch_rx) = tokio::sync::mpsc::unbounded_channel::<Dispatch>();
    let mut handle = handle;
    // `Err` on a job result's write failing (CodeRabbit on #344) — see this
    // function's own doc on `handle`'s return and `DispatchLoopExit::Faulted`.
    // `Ok(())` is only ever reached once `dispatch_rx.recv()` yields `None`,
    // which can't happen until `dispatch_tx` is dropped, below.
    let worker_fut = async {
        while let Some(dispatch) = dispatch_rx.recv().await {
            let job_id = dispatch.job_id.clone();
            if stopping.load(Ordering::Relaxed) {
                tracing::info!(
                    job_id,
                    "skipping a still-queued dispatch: the orchestrator connection's read loop has already ended, so \
                     this job could never receive an AttachStateChanged frame"
                );
                continue;
            }
            let control = RunControl::with_timeout_secs(STAGE1_TIMEOUT_SECS);
            if let Some(state) = attach_states
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .get(&job_id)
                && state.attached
            {
                // A pending attach arrived before this job's own Dispatch —
                // apply it now rather than leaving the fresh control's
                // default timeout in place.
                control.suspend_deadline();
            }
            controls
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(job_id.clone(), control.clone());
            let result = handle(dispatch, control).await;
            controls.lock().unwrap_or_else(PoisonError::into_inner).remove(&job_id);
            attach_states
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .remove(&job_id);
            if let Some(result) = result {
                let mut write_half = write_half.lock().await;
                if let Err(e) = write_frame(&mut *write_half, &result).await {
                    // The connection is presumed broken for writes from here
                    // on: stop rather than silently continue running further
                    // queued dispatches whose own results could never be
                    // delivered either (CodeRabbit on #344).
                    return Err(format!(
                        "failed writing job {job_id}'s result back to the orchestrator: {e}"
                    ));
                }
            }
        }
        Ok(())
    };
    tokio::pin!(worker_fut);

    tokio::pin!(shutdown);
    // Set the moment the worker branch below fires, so the drain step after
    // the loop knows `worker_fut` already resolved and must not poll it
    // again (undefined once a future has yielded Ready).
    let mut worker_already_ended = false;
    let exit = loop {
        tokio::select! {
            frame = read_frame::<OrchestratorMessage>(&mut read_half) => {
                match frame {
                    Ok(Some(message)) => match message.op {
                        Some(orchestrator_message::Op::Dispatch(dispatch)) => {
                            // Never blocks (see this function's own doc) —
                            // only fails if the worker future itself has
                            // already ended, which only happens after this
                            // loop drops `dispatch_tx` below.
                            let _ = dispatch_tx.send(dispatch);
                        }
                        Some(orchestrator_message::Op::AttachStateChanged(changed)) => {
                            let should_apply = {
                                let mut attach_states =
                                    attach_states.lock().unwrap_or_else(PoisonError::into_inner);
                                let should_apply = attach_states
                                    .get(&changed.job_id)
                                    .is_none_or(|state| changed.sequence > state.sequence);
                                if should_apply {
                                    attach_states.insert(
                                        changed.job_id.clone(),
                                        AttachState { sequence: changed.sequence, attached: changed.attached },
                                    );
                                }
                                should_apply
                            };
                            // A sequence not strictly greater than what's already recorded is a
                            // reordered duplicate of older state and must not overwrite newer state.
                            if should_apply {
                                let controls = controls.lock().unwrap_or_else(PoisonError::into_inner);
                                if let Some(control) = controls.get(&changed.job_id) {
                                    if changed.attached {
                                        control.suspend_deadline();
                                    } else {
                                        control.set_deadline(
                                            std::time::Instant::now()
                                                + Duration::from_secs(u64::from(STAGE1_TIMEOUT_SECS)),
                                        );
                                    }
                                }
                                // An unknown job_id with no RunControl yet isn't dropped: it's
                                // already recorded in attach_states above, and the worker applies
                                // it the moment that job_id's RunControl is registered.
                            }
                        }
                        _ => tracing::debug!("ignoring an unexpected frame from the orchestrator"),
                    },
                    Ok(None) => {
                        tracing::info!("the orchestrator closed the connection");
                        break DispatchLoopExit::Closed;
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "the orchestrator connection faulted");
                        break DispatchLoopExit::Faulted(e.to_string());
                    }
                }
            }
            worker_result = &mut worker_fut => {
                // `dispatch_tx` is still held by this loop at this point, so
                // `dispatch_rx.recv()` returning `None` (`Ok(())`) can't
                // happen yet — only a write failure's early `Err` return can
                // reach here (CodeRabbit on #344).
                worker_already_ended = true;
                match worker_result {
                    Err(e) => break DispatchLoopExit::Faulted(e),
                    Ok(()) => unreachable!(
                        "worker_fut only completes with Ok(()) once dispatch_tx is dropped, after this loop"
                    ),
                }
            }
            () = &mut shutdown => {
                tracing::info!("shutdown signal received; no longer reading new dispatches");
                break DispatchLoopExit::Shutdown;
            }
        }
    };

    // Fail-safe on every exit (this function's own doc above): the read loop
    // has ended for good, so no further AttachStateChanged can ever arrive,
    // regardless of why it ended. Stop the worker from starting anything
    // still queued, and bound every job still running to a grace deadline.
    stopping.store(true, Ordering::Relaxed);
    {
        let controls = controls.lock().unwrap_or_else(PoisonError::into_inner);
        if !controls.is_empty() {
            tracing::warn!(
                jobs = controls.len(),
                exit = ?exit,
                "the dispatch loop is ending while jobs are still running; no further AttachStateChanged frame can \
                 arrive, so their deadlines are being bounded to a grace period"
            );
        }
        // Only a currently-suspended (attached, deadline() == None) control
        // is bounded to the grace deadline here — a control that already
        // carries a finite deadline (never attached, or already past
        // detach and running its own grace period) keeps it as-is, so this
        // fail-safe can only ever shorten an unbounded wait, never extend
        // or overwrite a deadline already in force (CodeRabbit on #344).
        let grace_deadline = std::time::Instant::now() + Duration::from_secs(u64::from(STAGE1_TIMEOUT_SECS));
        for control in controls.values() {
            if control.deadline().is_none() {
                control.set_deadline(grace_deadline);
            }
            // #300: an explicit requested shutdown asks every still-running
            // job to actually stop, not just run out its (possibly
            // grace-bounded) deadline while `TimeoutStopSec` counts down
            // underneath it — see this function's own doc above for why
            // `Closed`/`Faulted` deliberately don't cancel.
            if exit == DispatchLoopExit::Shutdown {
                control.cancel();
            }
        }
    }

    // Let the worker drain whatever is already queued or in flight, then
    // end — never left running detached from this function's own return,
    // or `main.rs`'s process exit would simply kill it along with
    // everything else (nothing outlives this function once it returns).
    // Dropping `dispatch_tx` is what finally lets `worker_fut` complete
    // (`dispatch_rx.recv()` yields `None`) when it wasn't already ended
    // above by a write failure — `worker_already_ended` guards against
    // polling the same future again once it has already resolved.
    drop(dispatch_tx);
    if worker_already_ended {
        exit
    } else {
        match worker_fut.await {
            Ok(()) => exit,
            Err(e) => {
                // A later queued dispatch's own result also failed to write
                // during the drain: report that, not whatever the reader
                // concluded — a write fault is the more serious, more
                // truthful reason this function is ending (CodeRabbit on
                // #344: this previously surfaced as a misleadingly clean
                // Shutdown/Closed).
                tracing::warn!(error = %e, prior_exit = ?exit, "a queued dispatch's result failed to write during the drain");
                DispatchLoopExit::Faulted(e)
            }
        }
    }
}

/// Build the `HostExecutorMessage::Result` the host-executor sends back after a
/// dispatch ran to a physical [`Outcome`] (#292). It carries the facts —
/// booted, exit code, timeout, transport error, console — for the orchestrator
/// to classify into a terminal status; it does NOT classify here (the same
/// physical-outcome/classification split the backend seam draws).
#[must_use]
pub fn outcome_result_message(job_id: String, outcome: Outcome) -> HostExecutorMessage {
    HostExecutorMessage {
        op: Some(host_executor_message::Op::Result(JobResult {
            job_id,
            booted: outcome.booted,
            exit_code: outcome.guest_exit,
            timed_out: outcome.timed_out,
            transport_error: outcome.transport_error,
            console: outcome.console,
        })),
    }
}

/// Build the `HostExecutorMessage::Result` for a dispatch that never reached a
/// physical outcome — refused before launch, or the run task itself failed
/// (#292). Reported as not-booted with no exit and `reason` as the transport
/// error, so the orchestrator moves the job to a terminal FAILED state instead
/// of leaving it stuck. `reason` is an error string: never a secret, never the
/// job's console.
#[must_use]
pub fn failure_result_message(job_id: String, reason: String) -> HostExecutorMessage {
    HostExecutorMessage {
        op: Some(host_executor_message::Op::Result(JobResult {
            job_id,
            booted: false,
            exit_code: None,
            timed_out: false,
            transport_error: Some(reason),
            console: String::new(),
        })),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use anyhow::Context;
    use sandy_executor_proto::{Arch, AttachStateChanged, IsolationClass, RegisterRefused, Registered, SandboxKind};

    use super::*;

    /// A generous bound for tests that expect `register` to resolve quickly
    /// (the happy path, a refusal, a clean close) — never expected to fire,
    /// unlike [`SHORT_TIMEOUT`] which exists specifically to fire fast.
    const TEST_TIMEOUT: Duration = Duration::from_secs(5);
    /// Short enough that a test proving [`RegisterError::ResponseTimedOut`]
    /// fires doesn't cost real seconds, long enough that the orchestrator
    /// task's own read has time to complete first even under a loaded CI
    /// runner (a 50ms margin here flaked once under coverage instrumentation
    /// overhead — widened after that, not guessed up front).
    const SHORT_TIMEOUT: Duration = Duration::from_millis(500);

    fn capabilities() -> Capabilities {
        Capabilities {
            supported_sandbox_kinds: vec![SandboxKind::Process.into()],
            arch: Arch::X8664.into(),
            attestation: false,
            supported_isolation_classes: vec![IsolationClass::Trusted.into()],
        }
    }

    #[tokio::test]
    async fn register_sends_the_right_frame_and_accepts_registered() -> anyhow::Result<()> {
        let (mut client, mut server) = tokio::io::duplex(4096);

        let orchestrator = tokio::spawn(async move {
            let received: HostExecutorMessage = read_frame(&mut server).await?.context("expected Register")?;
            write_frame(
                &mut server,
                &OrchestratorMessage {
                    op: Some(orchestrator_message::Op::Registered(Registered {
                        host_id: "remote-host".to_owned(),
                    })),
                },
            )
            .await?;
            Ok::<_, anyhow::Error>(received)
        });

        register(&mut client, "remote-host", capabilities(), TEST_TIMEOUT).await?;

        let received = tokio::time::timeout(std::time::Duration::from_secs(2), orchestrator)
            .await
            .context("orchestrator task did not finish")?
            .context("orchestrator task panicked")??;
        match received.op {
            Some(host_executor_message::Op::Register(r)) => {
                assert_eq!(r.host_id, "remote-host");
                assert_eq!(r.capabilities, Some(capabilities()));
            }
            other => anyhow::bail!("expected Register, got {other:?}"),
        }
        Ok(())
    }

    #[tokio::test]
    async fn register_surfaces_a_refusal_reason() -> anyhow::Result<()> {
        let (mut client, mut server) = tokio::io::duplex(4096);

        let orchestrator = tokio::spawn(async move {
            let _received: HostExecutorMessage = read_frame(&mut server).await?.context("expected Register")?;
            write_frame(
                &mut server,
                &OrchestratorMessage {
                    op: Some(orchestrator_message::Op::Refused(RegisterRefused {
                        reason: "not a permitted executor host".to_owned(),
                    })),
                },
            )
            .await?;
            Ok::<_, anyhow::Error>(())
        });

        let err = register(&mut client, "impostor", capabilities(), TEST_TIMEOUT)
            .await
            .expect_err("a RegisterRefused response must surface as an error");
        assert_eq!(err, RegisterError::Refused("not a permitted executor host".to_owned()));

        tokio::time::timeout(std::time::Duration::from_secs(2), orchestrator)
            .await
            .context("orchestrator task did not finish")??
            .context("orchestrator task failed")?;
        Ok(())
    }

    #[tokio::test]
    async fn register_reports_a_clean_close_before_any_response() -> anyhow::Result<()> {
        let (mut client, mut server) = tokio::io::duplex(4096);

        let orchestrator = tokio::spawn(async move {
            let _received: HostExecutorMessage = read_frame(&mut server).await?.context("expected Register")?;
            drop(server); // closes after reading Register, before writing any response
            Ok::<_, anyhow::Error>(())
        });

        let err = register(&mut client, "remote-host", capabilities(), TEST_TIMEOUT)
            .await
            .expect_err("a connection closed with no response must be refused, not hang or panic");
        assert_eq!(err, RegisterError::ClosedBeforeResponse);

        tokio::time::timeout(std::time::Duration::from_secs(2), orchestrator)
            .await
            .context("orchestrator task did not finish")??
            .context("orchestrator task failed")?;
        Ok(())
    }

    /// Regression (CodeRabbit on #294): an orchestrator that accepts the
    /// connection, reads `Register`, and then stalls forever (never replies,
    /// never closes) must not hang this process indefinitely — it directly
    /// contradicts `main.rs`'s own "exit non-zero so the supervisor restarts
    /// it" design if registration itself can never return.
    #[tokio::test]
    async fn register_times_out_when_no_response_ever_arrives() -> anyhow::Result<()> {
        let (mut client, mut server) = tokio::io::duplex(4096);

        let orchestrator = tokio::spawn(async move {
            let _received: HostExecutorMessage = read_frame(&mut server).await?.context("expected Register")?;
            std::future::pending::<()>().await;
            Ok::<_, anyhow::Error>(())
        });

        let err = register(&mut client, "remote-host", capabilities(), SHORT_TIMEOUT)
            .await
            .expect_err("a stalled orchestrator must time out, not hang forever");
        assert_eq!(err, RegisterError::ResponseTimedOut);

        orchestrator.abort(); // still pending by design; nothing left to assert from it
        Ok(())
    }

    #[tokio::test]
    async fn the_dispatch_loop_calls_handle_for_each_dispatch_in_order() -> anyhow::Result<()> {
        let (mut client, mut server) = tokio::io::duplex(8192);

        // Returns `server` rather than dropping it at the end of the task:
        // dropping it here would close the duplex the instant the last frame
        // is written, racing the explicit shutdown below and making the loop
        // see `Closed` instead — this test is about the shutdown path, not
        // the close-on-disconnect one (that's its own test).
        let orchestrator = tokio::spawn(async move {
            for job_id in ["job-1", "job-2"] {
                write_frame(
                    &mut server,
                    &OrchestratorMessage {
                        op: Some(orchestrator_message::Op::Dispatch(Dispatch {
                            job_id: job_id.to_owned(),
                            manifest: Vec::new(),
                            manifest_encoding: String::new(),
                            backend: SandboxKind::Process.into(),
                            link_token: vec![0u8; 32],
                            forward_back: "127.0.0.1:9000".to_owned(),
                            required_isolation_class: IsolationClass::Trusted.into(),
                        })),
                    },
                )
                .await?;
            }
            Ok::<_, anyhow::Error>(server)
        });

        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen_in_loop = Arc::clone(&seen);
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

        let loop_task = tokio::spawn(async move {
            run_dispatch_loop(
                &mut client,
                move |dispatch, _control| {
                    let seen = Arc::clone(&seen_in_loop);
                    async move {
                        seen.lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .push(dispatch.job_id);
                        None::<HostExecutorMessage>
                    }
                },
                async {
                    let _ = shutdown_rx.await;
                },
            )
            .await
        });

        let _server = tokio::time::timeout(std::time::Duration::from_secs(2), orchestrator)
            .await
            .context("orchestrator task did not finish")??
            .context("orchestrator task failed")?;

        // Give the loop a moment to process both frames before asking it to
        // stop; `_server` staying alive (not dropped) means the loop would
        // otherwise wait forever for a third frame.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let _ = shutdown_tx.send(());
        let exit = tokio::time::timeout(std::time::Duration::from_secs(2), loop_task)
            .await
            .context("dispatch loop did not stop after shutdown")?
            .context("dispatch loop task panicked")?;
        assert_eq!(exit, DispatchLoopExit::Shutdown);

        assert_eq!(
            *seen.lock().unwrap_or_else(std::sync::PoisonError::into_inner),
            vec!["job-1".to_owned(), "job-2".to_owned()]
        );
        Ok(())
    }

    #[tokio::test]
    async fn the_dispatch_loop_stops_reading_once_shutdown_resolves() -> anyhow::Result<()> {
        let (mut client, _server) = tokio::io::duplex(4096); // never writes, never closes

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let loop_task = tokio::spawn(async move {
            run_dispatch_loop(
                &mut client,
                |_dispatch: Dispatch, _control| async { None::<HostExecutorMessage> },
                async {
                    let _ = shutdown_rx.await;
                },
            )
            .await
        });

        shutdown_tx.send(()).expect("receiver still alive");
        let exit = tokio::time::timeout(std::time::Duration::from_secs(2), loop_task)
            .await
            .context("the loop did not stop once shutdown resolved, even with no frame ever arriving")?
            .context("dispatch loop task panicked")?;
        assert_eq!(exit, DispatchLoopExit::Shutdown);
        Ok(())
    }

    /// Regression (CodeRabbit on #294): when the orchestrator disconnects
    /// (not a requested shutdown), `run_dispatch_loop` must report `Closed`,
    /// not swallow the distinction — `main.rs` uses this to exit non-zero so
    /// its supervisor restarts it, per decision 12's "no in-process
    /// reconnect" design.
    #[tokio::test]
    async fn the_dispatch_loop_reports_closed_when_the_orchestrator_disconnects() -> anyhow::Result<()> {
        let (mut client, server) = tokio::io::duplex(4096);
        drop(server); // the orchestrator is already gone before the loop even starts

        let (_shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let exit = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            run_dispatch_loop(
                &mut client,
                |_dispatch: Dispatch, _control| async { None::<HostExecutorMessage> },
                async {
                    let _ = shutdown_rx.await;
                },
            ),
        )
        .await
        .context("the loop did not stop once the connection closed")?;
        assert_eq!(exit, DispatchLoopExit::Closed);
        Ok(())
    }

    /// Adversarial: a frame that isn't `Dispatch` (stage 1 has no other
    /// orchestrator-sent message once registered) is ignored, not a reason to
    /// stop the loop — the next real `Dispatch` still gets handled.
    #[tokio::test]
    async fn an_unexpected_frame_is_ignored_not_fatal() -> anyhow::Result<()> {
        let (mut client, mut server) = tokio::io::duplex(8192);

        // Returns `server` rather than dropping it (same reasoning as
        // `the_dispatch_loop_calls_handle_for_each_dispatch_in_order`): this
        // test is about the ignore-and-continue path, not close-on-EOF.
        let orchestrator = tokio::spawn(async move {
            // Registered is a legitimate OrchestratorMessage variant, just
            // never expected again after registration — exercises the ignore
            // path without needing a malformed frame.
            write_frame(
                &mut server,
                &OrchestratorMessage {
                    op: Some(orchestrator_message::Op::Registered(Registered {
                        host_id: "remote-host".to_owned(),
                    })),
                },
            )
            .await?;
            write_frame(
                &mut server,
                &OrchestratorMessage {
                    op: Some(orchestrator_message::Op::Dispatch(Dispatch {
                        job_id: "job-1".to_owned(),
                        manifest: Vec::new(),
                        manifest_encoding: String::new(),
                        backend: SandboxKind::Process.into(),
                        link_token: vec![0u8; 32],
                        forward_back: "127.0.0.1:9000".to_owned(),
                        required_isolation_class: IsolationClass::Trusted.into(),
                    })),
                },
            )
            .await?;
            Ok::<_, anyhow::Error>(server)
        });

        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen_in_loop = Arc::clone(&seen);
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let loop_task = tokio::spawn(async move {
            run_dispatch_loop(
                &mut client,
                move |dispatch, _control| {
                    let seen = Arc::clone(&seen_in_loop);
                    async move {
                        seen.lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .push(dispatch.job_id);
                        None::<HostExecutorMessage>
                    }
                },
                async {
                    let _ = shutdown_rx.await;
                },
            )
            .await
        });

        let _server = tokio::time::timeout(std::time::Duration::from_secs(2), orchestrator)
            .await
            .context("orchestrator task did not finish")??
            .context("orchestrator task failed")?;
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let _ = shutdown_tx.send(());
        let exit = tokio::time::timeout(std::time::Duration::from_secs(2), loop_task)
            .await
            .context("dispatch loop did not stop after shutdown")?
            .context("dispatch loop task panicked")?;
        assert_eq!(exit, DispatchLoopExit::Shutdown);

        assert_eq!(
            *seen.lock().unwrap_or_else(std::sync::PoisonError::into_inner),
            vec!["job-1".to_owned()]
        );
        Ok(())
    }

    /// The load-bearing property for #292: after a dispatch is handled, the
    /// loop writes the result message `handle` returned back on the SAME
    /// connection the Dispatch arrived on, so the orchestrator actually
    /// receives it. The fix exists because the result was previously only
    /// logged and never sent.
    #[tokio::test]
    async fn the_dispatch_loop_sends_the_result_back_on_the_same_connection() -> anyhow::Result<()> {
        let (mut client, mut server) = tokio::io::duplex(8192);

        // Orchestrator side: push one Dispatch, then read the frame the loop
        // sends back. Returns `server` (not dropped) so the loop ends on the
        // explicit shutdown below, not on a close racing the result write.
        let orchestrator = tokio::spawn(async move {
            write_frame(
                &mut server,
                &OrchestratorMessage {
                    op: Some(orchestrator_message::Op::Dispatch(Dispatch {
                        job_id: "job-1".to_owned(),
                        manifest: Vec::new(),
                        manifest_encoding: String::new(),
                        backend: SandboxKind::Process.into(),
                        link_token: vec![0u8; 32],
                        forward_back: "127.0.0.1:9000".to_owned(),
                        required_isolation_class: IsolationClass::Trusted.into(),
                    })),
                },
            )
            .await?;
            let result: HostExecutorMessage = read_frame(&mut server).await?.context("expected a result frame")?;
            Ok::<_, anyhow::Error>((server, result))
        });

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let loop_task = tokio::spawn(async move {
            run_dispatch_loop(
                &mut client,
                // Stand in for handle_dispatch: return a result for the job.
                |dispatch: Dispatch, _control| async move {
                    Some(failure_result_message(dispatch.job_id, "boom".to_owned()))
                },
                async {
                    let _ = shutdown_rx.await;
                },
            )
            .await
        });

        let (_server, result) = tokio::time::timeout(std::time::Duration::from_secs(2), orchestrator)
            .await
            .context("orchestrator task did not finish")??
            .context("orchestrator task failed")?;
        match result.op {
            Some(host_executor_message::Op::Result(r)) => {
                assert_eq!(r.job_id, "job-1");
                assert_eq!(r.transport_error.as_deref(), Some("boom"));
                assert!(!r.booted);
                assert_eq!(r.exit_code, None);
            }
            other => anyhow::bail!("expected a JobResult frame, got {other:?}"),
        }

        let _ = shutdown_tx.send(());
        let exit = tokio::time::timeout(std::time::Duration::from_secs(2), loop_task)
            .await
            .context("dispatch loop did not stop after shutdown")?
            .context("dispatch loop task panicked")?;
        assert_eq!(exit, DispatchLoopExit::Shutdown);
        Ok(())
    }

    /// A connection whose reads delegate to a real [`tokio::io::DuplexStream`]
    /// (so `Dispatch` frames arrive normally) but whose writes always fail —
    /// deterministically forcing the result-write failure path
    /// [`a_failed_result_write_faults_the_loop_instead_of_a_clean_exit`]
    /// exercises, instead of racing a dropped duplex's read-side EOF against
    /// its write-side error (both close together on drop, so which one a
    /// `tokio::select!` observes first is not guaranteed).
    struct ReadOkWriteFails(tokio::io::DuplexStream);

    impl AsyncRead for ReadOkWriteFails {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for ReadOkWriteFails {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            _buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::task::Poll::Ready(Err(std::io::Error::other("simulated write failure")))
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    /// Regression (CodeRabbit on #344): a failed result write must not be
    /// silently logged and ignored — it must end the loop as
    /// `DispatchLoopExit::Faulted`, overriding whatever the reader side would
    /// otherwise have concluded (even an ordinary clean `Shutdown`), since a
    /// job whose result could never be delivered is a more serious condition
    /// than a clean disconnect.
    #[tokio::test]
    async fn a_failed_result_write_faults_the_loop_instead_of_a_clean_exit() -> anyhow::Result<()> {
        let (mut server, client) = tokio::io::duplex(8192);
        let mut conn = ReadOkWriteFails(client);

        write_frame(
            &mut server,
            &OrchestratorMessage {
                op: Some(orchestrator_message::Op::Dispatch(Dispatch {
                    job_id: "job-1".to_owned(),
                    manifest: Vec::new(),
                    manifest_encoding: String::new(),
                    backend: SandboxKind::Process.into(),
                    link_token: vec![0u8; 32],
                    forward_back: "127.0.0.1:9000".to_owned(),
                    required_isolation_class: IsolationClass::Trusted.into(),
                })),
            },
        )
        .await?;

        let (_shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let loop_task = tokio::spawn(async move {
            run_dispatch_loop(
                &mut conn,
                |dispatch: Dispatch, _control| async move {
                    Some(failure_result_message(dispatch.job_id, "boom".to_owned()))
                },
                async {
                    let _ = shutdown_rx.await;
                },
            )
            .await
        });

        let exit = tokio::time::timeout(std::time::Duration::from_secs(2), loop_task)
            .await
            .context("dispatch loop did not end after its result write failed")?
            .context("dispatch loop task panicked")?;
        assert!(
            matches!(exit, DispatchLoopExit::Faulted(_)),
            "expected Faulted after a failed result write, got {exit:?}"
        );
        drop(server);
        Ok(())
    }

    /// Regression (CodeRabbit on #344): the shutdown fail-safe must actually
    /// bound a still-attached (suspended) job's deadline, and `stopping` must
    /// actually keep the worker from starting a dispatch still sitting in its
    /// queue, unstarted, once shutdown has ended the read loop. Job-1's
    /// `handle` blocks on a `Notify` so the test controls exactly when
    /// shutdown fires relative to job-1 still running and job-2 still queued;
    /// job-2's `handle` would record itself in `seen` if it were ever
    /// (incorrectly) called, so its absence from `seen` is the proof it was
    /// skipped, not merely never reached.
    #[tokio::test]
    async fn shutdown_bounds_an_attached_jobs_deadline_and_skips_a_still_queued_dispatch() -> anyhow::Result<()> {
        let (mut client, mut server) = tokio::io::duplex(8192);

        write_frame(
            &mut server,
            &OrchestratorMessage {
                op: Some(orchestrator_message::Op::Dispatch(Dispatch {
                    job_id: "job-1".to_owned(),
                    manifest: Vec::new(),
                    manifest_encoding: String::new(),
                    backend: SandboxKind::Process.into(),
                    link_token: vec![0u8; 32],
                    forward_back: "127.0.0.1:9000".to_owned(),
                    required_isolation_class: IsolationClass::Trusted.into(),
                })),
            },
        )
        .await?;

        let captured_control: Arc<Mutex<Option<RunControl>>> = Arc::new(Mutex::new(None));
        let captured_control_in_loop = Arc::clone(&captured_control);
        let job1_started = Arc::new(tokio::sync::Notify::new());
        let job1_started_in_loop = Arc::clone(&job1_started);
        let release_job1 = Arc::new(tokio::sync::Notify::new());
        let release_job1_in_loop = Arc::clone(&release_job1);
        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen_in_loop = Arc::clone(&seen);

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let loop_task = tokio::spawn(async move {
            run_dispatch_loop(
                &mut client,
                move |dispatch, control| {
                    let captured_control = Arc::clone(&captured_control_in_loop);
                    let job1_started = Arc::clone(&job1_started_in_loop);
                    let release_job1 = Arc::clone(&release_job1_in_loop);
                    let seen = Arc::clone(&seen_in_loop);
                    async move {
                        seen.lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .push(dispatch.job_id.clone());
                        if dispatch.job_id == "job-1" {
                            // Simulates an already-attached job: suspended,
                            // no deadline, exactly the state the shutdown
                            // fail-safe must bound.
                            control.suspend_deadline();
                            *captured_control
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(control.clone());
                            job1_started.notify_one();
                            release_job1.notified().await;
                        }
                        None::<HostExecutorMessage>
                    }
                },
                async {
                    let _ = shutdown_rx.await;
                },
            )
            .await
        });

        tokio::time::timeout(std::time::Duration::from_secs(2), job1_started.notified())
            .await
            .context("job-1's handle never started")?;

        // Queued but never started while job-1's handle still blocks below.
        write_frame(
            &mut server,
            &OrchestratorMessage {
                op: Some(orchestrator_message::Op::Dispatch(Dispatch {
                    job_id: "job-2".to_owned(),
                    manifest: Vec::new(),
                    manifest_encoding: String::new(),
                    backend: SandboxKind::Process.into(),
                    link_token: vec![0u8; 32],
                    forward_back: "127.0.0.1:9000".to_owned(),
                    required_isolation_class: IsolationClass::Trusted.into(),
                })),
            },
        )
        .await?;
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        let _ = shutdown_tx.send(());
        // Gives the now-broken-out select loop time to run the fail-safe
        // (synchronous, no further awaits of its own) before this checks
        // job-1's captured deadline below.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        let deadline = captured_control
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .expect("job-1's control was captured")
            .deadline();
        assert!(
            deadline.is_some(),
            "the shutdown fail-safe must bound a suspended (attached) job's deadline, got None (still suspended)"
        );

        release_job1.notify_one();
        let exit = tokio::time::timeout(std::time::Duration::from_secs(2), loop_task)
            .await
            .context("dispatch loop did not end after job-1 was released")?
            .context("dispatch loop task panicked")?;
        assert_eq!(exit, DispatchLoopExit::Shutdown);

        assert_eq!(
            *seen.lock().unwrap_or_else(std::sync::PoisonError::into_inner),
            vec!["job-1".to_owned()],
            "job-2 must never be handled: it was still queued, unstarted, once shutdown ended the read loop"
        );
        drop(server);
        Ok(())
    }

    /// Fix (#300): `systemctl stop sandy-executor` sends SIGTERM and SIGKILLs
    /// the whole process after `TimeoutStopSec` — shorter than a job's own
    /// up-to-`STAGE1_TIMEOUT_SECS` budget — so a requested shutdown must give
    /// a still-running job's `RunControl` a real `cancel()`, not just a
    /// bounded deadline: a backend's run loop polls `is_cancelled()` on every
    /// tick (far more often than it checks a deadline), so cancelling tears
    /// the job down fast instead of leaving its sandbox to be killed out from
    /// under it with no clean teardown (the orphan this issue is about).
    #[tokio::test]
    async fn shutdown_cancels_every_still_running_jobs_run_control() -> anyhow::Result<()> {
        let (mut client, mut server) = tokio::io::duplex(8192);

        write_frame(
            &mut server,
            &OrchestratorMessage {
                op: Some(orchestrator_message::Op::Dispatch(Dispatch {
                    job_id: "job-1".to_owned(),
                    manifest: Vec::new(),
                    manifest_encoding: String::new(),
                    backend: SandboxKind::Process.into(),
                    link_token: vec![0u8; 32],
                    forward_back: "127.0.0.1:9000".to_owned(),
                    required_isolation_class: IsolationClass::Trusted.into(),
                })),
            },
        )
        .await?;

        let captured_control: Arc<Mutex<Option<RunControl>>> = Arc::new(Mutex::new(None));
        let captured_control_in_loop = Arc::clone(&captured_control);
        let job1_started = Arc::new(tokio::sync::Notify::new());
        let job1_started_in_loop = Arc::clone(&job1_started);
        let release_job1 = Arc::new(tokio::sync::Notify::new());
        let release_job1_in_loop = Arc::clone(&release_job1);

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let loop_task = tokio::spawn(async move {
            run_dispatch_loop(
                &mut client,
                move |_dispatch, control| {
                    let captured_control = Arc::clone(&captured_control_in_loop);
                    let job1_started = Arc::clone(&job1_started_in_loop);
                    let release_job1 = Arc::clone(&release_job1_in_loop);
                    async move {
                        *captured_control
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(control.clone());
                        job1_started.notify_one();
                        release_job1.notified().await;
                        None::<HostExecutorMessage>
                    }
                },
                async {
                    let _ = shutdown_rx.await;
                },
            )
            .await
        });

        tokio::time::timeout(std::time::Duration::from_secs(2), job1_started.notified())
            .await
            .context("job-1's handle never started")?;

        let _ = shutdown_tx.send(());
        // Gives the now-broken-out select loop time to run the fail-safe
        // (synchronous, no further awaits of its own) before this checks
        // job-1's captured control below.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        let cancelled = captured_control
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .expect("job-1's control was captured")
            .is_cancelled();
        assert!(
            cancelled,
            "an explicit requested shutdown must cancel a still-running job's RunControl"
        );

        release_job1.notify_one();
        let exit = tokio::time::timeout(std::time::Duration::from_secs(2), loop_task)
            .await
            .context("dispatch loop did not end after job-1 was released")?
            .context("dispatch loop task panicked")?;
        assert_eq!(exit, DispatchLoopExit::Shutdown);
        drop(server);
        Ok(())
    }

    /// A lost connection (`Closed`) must NOT cancel a still-running job:
    /// nothing is racing a systemd kill in that case — `main.rs` lets the
    /// drain finish on its own time before exiting non-zero for its
    /// supervisor to restart it (decision 12). Only an explicit, requested
    /// [`DispatchLoopExit::Shutdown`] does (#300) — this pins that scoping
    /// decision so it can't silently drift to cancelling on every exit.
    #[tokio::test]
    async fn a_closed_connection_does_not_cancel_a_still_running_job() -> anyhow::Result<()> {
        let (mut client, mut server) = tokio::io::duplex(8192);

        write_frame(
            &mut server,
            &OrchestratorMessage {
                op: Some(orchestrator_message::Op::Dispatch(Dispatch {
                    job_id: "job-1".to_owned(),
                    manifest: Vec::new(),
                    manifest_encoding: String::new(),
                    backend: SandboxKind::Process.into(),
                    link_token: vec![0u8; 32],
                    forward_back: "127.0.0.1:9000".to_owned(),
                    required_isolation_class: IsolationClass::Trusted.into(),
                })),
            },
        )
        .await?;

        let captured_control: Arc<Mutex<Option<RunControl>>> = Arc::new(Mutex::new(None));
        let captured_control_in_loop = Arc::clone(&captured_control);
        let job1_started = Arc::new(tokio::sync::Notify::new());
        let job1_started_in_loop = Arc::clone(&job1_started);
        let release_job1 = Arc::new(tokio::sync::Notify::new());
        let release_job1_in_loop = Arc::clone(&release_job1);

        let (_shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let loop_task = tokio::spawn(async move {
            run_dispatch_loop(
                &mut client,
                move |_dispatch, control| {
                    let captured_control = Arc::clone(&captured_control_in_loop);
                    let job1_started = Arc::clone(&job1_started_in_loop);
                    let release_job1 = Arc::clone(&release_job1_in_loop);
                    async move {
                        *captured_control
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(control.clone());
                        job1_started.notify_one();
                        release_job1.notified().await;
                        None::<HostExecutorMessage>
                    }
                },
                async {
                    let _ = shutdown_rx.await;
                },
            )
            .await
        });

        tokio::time::timeout(std::time::Duration::from_secs(2), job1_started.notified())
            .await
            .context("job-1's handle never started")?;

        drop(server); // the orchestrator disconnects instead of a requested shutdown

        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        let cancelled = captured_control
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .expect("job-1's control was captured")
            .is_cancelled();
        assert!(
            !cancelled,
            "a Closed connection must not cancel a still-running job — only an explicit Shutdown does"
        );

        release_job1.notify_one();
        let exit = tokio::time::timeout(std::time::Duration::from_secs(2), loop_task)
            .await
            .context("dispatch loop did not end after job-1 was released")?
            .context("dispatch loop task panicked")?;
        assert_eq!(exit, DispatchLoopExit::Closed);
        Ok(())
    }

    /// Regression (CodeRabbit on #344): a reordered, stale-sequence
    /// `AttachStateChanged` must not overwrite the newer state a
    /// higher-sequence frame already applied.
    #[tokio::test]
    async fn a_lower_sequence_attach_state_change_is_ignored_after_a_higher_one() -> anyhow::Result<()> {
        let (mut client, mut server) = tokio::io::duplex(8192);

        let orchestrator = tokio::spawn(async move {
            write_frame(
                &mut server,
                &OrchestratorMessage {
                    op: Some(orchestrator_message::Op::Dispatch(Dispatch {
                        job_id: "job-1".to_owned(),
                        manifest: Vec::new(),
                        manifest_encoding: String::new(),
                        backend: SandboxKind::Process.into(),
                        link_token: vec![0u8; 32],
                        forward_back: "127.0.0.1:9000".to_owned(),
                        required_isolation_class: IsolationClass::Trusted.into(),
                    })),
                },
            )
            .await?;
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            write_frame(
                &mut server,
                &OrchestratorMessage {
                    op: Some(orchestrator_message::Op::AttachStateChanged(AttachStateChanged {
                        job_id: "job-1".to_owned(),
                        attached: true,
                        sequence: 5,
                    })),
                },
            )
            .await?;
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            // Reordered in flight: a stale detach with a LOWER sequence than
            // the attach already applied above.
            write_frame(
                &mut server,
                &OrchestratorMessage {
                    op: Some(orchestrator_message::Op::AttachStateChanged(AttachStateChanged {
                        job_id: "job-1".to_owned(),
                        attached: false,
                        sequence: 2,
                    })),
                },
            )
            .await?;
            Ok::<_, anyhow::Error>(server)
        });

        let seen_control = Arc::new(Mutex::new(None));
        let seen_control_in_loop = Arc::clone(&seen_control);
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let loop_task = tokio::spawn(async move {
            run_dispatch_loop(
                &mut client,
                move |_dispatch, control| {
                    let seen_control = Arc::clone(&seen_control_in_loop);
                    async move {
                        *seen_control.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Some(control);
                        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                        None::<HostExecutorMessage>
                    }
                },
                async {
                    let _ = shutdown_rx.await;
                },
            )
            .await
        });

        let _server = tokio::time::timeout(std::time::Duration::from_secs(2), orchestrator)
            .await
            .context("orchestrator task did not finish")??
            .context("orchestrator task failed")?;
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        let _ = shutdown_tx.send(());
        let exit = tokio::time::timeout(std::time::Duration::from_secs(2), loop_task)
            .await
            .context("dispatch loop did not stop after shutdown")?
            .context("dispatch loop task panicked")?;
        assert_eq!(exit, DispatchLoopExit::Shutdown);

        let control = seen_control
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
            .expect("handle was called");
        assert!(
            control.deadline().is_none(),
            "the stale, lower-sequence detach must not have overwritten the newer attach's suspended deadline"
        );
        Ok(())
    }

    /// Regression (CodeRabbit on #344): an `AttachStateChanged` that outraces
    /// its own job's `Dispatch` must still apply once that job registers a
    /// `RunControl`, not be silently dropped for an unknown job_id.
    #[tokio::test]
    async fn an_attach_state_change_received_before_its_jobs_dispatch_is_applied_once_it_starts() -> anyhow::Result<()>
    {
        let (mut client, mut server) = tokio::io::duplex(8192);

        let orchestrator = tokio::spawn(async move {
            write_frame(
                &mut server,
                &OrchestratorMessage {
                    op: Some(orchestrator_message::Op::AttachStateChanged(AttachStateChanged {
                        job_id: "job-1".to_owned(),
                        attached: true,
                        sequence: 1,
                    })),
                },
            )
            .await?;
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            write_frame(
                &mut server,
                &OrchestratorMessage {
                    op: Some(orchestrator_message::Op::Dispatch(Dispatch {
                        job_id: "job-1".to_owned(),
                        manifest: Vec::new(),
                        manifest_encoding: String::new(),
                        backend: SandboxKind::Process.into(),
                        link_token: vec![0u8; 32],
                        forward_back: "127.0.0.1:9000".to_owned(),
                        required_isolation_class: IsolationClass::Trusted.into(),
                    })),
                },
            )
            .await?;
            Ok::<_, anyhow::Error>(server)
        });

        let seen_deadline = Arc::new(Mutex::new(None));
        let seen_deadline_in_loop = Arc::clone(&seen_deadline);
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let loop_task = tokio::spawn(async move {
            run_dispatch_loop(
                &mut client,
                move |_dispatch, control| {
                    let seen_deadline = Arc::clone(&seen_deadline_in_loop);
                    async move {
                        *seen_deadline.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
                            Some(control.deadline());
                        None::<HostExecutorMessage>
                    }
                },
                async {
                    let _ = shutdown_rx.await;
                },
            )
            .await
        });

        let _server = tokio::time::timeout(std::time::Duration::from_secs(2), orchestrator)
            .await
            .context("orchestrator task did not finish")??
            .context("orchestrator task failed")?;
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let _ = shutdown_tx.send(());
        let exit = tokio::time::timeout(std::time::Duration::from_secs(2), loop_task)
            .await
            .context("dispatch loop did not stop after shutdown")?
            .context("dispatch loop task panicked")?;
        assert_eq!(exit, DispatchLoopExit::Shutdown);

        let deadline = seen_deadline
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .expect("handle was called");
        assert!(
            deadline.is_none(),
            "a pre-registration attach signal should already have suspended the job's deadline by the time it starts"
        );
        Ok(())
    }

    #[test]
    fn outcome_result_message_carries_the_physical_outcome_verbatim() {
        let outcome = Outcome {
            booted: true,
            guest_exit: Some(0),
            transport_error: None,
            timed_out: false,
            console: "hi\n".to_owned(),
        };
        let message = outcome_result_message("job-1".to_owned(), outcome);
        match message.op {
            Some(host_executor_message::Op::Result(result)) => {
                assert_eq!(result.job_id, "job-1");
                assert!(result.booted);
                assert_eq!(result.exit_code, Some(0));
                assert!(!result.timed_out);
                assert_eq!(result.transport_error, None);
                assert_eq!(result.console, "hi\n");
            }
            other => panic!("expected a JobResult, got {other:?}"),
        }
    }

    /// A refusal/panic reports a failure the orchestrator can move to FAILED:
    /// not booted, no exit, the reason as the transport error, empty console.
    #[test]
    fn failure_result_message_reports_no_exit_and_the_reason() {
        let message = failure_result_message("job-1".to_owned(), "refused".to_owned());
        match message.op {
            Some(host_executor_message::Op::Result(result)) => {
                assert_eq!(result.job_id, "job-1");
                assert!(!result.booted);
                assert_eq!(result.exit_code, None);
                assert!(!result.timed_out);
                assert_eq!(result.transport_error.as_deref(), Some("refused"));
                assert!(result.console.is_empty());
            }
            other => panic!("expected a JobResult, got {other:?}"),
        }
    }
}
