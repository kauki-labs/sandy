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

use std::time::Duration;

use sandy_api::backend::Outcome;
use sandy_control_proto::{read_frame, write_frame};
use sandy_executor_proto::{
    Capabilities, Dispatch, HostExecutorMessage, JobResult, OrchestratorMessage, host_executor_message,
    orchestrator_message,
};
use tokio::io::{AsyncRead, AsyncWrite};

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
    /// The connection faulted: a malformed frame, an I/O error.
    Faulted(String),
}

/// Read `OrchestratorMessage` frames off `conn` until it closes, faults, or
/// `shutdown` resolves, calling `handle` with each `Dispatch` and awaiting it
/// to completion before reading the next frame (decision 14: sequential, one
/// job at a time). Any other frame shape is logged and ignored — stage 1's
/// orchestrator never sends anything else once registered (`sandyd::
/// host_conn`'s own doc says the same of an unexpected frame on its side).
///
/// `handle` returns the result message to send back for that dispatch (#292):
/// the loop writes it on the SAME `conn` the Dispatch arrived on, before
/// reading the next frame, so a job's outcome reaches the orchestrator over
/// the one management connection rather than being dropped on the floor. A
/// `None` return sends nothing. A failure writing the result frame ends the
/// loop as [`DispatchLoopExit::Faulted`], same as any other connection fault —
/// the supervisor restarts the process (decision 12).
pub async fn run_dispatch_loop<F, Fut>(
    conn: &mut (impl AsyncRead + AsyncWrite + Unpin),
    mut handle: F,
    shutdown: impl std::future::Future<Output = ()>,
) -> DispatchLoopExit
where
    F: FnMut(Dispatch) -> Fut,
    Fut: std::future::Future<Output = Option<HostExecutorMessage>>,
{
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            frame = read_frame::<OrchestratorMessage>(conn) => {
                match frame {
                    Ok(Some(message)) => match message.op {
                        Some(orchestrator_message::Op::Dispatch(dispatch)) => {
                            // Sequential (decision 14): the Dispatch runs to
                            // completion here, and its result is written back
                            // before the next frame is read — conn is free to
                            // write on, since read_frame already resolved.
                            if let Some(result) = handle(dispatch).await
                                && let Err(e) = write_frame(conn, &result).await
                            {
                                tracing::warn!(error = %e, "failed writing a job result back to the orchestrator");
                                return DispatchLoopExit::Faulted(e.to_string());
                            }
                        }
                        _ => tracing::debug!("ignoring an unexpected frame from the orchestrator"),
                    },
                    Ok(None) => {
                        tracing::info!("the orchestrator closed the connection");
                        return DispatchLoopExit::Closed;
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "the orchestrator connection faulted");
                        return DispatchLoopExit::Faulted(e.to_string());
                    }
                }
            }
            () = &mut shutdown => {
                tracing::info!("shutdown signal received; no longer reading new dispatches");
                return DispatchLoopExit::Shutdown;
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
    use sandy_executor_proto::{Arch, IsolationClass, RegisterRefused, Registered, SandboxKind};

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
            kind: SandboxKind::Process.into(),
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
                        host_id: "ws01".to_owned(),
                    })),
                },
            )
            .await?;
            Ok::<_, anyhow::Error>(received)
        });

        register(&mut client, "ws01", capabilities(), TEST_TIMEOUT).await?;

        let received = tokio::time::timeout(std::time::Duration::from_secs(2), orchestrator)
            .await
            .context("orchestrator task did not finish")?
            .context("orchestrator task panicked")??;
        match received.op {
            Some(host_executor_message::Op::Register(r)) => {
                assert_eq!(r.host_id, "ws01");
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

        let err = register(&mut client, "ws01", capabilities(), TEST_TIMEOUT)
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

        let err = register(&mut client, "ws01", capabilities(), SHORT_TIMEOUT)
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
                move |dispatch| {
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
                |_dispatch: Dispatch| async { None::<HostExecutorMessage> },
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
                |_dispatch: Dispatch| async { None::<HostExecutorMessage> },
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
                        host_id: "ws01".to_owned(),
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
                move |dispatch| {
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
                |dispatch: Dispatch| async move { Some(failure_result_message(dispatch.job_id, "boom".to_owned())) },
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
