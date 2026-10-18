//! The host-client's main loop (#288): register once, then receive
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

use sandy_control_proto::{read_frame, write_frame};
use sandy_executor_proto::{
    Capabilities, Dispatch, HostClientMessage, OrchestratorMessage, host_client_message, orchestrator_message,
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
    let message = HostClientMessage {
        op: Some(host_client_message::Op::Register(sandy_executor_proto::Register {
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
/// host-client and it should exit non-zero for its supervisor to restart it
/// (CodeRabbit finding on #294: returning `()` unconditionally made a
/// disconnected host-client exit 0, exactly the case the module's own "the
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
pub async fn run_dispatch_loop<F, Fut>(
    conn: &mut (impl AsyncRead + AsyncWrite + Unpin),
    mut handle: F,
    shutdown: impl std::future::Future<Output = ()>,
) -> DispatchLoopExit
where
    F: FnMut(Dispatch) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            frame = read_frame::<OrchestratorMessage>(conn) => {
                match frame {
                    Ok(Some(message)) => match message.op {
                        Some(orchestrator_message::Op::Dispatch(dispatch)) => handle(dispatch).await,
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
            let received: HostClientMessage = read_frame(&mut server).await?.context("expected Register")?;
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
            Some(host_client_message::Op::Register(r)) => {
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
            let _received: HostClientMessage = read_frame(&mut server).await?.context("expected Register")?;
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
            let _received: HostClientMessage = read_frame(&mut server).await?.context("expected Register")?;
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
            let _received: HostClientMessage = read_frame(&mut server).await?.context("expected Register")?;
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
            run_dispatch_loop(&mut client, |_dispatch: Dispatch| async {}, async {
                let _ = shutdown_rx.await;
            })
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
            run_dispatch_loop(&mut client, |_dispatch: Dispatch| async {}, async {
                let _ = shutdown_rx.await;
            }),
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
}
